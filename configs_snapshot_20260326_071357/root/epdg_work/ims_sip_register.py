#!/usr/bin/env python3
import argparse
import base64
import binascii
import hashlib
import random
import re
import select
import socket
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

from swu_emulator import return_res_ck_ik


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="IMS SIP test client for SWu testbed")
    parser.add_argument("--local-ip", required=True, help="UE inner IP address, e.g. 10.46.0.100")
    parser.add_argument("--pcscf-ip", required=True, help="P-CSCF IP address, e.g. 10.46.0.2")
    parser.add_argument("--pcscf-port", type=int, default=5060, help="P-CSCF SIP port")
    parser.add_argument("--imsi", required=True, help="IMSI / private identity")
    parser.add_argument("--realm", default="localdomain", help="Home IMS realm/domain used by public/private identities")
    parser.add_argument("--register-domain", help="REGISTER request domain, defaults to P-CSCF IP")
    parser.add_argument("--public-id", help="Public SIP URI user part, defaults to IMSI")
    parser.add_argument("--private-id", help="Private identity username@realm, defaults to IMSI@realm")
    parser.add_argument("--contact-port", type=int, default=5062, help="UE SIP contact port")
    parser.add_argument("--invite-port", type=int, help="Local port for INVITE, defaults to sec-port-c or contact-port")
    parser.add_argument("--sec-port-c", type=int, help="Security-Client port-c, defaults to contact-port")
    parser.add_argument("--sec-port-s", type=int, default=5060, help="Security-Client port-s")
    parser.add_argument("--sec-prot", default="udp", help="Security-Client prot value")
    parser.add_argument("--sec-mode", default="trans", help="Security-Client mod value")
    parser.add_argument("--sec-alg", default="hmac-md5-96", help="Security-Client alg value")
    parser.add_argument("--sec-ealg", default="null", help="Security-Client ealg value")
    parser.add_argument("--expires", type=int, default=600, help="REGISTER expires")
    parser.add_argument("--invite-target", help="Target SIP URI for INVITE, defaults to own public URI")
    parser.add_argument("--pani", help="P-Access-Network-Info header value (optional)")
    parser.add_argument("--pvni", help="P-Visited-Network-ID header value (optional)")
    parser.add_argument("--p-asserted-id", help="P-Asserted-Identity URI (optional)")
    parser.add_argument(
        "--invite-same-dialog",
        action="store_true",
        help="Reuse REGISTER Call-ID/From tag for INVITE (not recommended)",
    )
    parser.add_argument(
        "--no-contact-tags",
        action="store_true",
        help="Omit +sip.instance and +g.3gpp.icsi-ref tags in Contact",
    )
    parser.add_argument("--actions", default="register", help="Comma-separated actions: register,re-register,deregister,invite")
    parser.add_argument("--ki", help="USIM Ki")
    parser.add_argument("--op", help="USIM OP")
    parser.add_argument("--opc", help="USIM OPc")
    parser.add_argument("--modem", default="", help="Optional modem / reader / https backend identifier")
    parser.add_argument("--timeout", type=float, default=1.0, help="UDP receive timeout in seconds")
    parser.add_argument("--window", type=float, default=8.0, help="Per-transaction receive window in seconds")
    return parser.parse_args()


def md5_hex(value: str) -> str:
    return hashlib.md5(value.encode()).hexdigest()


def md5_bytes_hex(value: bytes) -> str:
    return hashlib.md5(value).hexdigest()


def parse_headers(message: str) -> Tuple[str, Dict[str, List[str]], str]:
    head, _, body = message.partition("\r\n\r\n")
    lines = [line for line in head.split("\r\n") if line]
    start_line = lines[0] if lines else ""
    headers: Dict[str, List[str]] = {}
    current_name: Optional[str] = None
    for line in lines[1:]:
        if line.startswith((" ", "\t")) and current_name:
            headers[current_name][-1] += line.strip()
            continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        current_name = name.strip().lower()
        headers.setdefault(current_name, []).append(value.strip())
    return start_line, headers, body


def build_simple_response(request: str, status_code: int, reason: str) -> str:
    _, headers, _ = parse_headers(request)
    via = headers.get("via", [""])[0]
    from_header = headers.get("from", [""])[0]
    to_header = headers.get("to", [""])[0]
    call_id = headers.get("call-id", [""])[0]
    cseq = headers.get("cseq", [""])[0]
    lines = [
        f"SIP/2.0 {status_code} {reason}",
        f"Via: {via}",
        f"From: {from_header}",
        f"To: {to_header}",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq}",
        "Content-Length: 0",
        "",
        "",
    ]
    return "\r\n".join(lines)


def parse_auth_params(value: str) -> Dict[str, str]:
    params: Dict[str, str] = {}
    value = value.strip()
    if " " in value:
        scheme, rest = value.split(" ", 1)
        params["_scheme"] = scheme.strip()
    else:
        params["_scheme"] = value
        return params
    for match in re.finditer(r'([A-Za-z0-9_-]+)=("([^"]*)"|[^,]+)', rest):
        key = match.group(1).strip().lower()
        raw = match.group(2).strip()
        if raw.startswith('"') and raw.endswith('"'):
            raw = raw[1:-1]
        params[key] = raw
    return params


def parse_security_params(value: str) -> Dict[str, str]:
    params: Dict[str, str] = {}
    for index, part in enumerate(value.split(";")):
        item = part.strip()
        if not item:
            continue
        if "=" not in item:
            if index == 0:
                params["_scheme"] = item
            continue
        key, raw = item.split("=", 1)
        params[key.strip().lower()] = raw.strip().strip('"')
    return params


def normalize_sip_uri(value: str, default_domain: Optional[str] = None) -> str:
    cleaned = value.strip()
    if cleaned.startswith(("sip:", "sips:", "tel:")):
        return cleaned
    if "@" in cleaned:
        return f"sip:{cleaned}"
    if default_domain:
        return f"sip:{cleaned}@{default_domain}"
    return f"sip:{cleaned}"


def normalize_public_identity(value: Optional[str], realm: str, imsi: str) -> Tuple[str, str]:
    raw_value = (value or imsi).strip()
    if raw_value.startswith("sip:"):
        user_part = raw_value[4:].split("@", 1)[0]
        return user_part, raw_value
    if raw_value.startswith("sips:"):
        user_part = raw_value[5:].split("@", 1)[0]
        return user_part, raw_value
    if raw_value.startswith("tel:"):
        return raw_value[4:], raw_value
    if "@" in raw_value:
        user_part = raw_value.split("@", 1)[0]
        return user_part, f"sip:{raw_value}"
    return raw_value, f"sip:{raw_value}@{realm}"


def decode_nonce_to_rand_autn(nonce: str) -> Tuple[str, str]:
    cleaned = nonce.strip()
    raw = b""
    try:
        padded = cleaned + "=" * (-len(cleaned) % 4)
        raw = base64.b64decode(padded, validate=False)
    except Exception:
        raw = b""
    if len(raw) >= 32:
        return raw[:16].hex(), raw[16:32].hex()
    if re.fullmatch(r"[0-9A-Fa-f]{32,}", cleaned):
        return cleaned[:32], cleaned[32:64]
    raise ValueError(f"unable to decode nonce into RAND/AUTN: {nonce}")


def build_authorization(
    username: str,
    realm: str,
    method: str,
    uri: str,
    challenge: Dict[str, str],
    password: bytes | str,
) -> str:
    nonce = challenge["nonce"]
    algorithm = challenge.get("algorithm", "MD5")
    qop = challenge.get("qop", "")
    cnonce = f"{random.getrandbits(64):016x}"
    nc = "00000001"
    if isinstance(password, bytes):
        ha1 = md5_bytes_hex(username.encode() + b":" + realm.encode() + b":" + password)
    else:
        ha1 = md5_hex(f"{username}:{realm}:{password}")
    ha2 = md5_hex(f"{method}:{uri}")
    if qop:
        qop_token = qop.split(",")[0].strip()
        response = md5_hex(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop_token}:{ha2}")
    else:
        qop_token = ""
        response = md5_hex(f"{ha1}:{nonce}:{ha2}")
    parts = [
        f'username="{username}"',
        f'realm="{realm}"',
        f'nonce="{nonce}"',
        f'uri="{uri}"',
        f'response="{response}"',
        f'algorithm={algorithm}',
    ]
    if "opaque" in challenge:
        parts.append(f'opaque="{challenge["opaque"]}"')
    if qop_token:
        parts.extend([f"qop={qop_token}", f"nc={nc}", f'cnonce="{cnonce}"'])
    return "Digest " + ", ".join(parts)


class ImsSipClient:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.private_id = args.private_id or f"{args.imsi}@{args.realm}"
        self.public_user, self.public_uri = normalize_public_identity(args.public_id, args.realm, args.imsi)
        register_domain = args.register_domain or args.pcscf_ip
        self.register_uri = normalize_sip_uri(register_domain)
        self.invite_target = normalize_sip_uri(args.invite_target, args.realm) if args.invite_target else self.public_uri
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((args.local_ip, args.contact_port))
        self.sock.setblocking(False)
        self.sec_rx_sock: Optional[socket.socket] = None
        if args.sec_port_s and args.sec_port_s != args.contact_port:
            self.sec_rx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sec_rx_sock.bind((args.local_ip, args.sec_port_s))
            self.sec_rx_sock.setblocking(False)
        self.call_id = f"{random.randint(100000, 999999)}@{args.local_ip}"
        self.from_tag = f"{random.randint(100000, 999999)}"
        self.security_client = self._security_client()
        self.security_verify = ""
        self.cseq = 1
        self.last_nonce: Optional[str] = None
        self.last_auth_info: Optional[str] = None
        self.service_routes: List[str] = []
        self.invite_port = args.invite_port or args.sec_port_c or args.contact_port
        self.security_server_params: Dict[str, str] = {}
        self.last_ck: Optional[str] = None
        self.last_ik: Optional[str] = None

    def _parse_route_set(self, values: List[str]) -> List[str]:
        routes: List[str] = []
        for value in values:
            for part in value.split(","):
                item = part.strip()
                if item:
                    routes.append(item)
        return routes

    def _route_set(self) -> List[str]:
        return self.service_routes

    def _security_client(self) -> str:
        spi_c = random.randint(10000, 99999)
        spi_s = random.randint(10000, 99999)
        port_c = self.args.sec_port_c or self.args.contact_port
        return (
            f"ipsec-3gpp;alg={self.args.sec_alg};ealg={self.args.sec_ealg};"
            f"spi-c={spi_c};spi-s={spi_s};port-c={port_c};port-s={self.args.sec_port_s};"
            f"prot={self.args.sec_prot};mod={self.args.sec_mode}"
        )

    def _contact(self, port: Optional[int] = None) -> str:
        contact_port = port or self.args.contact_port
        base = f"<sip:{self.public_user}@{self.args.local_ip}:{contact_port};transport=udp>"
        if self.args.no_contact_tags:
            return base
        return (
            base
            + ';+sip.instance="<urn:uuid:00000000-0000-0000-0000-000000000001>";'
            + "+g.3gpp.icsi-ref=urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"
        )

    def _base_headers(
        self,
        method: str,
        request_uri: str,
        local_port: Optional[int] = None,
        contact_port: Optional[int] = None,
    ) -> List[str]:
        source_port = local_port or self.args.contact_port
        advertised_contact_port = contact_port or self.args.contact_port
        branch = f"z9hG4bK{random.randint(100000, 999999)}"
        return [
            f"{method} {request_uri} SIP/2.0",
            f"Via: SIP/2.0/UDP {self.args.local_ip}:{source_port};branch={branch};rport",
            "Max-Forwards: 70",
            f'From: <{self.public_uri}>;tag={self.from_tag}',
            f"To: <{self.public_uri if method == 'REGISTER' else self.invite_target}>",
            f"Call-ID: {self.call_id}",
            f"CSeq: {self.cseq} {method}",
            f"Contact: {self._contact(advertised_contact_port)}",
            "User-Agent: SWu-IMS-Minimal",
        ]

    def _build_register(self, authorization: str = "", expires: Optional[int] = None) -> str:
        lines = self._base_headers("REGISTER", self.register_uri)
        lines.extend(
            [
                f"Expires: {self.args.expires if expires is None else expires}",
                "Supported: path, sec-agree",
                "Require: sec-agree",
                "Proxy-Require: sec-agree",
                f"Security-Client: {self.security_client}",
            ]
        )
        if self.security_verify:
            lines.append(f"Security-Verify: {self.security_verify}")
        if authorization:
            lines.append(f"Authorization: {authorization}")
        lines.extend(["Allow: REGISTER, OPTIONS, INVITE, ACK, BYE, CANCEL", "Content-Length: 0", "", ""])
        return "\r\n".join(lines)

    def _build_invite(self) -> str:
        if not self.args.invite_same_dialog:
            self.call_id = f"{random.randint(100000, 999999)}@{self.args.local_ip}"
            self.from_tag = f"{random.randint(100000, 999999)}"
            self.cseq = 1
        body = (
            "v=0\r\n"
            f"o=- 0 0 IN IP4 {self.args.local_ip}\r\n"
            "s=SWu IMS Test\r\n"
            f"c=IN IP4 {self.args.local_ip}\r\n"
            "t=0 0\r\n"
            "m=audio 40000 RTP/AVP 0 8 96\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
            "a=rtpmap:8 PCMA/8000\r\n"
            "a=rtpmap:96 telephone-event/8000\r\n"
            "a=fmtp:96 0-15\r\n"
            "a=sendrecv\r\n"
        )
        lines = self._base_headers(
            "INVITE",
            self.invite_target,
            local_port=self.invite_port,
            contact_port=self.args.contact_port,
        )
        for route in self._route_set():
            lines.append(f"Route: {route}")
        lines.append(f"P-Preferred-Identity: <{self.public_uri}>")
        if self.args.p_asserted_id:
            lines.append(f"P-Asserted-Identity: <{normalize_sip_uri(self.args.p_asserted_id, self.args.realm)}>")
        if self.args.pani:
            lines.append(f"P-Access-Network-Info: {self.args.pani}")
        if self.args.pvni:
            lines.append(f"P-Visited-Network-ID: {self.args.pvni}")
        lines.extend(["Supported: path, sec-agree", "Require: sec-agree", "Proxy-Require: sec-agree"])
        if self.security_verify:
            lines.append(f"Security-Verify: {self.security_verify}")
        lines.extend(
            [
                "Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER",
                "Content-Type: application/sdp",
                f"Content-Length: {len(body)}",
                "",
                body,
            ]
        )
        return "\r\n".join(lines)

    def _exchange(self, payload: str, tx_sock: Optional[socket.socket] = None, target_port: Optional[int] = None) -> List[str]:
        sender = tx_sock or self.sock
        sender.sendto(payload.encode(), (self.args.pcscf_ip, target_port or self.args.pcscf_port))
        responses: List[str] = []
        deadline = time.time() + self.args.window
        sockets = [self.sock]
        if self.sec_rx_sock:
            sockets.append(self.sec_rx_sock)
        if tx_sock and tx_sock not in sockets:
            sockets.append(tx_sock)
        while time.time() < deadline:
            timeout = max(0.0, min(self.args.timeout, deadline - time.time()))
            readable, _, _ = select.select(sockets, [], [], timeout)
            if not readable:
                continue
            for sock in readable:
                try:
                    data, peer = sock.recvfrom(8192)
                    decoded = data.decode(errors="ignore")
                    if decoded.startswith("OPTIONS "):
                        response = build_simple_response(decoded, 200, "OK")
                        sock.sendto(response.encode(), peer)
                    responses.append(decoded)
                except BlockingIOError:
                    continue
        return responses

    def _make_authorization(self, method: str, uri: str, www_auth: str) -> str:
        challenge = parse_auth_params(www_auth)
        realm = challenge.get("realm", self.args.realm)
        scheme = challenge.get("_scheme", "")
        self.last_nonce = challenge.get("nonce")
        if "aka" in scheme.lower() or "akav1" in challenge.get("algorithm", "").lower():
            rand, autn = decode_nonce_to_rand_autn(challenge["nonce"])
            res, ck, ik = return_res_ck_ik(self.args.modem, rand, autn, self.args.ki, self.args.op, self.args.opc)
            self.last_ck = ck
            self.last_ik = ik
            if isinstance(res, bytes):
                password = binascii.unhexlify(res)
            else:
                password = binascii.unhexlify(str(res))
        else:
            password = self.args.imsi
        return build_authorization(self.private_id, realm, method, uri, challenge, password)

    def _run_ip_xfrm(self, command: List[str]) -> None:
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _install_ims_ipsec(self) -> None:
        if not self.last_ik or not self.security_server_params:
            return
        client_params = parse_security_params(self.security_client)
        ue_ip = self.args.local_ip
        pcscf_ip = self.args.pcscf_ip
        ue_port = int(self.security_server_params.get("port-c", self.args.contact_port))
        pcscf_port = int(self.security_server_params.get("port-s", self.args.sec_port_s or self.args.pcscf_port))
        spi_in = int(client_params.get("spi-c", "0"))
        spi_out = int(self.security_server_params.get("spi-s", "0"))
        ik_value = self.last_ik.hex() if isinstance(self.last_ik, bytes) else str(self.last_ik).lower()
        auth_key = "0x" + ik_value
        commands = [
            ["ip", "xfrm", "state", "delete", "src", pcscf_ip, "dst", ue_ip, "proto", "esp", "spi", str(spi_in)],
            ["ip", "xfrm", "state", "delete", "src", ue_ip, "dst", pcscf_ip, "proto", "esp", "spi", str(spi_out)],
            ["ip", "xfrm", "policy", "delete", "dir", "in", "src", pcscf_ip + "/32", "dst", ue_ip + "/32", "proto", "udp", "sport", str(pcscf_port), "dport", str(ue_port)],
            ["ip", "xfrm", "policy", "delete", "dir", "out", "src", ue_ip + "/32", "dst", pcscf_ip + "/32", "proto", "udp", "sport", str(ue_port), "dport", str(pcscf_port)],
        ]
        for command in commands:
            subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        add_commands = [
            [
                "ip", "xfrm", "state", "add", "src", pcscf_ip, "dst", ue_ip, "proto", "esp", "spi", str(spi_in),
                "mode", "transport", "enc", "cipher_null", "", "auth-trunc", "hmac(md5)", auth_key, "96",
                "sel", "src", pcscf_ip, "dst", ue_ip, "proto", "udp", "sport", str(pcscf_port), "dport", str(ue_port),
            ],
            [
                "ip", "xfrm", "state", "add", "src", ue_ip, "dst", pcscf_ip, "proto", "esp", "spi", str(spi_out),
                "mode", "transport", "enc", "cipher_null", "", "auth-trunc", "hmac(md5)", auth_key, "96",
                "sel", "src", ue_ip, "dst", pcscf_ip, "proto", "udp", "sport", str(ue_port), "dport", str(pcscf_port),
            ],
            [
                "ip", "xfrm", "policy", "add", "dir", "in", "src", pcscf_ip + "/32", "dst", ue_ip + "/32",
                "proto", "udp", "sport", str(pcscf_port), "dport", str(ue_port),
                "tmpl", "src", pcscf_ip, "dst", ue_ip, "proto", "esp", "mode", "transport",
            ],
            [
                "ip", "xfrm", "policy", "add", "dir", "out", "src", ue_ip + "/32", "dst", pcscf_ip + "/32",
                "proto", "udp", "sport", str(ue_port), "dport", str(pcscf_port),
                "tmpl", "src", ue_ip, "dst", pcscf_ip, "proto", "esp", "mode", "transport",
            ],
        ]
        for command in add_commands:
            self._run_ip_xfrm(command)

    def _print_exchange(self, label: str, payload: str, responses: List[str]) -> None:
        print(f"=== {label} ===")
        print(payload)
        for response in responses:
            print("=== RESPONSE ===")
            print(response)

    def _register_flow(self, expires: Optional[int] = None, label: str = "REGISTER") -> bool:
        request = self._build_register(expires=expires)
        responses = self._exchange(request)
        self._print_exchange(f"{label} #1", request, responses)
        for response in responses:
            start, headers, _ = parse_headers(response)
            if start.startswith("SIP/2.0 401"):
                self.security_verify = headers.get("security-server", [""])[0]
                self.security_server_params = parse_security_params(self.security_verify)
                authorization = self._make_authorization("REGISTER", self.register_uri, headers["www-authenticate"][0])
                self.cseq += 1
                second_request = self._build_register(authorization=authorization, expires=expires)
                second_responses = self._exchange(second_request)
                self._print_exchange(f"{label} #2", second_request, second_responses)
                for second in second_responses:
                    second_start, second_headers, _ = parse_headers(second)
                    if second_headers.get("authentication-info"):
                        self.last_auth_info = second_headers["authentication-info"][0]
                    if second_headers.get("service-route"):
                        self.service_routes = self._parse_route_set(second_headers["service-route"])
                    if second_start.startswith("SIP/2.0 200"):
                        self._install_ims_ipsec()
                        self.cseq += 1
                        return True
                return False
            if start.startswith("SIP/2.0 200"):
                if headers.get("authentication-info"):
                    self.last_auth_info = headers["authentication-info"][0]
                if headers.get("service-route"):
                    self.service_routes = self._parse_route_set(headers["service-route"])
                self.cseq += 1
                return True
        return False

    def register(self) -> bool:
        return self._register_flow(label="REGISTER")

    def re_register(self) -> bool:
        return self._register_flow(label="RE-REGISTER")

    def de_register(self) -> bool:
        return self._register_flow(expires=0, label="DE-REGISTER")

    def invite(self) -> bool:
        request = self._build_invite()
        tx_sock: Optional[socket.socket] = None
        if self.invite_port == self.args.contact_port:
            tx_sock = self.sock
        elif self.sec_rx_sock and self.invite_port == self.args.sec_port_s:
            tx_sock = self.sec_rx_sock
        else:
            tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tx_sock.bind((self.args.local_ip, self.invite_port))
            tx_sock.setblocking(False)
        protected_server_port = int(self.security_server_params.get("port-s", self.args.pcscf_port))
        responses = self._exchange(request, tx_sock=tx_sock, target_port=protected_server_port)
        if tx_sock not in (self.sock, self.sec_rx_sock) and tx_sock is not None:
            tx_sock.close()
        self._print_exchange("INVITE", request, responses)
        self.cseq += 1
        return any(
            response.startswith(("SIP/2.0 100", "SIP/2.0 180", "SIP/2.0 183", "SIP/2.0 200"))
            for response in responses
        )

    def run_actions(self) -> int:
        action_map = {
            "register": self.register,
            "re-register": self.re_register,
            "deregister": self.de_register,
            "invite": self.invite,
        }
        actions = [action.strip().lower() for action in self.args.actions.split(",") if action.strip()]
        for action in actions:
            handler = action_map.get(action)
            if handler is None:
                print(f"Unsupported action: {action}", file=sys.stderr)
                return 2
            ok = handler()
            if not ok:
                return 1
        return 0


def main() -> int:
    client = ImsSipClient(parse_args())
    return client.run_actions()


if __name__ == "__main__":
    sys.exit(main())
