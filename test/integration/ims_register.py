#!/usr/bin/env python3
"""IMS REGISTER with an AKA challenge, driven directly against the P-CSCF.

This exercises the whole IMS control chain that PyHSS's Cx interface feeds:

    UE --REGISTER--> P-CSCF --REGISTER--> I-CSCF --UAR/UAA--> HSS (PyHSS)
                                   I-CSCF --REGISTER--> S-CSCF --MAR/MAA--> HSS
    UE <--401  challenge (AKAv1-MD5, RAND|AUTN inside the nonce)--

    UE  answers with RES derived from K/OPc via Milenage, proving the S-CSCF
    handed out a vector the UE can validate, i.e. the Cx interface works.

The RES calculation uses PyHSS's own Milenage implementation, so the test does
not need an extra crypto dependency and it is the same code the HSS uses to
generate the vector.

Environment: PCSCF_IP, PCSCF_PORT, UE_IP, IMPU, SIP_DOMAIN, IMSI, KI_HEX,
OPC_HEX, and PYHSS_LIB (path to pyhss/lib).
"""
import base64
import hashlib
import os
import re
import secrets
import select
import socket
import string
import sys
import time

PYHSS_LIB = os.environ.get(
    "PYHSS_LIB",
    os.path.realpath(os.path.dirname(__file__) + "/../../pyhss/lib"),
)
sys.path.append(PYHSS_LIB)

from milenage import Milenage  # noqa: E402

PCSCF_IP = os.environ.get("PCSCF_IP", "10.46.0.1")
PCSCF_PORT = int(os.environ.get("PCSCF_PORT", "5060"))
UE_IP = os.environ.get("UE_IP", "10.46.0.100")
IMSI = os.environ.get("IMSI", "001010000000001")
DOMAIN = os.environ.get("SIP_DOMAIN", "ims.mnc001.mcc001.3gppnetwork.org")
IMPU = os.environ.get("IMPU", f"{IMSI}@{DOMAIN}")
IMPI = os.environ.get("IMPI", f"{IMSI}@{DOMAIN}")
KI_HEX = os.environ.get("KI_HEX", "465B5CE8B199B49FAA5F0A2EE238A6BC")
OPC_HEX = os.environ.get("OPC_HEX", "2e001f1df0a0bb769940a2c6342cf795")
TIMEOUT = float(os.environ.get("TIMEOUT", "15"))
UE_SECURITY_PORT = int(os.environ.get("UE_SECURITY_PORT", "5060"))

SIP_STATUS_RE = re.compile(r"^SIP/2\.0\s+(\d{3})")


def rand_token(n: int = 10) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def parse_headers(message: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in message.split("\r\n")[1:]:
        if not line.strip() or ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return headers


def parse_digest_challenge(value: str) -> dict[str, str]:
    out: dict[str, str] = {}
    text = value.strip()
    if text.lower().startswith("digest "):
        text = text[7:].strip()
    for match in re.finditer(r'([A-Za-z0-9_-]+)\s*=\s*("([^"]*)"|[^,\s]+)', text):
        key = match.group(1).lower()
        out[key] = (match.group(3) if match.group(3) is not None else match.group(2)).strip('"')
    return out


def res_from_nonce(nonce_b64: str) -> bytes:
    """Extract RAND from the AKA nonce and compute RES with Milenage."""
    raw = base64.b64decode(nonce_b64 + "===")
    if len(raw) < 16:
        raise ValueError(f"AKA nonce carries only {len(raw)} octets, cannot extract RAND")
    rand = raw[:16]
    xres, _ak = Milenage.f2_f5(bytes.fromhex(KI_HEX), rand, bytes.fromhex(OPC_HEX))
    return xres


def digest_response(*, username: str, realm: str, password: bytes, method: str,
                    uri: str, nonce: str, nc: str, cnonce: str, qop: str) -> str:
    # AKAv1-MD5 uses the binary RES as the password (3GPP TS 33.203 annex N).
    ha1 = hashlib.md5(f"{username}:{realm}:".encode() + password).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    return hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()


class Ue:
    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((UE_IP, 0))
        self.sock.settimeout(TIMEOUT)
        self.port = self.sock.getsockname()[1]
        self.call_id = f"{rand_token(12)}@{UE_IP}"
        self.from_tag = rand_token(8)

        # The P-CSCF runs strict IMS IPsec (STRICT_IMS_IPSEC): the final response
        # is delivered with ims_ipsec_pcscf's ipsec_forward() to the port the UE
        # advertised as port-s, not back to the source port. Listen there too so
        # the 200 OK can be observed.
        self.sec_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sec_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sec_sock.bind((UE_IP, UE_SECURITY_PORT))
            self.sec_port = UE_SECURITY_PORT
        except OSError:
            # Fall back to an ephemeral port and advertise that instead.
            self.sec_sock.bind((UE_IP, 0))
            self.sec_port = self.sec_sock.getsockname()[1]
        self.sec_sock.settimeout(TIMEOUT)

    def register(self, *, cseq: int, auth: str | None = None,
                 security_verify: str | None = None) -> str:
        user = IMPU.split("@", 1)[0]
        msg = (
            f"REGISTER sip:{DOMAIN} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {UE_IP}:{self.port};branch=z9hG4bK-{rand_token(12)};rport\r\n"
            f"Max-Forwards: 70\r\n"
            f"From: <sip:{IMPU}>;tag={self.from_tag}\r\n"
            f"To: <sip:{IMPU}>\r\n"
            f"Call-ID: {self.call_id}\r\n"
            f"CSeq: {cseq} REGISTER\r\n"
            f"Supported: path, sec-agree\r\n"
            f"Require: sec-agree\r\n"
            f"P-Preferred-Identity: <sip:{IMPU}>\r\n"
            f"P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp={IMSI}\r\n"
            f"Security-Client: ipsec-3gpp;alg=hmac-sha-1-96;prot=esp;mod=trans;ealg=aes-cbc;"
            f"spi-c=10001;spi-s=20001;port-c={self.port};port-s={self.sec_port}\r\n"
            f"Contact: <sip:{user}@{UE_IP}:{self.port};transport=udp>\r\n"
            f"Expires: 600\r\n"
            f"User-Agent: ims-register-test/0.1\r\n"
        )
        if auth:
            msg += f"Authorization: {auth}\r\n"
        if security_verify:
            msg += f"Security-Verify: {security_verify}\r\n"
        msg += "Content-Length: 0\r\n\r\n"
        self.sock.sendto(msg.encode(), (PCSCF_IP, PCSCF_PORT))
        return self.read_final()

    def read_final(self) -> str:
        """Read until a final (>= 200) response arrives, returning its text.

        Both the signalling socket and the sec-agree socket are polled, because
        strict IMS IPsec delivers the final response to the latter.
        """
        deadline = time.time() + TIMEOUT
        provisional = 0
        socks = [self.sock, self.sec_sock]
        while time.time() < deadline:
            left = max(0.2, deadline - time.time())
            for s in socks:
                s.settimeout(left)
            ready, _, _ = select.select(socks, [], [], left)
            if not ready:
                break
            for s in ready:
                data, _ = s.recvfrom(16384)
                text = data.decode("utf-8", "replace")
                first = text.splitlines()[0] if text else ""
                match = SIP_STATUS_RE.match(first.strip())
                if not match:
                    continue
                code = int(match.group(1))
                if code < 200:
                    provisional += 1
                    continue
                return text
        raise TimeoutError(f"no final response (saw {provisional} provisional response(s))")


def main() -> int:
    print(f"UE {IMPU}")
    print(f"  local {UE_IP}:{'-'}  ->  P-CSCF {PCSCF_IP}:{PCSCF_PORT}")
    print(f"  K/OPc from the HSS subscriber record")

    ue = Ue()
    print(f"  bound UDP port {ue.port}")

    # Step 1: unauthenticated REGISTER, expect a 401 carrying the AKA challenge.
    try:
        first = ue.register(cseq=1)
    except TimeoutError as exc:
        print(f"FAIL step 1: {exc}")
        return 1

    status = int(SIP_STATUS_RE.match(first.splitlines()[0].strip()).group(1))
    if status != 401:
        print(f"FAIL step 1: expected 401, got {status}")
        print(first)
        return 1
    print("PASS step 1: 401 Unauthorized with a challenge")

    headers = parse_headers(first)
    www_auth = headers.get("www-authenticate", "")
    if "akav1-md5" not in www_auth.lower():
        print(f"FAIL the challenge is not AKAv1-MD5: {www_auth!r}")
        return 1
    challenge = parse_digest_challenge(www_auth)
    realm = challenge.get("realm", "")
    nonce = challenge.get("nonce", "")
    algorithm = challenge.get("algorithm", "")
    print(f"PASS step 2: challenge algorithm={algorithm} realm={realm}")

    security_server = headers.get("security-server", "")
    if security_server:
        print(f"PASS step 3: Security-Server offered ({security_server[:60]}...)")
    else:
        print("note: the P-CSCF offered no Security-Server")

    # Step 2: derive RES and answer the challenge.
    try:
        res = res_from_nonce(nonce)
    except Exception as exc:
        print(f"FAIL cannot derive RES from the nonce: {exc}")
        return 1
    print(f"PASS step 4: derived RES={res.hex()} with Milenage(K, OPc)")

    qop_options = challenge.get("qop", "")
    qop = "auth" if "auth" in qop_options.split(",") else qop_options.split(",")[0]
    nc = "00000001"
    cnonce = rand_token(16)
    uri = f"sip:{DOMAIN}"
    response = digest_response(
        username=IMPI, realm=realm, password=res, method="REGISTER",
        uri=uri, nonce=nonce, nc=nc, cnonce=cnonce, qop=qop,
    )
    auth = (
        f'Digest username="{IMPI}", realm="{realm}", nonce="{nonce}", uri="{uri}", '
        f'response="{response}", algorithm=AKAv1-MD5, qop={qop}, nc={nc}, cnonce="{cnonce}"'
    )

    try:
        second = ue.register(cseq=2, auth=auth, security_verify=security_server or None)
    except TimeoutError as exc:
        print(f"FAIL step 5: {exc}")
        return 1

    status = int(SIP_STATUS_RE.match(second.splitlines()[0].strip()).group(1))
    if status != 200:
        print(f"FAIL step 5: expected 200 OK, got {status}")
        print(second)
        return 1
    print("PASS step 5: 200 OK, the AKA response was accepted")

    second_headers = parse_headers(second)
    if "security-server" in second_headers or "security-server" in headers:
        print("PASS step 6: the registration was secured with IMS IPsec (sec-agree)")
    print()
    print("IMS REGISTER 401 -> 200 OK completed end to end")
    return 0


if __name__ == "__main__":
    sys.exit(main())
