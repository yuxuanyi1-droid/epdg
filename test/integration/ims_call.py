#!/usr/bin/env python3
"""IMS call integration driver: register two UEs, then INVITE/ACK/BYE.

The two UEs authenticate with AKAv1-MD5 against the real P/I/S-CSCF, exactly as
test/integration/ims_register.py does, and then complete a dialog through the
P-CSCF (originating) and the S-CSCF (terminating). It is deliberately a plain
UDP UE: the CSCF configurations are relaxed by ims_call.sh so the call control
chain can be exercised without a UE-side IMS IPsec stack.

Environment: PCSCF_IP, UE_IP, SIP_DOMAIN, IMSI_A, IMSI_B, KI_HEX, OPC_HEX,
PYHSS_LIB.
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

sys.path.append(os.environ.get(
    "PYHSS_LIB",
    os.path.realpath(os.path.dirname(__file__) + "/../../pyhss/lib"),
))
from milenage import Milenage  # noqa: E402

PCSCF_IP = os.environ.get("PCSCF_IP", "10.46.0.1")
PCSCF_PORT = int(os.environ.get("PCSCF_PORT", "5060"))
UE_IP = os.environ.get("UE_IP", "10.46.0.100")
DOMAIN = os.environ.get("SIP_DOMAIN", "ims.mnc001.mcc001.3gppnetwork.org")
KI_HEX = os.environ.get("KI_HEX", "465B5CE8B199B49FAA5F0A2EE238A6BC")
OPC_HEX = os.environ.get("OPC_HEX", "2e001f1df0a0bb769940a2c6342cf795")
TIMEOUT = float(os.environ.get("TIMEOUT", "20"))
IMSI_A = os.environ.get("IMSI_A", "001010000000001")
IMSI_B = os.environ.get("IMSI_B", "001010000000002")

STATUS_RE = re.compile(r"^SIP/2\.0\s+(\d{3})")
SDP_OFFER = (
    "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=call\r\nc=IN IP4 {ip}\r\nt=0 0\r\n"
    "m=audio 40000 RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n"
    "a=sendrecv\r\n"
)
SDP_ANSWER = (
    "v=0\r\no=- 2 2 IN IP4 {ip}\r\ns=call\r\nc=IN IP4 {ip}\r\nt=0 0\r\n"
    "m=audio 40002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"
)


def tok(n=10):
    return "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def headers(msg):
    out = {}
    for line in msg.split("\r\n")[1:]:
        if not line.strip():
            break
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        out.setdefault(k.strip().lower(), []).append(v.strip())
    return out


def h1(h, k, default=""):
    v = h.get(k.lower())
    return v[0] if v else default


def digest_challenge(v):
    out = {}
    t = v.strip()
    if t.lower().startswith("digest "):
        t = t[7:].strip()
    for m in re.finditer(r'([A-Za-z0-9_-]+)\s*=\s*("([^"]*)"|[^,\s]+)', t):
        out[m.group(1).lower()] = (m.group(3) if m.group(3) is not None else m.group(2)).strip('"')
    return out


def res_from_nonce(nonce):
    raw = base64.b64decode(nonce + "===")
    xres, _ = Milenage.f2_f5(bytes.fromhex(KI_HEX), raw[:16], bytes.fromhex(OPC_HEX))
    return xres


def digest_response(username, realm, password, method, uri, nonce, nc, cnonce, qop):
    ha1 = hashlib.md5(f"{username}:{realm}:".encode() + password).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    return hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()


def debug(*args):
    if os.environ.get("CALL_DEBUG"):
        print(*args)


class Ue:
    def __init__(self, imsi, label):
        self.imsi = imsi
        self.label = label
        self.impu = f"{imsi}@{DOMAIN}"
        self.impi = self.impu
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((UE_IP, 0))
        self.port = self.sock.getsockname()[1]
        # Strict IMS IPsec would deliver the final response to port-s; the test
        # CSCFs are relaxed, but binding it keeps the UE shape realistic.
        self.sec_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sec_sock.bind((UE_IP, 5060))
            self.sec_port = 5060
        except OSError:
            self.sec_sock.bind((UE_IP, 0))
            self.sec_port = self.sec_sock.getsockname()[1]
        self.call_id = f"{tok(12)}@{UE_IP}"
        self.from_tag = tok(8)
        self.tag = None
        self.service_route = []

    def send(self, msg, to=None):
        self.sock.sendto(msg.encode(), to or (PCSCF_IP, PCSCF_PORT))

    def recv(self, timeout):
        ready, _, _ = select.select([self.sock, self.sec_sock], [], [], timeout)
        if not ready:
            return None, None
        data, _ = ready[0].recvfrom(65535)
        text = data.decode("utf-8", "replace")
        debug(f"    [{self.label} <- {ready[0].getsockname()}] {text.splitlines()[0] if text else ''}")
        return ready[0], text

    def wait_final(self, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            _, text = self.recv(max(0.1, deadline - time.time()))
            if not text:
                continue
            m = STATUS_RE.match(text.splitlines()[0].strip())
            if m and int(m.group(1)) >= 200:
                return int(m.group(1)), text
        return None, None

    def register(self):
        self.send(self._reg_msg(1))
        code, first = self.wait_final(TIMEOUT)
        if code != 401:
            raise RuntimeError(f"{self.label}: expected 401 got {code}\n{first}")
        hd = headers(first)
        chal = digest_challenge(h1(hd, "www-authenticate"))
        nonce, realm = chal.get("nonce", ""), chal.get("realm", "")
        res = res_from_nonce(nonce)
        qop, nc, cnonce = "auth", "00000001", tok(16)
        uri = f"sip:{DOMAIN}"
        resp = digest_response(self.impi, realm, res, "REGISTER", uri, nonce, nc, cnonce, qop)
        auth = (f'Digest username="{self.impi}", realm="{realm}", nonce="{nonce}", uri="{uri}", '
                f'response="{resp}", algorithm=AKAv1-MD5, qop={qop}, nc={nc}, cnonce="{cnonce}"')
        self.send(self._reg_msg(2, auth=auth, verify=h1(hd, "security-server")))
        code, second = self.wait_final(TIMEOUT)
        if code != 200:
            raise RuntimeError(f"{self.label}: expected 200 got {code}\n{second}")
        self.service_route = headers(second).get("service-route", [])
        print(f"  {self.label} registered ({self.impu})")
        return second

    def _reg_msg(self, cseq, auth=None, verify=None):
        user = self.impu.split("@", 1)[0]
        m = (
            f"REGISTER sip:{DOMAIN} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {UE_IP}:{self.port};branch=z9hG4bK-{tok(12)};rport\r\n"
            f"Max-Forwards: 70\r\n"
            f"From: <sip:{self.impu}>;tag={self.from_tag}\r\n"
            f"To: <sip:{self.impu}>\r\n"
            f"Call-ID: {self.call_id}\r\n"
            f"CSeq: {cseq} REGISTER\r\n"
            f"Supported: path, sec-agree\r\n"
            f"Require: sec-agree\r\n"
            f"P-Preferred-Identity: <sip:{self.impu}>\r\n"
            f"P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp={self.imsi}\r\n"
            f"Security-Client: ipsec-3gpp;alg=hmac-sha-1-96;prot=esp;mod=trans;ealg=aes-cbc;"
            f"spi-c=10001;spi-s=20001;port-c={self.port};port-s={self.sec_port}\r\n"
            f"Contact: <sip:{user}@{UE_IP}:{self.port};transport=udp>\r\n"
            f"Expires: 600\r\nUser-Agent: ims-call-test/0.1\r\n"
        )
        if auth:
            m += f"Authorization: {auth}\r\n"
        if verify:
            m += f"Security-Verify: {verify}\r\n"
        return m + "Content-Length: 0\r\n\r\n"


def parse_request(text):
    parts = text.split("\r\n", 1)[0].split(" ")
    method, ruri = parts[0], parts[1] if len(parts) > 1 else ""
    return method, ruri, headers(text)


def route_set_from(hd):
    return list(reversed(hd.get("record-route", [])))


def bare(v):
    v = (v or "").strip()
    if "<" in v and ">" in v:
        return v[v.find("<") + 1:v.find(">")]
    return v


def all_vias(hd):
    return "".join("Via: %s\r\n" % v for v in hd.get("via", []))


def all_record_routes(hd):
    return "".join(f"Record-Route: {r}\r\n" for r in hd.get("record-route", []))


def run():
    print(f"IMS call test; domain {DOMAIN}, P-CSCF {PCSCF_IP}:{PCSCF_PORT}")
    b = Ue(IMSI_B, "B-callee")
    a = Ue(IMSI_A, "A-caller")
    b.register()
    a.register()

    a_from_tag = a.from_tag
    callid = f"callid-{tok(12)}@{UE_IP}"
    invite = (
        f"INVITE sip:{b.impu} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {UE_IP}:{a.port};branch=z9hG4bK-{tok(12)};rport\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:{a.impu}>;tag={a_from_tag}\r\n"
        f"To: <sip:{b.impu}>\r\n"
        f"Call-ID: {callid}\r\n"
        f"CSeq: 1 INVITE\r\n"
        f"Contact: <sip:{a.impu.split('@')[0]}@{UE_IP}:{a.port}>\r\n"
        f"P-Preferred-Identity: <sip:{a.impu}>\r\n"
        f"Content-Type: application/sdp\r\n"
        f"Allow: INVITE, ACK, BYE, CANCEL, PRACK\r\n"
    )
    for sr in a.service_route:
        invite += f"Route: {sr}\r\n"
    sdp = SDP_OFFER.format(ip=UE_IP)
    a.send(invite + f"Content-Length: {len(sdp)}\r\n\r\n{sdp}")
    print("  A -> INVITE")

    conf = {"callid": callid, "to_full": None, "ruri": None, "routes": [], "answered": False}
    deadline = time.time() + TIMEOUT
    while time.time() < deadline and not conf["answered"]:
        _, text = b.recv(0.5)
        if text:
            method, _, hd = parse_request(text)
            debug(f"  B <- {text.splitlines()[0]}")
            if method == "INVITE":
                b.tag = tok(8)
                conf["callid"] = h1(hd, "call-id")
                conf["ruri"] = bare(h1(hd, "contact"))
                conf["routes"] = route_set_from(hd)
                vias, frm = all_vias(hd), h1(hd, "from")
                to = h1(hd, "to") + f";tag={b.tag}"
                cseq, rr = h1(hd, "cseq"), all_record_routes(hd)
                for code, reason in ((100, "Trying"), (180, "Ringing")):
                    b.send(f"SIP/2.0 {code} {reason}\r\n{vias}From: {frm}\r\nTo: {to}\r\n"
                           f"Call-ID: {conf['callid']}\r\nCSeq: {cseq}\r\n{rr}Content-Length: 0\r\n\r\n")
                ans = SDP_ANSWER.format(ip=UE_IP)
                b.send(f"SIP/2.0 200 OK\r\n{vias}From: {frm}\r\nTo: {to}\r\n"
                       f"Call-ID: {conf['callid']}\r\nCSeq: {cseq}\r\n"
                       f"Contact: <sip:{b.impu.split('@')[0]}@{UE_IP}:{b.port}>\r\n"
                       f"{rr}Content-Type: application/sdp\r\nAllow: INVITE, ACK, BYE, CANCEL\r\n"
                       f"Content-Length: {len(ans)}\r\n\r\n{ans}")
                print("  B -> 180/200 OK")
        _, text = a.recv(0.5)
        if text:
            m = STATUS_RE.match(text.splitlines()[0].strip())
            if m:
                debug(f"  A <- {text.splitlines()[0]}")
                if int(m.group(1)) == 200 and "1 INVITE" in text:
                    hd = headers(text)
                    conf["routes"] = route_set_from(hd)
                    conf["ruri"] = bare(h1(hd, "contact"))
                    conf["to_full"] = h1(hd, "to")
                    conf["answered"] = True
                    ack = (
                        f"ACK {conf['ruri']} SIP/2.0\r\n"
                        f"Via: SIP/2.0/UDP {UE_IP}:{a.port};branch=z9hG4bK-{tok(12)};rport\r\n"
                        f"Max-Forwards: 70\r\nFrom: <sip:{a.impu}>;tag={a_from_tag}\r\n"
                        f"To: {conf['to_full']}\r\nCall-ID: {conf['callid']}\r\n"
                        f"CSeq: 1 ACK\r\nContact: <sip:{a.impu.split('@')[0]}@{UE_IP}:{a.port}>\r\n"
                    )
                    for r in conf["routes"]:
                        ack += f"Route: {r}\r\n"
                    a.send(ack + "Content-Length: 0\r\n\r\n")
                    print("  A -> ACK")

    if not conf["answered"]:
        print("FAIL: the call was not answered (no 200 OK)")
        return 1
    print("PASS: INVITE -> 200 OK, call established")

    bye = (
        f"BYE {conf['ruri']} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {UE_IP}:{a.port};branch=z9hG4bK-{tok(12)};rport\r\n"
        f"Max-Forwards: 70\r\nFrom: <sip:{a.impu}>;tag={a_from_tag}\r\n"
        f"To: {conf['to_full']}\r\nCall-ID: {conf['callid']}\r\nCSeq: 2 BYE\r\n"
        f"Contact: <sip:{a.impu.split('@')[0]}@{UE_IP}:{a.port}>\r\n"
    )
    for r in conf["routes"]:
        bye += f"Route: {r}\r\n"
    a.send(bye + "Content-Length: 0\r\n\r\n")
    print("  A -> BYE")

    deadline, bye_ok = time.time() + 10, False
    while time.time() < deadline and not bye_ok:
        _, text = b.recv(0.5)
        if text:
            method, _, hd = parse_request(text)
            if method == "BYE":
                b.send(f"SIP/2.0 200 OK\r\n{all_vias(hd)}From: {h1(hd, 'from')}\r\nTo: {h1(hd, 'to')}\r\n"
                       f"Call-ID: {h1(hd, 'call-id')}\r\nCSeq: {h1(hd, 'cseq')}\r\n"
                       f"{all_record_routes(hd)}Content-Length: 0\r\n\r\n")
                print("  B -> 200 OK (BYE)")
                bye_ok = True
        _, text = a.recv(0.3)
        if text:
            m = STATUS_RE.match(text.splitlines()[0].strip())
            if m and int(m.group(1)) == 200 and "2 BYE" in text:
                bye_ok = True
    if bye_ok:
        print("PASS: call released (BYE -> 200 OK)")
        return 0
    print("FAIL: BYE was not completed")
    return 1


if __name__ == "__main__":
    sys.exit(run())
