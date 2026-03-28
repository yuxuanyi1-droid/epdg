#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import os
import queue
import re
import secrets
import socket
import string
import subprocess
import sys
import threading
import time
from pathlib import Path


IPV4_RE = re.compile(r"^IPV4 ADDRESS\s+\['([^']+)'\]\s*$")
PCSCF_RE = re.compile(r"^P-CSCF IPV4 ADDRESS\s+\[(.*)\]\s*$")
SIP_STATUS_RE = re.compile(r"^SIP/2.0\s+(\d{3})")


def _rand_token(n: int = 10) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _sudo_prefix(password: str) -> list[str]:
    return ["sudo", "-S", "-p", "", "-k"]


def _run_in_netns(password: str, netns: str, cmd: list[str], timeout: int = 10) -> subprocess.CompletedProcess[str]:
    full = _sudo_prefix(password) + ["ip", "netns", "exec", netns] + cmd
    return subprocess.run(
        full,
        input=password + "\n",
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _read_tun_counter(password: str, netns: str, counter: str) -> str:
    out = _run_in_netns(
        password,
        netns,
        ["cat", f"/sys/class/net/tun1/statistics/{counter}"],
        timeout=4,
    )
    return (out.stdout or "").strip()


def _cleanup_netns(password: str, netns: str) -> None:
    # Best-effort cleanup for previous SWu runs.
    _run_in_netns(password, netns, ["ip", "route", "del", "0.0.0.0/1"], timeout=4)
    _run_in_netns(password, netns, ["ip", "route", "del", "128.0.0.0/1"], timeout=4)
    _run_in_netns(password, netns, ["ip", "link", "del", "tun1"], timeout=4)


def _force_pcscf_via_tun(password: str, netns: str, pcscf_ip: str, ue_ip: str) -> None:
    # Ensure SIP towards P-CSCF goes through the SWu tunnel, not the veth underlay.
    _run_in_netns(
        password,
        netns,
        ["ip", "route", "replace", f"{pcscf_ip}/32", "dev", "tun1", "src", ue_ip],
        timeout=4,
    )


def _cleanup_host(password: str) -> None:
    # Avoid stale SWu sessions and old kernel IPsec SAs affecting new runs.
    subprocess.run(
        _sudo_prefix(password) + ["pkill", "-f", "SWu-IKEv2/swu_emulator.py"],
        input=password + "\n",
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )
    subprocess.run(
        _sudo_prefix(password) + ["ip", "xfrm", "state", "flush"],
        input=password + "\n",
        text=True,
        capture_output=True,
        timeout=8,
        check=False,
    )
    subprocess.run(
        _sudo_prefix(password) + ["ip", "xfrm", "policy", "flush"],
        input=password + "\n",
        text=True,
        capture_output=True,
        timeout=8,
        check=False,
    )
    # Test-lab cleanup: clear stale P-CSCF contacts to avoid IMS IPsec port exhaustion.
    subprocess.run(
        _sudo_prefix(password) + ["mysql", "-e", "DELETE FROM pcscf.location;"],
        input=password + "\n",
        text=True,
        capture_output=True,
        timeout=8,
        check=False,
    )


def _reader_thread(proc: subprocess.Popen[str], q: queue.Queue[str]) -> None:
    assert proc.stdout is not None
    for line in proc.stdout:
        q.put(line.rstrip("\n"))


def _parse_pcscf(raw_list: str) -> str | None:
    raw_list = raw_list.strip()
    if not raw_list:
        return None
    # expected like: "'10.0.0.1', '10.0.0.2'" or ""
    m = re.search(r"'([^']+)'", raw_list)
    return m.group(1) if m else None


def _build_register(local_ip: str, local_port: int, domain: str, impu: str, contact_user: str) -> tuple[str, str]:
    branch = f"z9hG4bK-{_rand_token(12)}"
    tag = _rand_token(8)
    call_id = f"{_rand_token(12)}@{local_ip}"
    contact = f"<sip:{contact_user}@{local_ip}:{local_port};transport=udp>"
    msg = (
        f"REGISTER sip:{domain} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch};rport\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:{impu}>;tag={tag}\r\n"
        f"To: <sip:{impu}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 REGISTER\r\n"
        f"Supported: path, sec-agree\r\n"
        f"Require: sec-agree\r\n"
        f"P-Preferred-Identity: <sip:{impu}>\r\n"
        f"P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=001001000000001\r\n"
        f"Security-Client: ipsec-3gpp;alg=hmac-sha-1-96;prot=esp;mod=trans;ealg=aes-cbc;spi-c=10001;spi-s=20001;port-c={local_port};port-s=5060\r\n"
        f"Contact: {contact}\r\n"
        f"Expires: 600\r\n"
        f"User-Agent: py-vowifi-sim/0.1\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    )
    return msg, call_id


def _sip_parse_headers(message: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in message.split("\r\n")[1:]:
        if not line.strip() or ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip().lower()] = v.strip()
    return headers


def _sip_extract_status(message: str) -> int | None:
    first = message.splitlines()[0] if message else ""
    m = SIP_STATUS_RE.match(first.strip())
    return int(m.group(1)) if m else None


def _sip_extract_cseq_num(message: str) -> int | None:
    for line in message.split("\r\n"):
        if line.lower().startswith("cseq:"):
            m = re.search(r"(\d+)\s+REGISTER", line, flags=re.IGNORECASE)
            if m:
                return int(m.group(1))
    return None


def _sip_extract_call_id(message: str) -> str | None:
    for line in message.split("\r\n"):
        if line.lower().startswith("call-id:"):
            return line.split(":", 1)[1].strip()
    return None


def _parse_digest_challenge(www_auth: str) -> dict[str, str]:
    out: dict[str, str] = {}
    s = www_auth.strip()
    if s.lower().startswith("digest "):
        s = s[7:].strip()
    for m in re.finditer(r'([A-Za-z0-9_-]+)\s*=\s*("([^"]*)"|[^,\s]+)', s):
        key = m.group(1).lower()
        val = m.group(3) if m.group(3) is not None else m.group(2)
        out[key] = val.strip('"')
    return out


def _compute_res_from_nonce(nonce_b64: str, ki_hex: str, opc_hex: str) -> bytes:
    from binascii import unhexlify
    from CryptoMobile.Milenage import Milenage

    raw = base64.b64decode(nonce_b64 + "===")
    if len(raw) < 16:
        raise ValueError("AKA nonce too short, cannot extract RAND")
    rand = raw[:16]
    m = Milenage(b"\x00" * 16)
    m.set_opc(unhexlify(opc_hex))
    res, _, _, _ = m.f2345(unhexlify(ki_hex), rand)
    return res


def _digest_response(
    *,
    username: str,
    realm: str,
    password_bytes: bytes,
    method: str,
    uri: str,
    nonce: str,
    nc: str,
    cnonce: str,
    qop: str,
) -> str:
    ha1 = hashlib.md5(f"{username}:{realm}:".encode() + password_bytes).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    return hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()


def _build_register_with_auth(
    *,
    local_ip: str,
    local_port: int,
    domain: str,
    impu: str,
    call_id: str,
    from_tag: str,
    cseq: int,
    auth_header: str | None = None,
    security_verify: str | None = None,
) -> str:
    branch = f"z9hG4bK-{_rand_token(12)}"
    user = impu.split("@", 1)[0]
    msg = (
        f"REGISTER sip:{domain} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch};rport\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:{impu}>;tag={from_tag}\r\n"
        f"To: <sip:{impu}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {cseq} REGISTER\r\n"
        f"Supported: path, sec-agree\r\n"
        f"Require: sec-agree\r\n"
        f"P-Preferred-Identity: <sip:{impu}>\r\n"
        f"P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=001001000000001\r\n"
        f"Security-Client: ipsec-3gpp;alg=hmac-sha-1-96;prot=esp;mod=trans;ealg=aes-cbc;spi-c=10001;spi-s=20001;port-c={local_port};port-s=5060\r\n"
        f"Contact: <sip:{user}@{local_ip}:{local_port};transport=udp>\r\n"
        f"Expires: 600\r\n"
        f"User-Agent: py-vowifi-sim/0.1\r\n"
    )
    if auth_header:
        msg += f"Authorization: {auth_header}\r\n"
    if security_verify:
        msg += f"Security-Verify: {security_verify}\r\n"
    msg += "Content-Length: 0\r\n\r\n"
    return msg


def _run_sip_register_aka(
    *,
    local_ip: str,
    pcscf_ip: str,
    pcscf_port: int,
    domain: str,
    impu: str,
    ki: str,
    opc: str,
    timeout_sec: int,
    ue_sip_port: int,
) -> tuple[int | None, str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout_sec)
    sock.bind((local_ip, ue_sip_port))
    port = sock.getsockname()[1]

    call_id = f"{_rand_token(12)}@{local_ip}"
    from_tag = _rand_token(8)
    all_msgs: list[str] = []

    try:
        cseq = 1
        auth_header: str | None = None
        sec_verify: str | None = None
        final_status: int | None = None
        for _challenge_round in range(4):
            req = _build_register_with_auth(
                local_ip=local_ip,
                local_port=port,
                domain=domain,
                impu=impu,
                call_id=call_id,
                from_tag=from_tag,
                cseq=cseq,
                auth_header=auth_header,
                security_verify=sec_verify,
            )
            all_msgs.append(
                f"SEND REGISTER cseq={cseq} call-id={call_id} auth={'yes' if auth_header else 'no'}"
            )
            sock.sendto(req.encode(), (pcscf_ip, pcscf_port))

            challenge_msg: str | None = None
            deadline = time.time() + timeout_sec
            while time.time() < deadline:
                try:
                    left = max(0.1, deadline - time.time())
                    sock.settimeout(left)
                    data, addr = sock.recvfrom(8192)
                except socket.timeout:
                    all_msgs.append(
                        f"TIMEOUT waiting response cseq={cseq} call-id={call_id}"
                    )
                    break
                text = data.decode(errors="replace")
                all_msgs.append(f"RECV_FROM {addr[0]}:{addr[1]}\n{text}")
                s = _sip_extract_status(text)
                if s is None:
                    continue
                rsp_call_id = _sip_extract_call_id(text)
                if rsp_call_id and rsp_call_id != call_id:
                    continue
                rsp_cseq = _sip_extract_cseq_num(text)
                # Ignore delayed responses from previous REGISTER attempts.
                if rsp_cseq is not None and rsp_cseq != cseq:
                    continue
                if s == 401:
                    challenge_msg = text
                    break
                if s >= 200:
                    final_status = s
                    break
            if final_status is not None:
                break
            if not challenge_msg:
                break

            h = _sip_parse_headers(challenge_msg)
            www = h.get("www-authenticate", "")
            d = _parse_digest_challenge(www)
            sec_server = h.get("security-server", "")
            nonce = d.get("nonce", "")
            realm = d.get("realm", domain)
            qop = "auth"
            if "qop" in d and "auth" not in d["qop"]:
                qop = d["qop"].split(",")[0].strip()
            nc = "00000001"
            cnonce = _rand_token(16)
            uri = f"sip:{domain}"
            username = impu
            res = _compute_res_from_nonce(nonce, ki, opc)
            response = _digest_response(
                username=username,
                realm=realm,
                password_bytes=res,
                method="REGISTER",
                uri=uri,
                nonce=nonce,
                nc=nc,
                cnonce=cnonce,
                qop=qop,
            )
            auth_header = (
                f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
                f'uri="{uri}", response="{response}", algorithm=AKAv1-MD5, '
                f'qop={qop}, nc={nc}, cnonce="{cnonce}"'
            )
            opaque = d.get("opaque")
            if opaque:
                auth_header += f', opaque="{opaque}"'
            sec_verify = sec_server if sec_server else None
            cseq += 1

        return final_status, "\n\n".join(all_msgs)
    finally:
        sock.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="VoWiFi SIP REGISTER simulator over SWu tunnel")
    parser.add_argument("--sudo-password", default="root", help="sudo password (test env)")
    parser.add_argument("--netns", default="swu-test", help="network namespace name")
    parser.add_argument("--swu-dir", default="test/SWu-IKEv2", help="path to SWu-IKEv2 directory")
    parser.add_argument("--swu-python", default=".venv/bin/python3", help="python binary used by SWu-IKEv2")
    parser.add_argument("--imsi", default="001010000000001")
    parser.add_argument("--ki", default="465B5CE8B199B49FAA5F0A2EE238A6BC")
    parser.add_argument("--opc", default="2e001f1df0a0bb769940a2c6342cf795")
    parser.add_argument("--epdg", default="10.255.0.1", help="ePDG IP")
    parser.add_argument("--apn", default="ims")
    parser.add_argument("--mcc", default="001")
    parser.add_argument("--mnc", default="001")
    parser.add_argument("--pcscf-ip", default="", help="P-CSCF IP override; if empty, use SWu output")
    parser.add_argument("--pcscf-port", type=int, default=5060)
    parser.add_argument("--ue-sip-port", type=int, default=5060, help="UE local SIP UDP port")
    parser.add_argument("--impu", default="001010000000001@ims.mnc001.mcc001.3gppnetwork.org")
    parser.add_argument("--sip-domain", default="ims.mnc001.mcc001.3gppnetwork.org")
    parser.add_argument("--swu-timeout", type=int, default=40, help="seconds to wait for SWu connected state")
    parser.add_argument("--sip-timeout", type=int, default=5, help="seconds to wait for SIP response")
    parser.add_argument("--cleanup-netns", action="store_true", help="cleanup stale SWu routes/tun before start")
    parser.add_argument("--sip-only", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.sip_only:
        status, out = _run_sip_register_aka(
            local_ip=args.epdg,  # overloaded in sip-only mode as local ue ip
            pcscf_ip=args.pcscf_ip,
            pcscf_port=args.pcscf_port,
            domain=args.sip_domain,
            impu=args.impu,
            ki=args.ki,
            opc=args.opc,
            timeout_sec=args.sip_timeout,
            ue_sip_port=args.ue_sip_port,
        )
        print(out)
        return 0 if status == 200 else 7

    swu_path = Path(args.swu_dir).resolve()
    swu_prog = swu_path / "swu_emulator.py"
    swu_py = swu_path / args.swu_python
    if not swu_prog.exists() or not swu_py.exists():
        print(f"[ERR] SWu files not found under {swu_path}", file=sys.stderr)
        return 2

    if args.cleanup_netns:
        _cleanup_host(args.sudo_password)
        _cleanup_netns(args.sudo_password, args.netns)

    ping = _run_in_netns(args.sudo_password, args.netns, ["ping", "-c", "1", "-W", "1", args.epdg], timeout=8)
    if ping.returncode != 0:
        print("[ERR] netns connectivity check failed:")
        print(ping.stderr.strip() or ping.stdout.strip())
        return 3

    cmd = _sudo_prefix(args.sudo_password) + [
        "ip",
        "netns",
        "exec",
        args.netns,
        str(swu_py),
        str(swu_prog),
        "--imsi",
        args.imsi,
        "--ki",
        args.ki,
        "--opc",
        args.opc,
        "--dest",
        args.epdg,
        "--apn",
        args.apn,
        "--mcc",
        args.mcc,
        "--mnc",
        args.mnc,
    ]

    print("[INFO] starting SWu tunnel...")
    proc = subprocess.Popen(
        cmd,
        cwd=str(swu_path),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdin is not None
    proc.stdin.write(args.sudo_password + "\n")
    proc.stdin.flush()

    q: queue.Queue[str] = queue.Queue()
    t = threading.Thread(target=_reader_thread, args=(proc, q), daemon=True)
    t.start()

    start = time.time()
    ue_ip: str | None = None
    pcscf_ip: str | None = args.pcscf_ip or None
    connected = False

    try:
        while time.time() - start < args.swu_timeout:
            try:
                line = q.get(timeout=0.5)
            except queue.Empty:
                if proc.poll() is not None:
                    break
                continue
            print(f"[SWU] {line}")
            m = IPV4_RE.search(line)
            if m:
                ue_ip = m.group(1)
            p = PCSCF_RE.search(line)
            if p and not pcscf_ip:
                pcscf_ip = _parse_pcscf(p.group(1))
            if "STATE CONNECTED" in line:
                connected = True
                break

        if not connected:
            print("[ERR] SWu tunnel did not reach connected state in time", file=sys.stderr)
            return 4
        if not ue_ip:
            print("[ERR] SWu connected but UE IPv4 not parsed", file=sys.stderr)
            return 5
        if not pcscf_ip:
            print("[WARN] P-CSCF not provided by SWu, fallback to ePDG IP")
            pcscf_ip = args.epdg

        _force_pcscf_via_tun(args.sudo_password, args.netns, pcscf_ip, ue_ip)
        route_chk = _run_in_netns(
            args.sudo_password,
            args.netns,
            ["ip", "route", "get", pcscf_ip],
            timeout=4,
        )
        if route_chk.returncode == 0 and route_chk.stdout.strip():
            print(f"[INFO] pcscf route: {route_chk.stdout.strip()}")
        tx_before = _read_tun_counter(args.sudo_password, args.netns, "tx_packets")
        rx_before = _read_tun_counter(args.sudo_password, args.netns, "rx_packets")
        print(f"[INFO] tun1 counters before SIP: tx={tx_before or '?'} rx={rx_before or '?'}")

        print(f"[INFO] tunnel ready: ue_ip={ue_ip} pcscf={pcscf_ip}:{args.pcscf_port}")

        sip = _run_in_netns(
            args.sudo_password,
            args.netns,
            [
                str(swu_py),
                str(Path(__file__).resolve()),
                "--sip-only",
                "--epdg",
                ue_ip,
                "--pcscf-ip",
                pcscf_ip,
                "--pcscf-port",
                str(args.pcscf_port),
                "--sip-domain",
                args.sip_domain,
                "--impu",
                args.impu,
                "--ki",
                args.ki,
                "--opc",
                args.opc,
                "--sip-timeout",
                str(args.sip_timeout),
                "--ue-sip-port",
                str(args.ue_sip_port),
            ],
            timeout=max(args.sip_timeout * 3, args.sip_timeout + 12),
        )
        if sip.returncode != 0:
            print("[ERR] SIP REGISTER send failed", file=sys.stderr)
            combined = ((sip.stdout or "") + ("\n" + sip.stderr if sip.stderr else "")).strip()
            print(combined, file=sys.stderr)
            tx_after = _read_tun_counter(args.sudo_password, args.netns, "tx_packets")
            rx_after = _read_tun_counter(args.sudo_password, args.netns, "rx_packets")
            print(f"[INFO] tun1 counters after SIP fail: tx={tx_after or '?'} rx={rx_after or '?'}")
            return 6

        tx_after = _read_tun_counter(args.sudo_password, args.netns, "tx_packets")
        rx_after = _read_tun_counter(args.sudo_password, args.netns, "rx_packets")
        print(f"[INFO] tun1 counters after SIP: tx={tx_after or '?'} rx={rx_after or '?'}")
        print("[INFO] SIP REGISTER response:")
        print(sip.stdout.strip())
        return 0
    finally:
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
