#!/usr/bin/env python3
"""Send one SIP REGISTER to the P-CSCF and print the response.

A quick probe used while bringing the IMS topology up. The full registration
flow with the AKA challenge lives in ims_register.py.
"""
import os
import socket
import sys

PCSCF_IP = os.environ.get("PCSCF_IP", "10.46.0.1")
PCSCF_PORT = int(os.environ.get("PCSCF_PORT", "5060"))
UE_IP = os.environ.get("UE_IP", "10.46.0.100")
IMPU = os.environ.get("IMPU", "001010000000001@ims.mnc001.mcc001.3gppnetwork.org")
DOMAIN = os.environ.get("SIP_DOMAIN", "ims.mnc001.mcc001.3gppnetwork.org")


def main() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UE_IP, 0))
    sock.settimeout(8)
    port = sock.getsockname()[1]
    print(f"UE bound to {UE_IP}:{port}, sending REGISTER to {PCSCF_IP}:{PCSCF_PORT}")

    user = IMPU.split("@", 1)[0]
    msg = (
        f"REGISTER sip:{DOMAIN} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {UE_IP}:{port};branch=z9hG4bK-probe;rport\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:{IMPU}>;tag=probe1\r\n"
        f"To: <sip:{IMPU}>\r\n"
        f"Call-ID: probe-{port}@{UE_IP}\r\n"
        f"CSeq: 1 REGISTER\r\n"
        f"Supported: path, sec-agree\r\n"
        f"Require: sec-agree\r\n"
        f"P-Preferred-Identity: <sip:{IMPU}>\r\n"
        f"P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=001001000000001\r\n"
        f"Security-Client: ipsec-3gpp;alg=hmac-sha-1-96;prot=esp;mod=trans;ealg=aes-cbc;"
        f"spi-c=10001;spi-s=20001;port-c={port};port-s=5060\r\n"
        f"Contact: <sip:{user}@{UE_IP}:{port};transport=udp>\r\n"
        f"Expires: 600\r\n"
        f"User-Agent: ims-probe/0.1\r\n"
        f"Content-Length: 0\r\n\r\n"
    )
    sock.sendto(msg.encode(), (PCSCF_IP, PCSCF_PORT))

    # The P-CSCF answers 100 Trying first and the challenge arrives later, so keep
    # reading until a final response shows up or the timeout expires.
    deadline = 10.0
    sock.settimeout(deadline)
    import time as _time
    end = _time.time() + deadline
    while _time.time() < end:
        try:
            data, addr = sock.recvfrom(8192)
        except socket.timeout:
            break
        text = data.decode("utf-8", "replace")
        first = text.splitlines()[0] if text else ""
        print(f"--- response from {addr}: {first} ---")
        code = first.split()[1] if len(first.split()) > 1 else ""
        if code and code[0] in "23456":
            print(text)
            print("--- end ---")
            if code.startswith("401"):
                print("PASS the P-CSCF answered with a 401 challenge")
                return 0
            if code.startswith("200"):
                print("PASS the P-CSCF answered with 200 OK")
                return 0
            print(f"FAIL unexpected final response: {first!r}")
            return 1

    print("FAIL no final response from the P-CSCF within the timeout")
    return 1


if __name__ == "__main__":
    sys.exit(main())
