#!/usr/bin/env python3
"""Send a Diameter CER to PyHSS and report whether a CEA comes back.

This isolates the PyHSS Diameter stack (diameterService.py + hssService.py) from
Kamailio, so a failure can be attributed to one side unambiguously. The CER is
built with PyHSS's own Diameter encoder so the bytes are exactly what the stack
expects.
"""
import os
import socket
import struct
import sys

sys.path.append(os.path.realpath(os.path.dirname(__file__) + "/../../pyhss/lib"))

from diameter import Diameter  # noqa: E402
from logtool import LogTool  # noqa: E402
from pyhss_config import config  # noqa: E402

HOST = os.environ.get("CER_HOST", "127.0.0.8")
PORT = int(os.environ.get("CER_PORT", "3868"))
TIMEOUT = float(os.environ.get("CER_TIMEOUT", "5"))


def main() -> int:
    logTool = LogTool(config=config)
    diam = Diameter(
        logTool=logTool,
        originHost="ims-test-client.localdomain",
        originRealm="localdomain",
        productName="cer-probe",
        mcc=config.get("hss", {}).get("MCC", "001"),
        mnc=config.get("hss", {}).get("MNC", "01"),
    )

    cer_hex = diam.Request_257()
    cer = bytes.fromhex(cer_hex)
    print(f"CER ({len(cer)} octets): {cer_hex}")

    sock = socket.create_connection((HOST, PORT), timeout=TIMEOUT)
    sock.settimeout(TIMEOUT)
    try:
        sock.sendall(cer)
        print(f"sent CER to {HOST}:{PORT}, waiting for a response")
        try:
            data = sock.recv(8192)
        except socket.timeout:
            print("FAIL no response before the timeout")
            return 1
    finally:
        sock.close()

    if not data:
        print("FAIL the peer closed the connection without answering")
        return 1

    print(f"response ({len(data)} octets): {data.hex()}")
    if len(data) < 20:
        print("FAIL the response is shorter than a Diameter header")
        return 1

    version = data[0]
    flags = data[4]
    length = int.from_bytes(data[1:4], "big")
    command = int.from_bytes(data[5:8], "big")
    app_id = int.from_bytes(data[8:12], "big")
    print(f"version={version} flags={flags:#04x} length={length} command={command} app_id={app_id}")

    if version != 1:
        print(f"FAIL unexpected Diameter version {version}")
        return 1
    if command != 257:
        print(f"FAIL expected a CER/CEA command code of 257, got {command}")
        return 1
    if flags & 0x80:
        print("FAIL the response still has the Request bit set")
        return 1

    # Walk the AVPs looking for Result-Code (268) and Origin-Host (264).
    result_code = None
    origin_host = None
    pos = 20
    while pos + 8 <= length:
        code = int.from_bytes(data[pos:pos + 4], "big")
        avp_flags = data[pos + 4]
        avp_len = int.from_bytes(data[pos + 5:pos + 8], "big")
        if avp_len < 8 or pos + avp_len > length:
            break
        header = 12 if avp_flags & 0x80 else 8
        value = data[pos + header:pos + avp_len]
        if code == 268 and len(value) == 4:
            result_code = int.from_bytes(value, "big")
        if code == 264:
            origin_host = value.decode("utf-8", "replace")
        pos += (avp_len + 3) & ~3

    print(f"origin-host={origin_host} result-code={result_code}")
    if result_code != 2001:
        print(f"FAIL expected Result-Code 2001 (DIAMETER_SUCCESS), got {result_code}")
        return 1
    print("PASS PyHSS answered the CER with a DIAMETER_SUCCESS CEA")
    return 0


if __name__ == "__main__":
    sys.exit(main())
