#!/usr/bin/env python3
from __future__ import annotations

import logging
import os
import socket
import sys
from pathlib import Path

from pyrad import dictionary, packet, server

sys.path.append(os.path.realpath(os.path.dirname(__file__) + "/../lib"))


RADIUS_DICTIONARY = """
ATTRIBUTE	User-Name	1	string
ATTRIBUTE	User-Password	2	string
ATTRIBUTE	NAS-IP-Address	4	ipaddr
ATTRIBUTE	NAS-Port	5	integer
ATTRIBUTE	Service-Type	6	integer
ATTRIBUTE	Framed-MTU	12	integer
ATTRIBUTE	Reply-Message	18	string
ATTRIBUTE	State	24	octets
ATTRIBUTE	Class	25	octets
ATTRIBUTE	Vendor-Specific	26	octets
ATTRIBUTE	Called-Station-Id	30	string
ATTRIBUTE	Calling-Station-Id	31	string
ATTRIBUTE	NAS-Identifier	32	string
ATTRIBUTE	Proxy-State	33	octets
ATTRIBUTE	Acct-Session-Id	44	string
ATTRIBUTE	NAS-Port-Type	61	integer
ATTRIBUTE	EAP-Message	79	octets
ATTRIBUTE	Message-Authenticator	80	octets
ATTRIBUTE	NAS-Port-Id	87	string
ATTRIBUTE	Chargeable-User-Identity	89	string

VALUE	Service-Type	Framed-User	2
VALUE	NAS-Port-Type	Virtual	5
"""


def build_dictionary() -> dictionary.Dictionary:
    dictionary_path = Path("/tmp/pyhss-radius-bridge.dictionary")
    dictionary_path.write_text(RADIUS_DICTIONARY)
    return dictionary.Dictionary(str(dictionary_path))


class RadiusBridgeServer(server.Server):
    def __init__(self, secret: bytes, bind_address: str = "127.0.0.1", auth_port: int = 18120):
        super().__init__(
            addresses=[bind_address],
            authport=auth_port,
            acct_enabled=False,
            coa_enabled=False,
            hosts={bind_address: server.RemoteHost(bind_address, secret, "strongswan")},
            dict=build_dictionary(),
        )
        self.secret = secret
        self.logger = logging.getLogger("pyhss.radius_bridge")

    def HandleAuthPacket(self, pkt: packet.Packet) -> None:  # noqa: N802
        attrs: dict[str, list[str]] = {}
        for key in pkt.keys():
            values = []
            for value in pkt[key]:
                if isinstance(value, bytes):
                    values.append(value.hex())
                else:
                    values.append(str(value))
            attrs[str(key)] = values

        self.logger.info(
            "Access-Request from %s:%s code=%s user=%s attrs=%s",
            pkt.source[0],
            pkt.source[1],
            pkt.code,
            attrs.get("User-Name", [""])[0],
            attrs,
        )

        reply = self.CreateReplyPacket(pkt, **{"Reply-Message": "pyhss radius bridge placeholder"})
        reply.code = packet.AccessReject
        self.SendReplyPacket(pkt.fd, reply)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    secret = os.environ.get("PYHSS_RADIUS_SECRET", "pyhss-radius-secret").encode()
    bind_address = os.environ.get("PYHSS_RADIUS_BIND", "127.0.0.1")
    auth_port = int(os.environ.get("PYHSS_RADIUS_PORT", "18120"))
    srv = RadiusBridgeServer(secret=secret, bind_address=bind_address, auth_port=auth_port)
    logging.getLogger("pyhss.radius_bridge").info("listening on %s:%s", bind_address, auth_port)
    srv.Run()


if __name__ == "__main__":
    main()
