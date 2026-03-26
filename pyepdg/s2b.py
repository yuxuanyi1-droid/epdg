from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass


@dataclass
class NoopClient:
    def create_session(self, ue_id: str) -> None:
        if not ue_id:
            raise ValueError("ue_id required")

    def delete_session(self, ue_id: str) -> None:
        if not ue_id:
            raise ValueError("ue_id required")

    def ping(self) -> None:
        return None


@dataclass
class GTPv2EchoClient:
    pgw_address: str
    port: int
    timeout_seconds: float = 2.0

    def create_session(self, ue_id: str) -> None:
        if not ue_id:
            raise ValueError("ue_id required")
        self.ping()

    def delete_session(self, ue_id: str) -> None:
        if not ue_id:
            raise ValueError("ue_id required")

    def ping(self) -> None:
        if not self.pgw_address or not self.port:
            raise ValueError("s2b config incomplete")
        seq = int(time.time_ns()) & 0x00FFFFFF
        req = bytearray(8)
        req[0] = 0x40
        req[1] = 1
        struct.pack_into(">H", req, 2, 4)
        req[4] = (seq >> 16) & 0xFF
        req[5] = (seq >> 8) & 0xFF
        req[6] = seq & 0xFF
        req[7] = 0

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout_seconds)
            sock.sendto(req, (self.pgw_address, self.port))
            resp, _ = sock.recvfrom(4096)
        if len(resp) < 8:
            raise RuntimeError(f"short gtpv2 response: {len(resp)} bytes")
        if resp[1] != 2:
            raise RuntimeError(f"unexpected gtpv2 message type: {resp[1]}")
        header_len = 8
        if resp[0] & 0x08:
            header_len = 12
            if len(resp) < header_len:
                raise RuntimeError(f"short gtpv2 response for teid header: {len(resp)} bytes")
        got_seq = (resp[header_len - 4] << 16) | (resp[header_len - 3] << 8) | resp[header_len - 2]
        if got_seq != seq:
            raise RuntimeError(f"gtpv2 seq mismatch: sent {seq} got {got_seq}")

