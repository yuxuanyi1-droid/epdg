#!/usr/bin/env python3
from __future__ import annotations

import logging
import os
import socket
import sys
import hashlib
import hmac
import json
import urllib.error
import urllib.request
import struct
import secrets
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
ATTRIBUTE	State	24	octets

VENDOR Microsoft	311
BEGIN-VENDOR Microsoft
ATTRIBUTE	MS-MPPE-Send-Key	16	string	encrypt=2
ATTRIBUTE	MS-MPPE-Recv-Key	17	string	encrypt=2
END-VENDOR Microsoft

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
        self.pyhss_base = os.environ.get("PYHSS_API_BASE", "http://127.0.0.1:8080").rstrip("/")
        self.plmn = os.environ.get("PYHSS_PLMN", "001001")
        self.allow_plain_accept = os.environ.get("PYHSS_RADIUS_ALLOW_PLAIN_ACCEPT", "1") == "1"
        self.force_accept = os.environ.get("PYHSS_RADIUS_FORCE_ACCEPT", "0") == "1"
        self.skip_aka_mac = os.environ.get("PYHSS_RADIUS_SKIP_AKA_MAC", "0") == "1"
        self.require_at_mac = os.environ.get("PYHSS_RADIUS_REQUIRE_AT_MAC", "1") == "1"
        self.require_message_auth = os.environ.get("PYHSS_RADIUS_REQUIRE_MESSAGE_AUTH", "1") == "1"
        self.strict_eap_length = os.environ.get("PYHSS_RADIUS_STRICT_EAP_LENGTH", "1") == "1"
        self.reject_unknown_aka_subtype = os.environ.get("PYHSS_RADIUS_REJECT_UNKNOWN_AKA_SUBTYPE", "1") == "1"
        self.allow_legacy_auts_in_res = os.environ.get("PYHSS_RADIUS_ALLOW_LEGACY_AUTS_IN_RES", "1") == "1"
        self.sessions: dict[bytes, dict[str, bytes]] = {}

    def _extract_imsi(self, user_name: str) -> str | None:
        # expected test format in this lab: 0<IMSI>@nai.epc...
        if "@" not in user_name:
            return None
        left = user_name.split("@", 1)[0]
        if not left.isdigit() or len(left) < 2:
            return None
        if len(left) == 16 and left.startswith("0"):
            imsi = left[1:]
        else:
            # fallback to historical assumption used by some clients
            imsi = left[4:] if len(left) > 4 else left
        if not imsi.isdigit():
            return None
        return imsi

    def _pyhss_vector_exists(self, imsi: str) -> bool:
        url = f"{self.pyhss_base}/auc/swm/eap_aka/plmn/{self.plmn}/imsi/{imsi}"
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                return 200 <= resp.status < 300
        except urllib.error.URLError as exc:
            self.logger.warning("PyHSS vector query failed for imsi=%s: %s", imsi, exc)
            return False

    def _fetch_aka_vector(self, imsi: str) -> dict[str, bytes] | None:
        url = f"{self.pyhss_base}/auc/aka/vector_count/1/imsi/{imsi}"
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            self.logger.warning("AKA vector query failed for imsi=%s: %s", imsi, exc)
            return None
        if not isinstance(payload, list) or not payload:
            return None
        vect = payload[0]
        try:
            return {
                "rand": bytes.fromhex(vect["rand"]),
                "autn": bytes.fromhex(vect["autn"]),
                "xres": bytes.fromhex(vect["xres"]),
                "ck": bytes.fromhex(vect["ck"]),
                "ik": bytes.fromhex(vect["ik"]),
            }
        except Exception:
            return None

    def _fetch_aka_vector_resync(self, imsi: str, auts: bytes, rand: bytes) -> dict[str, bytes] | None:
        url = f"{self.pyhss_base}/auc/aka/resync/imsi/{imsi}/auts/{auts.hex()}/rand/{rand.hex()}"
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            self.logger.warning("AKA resync query failed for imsi=%s: %s", imsi, exc)
            return None
        if not isinstance(payload, dict):
            return None
        try:
            return {
                "rand": bytes.fromhex(payload["rand"]),
                "autn": bytes.fromhex(payload["autn"]),
                "xres": bytes.fromhex(payload["xres"]),
                "ck": bytes.fromhex(payload["ck"]),
                "ik": bytes.fromhex(payload["ik"]),
            }
        except Exception:
            return None

    @staticmethod
    def _sha1_dss(data: bytes) -> bytes:
        # Match SWu-IKEv2 implementation (special zero-padding, not RFC SHA1 padding)
        h0 = 0x67452301
        h1 = 0xEFCDAB89
        h2 = 0x98BADCFE
        h3 = 0x10325476
        h4 = 0xC3D2E1F0

        def rol(n: int, b: int) -> int:
            return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

        padded = data + (b"\x00" * 44)
        for off in range(0, len(padded), 64):
            thunk = padded[off:off + 64]
            w = list(struct.unpack(">16L", thunk)) + [0] * 64
            for i in range(16, 80):
                w[i] = rol((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]), 1)

            a, b, c, d, e = h0, h1, h2, h3, h4
            for i in range(80):
                if i < 20:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                elif i < 40:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif i < 60:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                else:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6
                a, b, c, d, e = (rol(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF, a, rol(b, 30), c, d

            h0 = (h0 + a) & 0xFFFFFFFF
            h1 = (h1 + b) & 0xFFFFFFFF
            h2 = (h2 + c) & 0xFFFFFFFF
            h3 = (h3 + d) & 0xFFFFFFFF
            h4 = (h4 + e) & 0xFFFFFFFF

        return struct.pack("!I", h0) + struct.pack("!I", h1) + struct.pack("!I", h2) + struct.pack("!I", h3) + struct.pack("!I", h4)

    def _derive_aka_keys(self, identity: str, ck: bytes, ik: bytes) -> tuple[bytes, bytes, bytes]:
        mk = hashlib.sha1(identity.encode("utf-8") + ik + ck).digest()
        result = b""
        xval = mk
        modulus = 1 << 160
        for _ in range(4):
            w0 = self._sha1_dss(xval)
            xval = ((int.from_bytes(xval, "big") + int.from_bytes(w0, "big") + 1) % modulus).to_bytes(20, "big")
            w1 = self._sha1_dss(xval)
            xval = ((int.from_bytes(xval, "big") + int.from_bytes(w1, "big") + 1) % modulus).to_bytes(20, "big")
            result += w0 + w1
        k_aut = result[16:32]
        msk = result[32:96]
        return mk, k_aut, msk

    @staticmethod
    def _parse_eap_message(attrs: dict[str, list[str]]) -> bytes | None:
        parts = attrs.get("EAP-Message", [])
        if not parts:
            return None
        try:
            return b"".join(bytes.fromhex(p) for p in parts)
        except Exception:
            return None

    @staticmethod
    def _eap_header(code: int, identifier: int, body: bytes) -> bytes:
        length = 4 + len(body)
        return bytes([code, identifier]) + struct.pack("!H", length) + body

    def _build_aka_challenge(self, eap_identifier: int, rand: bytes, autn: bytes, k_aut: bytes) -> bytes:
        # Type(23), Subtype AKA-Challenge(1), Reserved(2)
        aka_hdr = bytes([23, 1, 0, 0])
        at_rand = bytes([1, 5, 0, 0]) + rand
        at_autn = bytes([2, 5, 0, 0]) + autn
        at_mac = bytes([11, 5, 0, 0]) + (b"\x00" * 16)
        pkt = self._eap_header(1, eap_identifier, aka_hdr + at_rand + at_autn + at_mac)
        mac = hmac.new(k_aut, pkt, hashlib.sha1).digest()[:16]
        pkt = pkt[:-16] + mac
        return pkt

    @staticmethod
    def _parse_aka_response(eap: bytes) -> tuple[bytes | None, bytes | None]:
        if len(eap) < 8:
            return None, None
        if eap[0] != 2 or eap[4] != 23 or eap[5] != 1:
            return None, None
        pos = 8
        at_res = None
        at_mac = None
        while pos + 4 <= len(eap):
            at_type = eap[pos]
            at_len = eap[pos + 1] * 4
            if at_len <= 0 or pos + at_len > len(eap):
                break
            if at_type == 3 and at_len >= 4:
                res_len_bits = struct.unpack("!H", eap[pos + 2:pos + 4])[0]
                res_len = res_len_bits // 8
                at_res = eap[pos + 4:pos + 4 + res_len]
            elif at_type == 11 and at_len >= 20:
                at_mac = eap[pos + 4:pos + 20]
            pos += at_len
        return at_res, at_mac

    @staticmethod
    def _parse_aka_attributes(eap: bytes) -> dict[int, bytes]:
        attrs: dict[int, bytes] = {}
        if len(eap) < 8:
            return attrs
        pos = 8
        while pos + 4 <= len(eap):
            at_type = eap[pos]
            at_len = eap[pos + 1] * 4
            if at_len <= 0 or pos + at_len > len(eap):
                break
            attrs[at_type] = eap[pos + 4:pos + at_len]
            pos += at_len
        return attrs

    @staticmethod
    def _eap_valid_length(eap: bytes) -> bool:
        if len(eap) < 4:
            return False
        declared = struct.unpack("!H", eap[2:4])[0]
        return declared == len(eap)

    @staticmethod
    def _zero_eap_mac(eap: bytes) -> bytes:
        out = bytearray(eap)
        pos = 8
        while pos + 4 <= len(out):
            at_type = out[pos]
            at_len = out[pos + 1] * 4
            if at_len <= 0 or pos + at_len > len(out):
                break
            if at_type == 11 and at_len >= 20:
                out[pos + 4:pos + 20] = b"\x00" * 16
                break
            pos += at_len
        return bytes(out)

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

        user_name = attrs.get("User-Name", [""])[0]
        imsi = self._extract_imsi(user_name)
        eap_msg = self._parse_eap_message(attrs)
        radius_state = pkt.get("State", [None])[0]

        reply = self.CreateReplyPacket(pkt)
        if self.force_accept and self.allow_plain_accept and eap_msg and len(eap_msg) >= 2:
            # Lab fallback: complete directly with EAP-Success
            reply.code = packet.AccessAccept
            reply["Reply-Message"] = "pyhss bridge forced accept"
            reply["EAP-Message"] = [bytes([3, eap_msg[1], 0, 4])]
            reply.add_message_authenticator()
            self.SendReplyPacket(pkt.fd, reply)
            return

        if self.require_message_auth and "Message-Authenticator" not in attrs:
            reply.code = packet.AccessReject
            reply["Reply-Message"] = "missing Message-Authenticator"
            reply.add_message_authenticator()
            self.SendReplyPacket(pkt.fd, reply)
            return

        if not eap_msg or len(eap_msg) < 8 or not imsi:
            reply.code = packet.AccessReject
            reply["Reply-Message"] = "invalid request"
            reply.add_message_authenticator()
            self.SendReplyPacket(pkt.fd, reply)
            return

        if self.strict_eap_length and not self._eap_valid_length(eap_msg):
            reply.code = packet.AccessReject
            reply["Reply-Message"] = "invalid eap length"
            reply.add_message_authenticator()
            self.SendReplyPacket(pkt.fd, reply)
            return

        # Phase 1: Identity -> send AKA-Challenge
        if eap_msg[0] == 2 and eap_msg[4] == 1 and radius_state is None:
            vector = self._fetch_aka_vector(imsi)
            if not vector:
                reply.code = packet.AccessReject
                reply["Reply-Message"] = "vector fetch failed"
                reply.add_message_authenticator()
                self.SendReplyPacket(pkt.fd, reply)
                return
            _, k_aut, msk = self._derive_aka_keys(user_name, vector["ck"], vector["ik"])
            challenge_id = (eap_msg[1] + 1) & 0xFF
            eap_challenge = self._build_aka_challenge(challenge_id, vector["rand"], vector["autn"], k_aut)
            state = secrets.token_bytes(16)
            self.sessions[state] = {
                "imsi": imsi.encode(),
                "identity": user_name.encode(),
                "xres": vector["xres"],
                "k_aut": k_aut,
                "msk": msk,
                "rand": vector["rand"],
            }
            reply.code = packet.AccessChallenge
            reply["State"] = [state]
            reply["EAP-Message"] = [eap_challenge]
            reply["Reply-Message"] = "aka challenge"
            reply.add_message_authenticator()
            self.logger.info("Access-Challenge for user=%s imsi=%s", user_name, imsi)
            self.SendReplyPacket(pkt.fd, reply)
            return

        # Phase 2: Challenge response -> verify RES/MAC -> success
        if eap_msg[0] == 2 and eap_msg[4] == 23 and isinstance(radius_state, bytes):
            sess = self.sessions.get(radius_state)
            if not sess:
                reply.code = packet.AccessReject
                reply["Reply-Message"] = "state not found"
                reply.add_message_authenticator()
                self.logger.warning("Access-Reject state not found for user=%s", user_name)
                self.SendReplyPacket(pkt.fd, reply)
                return
            aka_subtype = eap_msg[5]
            aka_attrs = self._parse_aka_attributes(eap_msg)
            res, mac_recv = self._parse_aka_response(eap_msg)
            auts = aka_attrs.get(4)  # AT_AUTS
            client_error = aka_attrs.get(22)  # AT_CLIENT_ERROR_CODE
            notification = aka_attrs.get(12)  # AT_NOTIFICATION

            # Handle explicit UE error/notification branches.
            if client_error is not None:
                self.sessions.pop(radius_state, None)
                reply.code = packet.AccessReject
                reply["Reply-Message"] = "aka client error"
                reply.add_message_authenticator()
                self.logger.warning("Access-Reject aka client error user=%s code=%s", user_name, client_error.hex())
                self.SendReplyPacket(pkt.fd, reply)
                return
            if notification is not None:
                self.sessions.pop(radius_state, None)
                reply.code = packet.AccessReject
                reply["Reply-Message"] = "aka notification"
                reply.add_message_authenticator()
                self.logger.warning("Access-Reject aka notification user=%s value=%s", user_name, notification.hex())
                self.SendReplyPacket(pkt.fd, reply)
                return

            # AUTS branch: trigger SQN resync and return a new challenge.
            if aka_subtype == 1 and auts:
                imsi_s = sess.get("imsi", b"").decode()
                rand = sess.get("rand")
                if not imsi_s or not isinstance(rand, bytes):
                    self.sessions.pop(radius_state, None)
                    reply.code = packet.AccessReject
                    reply["Reply-Message"] = "auts missing session context"
                    reply.add_message_authenticator()
                    self.SendReplyPacket(pkt.fd, reply)
                    return
                vector = self._fetch_aka_vector_resync(imsi_s, auts, rand)
                if not vector:
                    self.sessions.pop(radius_state, None)
                    reply.code = packet.AccessReject
                    reply["Reply-Message"] = "aka resync failed"
                    reply.add_message_authenticator()
                    self.logger.warning("Access-Reject aka resync failed user=%s imsi=%s", user_name, imsi_s)
                    self.SendReplyPacket(pkt.fd, reply)
                    return
                _, k_aut, msk = self._derive_aka_keys(user_name, vector["ck"], vector["ik"])
                challenge_id = (eap_msg[1] + 1) & 0xFF
                eap_challenge = self._build_aka_challenge(challenge_id, vector["rand"], vector["autn"], k_aut)
                self.sessions[radius_state] = {
                    "imsi": imsi_s.encode(),
                    "identity": user_name.encode(),
                    "xres": vector["xres"],
                    "k_aut": k_aut,
                    "msk": msk,
                    "rand": vector["rand"],
                }
                reply.code = packet.AccessChallenge
                reply["State"] = [radius_state]
                reply["EAP-Message"] = [eap_challenge]
                reply["Reply-Message"] = "aka challenge resync"
                reply.add_message_authenticator()
                self.logger.info("Access-Challenge resync user=%s imsi=%s", user_name, imsi_s)
                self.SendReplyPacket(pkt.fd, reply)
                return

            if aka_subtype != 1 and self.reject_unknown_aka_subtype:
                self.sessions.pop(radius_state, None)
                reply.code = packet.AccessReject
                reply["Reply-Message"] = f"unsupported aka subtype {aka_subtype}"
                reply.add_message_authenticator()
                self.logger.warning("Access-Reject unsupported aka subtype user=%s subtype=%s", user_name, aka_subtype)
                self.SendReplyPacket(pkt.fd, reply)
                return

            mac_calc = hmac.new(sess["k_aut"], self._zero_eap_mac(eap_msg), hashlib.sha1).digest()[:16]
            self.logger.info(
                "AKA verify user=%s res=%s xres=%s mac_recv=%s mac_calc=%s",
                user_name,
                res.hex() if res else None,
                sess["xres"].hex(),
                mac_recv.hex() if mac_recv else None,
                mac_calc.hex(),
            )
            mac_ok = (mac_recv == mac_calc) or self.skip_aka_mac
            if self.require_at_mac and mac_recv is None:
                mac_ok = False

            # Some legacy UE stacks may place AUTS bytes in AT_RES on sync failure.
            if self.allow_legacy_auts_in_res and res and len(res) == 14 and not mac_ok:
                imsi_s = sess.get("imsi", b"").decode()
                rand = sess.get("rand")
                if imsi_s and isinstance(rand, bytes):
                    vector = self._fetch_aka_vector_resync(imsi_s, res, rand)
                    if vector:
                        _, k_aut, msk = self._derive_aka_keys(user_name, vector["ck"], vector["ik"])
                        challenge_id = (eap_msg[1] + 1) & 0xFF
                        eap_challenge = self._build_aka_challenge(challenge_id, vector["rand"], vector["autn"], k_aut)
                        self.sessions[radius_state] = {
                            "imsi": imsi_s.encode(),
                            "identity": user_name.encode(),
                            "xres": vector["xres"],
                            "k_aut": k_aut,
                            "msk": msk,
                            "rand": vector["rand"],
                        }
                        reply.code = packet.AccessChallenge
                        reply["State"] = [radius_state]
                        reply["EAP-Message"] = [eap_challenge]
                        reply["Reply-Message"] = "aka challenge resync-legacy"
                        reply.add_message_authenticator()
                        self.logger.info("Access-Challenge legacy resync user=%s imsi=%s", user_name, imsi_s)
                        self.SendReplyPacket(pkt.fd, reply)
                        return
            if res != sess["xres"] or not mac_ok:
                reply.code = packet.AccessReject
                reply["Reply-Message"] = "aka verification failed"
                reply.add_message_authenticator()
                self.sessions.pop(radius_state, None)
                self.logger.warning("Access-Reject aka verification failed user=%s", user_name)
                self.SendReplyPacket(pkt.fd, reply)
                return
            success = bytes([3, eap_msg[1], 0, 4])  # EAP-Success
            reply.code = packet.AccessAccept
            reply["EAP-Message"] = [success]
            # strongSwan expects keying material via MS-MPPE attrs; direction
            # mapping is NAS-centric, so keep Recv/Send aligned for NAS side.
            reply["MS-MPPE-Recv-Key"] = [sess["msk"][:32]]
            reply["MS-MPPE-Send-Key"] = [sess["msk"][32:64]]
            reply["Reply-Message"] = "aka success"
            reply.add_message_authenticator()
            self.sessions.pop(radius_state, None)
            self.logger.info("Access-Accept AKA success user=%s imsi=%s", user_name, imsi)
            self.SendReplyPacket(pkt.fd, reply)
            return

        reply.code = packet.AccessReject
        reply["Reply-Message"] = "unsupported eap state"
        reply.add_message_authenticator()
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
