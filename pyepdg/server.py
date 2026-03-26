from __future__ import annotations

import json
from dataclasses import asdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .compliance import Item, Report, _run
from .config import Config
from .ipsec import CreateRequest, NoopBackend, PendingError, SwanctlBackend
from .pyhss_client import PyHSSClient, PyHSSClientError
from .s2b import GTPv2EchoClient, NoopClient
from .session import Session, SessionStatus, Store


class App:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.sessions = Store()
        self.aaa = self._build_aaa()
        self.ipsec = self._build_ipsec()
        self.s2b = self._build_s2b()

    def _build_aaa(self):
        backend = self.cfg.aaa.backend
        if backend == "noop":
            return None
        if backend == "pyhss_api":
            api = self.cfg.aaa.pyhss_api
            return PyHSSClient(
                base_url=api.base_url,
                timeout_seconds=api.timeout_seconds,
                swm_path_template=api.swm_path_template,
                oam_ping_path=api.oam_ping_path,
            )
        raise ValueError(f"unsupported aaa backend: {backend}")

    def _build_ipsec(self):
        backend = self.cfg.ipsec.backend
        if backend == "noop":
            return NoopBackend()
        if backend == "swanctl":
            return SwanctlBackend(
                binary=self.cfg.ipsec.swanctl_bin,
                mode=self.cfg.ipsec.mode,
                connection_name=self.cfg.ipsec.connection_name,
                child_prefix=self.cfg.ipsec.child_prefix,
                child_name=self.cfg.ipsec.child_name,
                timeout_seconds=self.cfg.ipsec.timeout_seconds,
            )
        raise ValueError(f"unsupported ipsec backend: {backend}")

    def _build_s2b(self):
        backend = self.cfg.protocol.s2b.backend
        if backend == "noop":
            return NoopClient()
        if backend == "gtpv2_echo":
            return GTPv2EchoClient(
                pgw_address=self.cfg.protocol.s2b.pgw_address,
                port=self.cfg.protocol.s2b.gtpv2_port,
                timeout_seconds=self.cfg.protocol.s2b.timeout_seconds,
            )
        raise ValueError(f"unsupported s2b backend: {backend}")

    def handle_create(self, payload: dict) -> tuple[int, dict]:
        ue_id = str(payload.get("ue_id", "")).strip()
        imsi = str(payload.get("imsi", "")).strip()
        apn = str(payload.get("apn", "")).strip()
        if not ue_id or not imsi or not apn:
            return HTTPStatus.BAD_REQUEST, {"error": "ue_id, imsi and apn are required"}

        if self.aaa is not None:
            try:
                self.aaa.authorize(
                    imsi=imsi,
                    mcc=self.cfg.protocol.plmn.mcc,
                    mnc=self.cfg.protocol.plmn.mnc,
                    apn=apn,
                )
            except (PyHSSClientError, Exception) as exc:
                return HTTPStatus.BAD_GATEWAY, {"error": f"aaa error: {exc}"}

        try:
            if hasattr(self.ipsec, "create_child_sa"):
                self.ipsec.create_child_sa(CreateRequest(ue_id=ue_id, imsi=imsi))
        except PendingError as exc:
            session = self.sessions.upsert(
                Session(
                    ue_id=ue_id,
                    imsi=imsi,
                    apn=apn,
                    status=SessionStatus.pending,
                    created_at="",
                    updated_at="",
                )
            )
            return HTTPStatus.ACCEPTED, {"session": session.to_dict(), "message": str(exc)}
        except Exception as exc:
            return HTTPStatus.BAD_GATEWAY, {"error": f"ipsec create failed: {exc}"}

        try:
            if hasattr(self.s2b, "create_session"):
                self.s2b.create_session(ue_id)
        except Exception as exc:
            if hasattr(self.ipsec, "delete_child_sa"):
                try:
                    self.ipsec.delete_child_sa(ue_id)
                except Exception:
                    pass
            return HTTPStatus.BAD_GATEWAY, {"error": f"s2b create failed: {exc}"}

        session = self.sessions.upsert(
            Session(
                ue_id=ue_id,
                imsi=imsi,
                apn=apn,
                status=SessionStatus.up,
                created_at="",
                updated_at="",
            )
        )
        return HTTPStatus.CREATED, session.to_dict()

    def handle_delete(self, payload: dict) -> tuple[int, dict]:
        ue_id = str(payload.get("ue_id", "")).strip()
        if not ue_id:
            return HTTPStatus.BAD_REQUEST, {"error": "ue_id is required"}
        if hasattr(self.ipsec, "delete_child_sa"):
            try:
                self.ipsec.delete_child_sa(ue_id)
            except Exception as exc:
                return HTTPStatus.BAD_GATEWAY, {"error": f"ipsec delete failed: {exc}"}
        if hasattr(self.s2b, "delete_session"):
            try:
                self.s2b.delete_session(ue_id)
            except Exception as exc:
                return HTTPStatus.BAD_GATEWAY, {"error": f"s2b delete failed: {exc}"}
        self.sessions.delete(ue_id)
        return HTTPStatus.OK, {"result": "deleted"}

    def compliance_report(self) -> dict:
        items: list[Item] = []
        if self.cfg.aaa.backend == "pyhss_api" and isinstance(self.aaa, PyHSSClient):
            try:
                self.aaa.ping()
                items.append(Item("PyHSS", True, "oam ping ok"))
            except Exception as exc:
                items.append(Item("PyHSS", False, str(exc)))
        else:
            items.append(Item("PyHSS", False, f"unsupported backend {self.cfg.aaa.backend}"))
        if self.cfg.ipsec.backend == "swanctl":
            ok, msg = _run([self.cfg.ipsec.swanctl_bin, "--version"])
            items.append(Item("strongSwan", ok, msg))
        else:
            items.append(Item("strongSwan", True, "noop backend"))
        if self.cfg.protocol.s2b.backend == "gtpv2_echo":
            try:
                self.s2b.ping()
                items.append(Item("S2b", True, f"gtpv2 echo ok {self.cfg.protocol.s2b.pgw_address}:{self.cfg.protocol.s2b.gtpv2_port}"))
            except Exception as exc:
                items.append(Item("S2b", False, str(exc)))
        else:
            items.append(Item("S2b", True, "noop backend"))
        passed = all(item.passed for item in items)
        return Report(
            profile=f"mcc={self.cfg.protocol.plmn.mcc},mnc={self.cfg.protocol.plmn.mnc}",
            passed=passed,
            items=items,
        ).to_dict()


def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, payload: dict) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0:
                return {}
            raw = self.rfile.read(length)
            if not raw:
                return {}
            return json.loads(raw.decode("utf-8"))

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/healthz":
                self._send(HTTPStatus.OK, {"status": "ok", "node": app.cfg.node_id})
                return
            if parsed.path == "/v1/sessions":
                self._send(HTTPStatus.OK, [s.to_dict() for s in app.sessions.list()])
                return
            if parsed.path == "/v1/compliance/check":
                self._send(HTTPStatus.OK if app.compliance_report()["passed"] else HTTPStatus.CONFLICT, app.compliance_report())
                return
            self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            try:
                payload = self._read_json()
            except Exception as exc:
                self._send(HTTPStatus.BAD_REQUEST, {"error": f"bad json: {exc}"})
                return
            if parsed.path == "/v1/sessions/create":
                code, body = app.handle_create(payload)
                self._send(code, body)
                return
            if parsed.path == "/v1/sessions/delete":
                code, body = app.handle_delete(payload)
                self._send(code, body)
                return
            self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def log_message(self, fmt: str, *args) -> None:  # noqa: A003
            return

    return Handler


def run(cfg: Config) -> None:
    app = App(cfg)
    host = "0.0.0.0"
    port = 19090
    listen = cfg.http.listen.strip()
    if listen.startswith(":"):
        port = int(listen[1:])
    elif ":" in listen:
        host, p = listen.rsplit(":", 1)
        port = int(p)
    elif listen:
        port = int(listen)
    server = ThreadingHTTPServer((host, port), make_handler(app))
    print(f"pyepdg listening on {host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
