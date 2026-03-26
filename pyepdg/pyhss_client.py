from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


class PyHSSClientError(RuntimeError):
    pass


@dataclass
class PyHSSClient:
    base_url: str
    timeout_seconds: float = 5.0
    swm_path_template: str = "/auc/swm/eap_aka/plmn/{plmn}/imsi/{imsi}"
    oam_ping_path: str = "/oam/ping"

    def _request(self, path: str) -> dict:
        url = self.base_url.rstrip("/") + path
        req = Request(url, headers={"Accept": "application/json"})
        try:
            with urlopen(req, timeout=self.timeout_seconds) as resp:
                payload = resp.read().decode("utf-8") or "{}"
                return json.loads(payload)
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise PyHSSClientError(f"pyhss request failed: {exc.code} {body}") from exc
        except URLError as exc:
            raise PyHSSClientError(f"pyhss request failed: {exc.reason}") from exc

    def ping(self) -> dict:
        return self._request(self.oam_ping_path)

    def get_eap_aka_vectors(self, imsi: str, mcc: str, mnc: str) -> dict:
        plmn = f"{mcc}{mnc}"
        path = self.swm_path_template.format(plmn=quote(plmn), imsi=quote(imsi))
        return self._request(path)

    def authorize(self, imsi: str, mcc: str, mnc: str, apn: str) -> dict:
        if not imsi:
            raise PyHSSClientError("imsi required")
        if not apn:
            raise PyHSSClientError("apn required")
        ping = self.ping()
        vectors = self.get_eap_aka_vectors(imsi=imsi, mcc=mcc, mnc=mnc)
        return {"ping": ping, "vectors": vectors, "allowed": True}
