from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from datetime import timedelta


class PendingError(RuntimeError):
    pass


@dataclass
class CreateRequest:
    ue_id: str
    imsi: str


class NoopBackend:
    def create_child_sa(self, req: CreateRequest) -> None:
        if not req.ue_id:
            raise ValueError("ue_id required")

    def delete_child_sa(self, ue_id: str) -> None:
        if not ue_id:
            raise ValueError("ue_id required")


@dataclass
class SwanctlBackend:
    binary: str = "/usr/sbin/swanctl"
    mode: str = "active"
    connection_name: str = "epdg-ike"
    child_prefix: str = "ue"
    child_name: str = "ue-default"
    timeout_seconds: float = 5.0

    def _child_name(self, ue_id: str) -> str:
        if self.child_name:
            return self.child_name
        prefix = self.child_prefix or "ue"
        clean = re.sub(r"[^a-zA-Z0-9_-]", "_", ue_id)
        return f"{prefix}-{clean}"

    def _run(self, args: list[str]) -> str:
        proc = subprocess.run(
            [self.binary, *args],
            capture_output=True,
            text=True,
            timeout=self.timeout_seconds,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"swanctl {' '.join(args)} failed: {proc.stdout}{proc.stderr}".strip())
        return (proc.stdout + proc.stderr).strip()

    def create_child_sa(self, req: CreateRequest) -> None:
        if not req.ue_id:
            raise ValueError("ue_id required")
        child = self._child_name(req.ue_id)
        if self.mode == "passive":
            self._run(["--load-all"])
            raise PendingError(f"waiting for UE initiated IKEv2/IPsec on child {child}")
        args = ["--initiate", "--child", child]
        if self.connection_name:
            args += ["--ike", self.connection_name]
        self._run(args)

    def delete_child_sa(self, ue_id: str) -> None:
        if not ue_id:
            raise ValueError("ue_id required")
        child = self._child_name(ue_id)
        self._run(["--terminate", "--child", child])
