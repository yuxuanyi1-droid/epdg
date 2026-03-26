from __future__ import annotations

import socket
import subprocess
from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class Item:
    name: str
    passed: bool
    details: str


@dataclass
class Report:
    profile: str
    passed: bool
    items: list[Item]

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "passed": self.passed,
            "items": [asdict(item) for item in self.items],
        }


def _tcp_check(host: str, port: int, timeout: float = 2.0) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"reachable {host}:{port}"
    except Exception as exc:
        return False, str(exc)


def _run(cmd: list[str], timeout: float = 3.0) -> tuple[bool, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        if proc.returncode == 0:
            return True, (proc.stdout + proc.stderr).strip()
        return False, (proc.stdout + proc.stderr).strip() or f"exit {proc.returncode}"
    except Exception as exc:
        return False, str(exc)
