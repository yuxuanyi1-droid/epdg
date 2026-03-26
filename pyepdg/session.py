from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from threading import RLock


class SessionStatus(str, Enum):
    pending = "pending"
    up = "up"
    down = "down"


@dataclass
class Session:
    ue_id: str
    imsi: str
    apn: str
    status: SessionStatus
    created_at: str
    updated_at: str

    def to_dict(self) -> dict:
        return asdict(self)


class Store:
    def __init__(self) -> None:
        self._lock = RLock()
        self._sessions: dict[str, Session] = {}

    def upsert(self, session: Session) -> Session:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            existing = self._sessions.get(session.ue_id)
            session.created_at = existing.created_at if existing else now
            session.updated_at = now
            self._sessions[session.ue_id] = session
            return session

    def get(self, ue_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(ue_id)

    def delete(self, ue_id: str) -> None:
        with self._lock:
            self._sessions.pop(ue_id, None)

    def list(self) -> list[Session]:
        with self._lock:
            return list(self._sessions.values())
