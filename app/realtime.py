"""
Realtime plumbing: an in-memory findings store plus a WebSocket broadcaster.

Every detection - whether from live traffic through the detection layer or
from an OWASP ZAP scan - is appended here and pushed to all connected
dashboards immediately, so the UI updates with no refresh.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from itertools import count

from fastapi import WebSocket

_MAX_FINDINGS = 300


class FindingsStore:
    def __init__(self) -> None:
        self._items: deque[dict] = deque(maxlen=_MAX_FINDINGS)
        self._ids = count(1)

    def add(self, finding: dict) -> dict:
        finding = dict(finding)
        finding["id"] = next(self._ids)
        finding.setdefault("ts", time.time())
        finding.setdefault("source", "live")
        self._items.append(finding)
        return finding

    def all(self) -> list[dict]:
        return list(self._items)

    def clear(self) -> None:
        self._items.clear()

    def stats(self) -> dict:
        items = self._items
        return {
            "total": len(items),
            "exploitable": sum(1 for f in items if f.get("exploitable")),
            "safe": sum(1 for f in items if f.get("severity") == "SAFE"),
            "critical": sum(1 for f in items if f.get("severity") == "CRITICAL"),
            "high": sum(1 for f in items if f.get("severity") == "HIGH"),
            "from_zap": sum(1 for f in items if f.get("source") == "zap"),
        }


class ConnectionManager:
    def __init__(self) -> None:
        self._active: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._active.add(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._active.discard(ws)

    async def broadcast(self, message: dict) -> None:
        async with self._lock:
            targets = list(self._active)
        dead = []
        for ws in targets:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._active.discard(ws)


store = FindingsStore()
manager = ConnectionManager()


async def publish(finding: dict) -> dict:
    """Store a finding and push it to every connected dashboard."""
    saved = store.add(finding)
    await manager.broadcast({"type": "finding", "finding": saved,
                             "stats": store.stats()})
    return saved
