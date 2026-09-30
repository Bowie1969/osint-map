#!/usr/bin/env python3
"""Persistence: case dirs, index, atomic + debounced writes.

Dropbox-safe: temp file + os.replace() (the sync client never sees a
half-written JSON), throttled to one flush per FLUSH_EVERY seconds, with
a rolling .bak chain per rev for rollback.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import threading
import time

from .core import Graph
from .model import now_iso

FLUSH_EVERY = 1.5
BACKUPS_KEPT = 20


def default_cases_dir() -> str:
    env = os.environ.get("OSINT_MAP_CASES")
    if env:
        return env
    return os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "cases")


def slugify(title: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return (s or "case")[:48]


class Store:
    def __init__(self, cases_dir: str | None = None) -> None:
        self.cases_dir = cases_dir or default_cases_dir()
        os.makedirs(self.cases_dir, exist_ok=True)
        self._lock = threading.RLock()
        self._last_flush = 0.0
        self._timer: threading.Timer | None = None
        self._pending_graph: Graph | None = None

    # -------------------------------------------------- index

    @property
    def index_path(self) -> str:
        return os.path.join(self.cases_dir, "index.json")

    def read_index(self) -> list[dict]:
        try:
            with open(self.index_path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return []

    def write_index(self, entries: list[dict]) -> None:
        _atomic_json(self.index_path, entries)

    def index_upsert(self, case_id: str, title: str, g: Graph) -> None:
        entries = [e for e in self.read_index() if e.get("case_id") != case_id]
        entries.insert(0, {
            "case_id": case_id, "title": title or case_id,
            "created": now_iso(),
            "entity_count": len(g.entities), "edge_count": len(g.edges),
            "modified": now_iso(), "rev": g.rev,
        })
        self.write_index(entries)

    # -------------------------------------------------- cases

    def case_dir(self, case_id: str) -> str:
        safe = slugify(case_id)
        if safe != case_id:
            raise ValueError("case id must be slug-safe")
        return os.path.join(self.cases_dir, case_id)

    def list_cases(self) -> list[dict]:
        index = self.read_index()
        known = {e["case_id"] for e in index}
        for name in os.listdir(self.cases_dir):
            p = os.path.join(self.cases_dir, name)
            if name.endswith(".json") or not os.path.isdir(p) or name in known:
                continue
            g = self.load_case(name)
            if g:
                self.index_upsert(name, g.title, g)
                index = self.read_index()
                known.add(name)
        return index

    def new_case(self, title: str, slug: str = "") -> dict:
        cid = slugify(slug or title)
        d = self.case_dir(cid)
        if os.path.exists(os.path.join(d, "case.json")):
            return {"error": f"case {cid!r} already exists",
                    "hint": "graph_case switch to open it"}
        os.makedirs(d, exist_ok=True)
        g = Graph()
        g.title = title or cid
        g.case_id = cid
        self.write_case(g, immediate=True)  # must be visible to the next request
        return {"case_id": cid, "title": g.title}

    def case_exists(self, case_id: str) -> bool:
        return os.path.exists(os.path.join(self.case_dir(case_id), "case.json"))

    def load_case(self, case_id: str) -> Graph | None:
        p = os.path.join(self.case_dir(slugify(case_id)), "case.json")
        try:
            with open(p, encoding="utf-8") as f:
                raw = json.load(f)
            g = Graph.from_dict(raw, case_id=slugify(case_id))
            return g
        except (OSError, ValueError):
            return None

    def write_case(self, g: Graph, immediate: bool = False) -> int:
        """Persist. Debounced: at most one flush per FLUSH_EVERY; `immediate`
        bypasses only for final flushes (CLI exit, tests)."""
        with self._lock:
            if immediate:
                self._pending_graph = None
                return self._flush(g)
            if time.monotonic() - self._last_flush >= FLUSH_EVERY:
                return self._flush(g)
            self._pending_graph = g
            if self._timer is None or not self._timer.is_alive():
                delay = FLUSH_EVERY - (time.monotonic() - self._last_flush)
                self._timer = threading.Timer(max(delay, 0.1), self._flush_later)
                self._timer.daemon = True
                self._timer.start()
            return g.rev

    def flush(self, g: Graph) -> int:
        """Force-write now (MCP shutdown, CLI exit)."""
        with self._lock:
            if self._timer and self._timer.is_alive():
                self._timer.cancel()
            self._pending_graph = None
            return self._flush(g)

    def _flush_later(self) -> None:
        with self._lock:
            g = self._pending_graph
            self._pending_graph = None
        if g:
            self._flush(g)

    def _flush(self, g: Graph) -> int:
        with self._lock:
            d = self.case_dir(g.case_id)
            os.makedirs(d, exist_ok=True)
            path = os.path.join(d, "case.json")
            if os.path.exists(path) and g.rev:  # keep a rollback copy
                bak = os.path.join(d, f"case.json.bak-{g.rev}")
                shutil.copy2(path, bak)
                self._prune_backups(d)
            g.rev += 1
            _atomic_json(path, g.to_dict())
            self.index_upsert(g.case_id, g.title, g)
            g.dirty = False
            self._last_flush = time.monotonic()
            return g.rev

    def _prune_backups(self, d: str) -> None:
        baks = sorted(
            (f for f in os.listdir(d) if f.startswith("case.json.bak-")),
            key=lambda f: int(f.rsplit("-", 1)[1]),
        )
        for f in baks[:-BACKUPS_KEPT]:
            os.unlink(os.path.join(d, f))


def _atomic_json(path: str, payload) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=1, ensure_ascii=False, default=str)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)