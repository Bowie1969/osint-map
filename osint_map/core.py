#!/usr/bin/env python3
"""Graph engine: entities, edges, sources, findings, gaps, queue.

Holds everything that lives in one case.json. Knows nothing about MCP,
HTTP or the filesystem (store.py owns persistence).
"""
from __future__ import annotations

import difflib
from collections import deque

from . import resolver as rs
from .model import (
    CANONICAL_REL_SET,
    ENTITY_TYPES,
    Edge,
    Entity,
    coerce_amount,
    coerce_date,
    entity_key,
    new_id,
    norm_name,
    now_iso,
)


MAX_FINDINGS = 200


class Graph:
    """One investigation case, in memory. store.py loads/saves it."""

    def __init__(self) -> None:
        self.reindex()

    # -------------------------------------------------- load/dump

    def reindex(self) -> None:
        """(Re)initialise; called by store.load_case."""
        self.entities: dict[str, Entity] = {}
        self.edges: list[Edge] = []
        self.sources: dict[str, dict] = {}
        self.findings: list[str] = []
        self.no_links: list[dict] = []   # explicitly refuted gap pairs
        self.gaps: list[dict] = []
        self.pending_merge: list[dict] = []
        self.staged_items: list[dict] = []
        self.search_queue: list[str] = []
        self.seeds: list[str] = []
        self.write_mode: str = "auto"
        self.title: str = ""
        self.case_id: str = ""
        self.rev: int = 0
        self.dirty: bool = False  # changed since last flush
        self._rebuild_indexes()

    def _rebuild_indexes(self) -> None:
        self.by_key: dict[str, Entity] = {}
        for e in self.entities.values():
            self.by_key[e.key] = e
        self.by_edge: dict[tuple, Edge] = {
            (e.source, e.target, e.relationship): e for e in self.edges
        }

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "case_id": self.case_id,
            "rev": self.rev,
            "write_mode": self.write_mode,
            "seeds": list(self.seeds),
            "entities": {e.id: e.to_dict() for e in self.entities.values()},
            "edges": [e.to_dict() for e in self.edges],
            "sources": self.sources,
            "findings": list(self.findings),
            "no_links": list(self.no_links),
            "gaps": list(self.gaps),
            "pending_merge": list(self.pending_merge),
            "staged_items": list(self.staged_items),
            "search_queue": list(self.search_queue),
        }

    @staticmethod
    def from_dict(d: dict, case_id: str = "") -> "Graph":
        g = Graph()
        g.reindex()
        g.title = d.get("title", "")
        g.case_id = case_id or d.get("case_id", "")
        g.rev = int(d.get("rev", 0))
        g.write_mode = d.get("write_mode", "auto")
        for e in d.get("entities", {}).values():
            ent = Entity.parse(e)
            g.entities[ent.id] = ent
        g.seeds = [s for s in d.get("seeds", []) if s in g.entities]
        for ed in d.get("edges", []):
            g.edges.append(Edge.parse(ed))
        g.sources = dict(d.get("sources", {}))
        g.findings = list(d.get("findings", []))
        g.no_links = list(d.get("no_links", []))
        g.gaps = list(d.get("gaps", []))
        g.pending_merge = list(d.get("pending_merge", []))
        g.staged_items = list(d.get("staged_items", []))
        g.search_queue = [s for s in d.get("search_queue", []) if s in g.entities]
        g._rebuild_indexes()
        return g

    # -------------------------------------------------- sources

    def add_source(self, tool: str, query: str = "", url: str | None = None,
                   note: str = "") -> str:
        sid = f"s-{len(self.sources) + 1}"
        self.sources[sid] = {
            "tool": tool, "query": query, "asof": now_iso(),
        }
        if url:
            self.sources[sid]["url"] = url
        if note:
            self.sources[sid]["note"] = note
        self.dirty = True
        return sid

    # -------------------------------------------------- entities

    def add_entity(self, name: str, etype: str, aliases: list[str] | None = None,
                   source_note: str = "", metadata: dict | None = None,
                   source_tool: str = "human", discovered_at: str | None = None,
                   depth: int = 0) -> dict:
        """Resolve → absorb or create. Fuzzy near-matches are returned as
        suggestions, never merged silently."""
        if etype not in ENTITY_TYPES:
            return {"error": f"unknown entity type {etype!r}",
                    "valid_types": ENTITY_TYPES}
        src = self.add_source(source_tool, source_note)
        key = entity_key(etype, name, (metadata or {}).get("platform"))
        existing = self.by_key.get(key)
        if existing is not None:
            self._absorb(existing, name, aliases, src, metadata or {},
                         discovered_at, depth)
            eid = existing.id
        else:
            ent = Entity(
                id=new_id("e"), type=etype, name=name.strip(),
                aliases=[a for a in (aliases or []) if a],
                created_at=now_iso(),
                discovered_at=coerce_date(discovered_at),
                depth=depth, key=key, sources=[src],
            )
            self.entities[ent.id] = ent
            self.by_key[key] = ent
            eid = ent.id
            self._absorb(ent, None, aliases, src, metadata or {},
                         discovered_at, depth)
        fuzzy: list[dict] = []
        for other, ratio in rs.fuzzy_matches(self, etype, name, rs.IN_CASE_FUZZ,
                                             exclude=eid):
            if other.id == eid:
                continue
            # a=existing (survives), b=new (typo candidate gets absorbed)
            rs.suggest_merge(self, other, self.entities[eid],
                             f"name similarity {ratio:.2f} >= {rs.IN_CASE_FUZZ}")
            fuzzy.append({"id": other.id, "name": other.name,
                          "ratio": round(ratio, 3)})
        self.dirty = True
        return {"id": eid, "matched_existing": existing is not None,
                "fuzzy": fuzzy}

    def _absorb(self, ent: Entity, name: str | None, aliases: list | None,
                src: str | None, metadata: dict, discovered_at: str | None,
                depth: int) -> None:
        """Fold new information into an existing entity without ever
        overwriting provenance."""
        if name and name.lower() != ent.name.lower() and name not in ent.aliases:
            ent.aliases.append(name)
        for a in aliases or []:
            if a and a.lower() != ent.name.lower() and a not in ent.aliases:
                ent.aliases.append(a)
        if src and src not in ent.sources:
            ent.sources.append(src)
        if discovered_at:
            d = coerce_date(discovered_at)
            if d and (not ent.discovered_at or d < ent.discovered_at):
                ent.discovered_at = d
        if depth and ent.depth and depth < ent.depth:
            ent.depth = depth
        elif depth and not ent.depth:
            ent.depth = depth
        for k, v in (metadata or {}).items():
            if isinstance(v, dict) and "value" in v:
                triple = {"value": v.get("value"), "src": src or "",
                          "ts": v.get("ts") or now_iso()}
                if v.get("src") and not src:
                    triple["src"] = v["src"]
            else:
                triple = {"value": v, "src": src or "", "ts": now_iso()}
            if k not in ent.metadata:
                ent.metadata[k] = triple
            elif ent.metadata[k].get("value") != triple.get("value") and triple["value"]:
                hist = ent.provenance.setdefault(k, [])
                hist.append(triple)

    def lookup(self, ref: str) -> Entity | None:
        """Find one entity by id, exact name or unique name prefix."""
        ref = (ref or "").strip()
        if not ref:
            return None
        if ref in self.entities:
            return self.entities[ref]
        hit = self.by_key.get(ref)
        if hit:
            return hit
        low = ref.lower()
        cand = [x for x in self.entities.values() if x.name.lower() == low]
        if len(cand) == 1:
            return cand[0]
        pref = [x for x in self.entities.values()
                if x.name.lower().startswith(low)
                or low in any_alias(x)]
        if len(pref) == 1:
            return pref[0]
        return None

    def resolve_ref(self, ref: str) -> dict:
        """Resolve id/name to one entity: exact → unique prefix → substring
        or difflib similarity. Ambiguity returns candidates, never guesses."""
        e = self.lookup(ref)
        if e:
            return {"entity": e}
        low = norm_name(ref)
        seed = low[:5] if len(low[:5]) >= 3 else ""
        pool: dict[str, tuple[float, Entity]] = {}
        for x in self.entities.values():
            xn = norm_name(x.name)
            score = 0.65 if (seed and seed in xn) else \
                difflib.SequenceMatcher(None, low, xn).ratio()
            if score < 0.65:
                continue
            if x.id not in pool or pool[x.id][0] < score:
                pool[x.id] = (score, x)
        if len(pool) == 1:
            return {"entity": list(pool.values())[0][1]}
        return {"error": f"ambiguous or unknown reference {ref!r}",
                "candidates": [{"id": x.id, "type": x.type, "name": x.name,
                                "score": round(s, 2)}
                               for s, x in pool.values()]}

    # -------------------------------------------------- edges

    def link(self, source: str, target: str, relationship: str,
             confidence: float = 0.5, when_start: str = "", when_end: str = "",
             amount=None, currency: str = "", source_note: str = "",
             source_tool: str = "human") -> dict:
        """Add/merge an edge between two refs (id or name)."""
        sa, ta = self.resolve_ref(source), self.resolve_ref(target)
        failed = {k: v for d in (sa, ta) if "error" in d for k, v in d.items()}
        if failed:
            return failed
        src_e, tgt_e = sa["entity"], ta["entity"]
        rel = relationship.strip().lower().replace(" ", "_")
        if not rel:
            return {"error": "empty relationship"}
        w = None
        if when_start or when_end:
            w = {"start": coerce_date(when_start) or "",
                 "end": coerce_date(when_end) or ""}
            if not w["start"]:
                w.pop("start")
            if not w["end"]:
                w.pop("end", None)
            w = w or None
        amt = coerce_amount(amount)
        if amt and currency:
            amt["currency"] = currency.upper()
        key = (src_e.id, tgt_e.id, rel)
        sid = self.add_source(source_tool, source_note)
        if key in self.by_edge:
            e = self.by_edge[key]
            e.confidence = max(e.confidence, confidence)
            if sid not in e.sources:
                e.sources.append(sid)
            if w and not e.when:
                e.when = w
            if amt and not e.amount:
                e.amount = amt
            new = False
        else:
            e = Edge(id=new_id("x"), source=src_e.id, target=tgt_e.id,
                     relationship=rel, confidence=confidence, when=w,
                     amount=amt, sources=[sid])
            self.edges.append(e)
            self.by_edge[key] = e
            new = True
        self.dirty = True
        out = {"id": e.id, "source": src_e.id, "target": tgt_e.id,
               "relationship": rel, "new": new}
        if rel not in CANONICAL_REL_SET:
            out["note"] = (f"free-form relationship {rel!r}; prefer one of: "
                           + ", ".join(sorted(CANONICAL_REL_SET)))
        return out

    def drop_entity(self, eid: str) -> None:
        """Remove an entity and re-point or drop dependent structures."""
        e = self.entities.pop(eid, None)
        if not e:
            return
        self.by_key.pop(e.key, None)
        self.edges = [x for x in self.edges
                      if x.source != eid and x.target != eid]
        self._rebuild_indexes_for_drop(eid)
        self.dirty = True

    def _rebuild_indexes_for_drop(self, dropped: str) -> None:
        self.by_edge = {(x.source, x.target, x.relationship): x
                        for x in self.edges}
        self.pending_merge = [m for m in self.pending_merge
                              if dropped not in (m.get("a_id"), m.get("b_id"))]
        self.search_queue = [s for s in self.search_queue if s != dropped]
        self.seeds = [s for s in self.seeds if s != dropped]

    def dedupe_edges(self, symmetric: bool = False) -> None:
        """Collapse duplicate (source,target,relationship) edges: union
        sources, keep max confidence. symmetric=True also collapses the
        reverse-direction twin (used after merges, where orientation of the
        re-parented edge may mirror an existing one)."""
        seen: dict[tuple, Edge] = {}
        for e in self.edges:
            k = (e.source, e.target, e.relationship)
            hit = seen.get(k)
            if hit is None and symmetric:
                hit = seen.get((e.target, e.source, e.relationship))
            if hit is not None:
                hit.confidence = max(hit.confidence, e.confidence)
                for s in e.sources:
                    if s not in hit.sources:
                        hit.sources.append(s)
                if e.when and not hit.when:
                    hit.when = e.when
                if e.amount and not hit.amount:
                    hit.amount = e.amount
            else:
                seen[k] = e
        self.edges = list(seen.values())
        self.by_edge = seen

    def prune(self, eid: str) -> dict:
        name = self.entities[eid].name if eid in self.entities else eid
        self.drop_entity(eid)
        return {"pruned": eid, "name": name,
                "remaining": len(self.entities)}

    # -------------------------------------------------- queue / depth

    def queue(self, ref: str) -> dict:
        e = self.resolve_ref(ref)
        if "error" in e:
            return e
        eid = e["entity"].id
        if eid not in self.search_queue:
            self.search_queue.append(eid)
            self.dirty = True
        return {"queued": eid, "queue_len": len(self.search_queue)}

    def next_target(self) -> Entity | None:
        while self.search_queue:
            eid = self.search_queue.pop(0)
            e = self.entities.get(eid)
            if e and not e.investigated:
                e.investigated = True
                self.dirty = True
                return e
        return None

    def recompute_depth(self) -> None:
        """BFS from seeds over undirected edges; unreachable keeps depth."""
        if not self.seeds:
            return
        adj: dict[str, list[str]] = {}
        for x in self.edges:
            adj.setdefault(x.source, []).append(x.target)
            adj.setdefault(x.target, []).append(x.source)
        seen = {s: 0 for s in self.seeds if s in self.entities}
        q = deque((eid, 0) for eid in list(seen))
        while q:
            eid, d = q.popleft()
            for nid in adj.get(eid, []):
                if nid not in seen:
                    seen[nid] = d + 1
                    q.append((nid, d + 1))
        for eid, d in seen.items():
            self.entities[eid].depth = d
        self.dirty = True

    # -------------------------------------------------- findings

    def add_finding(self, text: str) -> None:
        if text and text not in self.findings:
            self.findings.append(text)
            if len(self.findings) > MAX_FINDINGS:
                self.findings = self.findings[-MAX_FINDINGS:]
            self.dirty = True


def any_alias(e: Entity) -> str:
    return "|".join([e.name] + e.aliases).lower()