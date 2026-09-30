#!/usr/bin/env python3
"""Cross-case entity linking: exact canonical-id matches and difflib fuzzy
matches across every other saved case. Exact hits can be applied directly;
fuzzy hits become merge suggestions requiring human confirmation.

Optional local-embedding similarity (Ollama) is deliberately out of v1.
"""
from __future__ import annotations

import difflib
from typing import TYPE_CHECKING

from .model import (
    CROSS_CASE_FUZZ,
    FUZZ_MIN_NAME_LEN,
    entity_key,
    norm_name,
)
from .resolver import EXACT_ONLY_TYPES

if TYPE_CHECKING:  # pragma: no cover
    from .core import Graph

# Types allowed to fuzzy-match across cases (same-type or the identity trio).
TRIO = frozenset({"person", "username", "email"})


def crosslink(graph: "Graph", others: list["Graph"]) -> dict:
    """Compare graph against each other case. Returns suggestions; with
    apply=True (caller), exact hits are merged into THIS graph."""
    exact, fuzzy = [], []
    my_keys = graph.by_key
    for other in others:
        for ent in other.entities.values():
            if ent.key in my_keys:
                exact.append({"case": other.case_id,
                              "id": ent.id, "key": ent.key,
                              "name": ent.name, "type": ent.type})
                continue
            if _fuzzy_blocked(ent.type):
                continue
            probe = norm_name(ent.name)
            if len(probe) < FUZZ_MIN_NAME_LEN:
                continue
            best = None
            for mine in graph.entities.values():
                if not _types_ok(ent.type, mine.type):
                    continue
                m = norm_name(mine.name)
                if len(m) < FUZZ_MIN_NAME_LEN:
                    continue
                ratio = difflib.SequenceMatcher(None, probe, m).ratio()
                if ratio >= CROSS_CASE_FUZZ and (best is None or ratio > best[1]):
                    best = (mine, ratio)
            if best:
                mine, ratio = best
                fuzzy.append({
                    "case": other.case_id,
                    "a": mine.id, "a_name": mine.name, "a_type": mine.type,
                    "b": ent.id, "b_name": ent.name, "b_type": ent.type,
                    "ratio": round(ratio, 3), "other_case": other.case_id,
                })
    return {"exact": exact, "fuzzy": fuzzy}


def _types_ok(a: str, b: str) -> bool:
    return a == b or (a in TRIO and b in TRIO)


def _fuzzy_blocked(t: str) -> bool:
    """Types where a name similarity never implies identity across cases
    (two IPs can't fuzzy-match; companies differ by one letter all the time).
    Strictly wider than resolver.EXACT_ONLY_TYPES: usernames are trio-fuzzy
    within a case but cross-case they collide too easily (common handles)."""
    return t in EXACT_ONLY_TYPES or t == "username"


def bring_in(graph: "Graph", other: "Graph", entity_ids: list[str]) -> dict:
    """Copy foreign entities (and their edges, when both ends copy) into
    this case, remapping ids; sources tagged with the origin case."""
    remap: dict[str, str] = {}
    from .model import Entity  # local import keeps crosslink dependency-light
    for eid in entity_ids:
        ent = other.entities.get(eid)
        if not ent:
            continue
        if ent.key in graph.by_key:
            remap[eid] = graph.by_key[ent.key].id
            continue
        clone = Entity(
            id=f"f-{ent.id}", type=ent.type, name=ent.name,
            aliases=list(ent.aliases), discovered_at=ent.discovered_at,
            key=ent.key, metadata=dict(ent.metadata),
            provenance=dict(ent.provenance),
        )
        clone.sources.append(f"case:{other.case_id}")
        graph.entities[clone.id] = clone
        graph.by_key[clone.key] = clone
        remap[eid] = clone.id
    copied = 0
    for edge in other.edges:
        if edge.source in remap and edge.target in remap:
            new_key = (remap[edge.source], remap[edge.target], edge.relationship)
            if new_key not in graph.by_edge:
                from .model import Edge
                clone = Edge(
                    id=f"f-{edge.id}", source=remap[edge.source],
                    target=remap[edge.target], relationship=edge.relationship,
                    confidence=edge.confidence, when=edge.when,
                    amount=edge.amount, metadata=dict(edge.metadata),
                )
                clone.sources.append(f"case:{other.case_id}")
                graph.edges.append(clone)
                graph.by_edge[new_key] = clone
                copied += 1
    graph.dirty = True
    return {"imported": len(remap), "edges": copied}