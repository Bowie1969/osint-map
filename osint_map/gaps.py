#!/usr/bin/env python3
"""Suspicion-scored gap detection: triadic closure over the graph.

For every a↔b↔c triangle where the a↔c edge is missing, score how
interesting the missing connection is (transparent rubric, design idea
credited to DeepDive, reimplemented):

  +2   a and c are the same entity type
  +3   both person, or both company
  +3   both are money-adjacent (money entities or paid/owned edges)
  +2   each end is well connected (>5 edges)
  +2×N (N-1) beyond the first shared bridge

Gaps with score >= MIN_GAP_SCORE are kept, highest first. An explicitly
researched negative becomes a `no_links` record and is never re-proposed.
"""
from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

from .model import now_iso

if TYPE_CHECKING:  # pragma: no cover
    from .core import Graph

SAME_TYPE_SCORE = 2
PEER_SCORE = 3                      # person/person or company/company
MONEY_SCORE = 3
DEGREE_SCORE = 2
WELL_CONNECTED = 5
BRIDGE_SCORE = 2                    # per shared bridge beyond the first
MIN_GAP_SCORE = 2
STRUCTURAL_PENALTY = 4
# relations that express "hanging off the same parent" rather than "these
# two things themselves are connected" — a pair whose ONLY bridges are
# structural is org-chart noise, not a lead
STRUCTURAL_RELS = frozenset({
    "employs", "subdomain_of", "located_in", "registered_to",
    "resolves_to", "uses_serves",
})
PEER_PAIR = frozenset({"person", "company", "money"})

_NO_CONN_SENTINEL = "no_connection"


def score_gap(graph: "Graph", a: str, c: str, n_bridges: int) -> tuple[int, str]:
    """Score one missing edge pair. Returns (score, human-readable reasons)."""
    ea, ec = graph.entities.get(a), graph.entities.get(c)
    if not ea or not ec:
        return 0, ""
    s = Counter()
    for e in (ea, ec):
        degree = sum(1 for x in graph.edges
                     if x.source == e.id or x.target == e.id)
        if degree > WELL_CONNECTED:
            s["well_connected"] += DEGREE_SCORE
    if ea.type == ec.type:
        s["same_type"] += SAME_TYPE_SCORE
        if ea.type in PEER_PAIR:
            s["peer_pair"] += PEER_SCORE
    if _money_adjacent(graph, ea) and _money_adjacent(graph, ec):
        s["money"] += MONEY_SCORE
    if n_bridges > 1:
        s["bridges"] += BRIDGE_SCORE * (n_bridges - 1)
    reasons = ", ".join(f"{k}:+{v}" for k, v in s.most_common())
    return sum(s.values()), reasons


def _structural_bridges_only(graph: "Graph", a: str, c: str,
                             bridges: set[str]) -> bool:
    """True if every shared bridge connects to both ends only via
    structural relations (co-workers, subdomains of one domain...)."""
    rel = {}
    for x in graph.edges:
        rel[(x.source, x.target)] = x.relationship
        rel[(x.target, x.source)] = x.relationship
    for b in bridges:
        if (rel.get((a, b)) not in STRUCTURAL_RELS
                or rel.get((c, b)) not in STRUCTURAL_RELS):
            return False
    return True


def _money_adjacent(graph: "Graph", e) -> bool:
    meta = e.metadata or {}
    if e.type == "money":
        return True
    if any(k in meta for k in ("amount", "currency", "revenue")):
        return True
    return any(x.relationship in ("paid_to", "owns", "controls")
               for x in graph.edges
               if x.source == e.id or x.target == e.id)


def find_gaps(graph: "Graph", limit: int = 10,
              min_score: int = MIN_GAP_SCORE) -> list[dict]:
    """All unlinked pairs that share at least one bridge, scored."""
    adj: dict[str, set[str]] = {}
    linked: set[tuple[str, str]] = set()
    for x in graph.edges:
        adj.setdefault(x.source, set()).add(x.target)
        adj.setdefault(x.target, set()).add(x.source)
        linked.add((x.source, x.target))
        linked.add((x.target, x.source))
    negatives = {(r["a"], r["c"]) for r in graph.no_links} | \
                {(r["c"], r["a"]) for r in graph.no_links}

    candidates: dict[tuple[str, str], set[str]] = {}
    for a, nbrs in adj.items():
        for b in nbrs:
            for c in adj.get(b, ()):  # two-hop partner through b
                if c == a or (a, c) in linked or (c, a) in linked:
                    continue
                if (a, c) in negatives:
                    continue
                pair = (a, c) if a < c else (c, a)
                candidates.setdefault(pair, set()).add(b)

    scored = []
    for (a, c), seen in candidates.items():
        # the real bridge count: neighbours shared by BOTH ends
        bridges = adj.get(a, set()) & adj.get(c, set())
        bridges |= seen
        if not bridges:
            continue
        score, reasons = score_gap(graph, a, c, len(bridges))
        if score >= min_score and _structural_bridges_only(graph, a, c, bridges):
            # every bridge is structural (co-workers of one company, subdomains
            # of one domain): connected through the parent, not to each other
            score -= STRUCTURAL_PENALTY
            reasons += f", structural_only:-{STRUCTURAL_PENALTY}"
        if score < min_score:
            continue
        ea, ec = graph.entities[a], graph.entities[c]
        scored.append({
            "a": a, "a_name": ea.name, "a_type": ea.type,
            "c": c, "c_name": ec.name, "c_type": ec.type,
            "score": score, "reasons": reasons,
            "bridges": sorted((graph.entities[b].name for b in bridges
                               if b in graph.entities),
                              key=str.lower)[:4],
            "researched": False, "found_at": now_iso(),
        })
    scored.sort(key=lambda g: -g["score"])
    return _sync(graph, scored[:limit])


def _sync(graph: "Graph", fresh: list[dict]) -> list[dict]:
    """Merge the fresh scan into graph.gaps: carry forward researched /
    dispositioned flags; skip refuted pairs; drop stale cards."""
    out: list[dict] = []
    for s in fresh:
        prev = next((g for g in graph.gaps
                     if {g["a"], g["c"]} == {s["a"], s["c"]}), None)
        if prev:
            s["researched"] = prev.get("researched", False)
            s["found_at"] = prev.get("found_at") or s["found_at"]
        out.append(s)
    graph.gaps = out
    graph.dirty = True
    return graph.gaps


def close_gap(graph: "Graph", a: str, c: str, confirmed: bool,
              detail: str = "") -> dict:
    """Record the outcome of researching a gap.

    confirmed=False: explicit negative → no_links record, the pair is never
    re-proposed. confirmed=True: the edge goes in via graph_link and the
    gap card is retired ("GAP FILLED").
    """
    def nm(x: str) -> str:
        return graph.entities[x].name if x in graph.entities else x

    if not confirmed:
        graph.no_links.append({"a": a, "c": c, "detail": detail,
                               "at": now_iso()})
        graph.add_finding(f"GAP CONFIRMED no connection: {nm(a)} ↔ {nm(c)}"
                          + (f" — {detail}" if detail else ""))
    else:
        graph.add_finding(f"GAP FILLED: {nm(a)} ↔ {nm(c)}"
                          + (f" — {detail}" if detail else ""))
    graph.gaps = [g for g in graph.gaps if {g["a"], g["c"]} != {a, c}]
    graph.dirty = True
    return {"closed": True, "confirmed": confirmed, "a": a, "c": c}