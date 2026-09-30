#!/usr/bin/env python3
"""Entity resolution: identity keys, exact/fuzzy matching, merge engine.

The DeepDive lesson baked in here: within-case fuzzy matches are NEVER
silently applied — they raise a merge suggestion for human review. Only
canonical-value collisions (same email, same FQDN, same IP...) merge
automatically.
"""
from __future__ import annotations

import difflib
from typing import TYPE_CHECKING

from .model import (
    CROSS_CASE_FUZZ,
    FUZZ_MIN_NAME_LEN,
    FUZZ_TRIO,
    IN_CASE_FUZZ,
    entity_key,
    new_id,
    norm_name,
)

__all__ = ["IN_CASE_FUZZ", "CROSS_CASE_FUZZ"]

if TYPE_CHECKING:  # pragma: no cover
    from .core import Graph


def _fuzzy_ok(a_type: str, b_type: str) -> bool:
    """Same type required, with the person/username/email exception trio."""
    return a_type == b_type or (a_type in FUZZ_TRIO and b_type in FUZZ_TRIO)


def exact_match(graph: "Graph", etype: str, name: str, platform: str | None) -> object | None:
    """Entity whose derived key matches this one exactly, if any."""
    key = entity_key(etype, name, platform)
    return graph.by_key.get(key)


def _name_key(e) -> str:
    """Entity name normalized for similarity search; key types canonical
    values (mail/FQDN/ip) compare better than display names."""
    return norm_name(e.name)


def fuzzy_matches(graph: "Graph", etype: str, name: str, threshold: float,
                  limit: int = 5, exclude: str | None = None
                  ) -> list[tuple["Entity", float]]:
    """Same-type (or trio) entities whose norm_name is >= threshold similar.
    Short names are skipped — 'Lee' vs 'Lea' is noise, not signal."""
    probe = norm_name(name)
    if len(probe) < FUZZ_MIN_NAME_LEN:
        return []
    hits = []
    for e in graph.entities.values():
        if exclude and e.id == exclude:
            continue
        if not _fuzzy_ok(etype, e.type):
            continue
        if len(norm_name(e.name)) < FUZZ_MIN_NAME_LEN:
            continue
        ratio = difflib.SequenceMatcher(None, probe, _name_key(e)).ratio()
        if ratio >= threshold:
            hits.append((e, ratio))
    hits.sort(key=lambda t: -t[1])
    return hits[:limit]


def merge(graph: "Graph", keep_id: str, other_id: str, note: str = "") -> str:
    """Merge `other` into `keep`: re-parent edges, union aliases and
    sources, concat provenance, keep names as aliases, record merged_from.
    Returns keep_id."""
    keep, other = graph.entities.get(keep_id), graph.entities.get(other_id)
    if not keep or not other or keep_id == other_id:
        return keep_id
    for e in graph.edges:
        if e.source == other_id:
            e.source = keep_id
        if e.target == other_id:
            e.target = keep_id
    if other.name.lower() != keep.name.lower() and other.name not in keep.aliases:
        keep.aliases.append(other.name)
    keep.aliases = sorted(set(keep.aliases) | set(other.aliases))
    # Additive metadata merge; conflicts -> other's value appended to provenance.
    for k, trip in other.metadata.items():
        if k not in keep.metadata:
            keep.metadata[k] = trip
        elif keep.metadata[k].get("value") != trip.get("value"):
            keep.provenance.setdefault(k, []).append(
                {"value": keep.metadata[k].get("value"), **keep.metadata[k]}
            )
            keep.metadata[k] = trip
    for k, hist in other.provenance.items():
        keep.provenance.setdefault(k, [])
        for item in hist:
            if item not in keep.provenance[k]:
                keep.provenance[k].append(item)
    keep.sources = sorted(set(keep.sources) | set(other.sources))
    keep.discovered_at = min(x for x in (keep.discovered_at, other.discovered_at,
                                         "") if x is not None) or keep.discovered_at
    keep.merged_from.append(other_id)
    graph.drop_entity(other_id)
    graph.dedupe_edges(symmetric=True)  # re-parenting can mirror a link
    graph.add_finding(f"MERGED: {other.name} -> {keep.name}"
                      + (f" ({note})" if note else ""))
    # Merge suggestions referencing the dead id are now obsolete.
    graph.pending_merge = [
        m for m in graph.pending_merge if other_id not in (m.get("a_id"), m.get("b_id"))
    ]
    return keep_id


def suggest_merge(graph: "Graph", cand, other, why: str = "") -> None:
    """Queue a fuzzy merge suggestion unless one already pending."""
    for m in graph.pending_merge:
        if {cand.id, other.id} == {m.get("a_id"), m.get("b_id")}:
            return
    graph.pending_merge.append({
        "id": new_id("m"),
        "a_id": cand.id, "a_name": cand.name, "a_type": cand.type,
        "b_id": other.id, "b_name": other.name, "b_type": other.type,
        "why": why,
    })