#!/usr/bin/env python3
"""Staged write gate + merge queue.

Two queues live on each case:
- staged_items  — proposed entities/edges in `stage` write mode
- pending_merge — fuzzy merge suggestions (never applied silently)

In `auto` mode (the default) nothing is staged: the MCP permission prompt
is the human approval, and case.json backups allow rollback. In `stage`
mode (intended for unattended agents) write-tools park their payload here
instead of writing to the graph.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from . import resolver as rs
from .model import new_id, now_iso

if TYPE_CHECKING:  # pragma: no cover
    from .core import Graph

BATCH_LIMIT = 500  # refuse to grow one batch beyond sanity


def stage(graph: "Graph", kind: str, payload: dict, batch_id: str = "") -> dict:
    """Park a proposed write. Returns the staged record."""
    batch_id = batch_id or new_id("b")[:12]
    item = {
        "id": new_id("s"),
        "batch_id": batch_id,
        "kind": kind,  # entity | link
        "payload": payload,
        "proposed_at": now_iso(),
    }
    if len(graph.staged_items) >= BATCH_LIMIT:
        return {"error": f"staging queue full (>{BATCH_LIMIT})",
                "hint": "approve or clear graph.staged_items first"}
    graph.staged_items.append(item)
    graph.dirty = True
    return {"staged": True, "item_id": item["id"], "batch_id": batch_id,
            "count": len(graph.staged_items)}


def stage_ops(graph: "Graph", ops_item: dict) -> dict:
    """Park a whole enrich ops-batch as one approval item (kind='ops')."""
    batch_id = new_id("b")[:12]
    item = {
        "id": new_id("s"), "batch_id": batch_id, "kind": "ops",
        "payload": ops_item,
        "proposed_at": now_iso(),
        "summary": {"tool": ops_item.get("tool"),
                    "target": ops_item.get("target"),
                    "entities": sum(1 for o in ops_item.get("ops", [])
                                    if o[0] == "entity"),
                    "links": sum(1 for o in ops_item.get("ops", [])
                                 if o[0] == "link")},
    }
    graph.staged_items.append(item)
    graph.dirty = True
    return {"staged": True, "item_id": item["id"], "batch_id": batch_id,
            "count": len(graph.staged_items)}


def review(graph: "Graph") -> list[dict]:
    """Everything awaiting human action, UI-shaped."""
    return graph.staged_items + [
        {**m, "kind": "merge"} for m in graph.pending_merge
    ]


def act(graph: "Graph", item_ids: list[str], action: str) -> dict:
    """approve|reject staged items and/or merge suggestions.

    For merged entities, `id` is a pending_merge suggestion; approving it
    performs the merge (b into a), rejecting declines it.
    """
    if action not in ("approve", "reject"):
        return {"error": f"action must be approve|reject, got {action!r}"}
    applied = rejected = 0
    errors: list[str] = []
    for iid in item_ids:
        staged = next((s for s in graph.staged_items if s["id"] == iid), None)
        if staged:
            if action == "approve":
                p = staged["payload"]
                if staged["kind"] == "ops":  # whole enrich batch
                    from . import enrich as enrichm
                    res = enrichm.apply_ops(
                        graph, p.get("ops", []),
                        source_note=f"approved:{p.get('tool')}",
                        source_tool=p.get("tool", "approved"))
                    graph.add_finding(
                        f"STAGE APPROVED: enrich {p.get('tool')} "
                        f"{p.get('target')} — {res}")
                elif staged["kind"] == "entity":
                    r = graph.add_entity(p["name"], p["type"],
                                         aliases=p.get("aliases"),
                                         source_note=p.get("source_note", ""),
                                         metadata=p.get("metadata"),
                                         source_tool="approved",
                                         seed=bool(p.get("seed")))
                    if "error" in r:
                        errors.append(f'{staged["id"]}: {r["error"]}')
                elif staged["kind"] == "link":
                    r = graph.link(p["source"], p["target"], p["relationship"],
                                   p.get("confidence", 0.5),
                                   when_start=p.get("when_start", ""),
                                   when_end=p.get("when_end", ""),
                                   amount=p.get("amount"),
                                   source_tool="approved")
                    if "error" in r:
                        errors.append(f'{staged["id"]}: {r["error"]}')
                applied += 1
            else:
                rejected += 1
            graph.staged_items.remove(staged)
            continue
        merge_sug = next((m for m in graph.pending_merge if m["id"] == iid),
                         None)
        if merge_sug is None:
            continue
        if action == "approve":
            keep_id = rs.merge(graph, merge_sug["a_id"], merge_sug["b_id"],
                               merge_sug.get("why", ""))
            if keep_id:
                applied += 1
        else:
            rejected += 1
        if merge_sug in graph.pending_merge:
            graph.pending_merge.remove(merge_sug)
    graph.dirty = True
    out = {"approved" if action == "approve" else "rejected": applied,
           "remaining": len(graph.staged_items) + len(graph.pending_merge)}
    if errors:
        out["errors"] = errors
    return out


def clear(graph: "Graph", batch_id: str = "") -> int:
    """Drop staged items (all, or one batch)."""
    before = len(graph.staged_items)
    graph.staged_items = [s for s in graph.staged_items
                          if not batch_id or s.get("batch_id") != batch_id]
    graph.dirty = True
    return before - len(graph.staged_items)