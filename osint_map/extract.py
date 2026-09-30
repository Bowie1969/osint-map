#!/usr/bin/env python3
"""Pipe-delimited extraction contract: lets ANY model (including ones
without function calling) add graph data.

Format, one row per line:

  NAME | TYPE | RELATION | CONF
  NAME | TYPE | RELATION-> TARGET | CONF | WHEN | AMOUNT

- RELATION may carry an arrow plus a TARGET name; a bare relation links
  NAME to the case's seed entity.
- CONF is 0.0-1.0 (words high/med/low map to 0.9/0.7/0.4).
- WHEN is a date ('2021', 'since-1988'); AMOUNT is money ('$25k', '1.2M USD').

Junk rows are rejected with reasons so the caller can replay them.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .model import (
    ENTITY_TYPES,
    coerce_amount,
    coerce_date,
)

if TYPE_CHECKING:  # pragma: no cover
    from .core import Graph

JUNK = frozenset({
    "", "-", "?", "n/a", "na", "n.a.", "none", "null", "unknown", "unk",
    "tbc", "tbd", "nobody", "not known", "no idea", "redacted", "withheld",
    "[name]", "person", "people", "someone", "the company", "they", "it",
    "target", "self", "same",
})
MAX_NAME_LEN = 90
ARROW = re.compile(r"^([A-Za-z_ -]+?)\s*(?:->|=>|\bto:)\s*(.+)$")
CONF_WORDS = {"high": 0.9, "med": 0.7, "medium": 0.7, "mid": 0.7, "low": 0.4,
              "certain": 1.0, "confirmed": 1.0, "speculative": 0.3}


def parse_line(line: str) -> dict | None:
    """One pipe line -> row dict, or {'reject': reason}. Never raises."""
    raw = [p.strip() for p in line.split("|")]
    if len(raw) < 3:
        return {"reject": "need at least NAME | TYPE | RELATION"}
    name, etype, relation = raw[0], raw[1].lower(), raw[2]
    if len(name) > MAX_NAME_LEN:
        return {"reject": f"name > {MAX_NAME_LEN} chars"}
    if name.lower() in JUNK:
        return {"reject": f"junk name {name!r}"}
    if not any(c.isalnum() for c in name) and not any(c.isdigit() for c in name):
        return {"reject": f"punctuation-only name {name!r}"}
    digits = sum(c.isdigit() for c in name)
    if name and digits / len(name) > 0.4 and etype not in ("ip", "phone"):
        return {"reject": f"digit-heavy name {name!r}"}
    if etype not in ENTITY_TYPES:
        return {"reject": f"unknown type {etype!r} (valid: "
                          f"{', '.join(ENTITY_TYPES)})"}
    conf_raw = raw[3].lower() if len(raw) > 3 else "0.5"
    conf = CONF_WORDS.get(conf_raw)
    if conf is None:
        try:
            conf = max(0.0, min(1.0, float(conf_raw)))
        except ValueError:
            return {"reject": f"bad confidence {raw[3]!r}"}
    when = coerce_date(raw[4]) if len(raw) > 4 else None
    amount = coerce_amount(raw[5]) if len(raw) > 5 else None

    rel, target = relation, ""
    arrow = ARROW.match(rel)
    if arrow:
        rel, target = arrow.group(1).strip(), arrow.group(2).strip()
    if target.lower() in JUNK:
        target = ""
    rel = rel.lower().strip().replace(" ", "_").strip("_-")
    if not rel:
        return {"reject": "empty relation"}
    out = {"name": name, "type": etype, "relation": rel, "conf": conf}
    if target:
        out["target"] = target
    if when:
        out["when"] = when
    if amount:
        out["amount"] = amount
    return out


def _infer_type(row: dict) -> str:
    """Type for an inline arrow target: inherit the row's type for
    organisation-ish types, else company."""
    if row["type"] in ("person", "company", "domain", "subdomain", "username",
                       "account"):
        return row["type"]
    return "company"


def apply_extract(graph: "Graph", text: str, source_note: str = "",
                  source_tool: str = "extract") -> dict:
    """Parse `text`; write entities + edges. Returns a compact counts
    summary plus rejected lines verbatim for the caller to replay."""
    rejected: list[dict] = []
    created = linked = 0
    seed = graph.entities[graph.seeds[0]] if graph.seeds else None
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        p = parse_line(ln)
        if "reject" in p:
            rejected.append({"line": ln, "reason": p["reject"]})
            continue
        res = graph.add_entity(p["name"], p["type"], source_tool=source_tool,
                               source_note=source_note)
        if "error" in res:
            rejected.append({"line": ln, "reason": res["error"]})
            continue
        if not res["matched_existing"]:
            created += 1
        ent_id = res["id"]
        if p.get("target"):
            tres = graph.add_entity(p["target"], _infer_type(p),
                                    source_tool=source_tool,
                                    source_note=source_note)
            if "error" in tres:
                rejected.append({"line": ln, "reason": tres["error"]})
                continue
            if not tres["matched_existing"]:
                created += 1
            tgt_id = tres["id"]
        elif seed and p["name"].lower() != seed.name.lower():
            tgt_id = seed.id
        else:
            rejected.append({"line": ln,
                             "reason": "no arrow target and line names the seed"})
            continue
        link = graph.link(ent_id, tgt_id, p["relation"], p["conf"],
                          when_start=p.get("when", ""),
                          amount=p.get("amount"),
                          source_note=source_note, source_tool=source_tool)
        if "error" in link:
            rejected.append({"line": ln, "reason": link["error"]})
        else:
            linked += 1
    return {
        "summary": {
            "lines": len([l for l in text.splitlines() if l.strip()]),
            "entities_created": created,
            "links": linked,
            "rejected": len(rejected),
        },
        "rejected_lines": rejected,
    }