#!/usr/bin/env python3
"""Data model, types and coercion helpers for osint-map.

Knows nothing about MCP or HTTP: plain dataclasses and pure functions.
"""
from __future__ import annotations

import re
import unicodedata
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------- enums

ENTITY_TYPES = [
    "person", "company", "domain", "subdomain", "ip", "netblock", "asn",
    "username", "account", "email", "phone", "location",
    "event", "document", "device", "money",
]

# Fuzzy matching is allowed across these types (same human, identity surfaces).
FUZZ_TRIO = frozenset({"person", "username", "email"})

# Canonical relationships; free-form additions are allowed but flagged.
CANONICAL_RELATIONS = [
    "owns", "controls", "employs", "subsidiary_of", "affiliated_with",
    "subdomain_of", "resolves_to", "hosted_on", "registered_to",
    "located_in", "uses_serves", "communicates_with", "mentions",
    "paid_to", "related_to",
]

CANONICAL_REL_SET = frozenset(CANONICAL_RELATIONS)

# JEXL-style thresholds used by resolver and cross-link.
IN_CASE_FUZZ = 0.90
CROSS_CASE_FUZZ = 0.82
FUZZ_MIN_NAME_LEN = 5  # substring len — shorter names are too generic

# Types whose canonical value is a hard identity key: an exact canonical
# collision is the same entity, silently merged.
EXACT_KEY_TYPES = frozenset({
    "email", "phone", "domain", "subdomain", "ip", "netblock", "asn",
})

# ---------------------------------------------------------------- ids

def new_id(kind: str = "e") -> str:
    """Short stable id, e.g. e-D3FA2B71. ULID-adjacent, collision-safe enough
    for single-user scale."""
    return f"{kind}-{uuid.uuid4().hex[:8].upper()}"


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def today_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")

# ---------------------------------------------------------------- text

_WORD_SPLIT = re.compile(r"[\s_]+")


def norm_name(name: str) -> str:
    """Canonical display-independent form: fold accents, lowercase, drop
    punctuation except - . @ : /, collapse whitespace. Used for exact-key
    derivation and fuzzy matching."""
    name = unicodedata.normalize("NFKD", name)
    name = "".join(c for c in name if not unicodedata.combining(c))
    name = name.lower()
    name = re.sub(r"[^a-z0-9@.:/ _-]", "", name)
    return re.sub(r"[\s_]+", " ", name).strip()


def entity_key(etype: str, name: str, platform: str | None = None) -> str:
    """Derived resolution key. Exact-key types canonicalise the value
    itself (email->lowercase address); others use norm_name."""
    if etype in ("email", "domain", "subdomain", "url"):
        return f"{etype}|{name.strip().lower()}"
    if etype == "ip":
        return f"ip|{_norm_ip(name)}"
    if etype == "netblock":
        return f"netblock|{_norm_netblock(name)}"
    if etype == "asn":
        m = re.search(r"\d+", name)
        return f"asn|AS{m.group(0)}" if m else f"asn|{norm_name(name)}"
    if etype == "phone":
        canon = _e164(name)
        return f"phone|{canon}" if canon else f"phone|{norm_name(name)}"
    if etype == "username":
        base = norm_name(name.split("@", 1)[0] if name.count("@") == 1 else name)
        if platform:
            return f"username|{norm_name(platform)}:{base}"
        return f"username|{base}"
    return f"{etype}|{norm_name(name)}"


def _norm_ip(value: str) -> str:
    v = value.strip().lower()
    if ":" in v:  # ipv6 — lowercased, compressed leading zeros
        try:
            import ipaddress
            return str(ipaddress.ip_address(v))
        except Exception:
            return v
    parts = v.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return ".".join(str(int(p)) for p in parts)
    return v


def _norm_netblock(value: str) -> str:
    """Normalize CIDR/bare IP → 'x.x.x.x/nn' where possible."""
    v = value.strip().lower().replace(" ", "")
    try:
        import ipaddress
        net = ipaddress.ip_network(v, strict=False)
        return str(net)
    except Exception:
        return v


def _e164(number: str, default_cc: str = "+61") -> str:
    """National-format input -> E.164 (mirrors osint-mcp's phoneinfoga rule)."""
    n = re.sub(r"[ \-()]", "", number.strip())
    if n.startswith("+"):
        return n
    if default_cc and n.startswith("0"):
        return default_cc + n[1:]
    if n and not n.startswith("+"):
        return default_cc + n
    return n

# ---------------------------------------------------------------- coercion

_DATE_PATTERNS = (
    "%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%Y/%m/%d",
    "%d-%m-%Y", "%Y%m", "%Y",
)


def coerce_date(value: str | None) -> str | None:
    """Best-effort ISO date (YYYY[-MM[-DD]]) or None. Never scrapes dates
    from arbitrary text — only from fields meant to hold dates."""
    if not value:
        return None
    v = str(value).strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}T.*", v):
        return v[:10] if "T" not in v[:10] else v
    for pat in _DATE_PATTERNS:
        try:
            d = datetime.strptime(v.split("T")[0], pat)
            if pat == "%Y%m":
                return d.strftime("%Y-%m")
            if pat == "%Y":
                return d.strftime("%Y")
            return d.strftime("%Y-%m-%d")
        except ValueError:
            continue
    return None


_MONEY_RE = re.compile(
    r"(?P<cur>[A-Z]{3}|[$€£¥]|AUD|USD|EUR|GBP)?\s*"
    r"(?P<num>[0-9][0-9.,\s]*(?:[kbm]n?)?)",
    re.IGNORECASE,
)
_CUR_MAP = {"$": "AUD", "AUD": "AUD", "USD": "USD", "€": "EUR", "EUR": "EUR",
            "£": "GBP", "GBP": "GBP", "¥": "JPY", "JPY": "JPY"}
# bare '$' assumed AUD: the operator's default jurisdiction.


def coerce_amount(value: str | int | float | None) -> dict | None:
    """'$25,000' / '25k' / '1.2M USD' -> {'value': 25000, 'currency': 'AUD'}."""
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return {"value": float(value), "currency": "AUD"}
    s = str(value)
    m = _MONEY_RE.search(s)
    if not m:
        return None
    cur_raw, num_raw = m.group("cur"), m.group("num")
    word = re.search(r"\b(USD|EUR|GBP|JPY|AUD)\b", s.upper())
    if word:
        currency = word.group(1)
    else:
        currency = _CUR_MAP.get((cur_raw or "").strip()) or "AUD"
    num = num_raw.lower().replace(",", "").replace(" ", "")
    mult = 1.0
    if num.endswith("bn"):
        mult, num = 1e9, num[:-2]
    elif num.endswith("b"):
        mult, num = 1e9, num[:-1]
    elif num.endswith("mn"):
        mult, num = 1e6, num[:-2]
    elif num.endswith("m"):
        mult, num = 1e6, num[:-1]
    elif num.endswith("k"):
        mult, num = 1e3, num[:-1]
    try:
        val = float(num) * mult
    except ValueError:
        return None
    return {"value": val, "currency": currency}

# ---------------------------------------------------------------- records

@dataclass
class Source:
    id: str
    tool: str
    query: str = ""
    asof: str = ""
    url: str | None = None
    note: str = ""

    def to_dict(self) -> dict:
        d = {"tool": self.tool, "query": self.query, "asof": self.asof or now_iso()}
        if self.url:
            d["url"] = self.url
        if self.note:
            d["note"] = self.note
        return d

    @staticmethod
    def parse(d: dict, sid: str) -> "Source":
        return Source(sid, d.get("tool", "unknown"), d.get("query", ""),
                      d.get("asof", ""), d.get("url"), d.get("note", ""))


@dataclass
class Entity:
    id: str
    type: str
    name: str
    aliases: list[str] = field(default_factory=list)
    created_at: str = ""
    discovered_at: str | None = None
    depth: int = 0
    investigated: bool = False
    key: str = ""
    metadata: dict[str, dict] = field(default_factory=dict)   # k -> {value, src, ts}
    provenance: dict[str, list] = field(default_factory=dict)  # k -> [challengers]
    sources: list[str] = field(default_factory=list)
    merged_from: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        out = {
            "id": self.id, "type": self.type, "name": self.name,
            "created_at": self.created_at or now_iso(),
            "depth": self.depth, "investigated": self.investigated,
            "key": self.key,
            "metadata": self.metadata,
        }
        if self.aliases:
            out["aliases"] = self.aliases
        if self.discovered_at:
            out["discovered_at"] = self.discovered_at
        if self.provenance:
            out["provenance"] = self.provenance
        if self.sources:
            out["sources"] = self.sources
        if self.merged_from:
            out["merged_from"] = self.merged_from
        return out

    @staticmethod
    def parse(d: dict) -> "Entity":
        return Entity(
            id=d["id"], type=d["type"], name=d["name"],
            aliases=list(d.get("aliases", [])),
            created_at=d.get("created_at", ""),
            discovered_at=d.get("discovered_at"),
            depth=int(d.get("depth", 0)),
            investigated=bool(d.get("investigated", False)),
            key=d.get("key", ""),
            metadata=dict(d.get("metadata", {})),
            provenance=dict(d.get("provenance", {})),
            sources=list(d.get("sources", [])),
            merged_from=list(d.get("merged_from", [])),
        )


@dataclass
class Edge:
    id: str
    source: str
    target: str
    relationship: str
    confidence: float = 0.5
    when: dict | None = None          # {"start": ISO, "end": ISO|None}
    amount: dict | None = None        # {"value": float, "currency": str}
    metadata: dict[str, dict] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        out = {"id": self.id, "source": self.source, "target": self.target,
               "relationship": self.relationship,
               "confidence": round(float(self.confidence), 2),
               "metadata": self.metadata}
        if self.when:
            out["when"] = {k: v for k, v in self.when.items() if v}
            if not out["when"]:
                out.pop("when")
        if self.amount:
            out["amount"] = self.amount
        if self.sources:
            out["sources"] = self.sources
        return out

    @staticmethod
    def parse(d: dict) -> "Edge":
        return Edge(
            id=d["id"], source=d["source"], target=d["target"],
            relationship=d["relationship"],
            confidence=float(d.get("confidence", 0.5)),
            when=d.get("when"), amount=d.get("amount"),
            metadata=dict(d.get("metadata", {})),
            sources=list(d.get("sources", [])),
        )