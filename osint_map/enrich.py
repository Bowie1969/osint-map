#!/usr/bin/env python3
"""graph_enrich parsers: raw tool output → graph ops, write-through.

Each parser turns one tool's raw output into a list of ops the caller can
feed to Graph.add_entity / Graph.link:

    ("entity", name, entity_type, metadata, aliases)
    ("link",   source_name, target_name, relationship, confidence)

Parsers are lenient and lossless-where-it-matters: names not matching get
skipped and counted. The pipe contract (extract.py) remains the fallback
for tools without a parser.
"""
from __future__ import annotations

import json
import re

# Tools graph_enrich can parse; everything else: run the raw tool, then
# hand the dump to graph_extract.
PARSER_TOOLS = (
    "subfinder", "crtsh_certificates", "dns_records", "theharvester",
    "ip_intel", "shodan_internetdb", "whois_domain", "github_user",
    "breach_check", "sherlock",
)

EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.\w{2,}")
HOST_RE = re.compile(r"\b(?:[\w-]+\.)+[a-z]{2,}\b", re.IGNORECASE)


def _link(src, dst, rel, conf):
    return ("link", src, dst, rel, conf)


# ---------------------------------------------------------------- subdomain feeds

def parse_subfinder(raw, target, _j):
    ops = []
    for name in raw.split():
        name = name.strip().lower().rstrip(".")
        if not name or not name.endswith(target.lower()) or "*" in name:
            continue
        ops.append(("entity", name, "subdomain", {}, []))
        ops.append(_link(name, target, "subdomain_of", 0.9))
    return ops


def parse_crtsh(raw, target, _j):
    try:
        data = json.loads(raw)
    except ValueError:
        return []
    ops = []
    for name in (data.get("unique_names") or []):
        name = name.lower().lstrip("*.").rstrip(".")
        if not name or not name.endswith(target.lower()):
            continue
        if name == target.lower():
            continue
        ops.append(("entity", name, "subdomain", {}, []))
        ops.append(_link(name, target, "subdomain_of", 0.9))
    return ops


DNS_KIND = {
    "A": ("ip", "resolves_to", 0.9),
    "AAAA": ("ip", "resolves_to", 0.9),
    "CNAME": ("domain", "resolves_to", 0.8),
    "NS": ("subdomain", "uses_serves", 0.8),
    "MX": ("subdomain", "uses_serves", 0.8),
}


def parse_dns_records(raw, target, _j):
    try:
        data = json.loads(raw)
    except ValueError:
        return []
    ops, seen = [], set()
    for rtype, vals in data.items():
        kind = DNS_KIND.get(rtype)
        if not kind:
            continue
        etype, rel, conf = kind
        for v in vals or []:
            v = str(v).strip().lower().rstrip(".")
            if not v or v == target.lower():
                continue
            if rtype in ("MX", "NS", "CNAME"):
                m = HOST_RE.search(v)
                if not m:
                    continue
                v = m.group(0).lower()
            if (etype, v) in seen:
                continue
            seen.add((etype, v))
            ops.append(("entity", v, etype, {}, []))
            ops.append(_link(target, v, rel, conf))
    return ops


# ---------------------------------------------------------------- text dumps

def parse_theharvester(raw, target, _j):
    tgt = target.lower().lstrip(".")
    ops = []
    seen = set()
    for m in EMAIL_RE.finditer(raw):
        mail = m.group(0).lower()
        if mail.endswith("@" + tgt) and mail not in seen:
            seen.add(mail)
            ops.append(("entity", mail, "email", {}, []))
    for m in HOST_RE.finditer(raw):
        host = m.group(0).lower()
        if host.endswith("." + tgt) and host not in seen:
            seen.add(host)
            ops.append(("entity", host, "subdomain", {}, []))
            ops.append(_link(host, tgt, "subdomain_of", 0.7))
    return ops


_SHERLOCK_HIT = re.compile(r"^\[\+\]\s*(\S+?):\s*(\S+)", re.M)


def parse_sherlock(raw, target, _j):
    """target = username. Hits become `user:platform` account entities."""
    ops = [("entity", target, "username", {}, [])]
    for m in _SHERLOCK_HIT.finditer(raw):
        site, url = m.group(1), m.group(2)
        if not url.lower().startswith(("http://", "https://")):
            continue
        name = f"{target}:{site}"
        ops.append(("entity", name, "account",
                    {"platform": site, "url": url}, []))
        ops.append(_link(target, name, "registered_to", 0.9))
    return ops


_KEY_RE = re.compile(
    r"^(Registrar Name|Registrar|Registrant Organization|Registrant Name|Creation Date|"
    r"Updated Date|Registry Expiry Date|Expiry Date|Expiry|"
    r"Registrar Abuse Contact Email):\s*(.+)$", re.M)
_NS_RE = re.compile(r"^Name Server[s]?:\s*(.+)$", re.M | re.I)
_KEY_ALIAS = {
    "registrar name": "registrar", "registrar": "registrar",
    "creation date": "created", "updated date": "updated",
    "registry expiry date": "expires", "expiry date": "expires",
    "expiry": "expires",
    "registrar abuse contact email": "abuse_contact",
    "registrant organization": "registrant",
    "registrant name": "registrant",
}


def parse_whois_domain(raw, target, _j):
    ops: list = []
    for m in _KEY_RE.finditer(raw):
        k = _KEY_ALIAS.get(m.group(1).strip().lower(), m.group(1).lower())
        v = m.group(2).strip().rstrip(".")
        if "@" in v:
            v = v.split()[0]
        if v and v.lower() not in ("redacted", "none", "n/a", "not available") \
                and "(cidr" not in v:
            ops.append(("entity", target, "domain", {k: v}, []))
    org = None
    for m in _KEY_RE.finditer(raw):
        if m.group(1).lower() in ("registrant organization", "registrant name"):
            org = m.group(2).strip()
            break
    if org and org.lower() not in ("redacted", "none", "n/a"):
        ops.append(("entity", org, "company", {}, []))
        ops.append(_link(target, org, "registered_to", 0.8))
    ns_seen = set()
    for m in _NS_RE.finditer(raw):
        for v in m.group(1).split():
            ns = v.strip().lower().rstrip(".")
            if "." not in ns:
                continue
            if ns not in ns_seen and ns != target.lower():
                ns_seen.add(ns)
                ops.append(("entity", ns, "domain", {}, []))
                ops.append(_link(target, ns, "uses_serves", 0.9))
    return ops


# ---------------------------------------------------------------- json lookups

def parse_ip_intel(raw, target, _j):
    try:
        data = json.loads(raw)
    except ValueError:
        return []
    ops = []
    ipinfo = data.get("ipinfo", {})
    if isinstance(ipinfo, dict):
        meta = {}
        for k in ("city", "region", "country", "org", "timezone", "hostname"):
            if ipinfo.get(k):
                meta[k] = ipinfo[k]
        if meta:
            ops.append(("entity", target, "ip", meta, []))
        loc = ipinfo.get("city")
        if loc:
            ops.append(("entity", loc, "location", {}, []))
            ops.append(_link(target, loc, "located_in", 0.8))
    rdap = data.get("rdap", {})
    if isinstance(rdap, dict):
        for k in ("name", "country", "abuse_contact"):
            if rdap.get(k) and rdap[k] != "(not published)":
                rk = "registrar" if k == "name" else k
                ops.append(("entity", target, "ip", {rk: rdap[k]}, []))
        nb = rdap.get("netblock", "")
        if " - " in nb:
            start, end = nb.split(" - ", 1)
            ops.append(("entity", nb, "netblock",
                        {"range_start": start, "range_end": end}, []))
            ops.append(_link(target, nb, "hosted_on", 0.9))
            abuse = rdap.get("abuse_contact")
            if abuse and "@" in abuse:
                ops.append(("entity", abuse, "email", {}, []))
                ops.append(_link(nb, abuse, "mentions", 0.7))
    return ops


def parse_shodan_internetdb(raw, target, _j):
    try:
        data = json.loads(raw)
    except ValueError:
        return []
    ops = []
    ports = data.get("ports") or []
    meta = {}
    if ports:
        meta["open_ports"] = ", ".join(str(p) for p in ports)
    if data.get("cpes"):
        meta["software"] = ", ".join(data["cpes"][:8])
    if meta:
        ops.append(("entity", target, "ip", meta, []))
    for h in (data.get("hostnames") or []):
        h = str(h).lower().rstrip(".")
        if h and "." in h:
            ops.append(("entity", h, "subdomain", {}, []))
            ops.append(_link(h, target, "resolves_to", 0.8))
    for v in (data.get("vulns") or [])[:12]:
        ops.append(("entity", v, "event", {"kind": "cve"}, []))
        ops.append(_link(target, v, "mentions", 0.9))
    return ops


def parse_breach_check(raw, target, _j):
    try:
        data = json.loads(raw)
    except ValueError:
        return []
    ops = []
    for b in (data.get("breaches") or [])[:20]:
        b = str(b).strip()
        if b:
            ops.append(("entity", b, "event", {"kind": "breach_of"}, []))
            ops.append(_link(b, target, "mentions", 0.9))
    return ops


def parse_github_user(raw, target, _j):
    try:
        data = json.loads(raw)
    except ValueError:
        return []
    if not data.get("login"):
        return []
    meta = {k: v for k, v in (
        ("name", data.get("name")), ("company", data.get("company")),
        ("location", data.get("location")), ("bio", data.get("bio")),
        ("blog", data.get("blog")), ("created", data.get("created")),
        ("followers", data.get("followers"))) if v}
    ops = [("entity", target, "username", meta, [])]
    ops.append(("entity", f"{target}:github", "account",
                {"platform": "github", "url": f"github.com/{target}"}, []))
    ops.append(_link(target, f"{target}:github", "registered_to", 0.9))
    for r in (data.get("repos_updated_first") or [])[:15]:
        name = r.get("name")
        if name:
            full = f"github.com/{target}/{name}"
            ops.append(("entity", full, "document", {"kind": "repository",
                                                     "stars": r.get("stars")}, []))
            ops.append(_link(target, full, "owns", 0.9))
    return ops


PARSERS = {
    "subfinder": parse_subfinder,
    "crtsh_certificates": parse_crtsh,
    "dns_records": parse_dns_records,
    "theharvester": parse_theharvester,
    "sherlock": parse_sherlock,
    "whois_domain": parse_whois_domain,
    "ip_intel": parse_ip_intel,
    "shodan_internetdb": parse_shodan_internetdb,
    "breach_check": parse_breach_check,
    "github_user": parse_github_user,
}


def apply_ops(graph, ops, source_note: str, source_tool: str) -> dict:
    """Run parser ops through the graph engine (entity then link phases)."""
    created, linked = 0, 0
    entity_ops = [o for o in ops if o[0] == "entity"]
    link_ops = [o for o in ops if o[0] == "link"]
    for _, name, etype, meta, aliases in entity_ops:
        r = graph.add_entity(name, etype, aliases=aliases,
                             metadata=dict(meta), source_note=source_note,
                             source_tool=source_tool)
        if "id" in r and not r.get("matched_existing"):
            created += 1
    for _, src, dst, rel, conf in link_ops:
        r = graph.link(src, dst, rel, conf, source_note=source_note,
                       source_tool=source_tool)
        if "id" in r and r.get("new"):
            linked += 1
    return {"parsed_ops": len(ops), "entities_created": created,
            "links_new": linked}