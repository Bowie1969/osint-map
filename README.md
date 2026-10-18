# osint-map

An AI-attached OSINT entity-graph mapper that turns passive-source reconnaissance into a Maltego-style force-directed map — built, linked and analysed by an AI agent, reviewed by a human.

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Stdlib only](https://img.shields.io/badge/deps-stdlib%20only-brightgreen)](#requirements)
[![MCP](https://img.shields.io/badge/MCP-tools-orange)](https://modelcontextprotocol.io)
[![Tests](https://img.shields.io/badge/tests-45%20passing-brightgreen)](#tests)
[![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

**What it is.** A Python (stdlib-only) engine and local web board for mapping an
organisation or social ecosystem as an entity graph. An AI agent — attached
through Model Context Protocol — drives the investigation: it adds entities,
links them with confidence-scored, provenance-carrying edges, enriches them
from passive OSINT sources, and researches the "missing link" gaps the graph
itself surfaces. Every fuzzy match and staged write waits for human approval.

## Highlights

- **Entity graph, not a flat report** — 16 entity types and 15 canonical
  relationship types, rendered as a live Cytoscape.js force-directed board.
- **AI-attached** — 11 `graph_*` MCP tools let Claude (or any MCP client)
  build and interrogate the graph while you watch.
- **Identity before matching** — exact keys (email, FQDN, IP, phone, ASN)
  merge silently; fuzzy name matches *never* do — they queue as merge cards.
- **Provenance everywhere** — every field records `{value, source, timestamp}`;
  conflicting values are kept in a provenance chain, never overwritten.
- **It finds its own next steps** — suspicion-scored triadic-closure gap
  detection ranks the missing links most worth researching.
- **Human-in-the-loop by default** — staged-write mode parks agent output for
  approval; rollback `.bak` chain and atomic writes protect the case file.
- **Zero Python dependencies** — `http.server` + vendored Cytoscape.js; tests
  run with no network.

## What it does

### Entity graph mapping

A *case* is a graph of entities (people, companies, domains, subdomains, IPs,
netblocks, ASNs, usernames, accounts, emails, phones, locations, events,
documents, devices, money) connected by directed edges (`owns`, `employs`,
`subdomain_of`, `resolves_to`, `registered_to`, `paid_to`, …). Each edge
carries a confidence score, optional date range and money amount, and the
sources that support it.

The resolver collapses the same real-world thing into one node: a canonical
value collision (same email address, same FQDN, same IP) merges automatically,
while a fuzzy near-match becomes a *pending merge* card for a human to confirm
or reject. Cross-case linking finds the same entity across separate
investigations.

### AI-attached analysis

The graph is the AI agent's working memory. Through the MCP tools the agent
adds entities and links, bulk-loads findings from pipe-delimited text
(`graph_extract`), runs passive OSINT tools and writes the parsed results
straight into the graph in one call (`graph_enrich` — subfinder, crt.sh,
DNS, theHarvester, WHOIS, Shodan InternetDB, breach checks, sherlock, GitHub,
IP intel), and works the search queue of entities it hasn't investigated yet.

The engine closes the loop: triadic closure scores every unlinked pair that
shares a neighbour, ranks the most interesting "what's the connection here?"
questions, and the agent researches them — confirming a real link (the edge
goes in) or recording an explicit negative so it's never re-proposed.

## Requirements

- Python **3.10+** — no `pip install`, no third-party Python packages.
- A bash shell for the launcher (`desktop/osint-map`). On Windows, run the
  server directly with `python3 -m osint_map --serve` and open the URL.
- The optional MCP wiring lives outside this repo in the existing
  `~/tools/osint-mcp` server (see [Server wiring](#server-wiring)).

## Install

```sh
git clone https://github.com/Bowie1969/osint-map.git
cd osint-map
./install.sh          # symlinks the `osint-map` launcher onto PATH; verifies MCP wiring
```

## Quick start

```sh
osint-map             # start the board → http://127.0.0.1:8788 (opens an app window)
osint-map --stop      # stop the background board server
```

Create your first case from an MCP client (`graph_case new`) or let the board
auto-create one on first launch.

## Usage

**CLI** (project-local, no install needed):

```sh
python3 -m osint_map --list                 # list cases
python3 -m osint_map --case <slug> --summarize
python3 -m osint_map --case <slug> --print-gaps
python3 -m osint_map --serve --port 8788    # board server only
```

**MCP client** (Claude Code, or any MCP client attached to the `osint` server):

```
graph_case new --title "Acme Corp"
graph_add_entity "acme.com" domain seed=true
graph_enrich subfinder acme.com
graph_gaps
graph_query entity=acme.com
```

Case files live in `cases/<slug>/` (`case.json` + `notes.md` + a rolling
`.bak-*` chain). Payloads are gitignored; only `cases/index.json` is tracked.
Environment overrides: `OSINT_MAP_CASES`, `OSINT_MAP_PORT`,
`OSINT_MAP_NO_BROWSER=1` (headless).

## Architecture

```
                   MCP client (Claude)
                         │  JSON-RPC (MCP)
                         ▼
         ~/tools/osint-mcp/server.py  +  graph_tools.py
                    (11 graph_* tools)        ← external, wired by install.sh
                         │  import osint_map (sys.path shim)
                         ▼
   ┌───────────────────────────────────────────────────────┐
   │                  osint_map  package                    │
   │   core      graph engine (entities, edges, findings)  │
   │   model     types, canonical keys, date/money coercion│
   │   resolver  exact/fuzzy identity + merge engine        │
   │   gaps      triadic-closure gap scoring                │
   │   extract   pipe-delimited bulk ingest                 │
   │   enrich    per-tool parsers (10 passive OSINT tools)  │
   │   crosslink same-entity linking across cases           │
   │   approval  staged writes + merge approval queue       │
   │   store     atomic, debounced persistence + .bak chain │
   │   web       stdlib board server (Cytoscape.js)         │
   └──────────────┬───────────────────────┬─────────────────┘
                  │ load / atomic flush   │ HTTP
                  ▼                       ▼
        cases/<slug>/case.json    board @ http://127.0.0.1:8788
        + notes.md + .bak-*       (human view / approval UI)
```

The case file on disk is the single source of truth. The MCP process and the
board mutate it concurrently: the board never caches (every request reloads),
MCP writes are debounced with an atexit flush, and every flush is an atomic
`os.replace` that bumps `rev` — the board's polling cursor.

### MCP tool surface

| Tool | Purpose |
|---|---|
| `graph_case` | list / new / switch / status |
| `graph_add_entity` | entity (16 types); `seed=true` anchors layout + depth |
| `graph_link` | edge by id **or** name; never guesses on ambiguity |
| `graph_query` | subgraph walks, pending queues, listings |
| `graph_next_target` | pop the agent's search queue |
| `graph_gaps` | scored missing-link candidates |
| `graph_note` | note / finding / `no_connection` (refutes a gap for good) |
| `graph_extract` | bulk-load pipe text `NAME \| TYPE \| RELATION \| CONF …` |
| `graph_crosslink` | merge two cases on exact identity (+ fuzzy suggestions) |
| `graph_enrich` | run a passive OSINT tool and write parsed results in one call |
| `graph_set_write_mode` / `graph_approve` | stage / inspect / approve batches |

## Server wiring

`~/tools/osint-mcp/server.py` inserts its own directory on `sys.path` and
imports `graph_tools`, which instantiates the store from `OSINT_MAP_HOME`
(default: this repo). If the import fails the osint tools still work and graph
tools return readable errors. Restart the MCP server (or reconnect Claude
Code) after running `install.sh` if `graph_case` isn't a known tool yet.

## Passive & authorized use

osint-map is a **research and attribution tool**, not a scanner or an attack
platform. It only consumes information from **public, passive sources** — DNS
and certificate registries, WHOIS, public profiles, breach and scan databases
that third parties already collected. It never probes, scans, or touches the
target.

Use it only on targets you are **authorized** to investigate: your own assets,
a client's assets under a signed scope, or public entities for legitimate
research in compliance with applicable law and the source services' terms.
You are responsible for lawful, ethical use of any data you collect.

## Tests

```sh
python3 -m unittest discover tests -v   # 45 tests, no network
```

## License

MIT © 2026 Will Archer. See [LICENSE](LICENSE).
