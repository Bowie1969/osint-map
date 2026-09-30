# osint-map

AI-attached OSINT entity-graph mapper — builds Maltego-style topological maps
of organisations and social ecosystems, as a force-directed board an AI agent
writes to while it works. Python stdlib only (+ vendored Cytoscape.js for the
board).

Two halves:

- **Engine** (`osint_map/`): case store, entity identity/merge engine,
  confidence-scored edges with provenance, triadic-closure gap detection,
  cross-case linking, staged-write approval queue.
- **MCP tools** (`~/tools/osint-mcp/graph_tools.py`, `server.py`): 11
  `graph_*` tools on the existing osint server, so Claude (or any MCP client)
  creates entities, links, extracts, enriches and researches gaps natively.

## Quick start

```sh
./install.sh          # symlink the launcher; verify the MCP wiring
osint-map             # board on http://127.0.0.1:8788 (+ app window)
osint-map --stop      # stop the background board server
```

Cases live in `cases/<slug>/` (`case.json` + `notes.md` + backups). Case
payloads are gitignored — only `cases/index.json` is tracked.

The MCP server registers the graph tools automatically on startup; restart
Claude Code (or reconnect the `osint` MCP server) if `graph_case` isn't a
known tool yet.

## MCP tools (write gate: `auto` by default)

| Tool | Purpose |
|---|---|
| `graph_case` | list / new / switch / status |
| `graph_add_entity` | entity (16 types); seed=True anchors layout + depth |
| `graph_link` | edge; takes ids **or** names; never guesses on ambiguity |
| `graph_query` | subgraph walks, pending queues, listing |
| `graph_next_target` | pops the agent's search queue |
| `graph_gaps` | scored missing-link candidates (`min_score`, `limit`) |
| `graph_note` | note / finding / `no_connection` (refutes a gap for good) |
| `graph_extract` | bulk-load from pipe text `NAME \| TYPE \| RELATION \| CONF [| WHEN \| AMOUNT]` |
| `graph_crosslink` | merge two cases on exact identity (+ fuzzy suggestions) |
| `graph_enrich` | run an osint tool and write the parsed results in one call |
| `graph_set_write_mode` / `graph_approve` | stage/inspect/approve batches (untrusted-agent mode) |

`graph_enrich` supports: `subfinder`, `crtsh_certificates`, `dns_records`,
`theharvester`, `ip_intel`, `shodan_internetdb`, `whois_domain`,
`github_user`, `breach_check`, `sherlock` — anything else: run the raw tool,
then `graph_extract`.

## Concurrency

Claude (MCP process) and the board mutate `case.json` concurrently: the board
never caches — every request reloads from disk; MCP writes are debounced
1.5 s with an atexit flush; every flush is an atomic rename and bumps `rev`
(the board's polling cursor).

## Server wiring (background)

`server.py` inserts its own directory on `sys.path` and imports
`graph_tools`, which lazily instantiates the store from `OSINT_MAP_HOME`
(default: `~/Dropbox/Shared Workspace/Projects/osint-map`). Degrades
gracefully: if the import fails the osint tools still work and graph tools
return readable errors.

## Design notes

- **Identity before matching**: exact keys (email E.164-style lowercase,
  phone, FQDN, IP, `platform:user`) auto-merge silently; fuzzy name matches
  never merge silently — they surface as `pending_merge` cards in the UI.
- **Provenance everywhere**: every entity field records `{value, src, ts}`;
  conflicting values keep the first and append the challenger to
  `provenance[k]` — nothing is lost.
- **Gap detection** is a transparent rubric (same-type +2, peer pair +3,
  money +3, well-connected +2, ×N extra bridges) with a −4 penalty when all
  bridges are structural relations only (`employs`, `subdomain_of`,
  `resolves_to`, …) — kills co-worker/vendor noise.
- **Confidence is visual**: edge width and opacity scale with confidence;
  non-canonical relations draw dashed.

## Tests

```sh
python3 -m unittest discover tests -v   # 44 tests, no network
```