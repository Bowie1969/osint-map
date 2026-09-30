#!/usr/bin/env python3
"""CLI: python3 -m osint_map [--case SLUG] [--list|summarize|serve|...]"""
from __future__ import annotations

import argparse
import sys

from .store import Store


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="osint_map", description="OSINT Graph Mapper (project local)")
    ap.add_argument("--cases", help="override cases dir")
    ap.add_argument("--case", help="case slug")
    ap.add_argument("--serve", action="store_true",
                    help="start the board web server")
    ap.add_argument("--port", type=int, default=8788)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--list", action="store_true", help="list cases")
    ap.add_argument("--summarize", action="store_true",
                    help="case summary: counts, findings, gaps")
    ap.add_argument("--gaps", action="store_true", help="print gap cards")
    ap.add_argument("--print-gaps", dest="print_gaps", action="store_true")
    args = ap.parse_args(argv)

    store = Store(args.cases)
    if args.list or (not args.case and not args.serve):
        cases = store.list_cases()
        if not cases:
            print("no cases yet — create one via the osint MCP server "
                  "(graph_case) or --case")
        for c in cases:
            print(f'{c["case_id"]:40} entities={c.get("entity_count"):4} '
                  f'edges={c.get("edge_count"):4} rev={c.get("rev", 0):3} '
                  f'  {c.get("title", "")}')
        return 0
    g = store.load_case(args.case) if args.case else None
    if args.serve:
        from .web import serve
        httpd = serve(store, args.case or "", host="127.0.0.1",
                      port=args.port)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()
        return 0
    if g is None:
        print(f"no case {args.case!r} (see --list)", file=sys.stderr)
        return 1
    if args.summarize or args.print_gaps:
        from .gaps import find_gaps
        gaps = find_gaps(g)
        print(f'case: {g.case_id} — {g.title}')
        print(f'  entities {len(g.entities)}   edges {len(g.edges)}   '
              f'sources {len(g.sources)}   rev {g.rev}')
        if g.findings:
            print("findings:")
            for f in g.findings[-12:]:
                print(f"  - {f}")
        if args.print_gaps:
            print(f"gaps ({len(gaps)}):")
            for gp in gaps:
                print(f'  [{gp["score"]:2}] {gp["a_name"]} ↔ {gp["c_name"]}'
                      f'  ({gp["reasons"]}; via {", ".join(gp["bridges"][:3])})')
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())