import json
import os
import tempfile
import unittest

from osint_map import extract, gaps
from osint_map.core import Graph
from osint_map.store import Store

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "seed-case.json")


def seed_graph() -> Graph:
    with open(FIXTURE, encoding="utf-8") as f:
        return Graph.from_dict(json.load(f), case_id="seed-progression")


class TestExtract(unittest.TestCase):
    PIPES = """
Nicholas Zoch | person | owns-> dnmg | 0.9
Tim Johnson | person | employs | 1.0
Progression Group | company | affiliated_with-> AuditShield | 1.0
43.247.131.185 | ip | related_to | 0.5
N/A | person | knows | 0.5
unknown | company | owns | high
Jane Smith | lawyer | employs | 0.9
Bob Blob | person | employs | high
123456789 | person | knows | low
Sue Wines | person | mentors-> Rodney Leeson | 0.8 | 2021 | $5,000
Sue Wines | person | | 0.9
""".strip()

    def test_parse_rows(self):
        p = extract.parse_line("A | person | mentors-> B | 0.8 | 2021 | $5k")
        self.assertEqual(p["relation"], "mentors")
        self.assertEqual(p["target"], "B")
        self.assertEqual(p["when"], "2021")
        self.assertEqual(p["amount"], {"value": 5000.0, "currency": "AUD"})
        p2 = extract.parse_line("A | person | employs | med")
        self.assertEqual(p2["conf"], 0.7)
        self.assertEqual(p2.get("target", ""), "")  # no arrow -> links to seed

    def test_rejections(self):
        for line in (
            "N/A | person | knows | 0.5",
            "unknown | company | owns | high",
            "Jane Smith | lawyer | employs | 0.9",
            "123456789 | person | knows | low",
            "Sue Wines | person | | 0.9",
            "only | two |",
        ):
            p = extract.parse_line(line)
            self.assertIn("reject", p, line)

    def test_ip_and_phone_are_digit_ok(self):
        self.assertNotIn("reject", extract.parse_line(
            "0437222111 | phone | registered_to | 0.5"))

    def test_apply(self):
        g = seed_graph()
        out = extract.apply_extract(g, self.PIPES, source_note="unit test")
        s = out["summary"]
        self.assertEqual(s["rejected"], 5)
        # new: 'Progression Group' (alias-style), 'dnmg', 'Bob Blob';
        # everything else resolves to existing entities
        self.assertEqual(s["entities_created"], 3)
        self.assertEqual(s["links"], 6)
        names = [e.name for e in g.entities.values()]
        self.assertNotIn("Jane Smith", names, "reject must not create entities")
        # 'Sue Wines' resolved to existing, never duplicated
        wines = [e for e in names if e == "Sue Wines"]
        self.assertEqual(len(wines), 1)
        self.assertEqual(out["rejected_lines"][0]["line"], "N/A | person | knows | 0.5")


class TestStore(unittest.TestCase):
    def test_roundtrip_and_backup(self):
        with tempfile.TemporaryDirectory() as td:
            store = Store(td)
            r = store.new_case("Testing Case")
            cid = r["case_id"]
            g = store.load_case(cid)
            self.assertIsNotNone(g)
            g.add_entity("Alice", "person", source_tool="test")
            store.write_case(g, immediate=True)
            self.assertGreaterEqual(g.rev, 1)
            g2 = store.load_case(cid)
            self.assertEqual(len(g2.entities), 1)
            self.assertEqual(list(g2.entities.values())[0].name, "Alice")
            # second flush creates a .bak of rev 1
            g2.add_entity("Bob", "person", source_tool="test")
            store.write_case(g2, immediate=True)
            # three flushes (new_case, +Alice, +Bob) → two rollback copies
            baks = [f for f in os.listdir(store.case_dir(cid))
                    if f.startswith("case.json.bak-")]
            self.assertEqual(len(baks), 2)
            idx = store.read_index()
            self.assertEqual(idx[0]["case_id"], cid)

    def test_slug_safety(self):
        with tempfile.TemporaryDirectory() as td:
            store = Store(td)
            r = store.new_case("Progression Group OSINT!! -- 2026")
            import re
            self.assertTrue(re.fullmatch(r"[a-z0-9-]+", r["case_id"]))
            fresh = store.new_case("Progression Group OSINT!! -- 2026")
            self.assertIn("error", fresh)


class TestApproval(unittest.TestCase):
    def test_stage_and_approve(self):
        from osint_map import approval as ap
        g = seed_graph()
        g.write_mode = "stage"
        s1 = ap.stage(g, "entity", {"name": "New Guy", "type": "person"})
        s2 = ap.stage(g, "link", {"source": "New Guy", "target": "se-02",
                                  "relationship": "employs", "confidence": 0.7})
        self.assertEqual(g.entities.get("New Guy") or
                         next((e for e in g.entities.values()
                               if e.name == "New Guy"), None), None,
                         "stage mode must not write immediately")
        items = ap.review(g)
        self.assertEqual(len(items), 2)
        out = ap.act(g, [s1["item_id"], s2["item_id"]], "approve")
        self.assertEqual(out["approved"], 2)
        guy = next(e for e in g.entities.values() if e.name == "New Guy")
        self.assertTrue(any(x.source == guy.id for x in g.edges))
        self.assertEqual(g.staged_items, [])

    def test_merge_queue_via_approval(self):
        from osint_map import approval as ap
        g = seed_graph()
        r = g.add_entity("Rodney Leeseon", "person", source_tool="test")
        self.assertEqual(len(g.pending_merge), 1)
        mid = g.pending_merge[0]["id"]
        out = ap.act(g, [mid], "approve")
        self.assertEqual(out["approved"], 1)
        names = [e.name for e in g.entities.values()]
        self.assertEqual(names.count("Rodney Leeson"), 1)
        self.assertEqual(names.count("Rodney Leeseon"), 0)


class TestCrosslink(unittest.TestCase):
    def test_exact_and_fuzzy_across_cases(self):
        from osint_map import crosslink
        with tempfile.TemporaryDirectory() as td:
            store = Store(td)
            store.new_case("Case A")
            ga = store.load_case("case-a")
            ga.add_entity("Rodney Leeseon", "person", source_tool="test")  # typo of gb's
            ga.add_entity("admin@progression.com.au", "email", source_tool="test")
            ga.add_entity("43.247.130.5", "ip", source_tool="test")
            store.write_case(ga, immediate=True)
            gb = seed_graph()
            res = crosslink.crosslink(gb, [ga])
            # exact: canonical key already present in gb
            self.assertIn("admin@progression.com.au",
                          [e["name"] for e in res["exact"]])
            # fuzzy: typo'd name vs the real one, same type, >= 0.82
            self.assertIn(("Rodney Leeson", "Rodney Leeseon"),
                          [(f["a_name"], f["b_name"]) for f in res["fuzzy"]])
            # short-name/noise types never fuzzy-suggest
            self.assertNotIn("43.247.130.5",
                             [e["name"] for e in res["exact"]])
            self.assertEqual(crosslink.bring_in(gb, ga, ["zzz"])["imported"], 0)


class TestGapScoringRubric(unittest.TestCase):
    def test_hand_computed_scores(self):
        g = seed_graph()
        # Zoch↔Nightingale: bridges {domain}: both person (peer+3, same+2) = 5
        score, reasons = gaps.score_gap(g, "se-03", "se-04", 1)
        self.assertEqual(score, 5, reasons)
        # Tim Johnson vs Aaron Burge: both person → peer+3, same+2 = 5
        # (co-worker pairs are the known noise class; UI shows reasons)
        score2, _2 = gaps.score_gap(g, "se-05", "se-07", 1)
        self.assertEqual(score2, 5)

    def test_structural_pairs_excluded(self):
        g = seed_graph()
        pairs = {(gp["a"], gp["c"]) for gp in gaps.find_gaps(g, limit=30)}
        # co-worker noise: both ends bridge only via the company (employs)
        self.assertNotIn(("se-05", "se-07"), pairs)
        self.assertNotIn(("se-07", "se-05"), pairs)
        # genuine planted gaps survive the penalty
        self.assertIn(("se-03", "se-04"), pairs)


if __name__ == "__main__":
    unittest.main()