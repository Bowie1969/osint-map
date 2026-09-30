import json
import os
import unittest

from osint_map.core import Graph

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "seed-case.json")


def seed_graph() -> Graph:
    with open(FIXTURE, encoding="utf-8") as f:
        return Graph.from_dict(json.load(f), case_id="seed-progression")


class TestSeedGraph(unittest.TestCase):
    def test_loads_and_indexes(self):
        g = seed_graph()
        self.assertEqual(len(g.entities), 32)
        self.assertEqual(len(g.edges), 36)
        self.assertEqual(g.entities["se-03"].name, "Nicholas Zoch")

    def test_exact_key_match_merges_silently(self):
        g = seed_graph()
        r = g.add_entity("Progression.com.AU", "domain", source_tool="dig")
        self.assertTrue(r["matched_existing"])
        self.assertEqual(r["id"], "se-01")
        # new source appended, never lost
        self.assertIn("dig", [g.sources[s]["tool"] for s in
                              g.entities["se-01"].sources[-1:]],
                      "absorb must attach a new source")

    def test_norm_name_variant_match(self):
        g = seed_graph()
        # ' Nick  Zoch ' normalises to the same key
        r = g.add_entity("NICHOLAS ZOCH", "person", source_tool="test")
        self.assertEqual(r["id"], "se-03")

    def test_alias_registered(self):
        g = seed_graph()
        # 'Nicholas  Zoch' normalises equal → same key → matched
        r = g.add_entity("Nicholas Zoch", "person", aliases=["Nick Zoch"])
        self.assertTrue(r["matched_existing"])

    def test_metadata_conflict_never_overwrites(self):
        g = seed_graph()
        z = g.entities["se-03"]
        g.add_entity("Nicholas Zoch", "person", metadata={"role": "Chairman"},
                     source_tool="test")
        # existing value holds; the challenger is preserved in provenance
        self.assertEqual(z.metadata["role"]["value"], "Managing Director")
        self.assertEqual(z.provenance["role"][-1]["value"], "Chairman")

    def test_type_mismatch_is_new_entity(self):
        g = seed_graph()
        r = g.add_entity("Nicholas Zoch", "email")
        self.assertFalse(r["matched_existing"])

    def test_fuzzy_suggests_never_merges(self):
        g = seed_graph()
        r = g.add_entity("Rodney Leeseon", "person", source_tool="test")
        self.assertFalse(r["matched_existing"])
        self.assertEqual(r["fuzzy"][0]["id"], "se-09")
        self.assertEqual(len(g.pending_merge), 1)
        # still two entities until a human approves
        self.assertIn("se-09", g.entities)

    def test_short_names_never_fuzzy(self):
        g = seed_graph()
        r = g.add_entity("Lea", "person")
        self.assertEqual(r["fuzzy"], [])

    def test_merge_reparents_edges(self):
        g = seed_graph()
        r = g.add_entity("Rodney Leeseon", "person", source_tool="test")
        new_id = r["id"]
        g.link(new_id, "se-02", "employs", 1.0, source_tool="test")
        edges_before = len(g.edges)
        import osint_map.resolver as rs
        rs.merge(g, "se-09", new_id)
        self.assertNotIn(new_id, g.entities)
        self.assertIn("Rodney Leeseon", g.entities["se-09"].aliases)
        self.assertEqual(len(g.edges), edges_before - 1)
        for e in g.edges:
            self.assertNotIn(new_id, (e.source, e.target))
        self.assertEqual(g.pending_merge, [])

    def test_lookup_paths(self):
        g = seed_graph()
        self.assertEqual(g.lookup("se-01").id, "se-01")
        self.assertEqual(g.lookup("PROGRESSION.COM.AU").id, "se-01")
        self.assertEqual(g.lookup("nick zoch").id, "se-03")
        self.assertIsNone(g.lookup("zebra"))
        # ambiguous prefix -> None, candidates offered by resolve_ref
        g.add_entity("John Smith A", "person")
        g.add_entity("John Smith B", "person")
        amb = g.resolve_ref("John Smith")
        self.assertIn("error", amb)
        self.assertGreaterEqual(len(amb["candidates"]), 2)

    def test_link_unknown_endpoint_gives_candidates(self):
        g = seed_graph()
        r = g.link("Nicholas Zoch", "Zebedee Zzylqxx", "employs")
        self.assertIn("error", r)

    def test_link_freeform_warns(self):
        g = seed_graph()
        r = g.link("se-02", "se-12", "is_a_customer_of")
        self.assertIn("note", r)

    def test_edge_dedupe_takes_max_confidence(self):
        g = seed_graph()
        r1 = g.link("se-22", "se-20", "resolves_to", 0.6)
        self.assertFalse(r1["new"])
        r2 = g.link("se-22", "se-20", "resolves_to", 1.0)
        self.assertFalse(r2["new"])
        e = g.by_edge[("se-22", "se-20", "resolves_to")]
        self.assertEqual(e.confidence, 1.0)

    def test_roundtrip(self):
        g = seed_graph()
        import osint_map.approval as ap
        ap.stage(g, "entity", {"name": "X", "type": "person"})
        g2 = Graph.from_dict(json.loads(json.dumps(g.to_dict())), "seed-progression")
        self.assertEqual(len(g2.staged_items), 1)
        self.assertEqual(g2.by_key["person|nicholas zoch"].id, "se-03")


class TestGapScoring(unittest.TestCase):
    def test_planted_gap_zoch_nightingale(self):
        g = seed_graph()
        from osint_map.gaps import find_gaps
        gaps = find_gaps(g, limit=25)
        zn = next((x for x in gaps if x["a"] == "se-03" and x["c"] == "se-04"
                   or x["a"] == "se-04" and x["c"] == "se-03"), None)
        self.assertIsNotNone(zn, "Zoch↔Nightingale must be a gap")
        # both person: same_type+2, peer_pair+3 → 5
        self.assertGreaterEqual(zn["score"], 4)

    def test_no_links_never_reappear(self):
        g = seed_graph()
        from osint_map.gaps import close_gap, find_gaps
        find_gaps(g, limit=25)
        close_gap(g, "se-03", "se-04", confirmed=False, detail="checked ABR")
        gaps = find_gaps(g, limit=25)
        self.assertEqual([x for x in gaps
                          if {x["a"], x["c"]} == {"se-03", "se-04"}], [])
        self.assertIn("se-03", g.no_links[0]["a"])
        g2 = Graph.from_dict(json.loads(json.dumps(g.to_dict())),
                             "seed-progression")
        gaps2 = find_gaps(g2, limit=25)
        self.assertEqual([x for x in gaps2
                          if {x["a"], x["c"]} == {"se-03", "se-04"}], [])

    def test_gap_filled_by_edge_disappears(self):
        g = seed_graph()
        from osint_map.gaps import find_gaps
        find_gaps(g, limit=25)
        g.link("se-03", "se-04", "related_to", 0.8, source_tool="test")
        gaps = find_gaps(g, limit=25)
        self.assertEqual([x for x in gaps
                          if {x["a"], x["c"]} == {"se-03", "se-04"}], [])


if __name__ == "__main__":
    unittest.main()