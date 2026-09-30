import json
import os
import unittest

from osint_map import enrich
from osint_map.core import Graph


def graph_of(ops, tool):
    g = Graph()
    g.add_entity("example.com.au", "domain", source_tool="seed", seed=True)
    res = enrich.apply_ops(g, ops, source_note="test", source_tool=tool)
    return g, res


RAW = {
    "subfinder": "a.example.com.au\nb.example.com.au\n*.other.com\nmail2.example.com.au",
    "crtsh_certificates": json.dumps({"unique_names": ["*.example.com.au",
                                          "vpn.example.com.au"],
                         "recent_certs": []}),
    "dns_records": json.dumps({"A": ["203.0.113.9", "203.0.113.10"],
                       "AAAA": ["2001:db8::1"],
                       "MX": ["5 mail.example.com.au."],
                       "NS": ["ns1.hosting.net."],
                       "TXT": ["v=spf1 include:_spf.example.com.au ~all"]}),
    "theharvester": """
[*] Target: example.com.au
contact@example.com.au
found: info@example.com.au
vpn.example.com.au  found: 3
nothing here without the domain suffix
""",
    "sherlock": """[*] Checking username willarcher
[+] github: https://github.com/willarcher
[+] twitter: https://twitter.com/willarcher
[-] reddit: Not Found
""",
    "whois_domain": """Domain Name: example.com.au
Registry Domain ID: 12345
Registrar Name: GoDaddy.com LLC
Registrar Abuse Contact Email: abuse@godaddy.com
Registrant Organization: Example Holdings Pty Ltd
Creation Date: 2019-03-02T00:00:00Z
Registry Expiry Date: 2027-03-02T00:00:00Z
Name Server: NS1.CLOUD.NET
Name Server: ns2.cloud.net
""",
    "ip_intel": json.dumps({
        "ipinfo": {"city": "Melbourne", "region": "Victoria",
                   "country": "AU", "org": "AS24516 Virtutel Pty Ltd",
                   "hostname": "host.example.com.au"},
        "rdap": {"name": "VIRTWEL-AU", "type": "ISP",
                 "handle": "VIRTWEL", "country": "AU",
                 "netblock": "43.247.130.0 - 43.247.131.255",
                 "abuse_contact": "abuse@virtutel.com.au"}}),
    "shodan_internetdb": json.dumps({"ports": [443, 8443],
                          "hostnames": ["vpn.example.com.au"],
                          "cpes": ["cpe:apache:httpd"],
                          "vulns": ["CVE-2021-44228"]}),
    "breach_check": json.dumps({"found": True,
                          "breaches": ["LinkedIn 2021", "Adobe"]}),
    "github_user": json.dumps({"login": "willarcher", "name": "Will Archer",
                          "company": None, "location": "Melbourne",
                          "email": None, "blog": "",
                          "created": "2019-01-15T00:00:00Z",
                          "followers": 12, "public_repos": 3,
                          "repos_updated_first": [
                              {"name": "evilkit", "stars": 5,
                               "updated": "2026-01-01",
                               "description": "x"}]}),
}

TARGET = {
    "subfinder": "example.com.au", "crtsh_certificates": "example.com.au",
    "dns_records": "example.com.au", "theharvester": "example.com.au",
    "sherlock": "willarcher", "whois_domain": "example.com.au",
    "ip_intel": "203.0.113.9", "shodan_internetdb": "203.0.113.9",
    "breach_check": "contact@example.com.au",
    "github_user": "willarcher",
}


class TestEnrichParsers(unittest.TestCase):
    def run_parser(self, tool):
        fn = enrich.PARSERS[tool]
        ops = fn(RAW[tool], TARGET[tool], json)
        g = Graph()
        # pre-plant the target so links resolve
        tt = TARGET[tool]
        etype = "email" if "@" in tt else ("ip" if tt.replace(".", "").isdigit()
                                           else ("username" if tool == "github_user"
                                                 or tool == "sherlock"
                                                 else "domain"))
        g.add_entity(tt, etype, source_tool="seed", seed=True)
        res = enrich.apply_ops(g, ops, source_note="test", source_tool=tool)
        return g, ops, res

    def test_parsers_all_produce(self):
        for tool in enrich.PARSER_TOOLS:
            g, ops, res = self.run_parser(tool)
            self.assertGreater(len(ops), 0, tool)
            self.assertEqual(res["parsed_ops"], len(ops), tool)
            self.assertGreaterEqual(res["entities_created"] + res["links_new"],
                                    1, tool)

    def test_subfinder_skips_foreign_wildcard(self):
        g, ops, _ = self.run_parser("subfinder")
        names = [e.name for e in g.entities.values()]
        self.assertIn("a.example.com.au", names)
        self.assertNotIn("other.com", names)

    def test_dns_creates_ips_and_mx(self):
        g, ops, _ = self.run_parser("dns_records")
        types = {e.name: e.type for e in g.entities.values()}
        self.assertEqual(types.get("203.0.113.9"), "ip")
        self.assertEqual(types.get("mail.example.com.au"), "subdomain")
        rels = {x.relationship for x in g.edges}
        self.assertIn("resolves_to", rels)
        self.assertIn("uses_serves", rels)

    def test_th_only_target_entities(self):
        g, ops, _ = self.run_parser("theharvester")
        names = [e.name for e in g.entities.values()]
        for n in names:
            self.assertTrue("example.com.au" in n or n == "example.com.au", n)

    def test_sherlock_accounts(self):
        g, ops, _ = self.run_parser("sherlock")
        accs = [e for e in g.entities.values() if e.type == "account"]
        self.assertEqual(len(accs), 2)  # reddit was Not Found
        self.assertIn("github", {e.metadata["platform"]["value"] for e in accs})

    def test_whois_nameservers_and_org(self):
        g, ops, _ = self.run_parser("whois_domain")
        domains = [e.name for e in g.entities.values() if e.type == "domain"]
        self.assertIn("ns1.cloud.net", domains)
        self.assertIn("ns2.cloud.net", domains)
        comps = [e.name for e in g.entities.values() if e.type == "company"]
        self.assertEqual(comps, ["Example Holdings Pty Ltd"])
        reg = [x for x in g.edges if x.relationship == "registered_to"]
        self.assertTrue(reg)
        meta = g.lookup("example.com.au").metadata
        self.assertIn("registrar", meta)

    def test_ip_intel_netblock_and_abuse(self):
        g, ops, _ = self.run_parser("ip_intel")
        nbs = [e.name for e in g.entities.values() if e.type == "netblock"]
        self.assertEqual(nbs, ["43.247.130.0 - 43.247.131.255"])
        mails = [e.name for e in g.entities.values() if e.type == "email"]
        self.assertIn("abuse@virtutel.com.au", mails)
        ip = g.lookup("203.0.113.9")
        self.assertEqual(ip.metadata["city"]["value"], "Melbourne")

    def test_shodan_cve_events_capped(self):
        g, ops, _ = self.run_parser("shodan_internetdb")
        cves = [e for e in g.entities.values() if e.type == "event"]
        self.assertEqual(len(cves), 1)
        self.assertIn("open_ports", g.lookup("203.0.113.9").metadata)

    def test_github_repos_and_profile(self):
        g, ops, _ = self.run_parser("github_user")
        docs = [e for e in g.entities.values() if e.type == "document"]
        self.assertEqual(docs[0].name, "github.com/willarcher/evilkit")
        user = g.lookup("willarcher")
        self.assertEqual(user.metadata["location"]["value"], "Melbourne")

    def test_enrich_stage_mode_queues_ops(self):
        from osint_map import approval
        g = Graph()
        g.write_mode = "stage"
        ops = [("entity", "X Co", "company", {}, []),
               ("link", "X Co", "example.com.au", "registered_to", 0.8)]
        r = approval.stage_ops(g, {"kind": "ops", "tool": "whois_domain",
                                   "target": "example.com.au", "ops": ops})
        self.assertEqual(g.entities, {}, "stage mode must not write")
        items = approval.review(g)
        self.assertEqual(items[0]["kind"], "ops")
        self.assertEqual(items[0]["summary"]["entities"], 1)
        out = approval.act(g, [r["item_id"]], "approve")
        self.assertEqual(out["approved"], 1)
        names = [e.name for e in g.entities.values()]
        self.assertIn("X Co", names)

    def test_junk_raw_is_safe(self):
        self.assertEqual(enrich.PARSERS["subfinder"]("", "example.com.au",
                                                    json), [])
        self.assertEqual(enrich.PARSERS["crtsh_certificates"]("not json",
                                                             "x.com", json), [])
        self.assertEqual(enrich.PARSERS["dns_records"]("not json",
                                                       "x.com", json), [])
        self.assertEqual(enrich.PARSERS["ip_intel"]("not json", "1.2.3.4",
                                                    json), [])
        self.assertEqual(enrich.PARSERS["github_user"]("{}", "user", json),
                         [])


if __name__ == "__main__":
    unittest.main()