import unittest

from osint_map.model import (
    coerce_amount, coerce_date, entity_key, norm_name,
)


class TestCoercion(unittest.TestCase):
    def test_date_forms(self):
        self.assertEqual(coerce_date("2026-03-14"), "2026-03-14")
        self.assertEqual(coerce_date("14/03/2026"), "2026-03-14")
        self.assertEqual(coerce_date("2026"), "2026")
        self.assertEqual(coerce_date("since-1988"), None)
        self.assertEqual(coerce_date(""), None)
        self.assertEqual(coerce_date(None), None)

    def test_amounts(self):
        self.assertEqual(coerce_amount("$25,000"), {"value": 25000.0, "currency": "AUD"})
        self.assertEqual(coerce_amount("1.2M USD"), {"value": 1200000.0, "currency": "USD"})
        self.assertEqual(coerce_amount("25k"), {"value": 25000.0, "currency": "AUD"})
        self.assertEqual(coerce_amount("1.5bn EUR"), {"value": 1.5e9, "currency": "EUR"})
        self.assertIsNone(coerce_amount("no money"))
        self.assertIsNone(coerce_amount(""))

    def test_amount_bare_number(self):
        self.assertEqual(coerce_amount(25000), {"value": 25000.0, "currency": "AUD"})


class TestKeys(unittest.TestCase):
    def test_norm_name(self):
        self.assertEqual(norm_name("  Hécker-Wills & Co. "), "hecker-wills co.")
        self.assertEqual(norm_name("Nicholas  Zoch"), "nicholas zoch")

    def test_entity_keys(self):
        self.assertEqual(entity_key("email", "Admin@Progression.com.AU"),
                         "email|admin@progression.com.au")
        self.assertEqual(entity_key("ip", "43.247.131.185"), "ip|43.247.131.185")
        self.assertEqual(entity_key("ip", "043.247.131.185"), "ip|43.247.131.185")
        self.assertEqual(entity_key("netblock", "43.247.130.0/23"),
                         "netblock|43.247.130.0/23")
        self.assertEqual(entity_key("phone", "03 9457 9000"),
                         "phone|+61394579000")
        self.assertEqual(
            entity_key("username", "adamnightingale", platform="LinkedIn"),
            "username|linkedin:adamnightingale")
        self.assertEqual(entity_key("person", "Nicholas Zoch"),
                         "person|nicholas zoch")


if __name__ == "__main__":
    unittest.main()