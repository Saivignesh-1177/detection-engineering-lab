"""Every rule has to fire on its true positives and stay quiet on its true negatives.

This is the detection-as-code contract. A rule without a fixture fails CI.
"""
import json
import unittest
from pathlib import Path

from detlab.engine import Rule, load_events, load_rules, run

ROOT = Path(__file__).resolve().parents[1]
RULES = {r.id: r for r in load_rules(ROOT / "rules")}
FIXTURES = ROOT / "tests" / "fixtures"


class RuleFixtures(unittest.TestCase):
    def test_every_rule_has_fixture(self):
        missing = [rid for rid in RULES if not (FIXTURES / f"{rid}.json").exists()]
        self.assertEqual(missing, [])

    def test_true_positives_and_negatives(self):
        for rid, rule in RULES.items():
            fx = json.loads((FIXTURES / f"{rid}.json").read_text(encoding="utf-8"))
            with self.subTest(rule=rid, kind="tp"):
                self.assertTrue(run([rule], fx["tp"]), f"{rid} missed its true positive")
            with self.subTest(rule=rid, kind="tn"):
                self.assertEqual(run([rule], fx["tn"]), [], f"{rid} fired on a true negative")

    def test_rule_metadata(self):
        for rid, rule in RULES.items():
            with self.subTest(rule=rid):
                self.assertIn(rule.spec["level"], {"low", "medium", "high", "critical"})
                self.assertTrue(rule.spec["attack"], "ATT&CK mapping required")
                self.assertTrue(rule.spec.get("falsepositives"), "document known false positives")


class EngineSemantics(unittest.TestCase):
    def test_unknown_modifier_rejected(self):
        with self.assertRaises(ValueError):
            Rule({"id": "X", "title": "x", "level": "low", "selection": {"a|fuzzy": "b"}})

    def test_threshold_fires_once_per_group(self):
        fx = json.loads((FIXTURES / "DET-004.json").read_text(encoding="utf-8"))
        alerts = run([RULES["DET-004"]], fx["tp"])
        self.assertEqual(len(alerts), 1)

    def test_case_insensitive(self):
        rule = Rule({"id": "X", "title": "x", "level": "low", "selection": {"Image|endswith": "\\CMD.EXE"}})
        self.assertTrue(rule.matches({"Image": "c:\\windows\\cmd.exe"}))


class IntrusionDay(unittest.TestCase):
    def test_all_rules_fire_on_simulated_day(self):
        alerts = run(list(RULES.values()), load_events(ROOT / "data" / "intrusion-day.jsonl"))
        self.assertEqual({a.rule_id for a in alerts}, set(RULES))
        self.assertEqual(len(alerts), len(RULES), "no duplicate or noise alerts")


if __name__ == "__main__":
    unittest.main()
