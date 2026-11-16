"""Run inside the NetBox container, see README."""
import unittest

import django

django.setup()

from netbox_snmp_modulator.views import _compared, _rule_values, _section, match_context, rules_context  # noqa: E402


class RuleValuesTest(unittest.TestCase):
    def test_literal_alternation_splits(self):
        self.assertEqual(_rule_values("ani|ana"), [("ani", False), ("ana", False)])

    def test_regex_stays(self):
        self.assertEqual(_rule_values("[2-9]|[1-9][0-9]+"), [("[2-9]|[1-9][0-9]+", True)])

    def test_list(self):
        self.assertEqual(_rule_values(["a", "b.*"]), [("a", False), ("b.*", True)])


class RulesContextTest(unittest.TestCase):
    def test_rows_and_no_snmp(self):
        rows, info = rules_context({
            "module_policy": "drop",
            "rules": [{"name": "x", "match": {"custom_fields.service_group": "ani"},
                       "modules": {"add": ["a"], "fast": {"try": ["b"]}}, "auth": {"use": None}}],
        })
        self.assertEqual(rows[0]["match"][0]["label"], "service_group")
        self.assertEqual(rows[0]["fast"]["try"], ["b"])
        self.assertEqual(rows[0]["auth"], {"kind": "use", "profiles": []})
        self.assertEqual(info["module_policy"], "drop")


class MatchContextTest(unittest.TestCase):
    def test_would_remove_only_on_drop(self):
        s = {"current": ["a", "b", "c"], "add": ["a"], "try": ["b"]}
        self.assertEqual(_section(s, drop=True)["would_remove"], ["c"])
        self.assertEqual(_section(s, drop=False)["would_remove"], [])

    def test_unknown_keys_and_no_fast(self):
        r = match_context({"schema_version": 9, "new_key": 1, "module_policy": "use",
                           "modules": {"current": []}, "fast": {"field": None},
                           "matched_rules": [{"index": 0, "name": "n", "match": [{"field": "tags", "value": ["x"]}]}]})
        self.assertIsNone(r["fast"])
        self.assertEqual(r["rules"][0]["match"][0][0], "Tag")


class ComparedTest(unittest.TestCase):
    def test_values(self):
        self.assertEqual(_compared(["a", "b"]), "a, b")
        self.assertEqual(_compared([]), "—")
        self.assertEqual(_compared(None), "—")
        self.assertEqual(_compared("3650"), "3650")
