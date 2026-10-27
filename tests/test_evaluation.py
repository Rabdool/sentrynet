"""Guards the evaluation harness so its results stay reproducible.

Run: python -m unittest discover -s tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evaluation.run_evaluation import run  # noqa: E402


class EvaluationTest(unittest.TestCase):
    def setUp(self):
        self.results = {r.attack_class: r for r in run()}

    def test_every_attack_scenario_is_detected(self):
        for cls in ("brute_force", "port_scan", "unauthorized_access"):
            r = self.results[cls]
            self.assertTrue(r.alert_raised, f"{cls} not detected")
            self.assertEqual(r.outcome, "TP")
            self.assertIn(cls, r.alert_types)

    def test_benign_control_raises_no_alert(self):
        r = self.results["benign"]
        self.assertFalse(r.alert_raised)
        self.assertEqual(r.outcome, "TN")

    def test_each_attack_raises_exactly_one_alert_of_its_class(self):
        for cls in ("brute_force", "port_scan", "unauthorized_access"):
            self.assertEqual(self.results[cls].alert_count, 1)

    def test_logging_is_complete(self):
        for r in self.results.values():
            self.assertEqual(r.logging_completeness, 1.0)

    def test_detection_latency_recorded_for_attacks(self):
        for cls in ("brute_force", "port_scan", "unauthorized_access"):
            self.assertIsNotNone(self.results[cls].detection_latency_s)


if __name__ == "__main__":
    unittest.main()
