import unittest
from shauditer.intelligence.correlation import correlate_findings
from shauditer.intelligence.prioritization import prioritize_findings


class IntelligenceTests(unittest.TestCase):
    def test_correlates_same_cve_same_asset(self):
        findings = [
            {"title":"A", "asset":"example.com", "cves":["CVE-2026-0001"], "sources":["nuclei"], "evidence_ids":["E1"], "confidence":0.8},
            {"title":"B", "asset":"example.com", "cves":["CVE-2026-0001"], "sources":["other"], "evidence_ids":["E2"], "confidence":0.9},
        ]
        out = correlate_findings(findings)
        self.assertEqual(len(out), 1)
        self.assertEqual(set(out[0]["sources"]), {"nuclei", "other"})
        self.assertEqual(out[0]["confidence"], 0.9)

    def test_priority_orders_critical_over_low(self):
        findings = [
            {"severity":"LOW", "confidence":0.9, "matched_at":"https://x", "evidence_ids":["E"]},
            {"severity":"CRITICAL", "confidence":0.8, "matched_at":"https://x", "evidence_ids":["E"]},
        ]
        out = prioritize_findings(findings)
        self.assertEqual(out[0]["severity"], "CRITICAL")
        self.assertEqual(out[0]["rank"], 1)


if __name__ == "__main__":
    unittest.main()
