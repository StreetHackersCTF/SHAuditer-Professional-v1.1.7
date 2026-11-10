import unittest
from shauditer.models.target import normalize_target
from shauditer.scope.models import ScopePolicy
from shauditer.scope.validator import ScopeValidator


class ScopeTests(unittest.TestCase):
    def test_in_scope(self):
        v = ScopeValidator(ScopePolicy(in_scope=["10.10.10.0/24"]))
        self.assertTrue(v.authorize(normalize_target("10.10.10.20")).allowed)

    def test_out_of_scope_wins(self):
        v = ScopeValidator(ScopePolicy(in_scope=["*.example.com"], out_of_scope=["admin.example.com"]))
        self.assertFalse(v.authorize(normalize_target("admin.example.com")).allowed)

    def test_ports(self):
        v = ScopeValidator(ScopePolicy(in_scope=["example.com"], allowed_ports={80,443}))
        self.assertTrue(v.authorize(normalize_target("example.com"), port=443).allowed)
        self.assertFalse(v.authorize(normalize_target("example.com"), port=22).allowed)


if __name__ == "__main__":
    unittest.main()
