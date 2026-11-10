import unittest
from shauditer.models.target import normalize_target, TargetType


class TargetTests(unittest.TestCase):
    def test_ipv4(self):
        t = normalize_target("192.168.1.10")
        self.assertEqual(t.type, TargetType.IPV4)

    def test_cidr(self):
        t = normalize_target("10.10.10.55/24")
        self.assertEqual(t.type, TargetType.CIDR)
        self.assertEqual(t.network, "10.10.10.0/24")

    def test_url(self):
        t = normalize_target("https://Example.com/admin")
        self.assertEqual(t.hostname, "example.com")
        self.assertEqual(t.port, 443)
        self.assertEqual(t.path, "/admin")

    def test_domain(self):
        self.assertEqual(normalize_target("example.com").type, TargetType.DOMAIN)


if __name__ == "__main__":
    unittest.main()
