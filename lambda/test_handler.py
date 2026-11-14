import unittest

from handler import is_allowlisted, load_allowlist, parse_attacker_ip


class TestIpChecks(unittest.TestCase):
    def test_accepts_public_ip(self):
        self.assertEqual(str(parse_attacker_ip("8.8.8.8")), "8.8.8.8")

    def test_strips_whitespace(self):
        self.assertEqual(str(parse_attacker_ip(" 8.8.8.8 ")), "8.8.8.8")

    def test_rejects_private_and_loopback(self):
        for bad in ["10.0.1.120", "192.168.1.1", "127.0.0.1"]:
            with self.assertRaises(ValueError):
                parse_attacker_ip(bad)

    def test_rejects_garbage(self):
        for bad in ["not-an-ip", "", "999.1.1.1"]:
            with self.assertRaises(ValueError):
                parse_attacker_ip(bad)

    def test_rejects_non_string(self):
        with self.assertRaises(ValueError):
            parse_attacker_ip(None)

    def test_rejects_ipv6(self):
        with self.assertRaises(ValueError):
            parse_attacker_ip("2001:4860:4860::8888")

    def test_allowlist_single_ip_and_network(self):
        nets = load_allowlist("8.8.8.8, 1.1.1.0/24")
        self.assertTrue(is_allowlisted(parse_attacker_ip("8.8.8.8"), nets))
        self.assertTrue(is_allowlisted(parse_attacker_ip("1.1.1.50"), nets))
        self.assertFalse(is_allowlisted(parse_attacker_ip("9.9.9.9"), nets))


if __name__ == "__main__":
    unittest.main()