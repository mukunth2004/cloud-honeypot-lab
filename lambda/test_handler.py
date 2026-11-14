import unittest

from botocore.exceptions import ClientError

from handler import (
    RULE_NUMBER_FIRST,
    RULE_NUMBER_LAST,
    is_allowlisted,
    load_allowlist,
    parse_attacker_ip,
    claim_rule_number,
)

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

class FakeTable:
    """A pretend DynamoDB table that refuses duplicate keys, like the real one."""

    def __init__(self):
        self.items = {}

    def put_item(self, Item, ConditionExpression):
        key = Item["rule_number"]
        if key in self.items:
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "exists"}},
                "PutItem",
            )
        self.items[key] = Item


class TestClaimRuleNumber(unittest.TestCase):
    def test_first_claim_gets_first_number(self):
        table = FakeTable()
        self.assertEqual(claim_rule_number(table, "8.8.8.8", now=1000), RULE_NUMBER_FIRST)

    def test_second_claim_gets_next_number(self):
        table = FakeTable()
        claim_rule_number(table, "8.8.8.8", now=1000)
        self.assertEqual(claim_rule_number(table, "1.1.1.1", now=1000), RULE_NUMBER_FIRST + 1)

    def test_row_records_ip_and_expiry(self):
        table = FakeTable()
        claim_rule_number(table, "8.8.8.8", now=1000, ttl_seconds=60)
        self.assertEqual(table.items[RULE_NUMBER_FIRST]["ip"], "8.8.8.8")
        self.assertEqual(table.items[RULE_NUMBER_FIRST]["expires_at"], 1060)

    def test_returns_none_when_all_taken(self):
        table = FakeTable()
        for n in range(RULE_NUMBER_FIRST, RULE_NUMBER_LAST + 1):
            table.items[n] = {"rule_number": n}
        self.assertIsNone(claim_rule_number(table, "8.8.8.8", now=1000))

    def test_other_errors_are_not_swallowed(self):
        class BrokenTable:
            def put_item(self, Item, ConditionExpression):
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
                    "PutItem",
                )

        with self.assertRaises(ClientError):
            claim_rule_number(BrokenTable(), "8.8.8.8", now=1000)
if __name__ == "__main__":
    unittest.main()