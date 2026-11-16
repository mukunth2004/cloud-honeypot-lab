import unittest
import base64
from botocore.exceptions import ClientError

from handler import (
    RULE_NUMBER_FIRST,
    RULE_NUMBER_LAST,
    block_ip,
    claim_rule_number,
    is_allowlisted,
    load_allowlist,
    parse_attacker_ip,
    handle
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
    def delete_item(self, Key):
        self.items.pop(Key["rule_number"], None)


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

class FakeEc2:
    """A pretend EC2 client that records the calls it receives."""

    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def create_network_acl_entry(self, **kwargs):
        if self.fail:
            raise ClientError(
                {"Error": {"Code": "UnauthorizedOperation", "Message": "no"}},
                "CreateNetworkAclEntry",
            )
        self.calls.append(kwargs)


class TestBlockIp(unittest.TestCase):
    def test_adds_deny_entry_with_right_settings(self):
        table, ec2 = FakeTable(), FakeEc2()
        ip = parse_attacker_ip("8.8.8.8")
        number = block_ip(table, ec2, "acl-123", ip, now=1000)
        self.assertEqual(number, RULE_NUMBER_FIRST)
        call = ec2.calls[0]
        self.assertEqual(call["NetworkAclId"], "acl-123")
        self.assertEqual(call["RuleAction"], "deny")
        self.assertEqual(call["CidrBlock"], "8.8.8.8/32")
        self.assertFalse(call["Egress"])

    def test_undoes_reservation_if_nacl_call_fails(self):
        table, ec2 = FakeTable(), FakeEc2(fail=True)
        ip = parse_attacker_ip("8.8.8.8")
        with self.assertRaises(ClientError):
            block_ip(table, ec2, "acl-123", ip, now=1000)
        self.assertEqual(table.items, {})

    def test_raises_when_no_numbers_free(self):
        table, ec2 = FakeTable(), FakeEc2()
        for n in range(RULE_NUMBER_FIRST, RULE_NUMBER_LAST + 1):
            table.items[n] = {"rule_number": n}
        with self.assertRaises(RuntimeError):
            block_ip(table, ec2, "acl-123", parse_attacker_ip("8.8.8.8"), now=1000)
        self.assertEqual(ec2.calls, [])

class TestHandle(unittest.TestCase):
    def run_handle(self, body, allowlist="", table=None, ec2=None, headers=None):
        table = table or FakeTable()
        ec2 = ec2 or FakeEc2()
        if headers is None:
            headers = {"x-webhook-secret": "test-secret"}
        event = {"headers": headers, "body": body}
        result = handle(
            event, table, ec2, "acl-123", load_allowlist(allowlist), "test-secret"
        )
        return result, table, ec2

    def test_blocks_valid_ip(self):
        result, table, ec2 = self.run_handle('{"attacker_ip": "8.8.8.8"}')
        self.assertEqual(result["statusCode"], 200)
        self.assertIn('"blocked"', result["body"])
        self.assertEqual(len(ec2.calls), 1)

    def test_bad_json_is_400(self):
        result, _, ec2 = self.run_handle("not json")
        self.assertEqual(result["statusCode"], 400)
        self.assertEqual(ec2.calls, [])

    def test_missing_ip_is_400(self):
        result, _, ec2 = self.run_handle("{}")
        self.assertEqual(result["statusCode"], 400)
        self.assertEqual(ec2.calls, [])

    def test_private_ip_is_400_and_not_blocked(self):
        result, _, ec2 = self.run_handle('{"attacker_ip": "10.0.1.120"}')
        self.assertEqual(result["statusCode"], 400)
        self.assertEqual(ec2.calls, [])

    def test_allowlisted_ip_is_skipped(self):
        result, table, ec2 = self.run_handle('{"attacker_ip": "8.8.8.8"}', allowlist="8.8.8.8")
        self.assertEqual(result["statusCode"], 200)
        self.assertIn("skipped", result["body"])
        self.assertEqual(ec2.calls, [])
        self.assertEqual(table.items, {})

    def test_no_free_numbers_is_503(self):
        table = FakeTable()
        for n in range(RULE_NUMBER_FIRST, RULE_NUMBER_LAST + 1):
            table.items[n] = {"rule_number": n}
        result, _, ec2 = self.run_handle('{"attacker_ip": "8.8.8.8"}', table=table)
        self.assertEqual(result["statusCode"], 503)
        self.assertEqual(ec2.calls, [])
    def test_missing_secret_is_401(self):
        result, table, ec2 = self.run_handle('{"attacker_ip": "8.8.8.8"}', headers={})
        self.assertEqual(result["statusCode"], 401)
        self.assertEqual(ec2.calls, [])
        self.assertEqual(table.items, {})

    def test_wrong_secret_is_401(self):
        result, _, ec2 = self.run_handle(
            '{"attacker_ip": "8.8.8.8"}', headers={"x-webhook-secret": "wrong"}
        )
        self.assertEqual(result["statusCode"], 401)
        self.assertEqual(ec2.calls, [])

    def test_empty_configured_secret_rejects_everything(self):
        event = {"headers": {"x-webhook-secret": ""}, "body": '{"attacker_ip": "8.8.8.8"}'}
        result = handle(event, FakeTable(), FakeEc2(), "acl-123", [], "")
        self.assertEqual(result["statusCode"], 401)
    
    def test_base64_encoded_body_is_decoded(self):
        encoded = base64.b64encode(b'{"attacker_ip": "8.8.8.8"}').decode()
        event = {
            "headers": {"x-webhook-secret": "test-secret"},
            "body": encoded,
            "isBase64Encoded": True,
        }
        result = handle(event, FakeTable(), FakeEc2(), "acl-123", [], "test-secret")
        self.assertEqual(result["statusCode"], 200)
        self.assertIn("blocked", result["body"])
    def test_invalid_base64_body_is_400(self):
        event = {
            "headers": {"x-webhook-secret": "test-secret"},
            "body": "!!!not-base64!!!",
            "isBase64Encoded": True,
        }
        result = handle(event, FakeTable(), FakeEc2(), "acl-123", [], "test-secret")
        self.assertEqual(result["statusCode"], 400)
if __name__ == "__main__":
    unittest.main()