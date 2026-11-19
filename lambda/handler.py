import json
import os
import base64
import boto3
import ipaddress
import time
import hmac

from botocore.exceptions import ClientError

RULE_NUMBER_FIRST = 10
RULE_NUMBER_LAST = 26          # 17 usable deny slots; the allow-all rule is 200
BLOCK_SECONDS = 2 * 60 * 60    # a block lasts 2 hours

def parse_attacker_ip(raw):
    """Return a public IPv4 address, or raise ValueError."""
    if not isinstance(raw, str):
        raise ValueError("attacker_ip must be a string")
    ip = ipaddress.ip_address(raw.strip())
    if ip.version != 4:
        raise ValueError("only IPv4 is supported")
    if not ip.is_global:
        raise ValueError(f"{ip} is not a public address")
    return ip


def load_allowlist(value):
    """Turn '1.2.3.4,5.6.7.0/24' into a list of networks."""
    networks = []
    for item in value.split(","):
        item = item.strip()
        if item:
            networks.append(ipaddress.ip_network(item, strict=False))
    return networks


def is_allowlisted(ip, networks):
    return any(ip in network for network in networks)

def claim_rule_number(table, ip, now=None, ttl_seconds=BLOCK_SECONDS):
    """Reserve a free NACL rule number for this IP.

    Returns the rule number, or None if every number is taken.
    """
    now = int(time.time()) if now is None else now
    for number in range(RULE_NUMBER_FIRST, RULE_NUMBER_LAST + 1):
        try:
            table.put_item(
                Item={
                    "rule_number": number,
                    "ip": str(ip),
                    "expires_at": now + ttl_seconds,
                },
                ConditionExpression="attribute_not_exists(rule_number)",
            )
            return number
        except ClientError as err:
            if err.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise
    return None

def find_active_block(table, ip, now=None):
    """Return the rule number already blocking this IP, or None."""
    now = int(time.time()) if now is None else now
    response = table.scan(
        FilterExpression="#ip = :ip",
        ExpressionAttributeNames={"#ip": "ip"},
        ExpressionAttributeValues={":ip": str(ip)},
    )
    for item in response.get("Items", []):
        if int(item["expires_at"]) > now:
            return int(item["rule_number"])
    return None


def extend_block(table, rule_number, ip, now=None, ttl_seconds=BLOCK_SECONDS):
    """Push an existing block's expiry forward."""
    now = int(time.time()) if now is None else now
    table.update_item(
        Key={"rule_number": rule_number},
        UpdateExpression="SET expires_at = :e",
        ConditionExpression="#ip = :ip",
        ExpressionAttributeNames={"#ip": "ip"},
        ExpressionAttributeValues={":e": now + ttl_seconds, ":ip": str(ip)},
    )

def block_ip(table, ec2, nacl_id, ip, now=None):
    """Reserve a rule number, then add a deny rule for this IP to the NACL.

    Returns the rule number used.
    """
    number = claim_rule_number(table, ip, now=now)
    if number is None:
        raise RuntimeError("no free NACL rule numbers")
    try:
        ec2.create_network_acl_entry(
            NetworkAclId=nacl_id,
            RuleNumber=number,
            Protocol="-1",
            RuleAction="deny",
            Egress=False,
            CidrBlock=f"{ip}/32",
        )
    except ClientError:
        table.delete_item(Key={"rule_number": number})
        raise
    return number

def _response(status, payload):
    return {"statusCode": status, "body": json.dumps(payload)}


def _is_authorised(event, secret):
    """True only if the request carries the correct shared secret."""
    if not secret:
        return False  # never accept requests if no secret is configured
    supplied = (event.get("headers") or {}).get("x-webhook-secret", "")
    return hmac.compare_digest(str(supplied).encode(), secret.encode())


def handle(event, table, ec2, nacl_id, allowlist, secret):
    """The logic: authenticate, validate, check the allowlist, block, report."""
    if not _is_authorised(event, secret):
        return _response(401, {"message": "unauthorised"})

    try:
        raw_body = event.get("body") or "{}"
        if event.get("isBase64Encoded"):
            raw_body = base64.b64decode(raw_body, validate=True).decode("utf-8")
        body = json.loads(raw_body)
        ip = parse_attacker_ip(body.get("attacker_ip"))
    except (ValueError, AttributeError):
        return _response(400, {"message": "invalid request"})

    if is_allowlisted(ip, allowlist):
        return _response(200, {"status": "skipped", "reason": "allowlisted"})

    existing = find_active_block(table, ip)
    if existing is not None:
        extend_block(table, existing, ip)
        return _response(
            200, {"status": "already_blocked", "ip": str(ip), "rule_number": existing}
        )
    
    try:
        number = block_ip(table, ec2, nacl_id, ip)
    except RuntimeError:
        return _response(503, {"message": "no free rule numbers"})

    return _response(200, {"status": "blocked", "ip": str(ip), "rule_number": number})


_secret_cache = {}


def _get_secret():
    """Read the shared secret from Parameter Store once per Lambda start."""
    if "value" not in _secret_cache:
        ssm = boto3.client("ssm")
        response = ssm.get_parameter(Name=os.environ["SECRET_PARAM"], WithDecryption=True)
        _secret_cache["value"] = response["Parameter"]["Value"]
    return _secret_cache["value"]


def lambda_handler(event, context):
    """What AWS calls. Connects the real services, then runs the logic."""
    table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])
    ec2 = boto3.client("ec2")
    allowlist = load_allowlist(os.environ.get("ALLOWLIST_IPS", ""))
    return handle(event, table, ec2, os.environ["NACL_ID"], allowlist, _get_secret())