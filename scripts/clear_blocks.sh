#!/bin/bash
# Lab helper: remove every block the Lambda created (NACL rule + table row).
set -euo pipefail
TABLE=cloud-honeypot-lab-blocked-ips
NACL=$(aws ec2 describe-network-acls --filters Name=tag:Project,Values=cloud-honeypot-lab --query 'NetworkAcls[0].NetworkAclId' --output text)
for n in $(aws dynamodb scan --table-name "$TABLE" --query 'Items[].rule_number.N' --output text); do
  aws ec2 delete-network-acl-entry --network-acl-id "$NACL" --ingress --rule-number "$n" || true
  aws dynamodb delete-item --table-name "$TABLE" --key "{\"rule_number\":{\"N\":\"$n\"}}"
  echo "removed rule $n"
done