resource "aws_dynamodb_table" "blocked_ips" {
  #checkov:skip=CKV_AWS_119:Table holds only blocked IPs and expiry times and is encrypted at rest by default and a customer managed key costs extra
  #checkov:skip=CKV_AWS_28:Table is short-lived state because entries expire within 2 hours so point-in-time recovery has no value
  name           = "${var.project_name}-blocked-ips"
  billing_mode   = "PROVISIONED"
  read_capacity  = 5
  write_capacity = 5
  hash_key       = "rule_number"

  attribute {
    name = "rule_number"
    type = "N"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = false
  }
}