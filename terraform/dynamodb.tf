resource "aws_dynamodb_table" "blocked_ips" {
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
    enabled        = true
  }
}