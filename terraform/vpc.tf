resource "aws_vpc" "honeypot" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${var.project_name}-vpc" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.honeypot.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true

  tags = { Name = "${var.project_name}-public" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.honeypot.id

  tags = { Name = "${var.project_name}-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.honeypot.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = { Name = "${var.project_name}-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# NACL for dynamic blocking.
# No inline ingress/egress blocks on purpose: inline blocks make Terraform
# authoritative and it would delete the deny entries the Lambda adds at runtime.
resource "aws_network_acl" "honeypot" {
  vpc_id     = aws_vpc.honeypot.id
  subnet_ids = [aws_subnet.public.id]

  tags = { Name = "${var.project_name}-nacl" }
}

# Rule 200: baseline allow. Deny rules added later get LOWER numbers.
resource "aws_network_acl_rule" "ingress_allow_all" {
  network_acl_id = aws_network_acl.honeypot.id
  rule_number    = 200
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}

resource "aws_network_acl_rule" "egress_allow_all" {
  network_acl_id = aws_network_acl.honeypot.id
  rule_number    = 200
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}