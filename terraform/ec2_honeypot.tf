resource "aws_security_group" "honeypot" {
  #checkov:skip=CKV_AWS_24:Intentional public SSH exposure because port 22 is served by the Cowrie honeypot and real admin access uses SSM
  name        = "${var.project_name}-sg"
  description = "Public SSH lure for Cowrie. No admin port; admin access is via SSM."
  vpc_id      = aws_vpc.honeypot.id

  ingress {
    description = "Public SSH honeypot lure (Cowrie)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTPS (SSM, Elastic, package mirrors)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTP (apt mirrors)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "DNS (UDP)"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "DNS (TCP)"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-sg" }
}

# Latest Ubuntu 22.04 AMI for this region, looked up from Canonical's public parameter
data "aws_ssm_parameter" "ubuntu_2204" {
  name = "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
}

resource "aws_instance" "honeypot" {
  #checkov:skip=CKV_AWS_126:Detailed monitoring costs extra and logs are already shipped to Elastic
  #checkov:skip=CKV_AWS_135:Performance setting and not a security control and changing it would stop the running honeypot
  ami                    = data.aws_ssm_parameter.ubuntu_2204.value
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.honeypot.id]
  iam_instance_profile   = aws_iam_instance_profile.honeypot.name

  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
    encrypted   = true
  }
  user_data = templatefile("${path.module}/../scripts/user_data.sh", {
    aws_region       = var.aws_region
    project_name     = var.project_name
    elastic_endpoint = var.elastic_endpoint
    filebeat_version = var.filebeat_version
  })
  user_data_replace_on_change = true
  tags                        = { Name = "${var.project_name}-honeypot" }

  lifecycle {
    ignore_changes = [ami]
  }
  credit_specification {
    cpu_credits = "standard"
  }
}