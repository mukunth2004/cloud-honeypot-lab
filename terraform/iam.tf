data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "honeypot" {
  name               = "${var.project_name}-ec2-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.honeypot.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "honeypot" {
  name = "${var.project_name}-ec2-profile"
  role = aws_iam_role.honeypot.name
}

data "aws_iam_policy_document" "ec2_read_filebeat_key" {
  statement {
    sid       = "ReadFilebeatKey"
    actions   = ["ssm:GetParameter"]
    resources = ["arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter/${var.project_name}/filebeat-api-key"]
  }
}

resource "aws_iam_role_policy" "ec2_read_filebeat_key" {
  name   = "${var.project_name}-ec2-read-filebeat-key"
  role   = aws_iam_role.honeypot.id
  policy = data.aws_iam_policy_document.ec2_read_filebeat_key.json
}