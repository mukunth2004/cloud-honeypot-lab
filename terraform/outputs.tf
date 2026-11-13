output "instance_id" {
  value = aws_instance.honeypot.id
}

output "public_ip" {
  value = aws_instance.honeypot.public_ip
}

output "ssm_connect_command" {
  value = "aws ssm start-session --target ${aws_instance.honeypot.id} --region ${var.aws_region}"
}