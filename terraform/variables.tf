variable "aws_region" {
  description = "AWS region for the lab"
  type        = string
  default     = "eu-north-1"
}

variable "project_name" {
  description = "Name prefix and tag value"
  type        = string
  default     = "cloud-honeypot-lab"
}

variable "availability_zone" {
  description = "AZ for the public subnet"
  type        = string
  default     = "eu-north-1a"
}