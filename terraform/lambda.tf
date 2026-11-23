data "archive_file" "lambda" {
  type        = "zip"
  source_file = "${path.module}/../lambda/handler.py"
  output_path = "${path.module}/build/lambda.zip"
}

resource "aws_lambda_function" "block_ip" {
  #checkov:skip=CKV_AWS_116:Called synchronously via Function URL and the scheduled cleanup repeats every 5 minutes so a DLQ adds little
  #checkov:skip=CKV_AWS_117:A VPC would need NAT or interface endpoints to reach AWS APIs which breaks the near-zero cost goal
  #checkov:skip=CKV_AWS_173:Environment variables hold no secrets because the webhook secret lives in Parameter Store as a SecureString
  #checkov:skip=CKV_AWS_50:X-Ray tracing adds cost and permissions and structured CloudWatch logs are enough for this lab
  #checkov:skip=CKV_AWS_115:Account concurrency quota is 10 and AWS requires that much to stay unreserved so no function level limit can be set
  function_name    = "${var.project_name}-block-ip"
  role             = aws_iam_role.lambda.arn
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  timeout          = 10
  memory_size      = 256

  environment {
    variables = {
      TABLE_NAME    = aws_dynamodb_table.blocked_ips.name
      NACL_ID       = aws_network_acl.honeypot.id
      SECRET_PARAM  = "/${var.project_name}/webhook-secret"
      ALLOWLIST_IPS = var.allowlist_ips
    }
  }
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${aws_lambda_function.block_ip.function_name}"
  retention_in_days = 7
}

resource "aws_lambda_function_url" "block_ip" {
  function_name      = aws_lambda_function.block_ip.function_name
  authorization_type = "NONE"
}

# Function URLs with no AWS-level auth need an explicit permission, or every
# request gets 403. AWS now requires BOTH of these statements.
resource "aws_lambda_permission" "url_invoke_url" {
  statement_id           = "AllowPublicInvokeFunctionUrl"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.block_ip.function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

resource "aws_lambda_permission" "url_invoke_function" {
  statement_id             = "AllowPublicInvokeFunction"
  action                   = "lambda:InvokeFunction"
  function_name            = aws_lambda_function.block_ip.function_name
  principal                = "*"
  invoked_via_function_url = true
}