resource "aws_cloudwatch_event_rule" "cleanup" {
  name                = "${var.project_name}-cleanup"
  description         = "Remove expired IP blocks"
  schedule_expression = "rate(5 minutes)"
}

resource "aws_cloudwatch_event_target" "cleanup" {
  rule      = aws_cloudwatch_event_rule.cleanup.name
  target_id = "block-ip-cleanup"
  arn       = aws_lambda_function.block_ip.arn
  input     = jsonencode({ action = "cleanup" })
}

resource "aws_lambda_permission" "events_invoke" {
  statement_id  = "AllowEventBridgeCleanup"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.block_ip.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cleanup.arn
}