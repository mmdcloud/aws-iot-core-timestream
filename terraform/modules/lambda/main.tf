# Lambda Function
resource "aws_lambda_function" "function" {
  function_name = var.function_name
  role          = var.role_arn
  handler       = var.handler
  runtime       = var.runtime
  s3_bucket     = var.s3_bucket
  s3_key        = var.s3_key
  environment {
    variables = var.env_variables
  }
  layers                  = var.layers
  code_signing_config_arn = var.code_signing_config_arn
  tags = {
    Name = var.function_name
  }
}

# Granting permissions for lambda
resource "aws_lambda_permission" "lambda_function_permission" {
  count         = length(var.permissions)
  statement_id  = var.permissions[count.index].statement_id
  function_name = aws_lambda_function.function.arn
  action        = var.permissions[count.index].action
  principal     = var.permissions[count.index].principal
  source_arn    = var.permissions[count.index].source_arn
}