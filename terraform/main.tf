# PAAP v2 AWS Deployment - Terraform Configuration
# Deploys Lambda + API Gateway for minimal cost (~$3.70/month)

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Zip the Lambda function
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../"
  output_path = "${path.module}/lambda_function.zip"
  excludes    = [".git*", "terraform", "keys", "*.log", "node_modules/aws-sdk"]
}

# IAM Role for Lambda
resource "aws_iam_role" "lambda_role" {
  name = "paapv2-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# IAM Policy for Lambda logs
resource "aws_iam_policy" "lambda_logs" {
  name        = "paapv2-lambda-logs"
  description = "IAM policy for logging from Lambda"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# Attach policy to role
resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_logs.arn
}

# Lambda Function
resource "aws_lambda_function" "paapv2" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "paapv2-demo"
  role            = aws_iam_role.lambda_role.arn
  handler         = "terraform/lambda-handler.handler"
  runtime         = "nodejs20.x"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  timeout     = 30
  memory_size = 128

  environment {
    variables = {
      PAAPV2_SUITE = var.paapv2_suite
      PORT         = "4040"
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_logs
  ]
}

# API Gateway - HTTP API (cheaper than REST API)
resource "aws_apigatewayv2_api" "paapv2" {
  name          = "paapv2-api"
  protocol_type = "HTTP"
  description   = "PAAP v2 API Gateway"
}

# API Gateway Integration with Lambda
resource "aws_apigatewayv2_integration" "paapv2_lambda" {
  api_id           = aws_apigatewayv2_api.paapv2.id
  integration_type = "AWS_PROXY"
  integration_uri  = aws_lambda_function.paapv2.invoke_arn
}

# API Gateway Route - /
resource "aws_apigatewayv2_route" "root" {
  api_id    = aws_apigatewayv2_api.paapv2.id
  route_key = "ANY /"
  target    = "integrations/${aws_apigatewayv2_integration.paapv2_lambda.id}"
}

# API Gateway Route - /issuer
resource "aws_apigatewayv2_route" "issuer" {
  api_id    = aws_apigatewayv2_api.paapv2.id
  route_key = "GET /issuer"
  target    = "integrations/${aws_apigatewayv2_integration.paapv2_lambda.id}"
}

# API Gateway Route - /issue
resource "aws_apigatewayv2_route" "issue" {
  api_id    = aws_apigatewayv2_api.paapv2.id
  route_key = "POST /issue"
  target    = "integrations/${aws_apigatewayv2_integration.paapv2_lambda.id}"
}

# API Gateway Route - /redeem
resource "aws_apigatewayv2_route" "redeem" {
  api_id    = aws_apigatewayv2_api.paapv2.id
  route_key = "POST /redeem"
  target    = "integrations/${aws_apigatewayv2_integration.paapv2_lambda.id}"
}

# API Gateway Deployment
resource "aws_apigatewayv2_deployment" "paapv2" {
  api_id      = aws_apigatewayv2_api.paapv2.id
  description = "PAAP v2 deployment"

  depends_on = [
    aws_apigatewayv2_route.root,
    aws_apigatewayv2_route.issuer,
    aws_apigatewayv2_route.issue,
    aws_apigatewayv2_route.redeem
  ]
}

# API Gateway Stage
resource "aws_apigatewayv2_stage" "paapv2" {
  api_id      = aws_apigatewayv2_api.paapv2.id
  deployment_id = aws_apigatewayv2_deployment.paapv2.id
  name        = var.environment
  auto_deploy = true
}

# Lambda Permission for API Gateway
resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.paapv2.function_name
  principal     = "apigateway.amazonaws.com"

  source_arn = "${aws_apigatewayv2_api.paapv2.execution_arn}/*/*"
}

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "paapv2_lambda" {
  name              = "/aws/lambda/${aws_lambda_function.paapv2.function_name}"
  retention_in_days = 7
}

# CloudWatch Log Group for API Gateway
resource "aws_cloudwatch_log_group" "paapv2_api" {
  name              = "/aws/apigateway/${aws_apigatewayv2_api.paapv2.name}"
  retention_in_days = 7
}

# Outputs
output "api_url" {
  description = "API Gateway URL"
  value       = aws_apigatewayv2_stage.paapv2.invoke_url
}

output "lambda_function_name" {
  description = "Lambda function name"
  value       = aws_lambda_function.paapv2.function_name
}

output "lambda_arn" {
  description = "Lambda function ARN"
  value       = aws_lambda_function.paapv2.arn
}
