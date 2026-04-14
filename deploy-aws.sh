#!/bin/bash
# PAAP v2 - Complete AWS Deployment Script
# Run this in AWS CloudShell: https://console.aws.amazon.com/cloudshell
# Takes ~15 minutes total (mostly CloudFront propagation)

set -e

REGION="us-east-1"
SUITE="PAAPv2-OPRF-MODP14-SHA256"
REPO="https://github.com/jaykrishna316/PAAPv2-Standalone.git"
DEPLOY_DIR="$HOME/paapv2-deploy"

# Check for destroy flag
if [ "$1" = "--destroy" ]; then
  echo "======================================"
  echo " PAAP v2 AWS Cleanup"
  echo "======================================"
  
  cd "$DEPLOY_DIR/terraform" 2>/dev/null || {
    echo "No deployment found. Nothing to destroy."
    exit 0
  }
  
  echo "[1/1] Destroying all resources..."
  terraform destroy -auto-approve
  echo ""
  echo "Cleanup complete! All PAAP v2 resources have been removed."
  exit 0
fi

echo "======================================"
echo " PAAP v2 AWS Deployment"
echo "======================================"

# ── 1. Install Terraform ──────────────────────────────────────────────────────
if ! command -v terraform &> /dev/null; then
  echo "[1/8] Installing Terraform..."
  wget -q https://releases.hashicorp.com/terraform/1.6.0/terraform_1.6.0_linux_amd64.zip
  unzip -q terraform_1.6.0_linux_amd64.zip
  sudo mv terraform /usr/local/bin/
  rm terraform_1.6.0_linux_amd64.zip
else
  echo "[1/8] Terraform already installed."
fi

# ── 2. Clone repo ─────────────────────────────────────────────────────────────
echo "[2/8] Cloning repository..."
rm -rf "$DEPLOY_DIR"
mkdir -p "$DEPLOY_DIR"
cd "$DEPLOY_DIR"
git clone "$REPO" .
npm install express serverless-http

# ── 3. Create Lambda handler ──────────────────────────────────────────────────
echo "[3/8] Creating Lambda handler..."
cat > index.js << 'HANDLER_EOF'
const paap = require('./protocol-server/src/index');

exports.handler = async (event) => {
  const path = (event.rawPath || event.path || '').replace(/^\/prod/, '');
  const method = event.requestContext?.http?.method || event.httpMethod;

  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json'
  };

  if (method === 'OPTIONS') return { statusCode: 200, headers, body: '' };

  try {
    if (method === 'GET' && path === '/issuer') {
      return { statusCode: 200, headers, body: JSON.stringify(paap.getIssuerInfo()) };
    }

    if (method === 'POST' && path === '/issue') {
      const reqBody = JSON.parse(event.body || '{}');
      const { issuanceCode, blinded } = reqBody;
      if (!issuanceCode || !blinded) return { statusCode: 400, headers, body: JSON.stringify({ error: 'Missing fields' }) };
      const issuerInfo = paap.getIssuerInfo();
      const { keyId, evaluatedElementHex } = paap.oprfEvaluateBlinded({ blindedElementHex: blinded });
      return { statusCode: 201, headers, body: JSON.stringify({ suiteId: issuerInfo.suiteId, keyId, evaluated: evaluatedElementHex }) };
    }

    if (method === 'POST' && path === '/redeem') {
      const reqBody = JSON.parse(event.body || '{}');
      const { contextId, credential } = reqBody;
      if (!contextId || !credential) return { statusCode: 400, headers, body: JSON.stringify({ error: 'Missing fields' }) };
      const submissionToken = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = Math.random() * 16 | 0;
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
      });
      return { statusCode: 200, headers, body: JSON.stringify({ submissionToken, expiresAt: new Date(Date.now() + 3600000).toISOString() }) };
    }

    return { statusCode: 404, headers, body: JSON.stringify({ error: 'Not Found' }) };
  } catch (error) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: error.message }) };
  }
};
HANDLER_EOF

# ── 4. Create Terraform config ────────────────────────────────────────────────
echo "[4/8] Creating Terraform configuration..."
mkdir -p terraform
cd terraform

cat > main.tf << 'TF_EOF'
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.0" }
  }
}

provider "aws" { region = var.aws_region }

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../"
  output_path = "${path.module}/lambda_function.zip"
  excludes    = [".git", "terraform", "keys", "*.log", "node_modules/aws-sdk"]
}

resource "aws_iam_role" "lambda_role" {
  name = "paapv2-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Action = "sts:AssumeRole", Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" } }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "paapv2" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "paapv2-demo"
  role             = aws_iam_role.lambda_role.arn
  handler          = "index.handler"
  runtime          = "nodejs20.x"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 30
  memory_size      = 128
  environment { variables = { PAAPV2_SUITE = var.paapv2_suite } }
}

resource "aws_apigatewayv2_api" "paapv2" {
  name          = "paapv2-api"
  protocol_type = "HTTP"
  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_headers = ["Content-Type", "Authorization"]
    max_age       = 300
  }
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id           = aws_apigatewayv2_api.paapv2.id
  integration_type = "AWS_PROXY"
  integration_uri  = aws_lambda_function.paapv2.invoke_arn
}

resource "aws_apigatewayv2_route" "issuer" {
  api_id    = aws_apigatewayv2_api.paapv2.id
  route_key = "GET /issuer"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_route" "issue" {
  api_id    = aws_apigatewayv2_api.paapv2.id
  route_key = "POST /issue"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_route" "redeem" {
  api_id    = aws_apigatewayv2_api.paapv2.id
  route_key = "POST /redeem"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_stage" "prod" {
  api_id      = aws_apigatewayv2_api.paapv2.id
  name        = "prod"
  auto_deploy = true
}

resource "aws_lambda_permission" "api_gw" {
  statement_id  = "AllowAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.paapv2.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.paapv2.execution_arn}/*/*"
}

resource "random_id" "bucket_suffix" { byte_length = 4 }

resource "aws_s3_bucket" "frontend" {
  bucket = "paapv2-frontend-${random_id.bucket_suffix.hex}"
}

resource "aws_s3_bucket_public_access_block" "frontend" {
  bucket                  = aws_s3_bucket.frontend.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_website_configuration" "frontend" {
  bucket = aws_s3_bucket.frontend.id
  index_document { suffix = "index.html" }
}

resource "aws_s3_bucket_policy" "frontend" {
  bucket     = aws_s3_bucket.frontend.id
  depends_on = [aws_s3_bucket_public_access_block.frontend]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = "*", Action = "s3:GetObject", Resource = "${aws_s3_bucket.frontend.arn}/*" }]
  })
}

resource "aws_cloudfront_distribution" "frontend" {
  origin {
    domain_name = aws_s3_bucket_website_configuration.frontend.website_endpoint
    origin_id   = "S3-Website"
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }
  enabled             = true
  default_root_object = "index.html"
  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3-Website"
    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 0
    max_ttl                = 0
    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }
  }
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
  viewer_certificate { cloudfront_default_certificate = true }
}

output "api_url"        { value = aws_apigatewayv2_stage.prod.invoke_url }
output "website_url"   { value = "https://${aws_cloudfront_distribution.frontend.domain_name}" }
output "bucket_name"   { value = aws_s3_bucket.frontend.id }
TF_EOF

cat > variables.tf << 'VARS_EOF'
variable "aws_region"   { default = "us-east-1" }
variable "paapv2_suite" { default = "PAAPv2-OPRF-MODP14-SHA256" }
VARS_EOF

# ── 5. Deploy infrastructure ──────────────────────────────────────────────────
echo "[5/8] Deploying infrastructure (this takes ~2 min)..."
terraform init -input=false
terraform apply -auto-approve -input=false

API_URL=$(terraform output -raw api_url)
BUCKET_NAME=$(terraform output -raw bucket_name)
CLOUDFRONT_URL=$(terraform output -raw website_url)

# ── 6. Update index.html with correct API URL ─────────────────────────────────
echo "[6/8] Updating frontend with API URL: $API_URL"
cd ..
sed "s|http://localhost:4040|$API_URL|g; s|fetch('/issuer')|fetch('$API_URL/issuer')|g; s|fetch('/issue'|fetch('$API_URL/issue'|g; s|fetch('/redeem'|fetch('$API_URL/redeem'|g" \
  demo/static/index.html > /tmp/index_updated.html

# ── 7. Upload frontend files ──────────────────────────────────────────────────
echo "[7/8] Uploading frontend files..."
aws s3 cp /tmp/index_updated.html s3://$BUCKET_NAME/index.html \
  --content-type "text/html" \
  --metadata-directive REPLACE \
  --cache-control "no-cache, no-store, must-revalidate"

aws s3 cp protocol-browser/src/index.js s3://$BUCKET_NAME/sdk/paapv2-browser.js \
  --content-type "application/javascript"

# ── 8. Test API ───────────────────────────────────────────────────────────────
echo "[8/8] Testing API endpoints..."
echo ""
ISSUER=$(curl -s "$API_URL/issuer")
if echo "$ISSUER" | grep -q "suiteId"; then
  echo "✅ /issuer endpoint working"
else
  echo "❌ /issuer endpoint failed: $ISSUER"
fi

echo ""
echo "======================================"
echo " Deployment Complete!"
echo "======================================"
echo ""
echo "🌐 Demo URL:  $CLOUDFRONT_URL"
echo "📊 API URL:   $API_URL"
echo "🪣 S3 Bucket: $BUCKET_NAME"
echo ""
echo "⏳ CloudFront may take 10-15 minutes to fully propagate."
echo "   Check readiness: curl -s -o /dev/null -w \"%{http_code}\" $CLOUDFRONT_URL"
echo ""
echo "Test endpoints:"
echo "  GET  $API_URL/issuer"
echo "  POST $API_URL/issue"
echo "  POST $API_URL/redeem"
