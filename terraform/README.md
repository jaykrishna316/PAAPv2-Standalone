# Terraform Deployment for PAAP v2

This Terraform configuration deploys PAAP v2 to AWS using Lambda + API Gateway for minimal cost (~$3.70/month).

## Prerequisites

1. **AWS Account**: You need an AWS account with appropriate permissions
2. **Terraform installed**: Install from https://www.terraform.io/downloads
3. **AWS CLI configured**: Run `aws configure` to set up credentials
4. **Node.js dependencies**: Ensure `node_modules` are installed in the parent directory

## Quick Start

```bash
# Navigate to terraform directory
cd terraform

# Initialize Terraform
terraform init

# Review the plan
terraform plan

# Deploy
terraform apply

# Get the API URL
terraform output api_url
```

## Configuration

### Using Default Variables

The configuration uses sensible defaults:
- **Region**: `us-east-1`
- **Environment**: `prod`
- **Suite**: `PAAPv2-OPRF-MODP14-SHA256`

### Custom Configuration

Create a `terraform.tfvars` file:

```hcl
aws_region   = "us-west-2"
environment  = "production"
paapv2_suite = "PAAPv2-OPRF-MODP14-SHA256"
```

Or pass variables inline:

```bash
terraform apply -var="aws_region=us-west-2"
```

## Cost Breakdown

- **Lambda**: ~$0.20/month for low traffic
- **API Gateway (HTTP API)**: ~$3.50/month
- **CloudWatch Logs**: ~$0.50/month
- **Total**: ~$4.20/month

For very low traffic (< 1M requests/month), costs will be lower.

## Architecture

```
Internet → API Gateway (HTTP) → Lambda Function → PAAP v2 Protocol
                                              ↓
                                        CloudWatch Logs
```

## What Gets Created

1. **Lambda Function**: Runs the PAAP v2 server logic
2. **API Gateway**: HTTP API with routes for /issuer, /issue, /redeem
3. **IAM Role**: Permissions for Lambda execution and logging
4. **CloudWatch Log Groups**: For Lambda and API Gateway logs
5. **API Gateway Stage**: Production deployment stage

## Endpoints

After deployment, you'll have:
- `GET /issuer` - Get public parameters
- `POST /issue` - Issue blind signature
- `POST /redeem` - Redeem credential for token

## Updating the Deployment

After making code changes:

```bash
# Re-apply Terraform
terraform apply

# This will update the Lambda function with new code
```

## Destroying Resources

To remove all AWS resources and stop incurring charges:

```bash
terraform destroy
```

## Troubleshooting

### Lambda Timeout Errors

If you get timeout errors, increase the timeout in `main.tf`:

```hcl
timeout = 60  # Increase from 30 to 60 seconds
```

### Memory Issues

If Lambda runs out of memory, increase memory in `main.tf`:

```hcl
memory_size = 256  # Increase from 128 to 256 MB
```

### Permission Errors

Ensure your AWS credentials have permissions to:
- Create Lambda functions
- Create API Gateway
- Create IAM roles
- Create CloudWatch log groups

## Production Considerations

For production deployment, consider:

1. **Database**: Add DynamoDB for nullifier storage
2. **Rate Limiting**: Implement rate limiting in API Gateway
3. **Monitoring**: Add CloudWatch alarms
4. **Custom Domain**: Add a custom domain with SSL
5. **CI/CD**: Integrate with GitHub Actions for automated deployments

## Adding Database (Optional)

To add DynamoDB for nullifier storage:

```hcl
# Add to main.tf
resource "aws_dynamodb_table" "nullifiers" {
  name           = "paapv2-nullifiers"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "commitmentHex"
  
  attribute {
    name = "commitmentHex"
    type = "S"
  }
  
  attribute {
    name = "contextId"
    type = "S"
  }
  
  global_secondary_index {
    name            = "ContextIndex"
    hash_key        = "contextId"
    projection_type = "ALL"
  }
}
```

Then update the Lambda handler to use DynamoDB.

## Support

- Terraform Documentation: https://www.terraform.io/docs
- AWS Lambda Documentation: https://docs.aws.amazon.com/lambda/
- PAAP v2 Documentation: See INTEGRATION.md
