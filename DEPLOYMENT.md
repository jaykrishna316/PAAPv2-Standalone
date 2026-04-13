# AWS Deployment Guide - Minimal Resources

This guide explains how to deploy PAAP v2 to AWS with the least number of resources and lowest cost.

## Recommended Option: AWS Lambda + API Gateway (Cheapest for Low Traffic)

**Cost**: ~$0.20/month for low traffic
**Pros**: Pay only when used, no server management, auto-scaling
**Cons**: Cold starts, requires some configuration

### Step 1: Prepare Your Code

Create a `lambda-handler.js` file:

```javascript
// lambda-handler.js
const http = require('http');
const paap = require('./protocol-server/src/index');

// Initialize outside handler for performance
const PORT = process.env.PORT || 4040;
const PAAPV2_SUITE = process.env.PAAPV2_SUITE || 'PAAPv2-OPRF-MODP14-SHA256';

// Simple HTTP server for Lambda
let server;

exports.handler = async (event, context) => {
  // Initialize server if not already done
  if (!server) {
    // Your existing server logic here
    // For Lambda, you might want to use an Express app instead
    // See Step 2 for Express version
  }
  
  // Handle API Gateway event
  const path = event.path;
  const method = event.httpMethod;
  const body = event.body ? JSON.parse(event.body) : {};
  
  // Your endpoint logic here
  if (method === 'GET' && path === '/issuer') {
    const issuerInfo = paap.getIssuerInfo();
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(issuerInfo)
    };
  }
  
  // Add other endpoints...
  
  return {
    statusCode: 404,
    body: JSON.stringify({ error: 'Not found' })
  };
};
```

### Step 2: Better Option - Express with Lambda

Create `server.js` for Lambda:

```javascript
// lambda-server.js
const serverless = require('serverless-http');
const express = require('express');
const paap = require('./protocol-server/src/index');

const app = express();
app.use(express.json());

app.get('/issuer', (req, res) => {
  res.json(paap.getIssuerInfo());
});

app.post('/issue', (req, res) => {
  // Your issue logic
});

app.post('/redeem', (req, res) => {
  // Your redeem logic
});

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/demo/static/index.html');
});

module.exports.handler = serverless(app);
```

### Step 3: Create Deployment Package

```bash
# Install dependencies
npm install express serverless-http

# Create zip
zip -r deployment.zip . -x "*.git*" "node_modules/aws-sdk/*"
```

### Step 4: Deploy to Lambda

1. Go to AWS Console → Lambda
2. Create function: `paapv2-demo`
3. Runtime: Node.js 20.x
4. Upload `deployment.zip`
5. Set environment variables:
   - `PAAPV2_SUITE`: `PAAPv2-OPRF-MODP14-SHA256`
   - `PORT`: `4040`
6. Memory: 128 MB (minimum)
7. Timeout: 30 seconds

### Step 5: Create API Gateway

1. Go to API Gateway → Create API
2. REST API (or HTTP API for cheaper option)
3. Create resources: `/issuer`, `/issue`, `/redeem`, `/`
4. Connect to Lambda function
5. Deploy to stage: `prod`

**API Gateway costs**: ~$3.50/month for HTTP API

---

## Alternative Option: AWS EC2 t2.nano (Free Tier Eligible)

**Cost**: Free for 12 months (t2.nano/t2.micro), then ~$4.75/month (t2.nano)

### Step 1: Launch EC2 Instance

1. Go to AWS Console → EC2
2. Launch Instance
3. AMI: Ubuntu 22.04 LTS
4. Instance type: `t2.nano` (1 vCPU, 0.5 GB RAM) or `t2.micro` (1 vCPU, 1 GB RAM)
5. Key pair: Create or use existing
6. Security group: Allow HTTP (80), HTTPS (443), SSH (22)

### Step 2: Connect to Instance

```bash
ssh -i your-key.pem ubuntu@your-instance-ip
```

### Step 3: Install Node.js

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
```

### Step 4: Clone and Setup

```bash
git clone https://github.com/jaykrishna316/PAAPv2-Standalone.git
cd PAAPv2-Standalone
npm install
```

### Step 5: Install PM2 for Process Management

```bash
sudo npm install -g pm2
```

### Step 6: Start Server

```bash
pm2 start npm --name "paapv2" -- start
pm2 save
pm2 startup
```

### Step 7: Setup Reverse Proxy with Nginx

```bash
sudo apt-get install nginx
sudo rm /etc/nginx/sites-enabled/default
sudo nano /etc/nginx/sites-available/paapv2
```

Add this config:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:4040;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/paapv2 /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### Step 8: Add SSL (Optional but Recommended)

```bash
sudo apt-get install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

---

## Alternative Option: AWS Elastic Beanstalk (Easiest)

**Cost**: ~$15-20/month (t2.micro)

### Step 1: Install EB CLI

```bash
pip install awsebcli
```

### Step 2: Initialize

```bash
eb init
# Select region
# Select application name
# Select platform: Node.js
```

### Step 3: Deploy

```bash
eb create production-env
```

### Step 4: Configure Environment

```bash
eb setenv PAAPV2_SUITE=PAAPv2-OPRF-MODP14-SHA256
```

---

## Cost Comparison

| Option | Monthly Cost (Low Traffic) | Setup Difficulty | Maintenance |
|--------|---------------------------|------------------|-------------|
| Lambda + API Gateway | ~$3.70 | Medium | Low |
| EC2 t2.nano | Free (12 mo) / $4.75 | Medium | Medium |
| EC2 t2.micro | Free (12 mo) / $9.50 | Medium | Medium |
| Elastic Beanstalk | ~$15-20 | Easy | Low |

---

## Security Best Practices

1. **Use HTTPS**: Set up SSL certificates
2. **Environment Variables**: Store secrets in AWS Secrets Manager
3. **Security Groups**: Restrict access to necessary ports only
4. **IAM Roles**: Use least privilege for Lambda functions
5. **Monitoring**: Enable CloudWatch logs

---

## Recommended for Demo/Concept Showcase

**Option**: AWS S3 Static Hosting + CloudFront (Frontend) + Lambda (Backend)

**Cost**: ~$1-2/month
**Setup**: Medium

### Steps:

1. **Frontend (S3 + CloudFront)**:
   - Upload `demo/static` to S3 bucket
   - Enable static website hosting
   - Add CloudFront CDN
   - Cost: ~$0.50/month

2. **Backend (Lambda + API Gateway)**:
   - Deploy server logic to Lambda
   - Use HTTP API Gateway (cheaper)
   - Cost: ~$0.20/month for low traffic

3. **Database (DynamoDB)**:
   - For nullifier storage
   - On-demand pricing
   - Cost: ~$0.25/month for low traffic

**Total**: ~$1/month for demo usage

---

## Quick Start for Demo (Cheapest)

If you just want to show the demo:

1. **Use GitHub Pages** (Free):
   - Deploy `demo/static` to GitHub Pages
   - Point to a publicly accessible backend

2. **Backend**: Use a free tier service like:
   - Render.com (free tier)
   - Railway.app (free tier)
   - Vercel (for serverless)

**Total cost**: $0 for demo showcase

---

## Monitoring

Enable CloudWatch for monitoring:

```bash
# For EC2
sudo apt-get install amazon-cloudwatch-agent
```

For Lambda, logs are automatically sent to CloudWatch Logs.

---

## Troubleshooting

### Lambda Timeout Errors

- Increase timeout to 30 seconds
- Increase memory to 256 MB if needed

### EC2 Out of Memory

- Upgrade to t2.micro (1 GB RAM)
- Add swap space

### API Gateway 502 Errors

- Check Lambda function is deployed correctly
- Verify environment variables are set

---

## Cleanup

To avoid charges after testing:

```bash
# Delete Lambda
aws lambda delete-function --function-name paapv2-demo

# Delete API Gateway
aws apigateway delete-rest-api --rest-api-id YOUR_API_ID

# Terminate EC2
aws ec2 terminate-instances --instance-ids YOUR_INSTANCE_ID
```

---

## Support

- AWS Documentation: https://docs.aws.amazon.com/
- For PAAP v2 specific issues: Check INTEGRATION.md
