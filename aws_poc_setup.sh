#!/bin/bash
# Project_Two - Scenario A AWS Setup Script
# This script configures the AWS environment for a minimal POC architecture.
# It creates an S3 bucket, a DynamoDB table, an IAM role, and pushes the local backend as a Lambda function.

set -e

echo "🚀 Starting AWS Scenario A Provisioning..."

# Configurable variables
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "123456789012")
REGION="ap-south-1"
TIMESTAMP=$(date +%s)
BUCKET_NAME="project-two-reports-poc-${ACCOUNT_ID}-${TIMESTAMP}"
DYNAMO_TABLE="ProjectTwo_ScanMetadata"
LAMBDA_ROLE_NAME="ProjectTwoLambdaExecutionRolePOC"
LAMBDA_FUNCTION_NAME="SecurityControllerPOC"

echo "=========================================="
echo "📍 Region: $REGION"
echo "🪣  S3 Bucket: $BUCKET_NAME"
echo "🗄️  DynamoDB Table: $DYNAMO_TABLE"
echo "=========================================="
echo ""

# 1. Create S3 Bucket
echo "── Step 1: Creating S3 Bucket ──────────────────────"
aws s3api create-bucket --bucket "$BUCKET_NAME" --region "$REGION" > /dev/null || echo "⚠️  Make sure you have AWS credentials configured."
echo "✅ S3 Bucket created: $BUCKET_NAME"
echo ""

# 2. Create DynamoDB Table
echo "── Step 2: Creating DynamoDB Table ────────────────"
if aws dynamodb describe-table --table-name "$DYNAMO_TABLE" --region "$REGION" 2>/dev/null; then
    echo "ℹ️  DynamoDB Table $DYNAMO_TABLE already exists. Skipping creation."
else
    aws dynamodb create-table \
        --table-name "$DYNAMO_TABLE" \
        --attribute-definitions AttributeName=scan_id,AttributeType=S \
        --key-schema AttributeName=scan_id,KeyType=HASH \
        --billing-mode PAY_PER_REQUEST \
        --region "$REGION" > /dev/null
    echo "✅ DynamoDB Table created: $DYNAMO_TABLE"
fi
echo ""

# 3. Create IAM Role for Lambda
echo "── Step 3: Creating IAM Role for Lambda ───────────"
ROLE_TRUST_POLICY='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}'

if aws iam get-role --role-name "$LAMBDA_ROLE_NAME" 2>/dev/null; then
    echo "ℹ️  IAM Role $LAMBDA_ROLE_NAME already exists. Skipping creation."
    ROLE_ARN=$(aws iam get-role --role-name "$LAMBDA_ROLE_NAME" --query 'Role.Arn' --output text)
else
    ROLE_ARN=$(aws iam create-role --role-name "$LAMBDA_ROLE_NAME" --assume-role-policy-document "$ROLE_TRUST_POLICY" --query 'Role.Arn' --output text)
    
    # Attach managed policy for basic execution
    aws iam attach-role-policy --role-name "$LAMBDA_ROLE_NAME" --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    
    # Attach custom policy for Bedrock, S3, DynamoDB
    CUSTOM_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "s3:PutObject",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:GetItem"
      ],
      "Resource": "*"
    }
  ]
}
EOF
)
    aws iam put-role-policy --role-name "$LAMBDA_ROLE_NAME" --policy-name "ProjectTwoPOCPolicy" --policy-document "$CUSTOM_POLICY"
    echo "✅ IAM Role created: $LAMBDA_ROLE_NAME"
    echo "⏳ Waiting 10 seconds for IAM role to propagate globally..."
    sleep 10
fi
echo ""

# 4. Package and Deploy Lambda
echo "── Step 4: Packaging and Deploying Lambda ─────────"
echo "📦 Creating ZIP package..."
cd backend
zip -rq ../deployment_package.zip . -x "tmp/*" -x "reports/*" -x "knowledge_base/chroma_db/*" -x "*/__pycache__/*"
cd ..

if aws lambda get-function --function-name "$LAMBDA_FUNCTION_NAME" --region "$REGION" 2>/dev/null; then
    echo "ℹ️  Lambda function already exists. Updating code..."
    aws lambda update-function-code \
        --function-name "$LAMBDA_FUNCTION_NAME" \
        --zip-file fileb://deployment_package.zip \
        --region "$REGION" > /dev/null
else
    echo "🚀 Creating new Lambda function..."
    aws lambda create-function \
        --function-name "$LAMBDA_FUNCTION_NAME" \
        --runtime python3.10 \
        --role "$ROLE_ARN" \
        --handler controller_lambda.handler.lambda_handler \
        --timeout 900 \
        --memory-size 1024 \
        --zip-file fileb://deployment_package.zip \
        --environment "Variables={S3_BUCKET=$BUCKET_NAME,DYNAMO_TABLE=$DYNAMO_TABLE}" \
        --region "$REGION" > /dev/null
fi

echo "✅ Lambda function deployed: $LAMBDA_FUNCTION_NAME"
rm deployment_package.zip

echo ""
echo "🎉 AWS Scenario A Provisioning Complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "You can now test the orchestrator in the cloud via AWS CLI:"
echo ""
echo "  aws lambda invoke \\"
echo "    --function-name $LAMBDA_FUNCTION_NAME \\"
echo "    --payload '{\"scanners\": [\"semgrep\", \"secrets\", \"dependency\"], \"target\": \"https://github.com/OWASP/NodeGoat\"}' \\"
echo "    --cli-binary-format raw-in-base64-out \\"
echo "    output.json"
echo ""
echo "The results will also be saved to S3 and DynamoDB automatically."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
