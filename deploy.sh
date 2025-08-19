set -e

# Configuration
FUNCTION_NAME="security-api-lambda"
ROLE_NAME="lambda-security-api-role"
API_NAME="security-api-gateway"
REGION="us-east-1"
RUNTIME="python3.9"

echo "🚀 Deploying Security API to AWS Lambda"
echo "Function: $FUNCTION_NAME"
echo "Region: $REGION"
echo "========================================"

# Create IAM role for Lambda if it doesn't exist
echo "🔐 Setting up IAM role..."
if ! aws iam get-role --role-name $ROLE_NAME 2>/dev/null; then
    echo "Creating IAM role: $ROLE_NAME"
    
    # Create trust policy
    cat > trust-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "lambda.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF

    # Create the role
    aws iam create-role \
        --role-name $ROLE_NAME \
        --assume-role-policy-document file://trust-policy.json
    
    # Attach basic Lambda execution policy
    aws iam attach-role-policy \
        --role-name $ROLE_NAME \
        --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
    
    echo "✅ IAM role created"
    rm trust-policy.json
    
    # Wait for role to be available
    echo "⏳ Waiting for IAM role to be available..."
    sleep 10
else
    echo "✅ IAM role already exists"
fi

# Get role ARN
ROLE_ARN=$(aws iam get-role --role-name $ROLE_NAME --query 'Role.Arn' --output text)
echo "Role ARN: $ROLE_ARN"

# Create deployment package
echo "📦 Creating deployment package..."
cd src
zip -r ../lambda-function.zip .
cd ..

# Deploy or update Lambda function
echo "🔧 Deploying Lambda function..."
if aws lambda get-function --function-name $FUNCTION_NAME 2>/dev/null; then
    # Update existing function
    echo "Updating existing function..."
    aws lambda update-function-code \
        --function-name $FUNCTION_NAME \
        --zip-file fileb://lambda-function.zip
    
    aws lambda update-function-configuration \
        --function-name $FUNCTION_NAME \
        --runtime $RUNTIME \
        --handler lambda_function.lambda_handler \
        --timeout 30 \
        --memory-size 256
else
    # Create new function
    echo "Creating new function..."
    aws lambda create-function \
        --function-name $FUNCTION_NAME \
        --runtime $RUNTIME \
        --role $ROLE_ARN \
        --handler lambda_function.lambda_handler \
        --zip-file fileb://lambda-function.zip \
        --timeout 30 \
        --memory-size 256 \
        --description "Security API for cybersecurity operations"
fi

echo "✅ Lambda function deployed"

# Create or update API Gateway
echo "🌐 Setting up API Gateway..."

# Check if API exists
API_ID=$(aws apigateway get-rest-apis --query "items[?name=='$API_NAME'].id" --output text)

if [ "$API_ID" == "" ] || [ "$API_ID" == "None" ]; then
    # Create new API
    echo "Creating new API Gateway..."
    API_ID=$(aws apigateway create-rest-api \
        --name $API_NAME \
        --description "Security API Gateway" \
        --query 'id' --output text)
    
    echo "✅ API Gateway created: $API_ID"
else
    echo "✅ Using existing API Gateway: $API_ID"
fi

# Get root resource ID
ROOT_RESOURCE_ID=$(aws apigateway get-resources \
    --rest-api-id $API_ID \
    --query 'items[?path==`/`].id' \
    --output text)

# Create proxy resource
echo "🔗 Setting up proxy resource..."
PROXY_RESOURCE_ID=$(aws apigateway create-resource \
    --rest-api-id $API_ID \
    --parent-id $ROOT_RESOURCE_ID \
    --path-part '{proxy+}' \
    --query 'id' --output text 2>/dev/null || echo "exists")

if [ "$PROXY_RESOURCE_ID" = "exists" ]; then
    PROXY_RESOURCE_ID=$(aws apigateway get-resources \
        --rest-api-id $API_ID \
        --query 'items[?pathPart==`{proxy+}`].id' \
        --output text)
fi

# Set up ANY method on root
echo "🔧 Configuring API methods..."
aws apigateway put-method \
    --rest-api-id $API_ID \
    --resource-id $ROOT_RESOURCE_ID \
    --http-method ANY \
    --authorization-type NONE 2>/dev/null || echo "Root method exists"

# Set up ANY method on proxy
aws apigateway put-method \
    --rest-api-id $API_ID \
    --resource-id $PROXY_RESOURCE_ID \
    --http-method ANY \
    --authorization-type NONE 2>/dev/null || echo "Proxy method exists"

# Get Lambda function ARN
LAMBDA_ARN=$(aws lambda get-function \
    --function-name $FUNCTION_NAME \
    --query 'Configuration.FunctionArn' \
    --output text)

# Set up Lambda integration for root
aws apigateway put-integration \
    --rest-api-id $API_ID \
    --resource-id $ROOT_RESOURCE_ID \
    --http-method ANY \
    --type AWS_PROXY \
    --integration-http-method POST \
    --uri "arn:aws:apigateway:$REGION:lambda:path/2015-03-31/functions/$LAMBDA_ARN/invocations" 2>/dev/null || echo "Root integration exists"

# Set up Lambda integration for proxy
aws apigateway put-integration \
    --rest-api-id $API_ID \
    --resource-id $PROXY_RESOURCE_ID \
    --http-method ANY \
    --type AWS_PROXY \
    --integration-http-method POST \
    --uri "arn:aws:apigateway:$REGION:lambda:path/2015-03-31/functions/$LAMBDA_ARN/invocations" 2>/dev/null || echo "Proxy integration exists"

# Add permission for API Gateway to invoke Lambda
echo "🔐 Setting Lambda permissions..."
aws lambda add-permission \
    --function-name $FUNCTION_NAME \
    --statement-id apigateway-invoke \
    --action lambda:InvokeFunction \
    --principal apigateway.amazonaws.com \
    --source-arn "arn:aws:execute-api:$REGION:*:$API_ID/*/*" 2>/dev/null || echo "Permission already exists"

# Deploy API
echo "🚢 Deploying API..."
aws apigateway create-deployment \
    --rest-api-id $API_ID \
    --stage-name prod \
    --stage-description "Production stage"

# Get API URL
API_URL="https://$API_ID.execute-api.$REGION.amazonaws.com/prod"

echo ""
echo "✅ Deployment completed successfully!"
echo "🌐 API URL: $API_URL"
echo "📋 Available endpoints:"
echo "   GET  $API_URL/"
echo "   GET  $API_URL/token"
echo "   POST $API_URL/hash"
echo "   POST $API_URL/password-strength"
echo "   GET  $API_URL/security-headers"
echo "   GET  $API_URL/csp"
echo ""
echo "💡 Test your API:"
echo "   curl $API_URL/"
echo "   curl \"$API_URL/token?length=16\""
echo ""

# Save configuration
cat > api-config.txt << EOF
API_ID=$API_ID
API_URL=$API_URL
FUNCTION_NAME=$FUNCTION_NAME
ROLE_NAME=$ROLE_NAME
REGION=$REGION
DEPLOYED_AT=$(date)
EOF

echo "💾 Configuration saved to api-config.txt"

# Cleanup
rm -f lambda-function.zip