set -e

# Load configuration
if [ ! -f "api-config.txt" ]; then
    echo "❌ api-config.txt not found. Nothing to clean up."
    exit 1
fi

source api-config.txt

echo "🧹 Cleaning up AWS resources..."
echo "========================================"

# Delete API Gateway
if [ ! -z "$API_ID" ]; then
    echo "🌐 Deleting API Gateway: $API_ID"
    aws apigateway delete-rest-api --rest-api-id $API_ID
    echo "✅ API Gateway deleted"
fi

# Delete Lambda function
if [ ! -z "$FUNCTION_NAME" ]; then
    echo "⚡ Deleting Lambda function: $FUNCTION_NAME"
    aws lambda delete-function --function-name $FUNCTION_NAME
    echo "✅ Lambda function deleted"
fi

# Delete IAM role (detach policies first)
if [ ! -z "$ROLE_NAME" ]; then
    echo "🔐 Deleting IAM role: $ROLE_NAME"
    
    # Detach policies
    aws iam detach-role-policy \
        --role-name $ROLE_NAME \
        --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole 2>/dev/null || true
    
    # Delete role
    aws iam delete-role --role-name $ROLE_NAME
    echo "✅ IAM role deleted"
fi

# Cleanup local files
rm -f api-config.txt

echo ""
echo "✅ Cleanup completed!"
echo "💰 All AWS resources have been removed to avoid charges."