import json
import logging
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

class SecurityAPI:
    """Security-themed API endpoints for Lambda"""
    
    def __init__(self):
        self.version = "1.0.0"
        self.service_name = "SecurityAPI"
    
    def generate_secure_token(self, length: int = 32) -> str:
        """Generate cryptographically secure token"""
        return secrets.token_urlsafe(length)
    
    def hash_password(self, password: str, salt: str = None) -> Dict[str, str]:
        """Hash password with salt (demo purposes)"""
        if not salt:
            salt = secrets.token_hex(16)
        
        # Use PBKDF2 for password hashing
        import hashlib
        hashed = hashlib.pbkdf2_hmac('sha256', 
                                   password.encode('utf-8'), 
                                   salt.encode('utf-8'), 
                                   100000)  # 100,000 iterations
        
        return {
            "hash": hashed.hex(),
            "salt": salt,
            "algorithm": "PBKDF2-SHA256",
            "iterations": 100000
        }
    
    def check_password_strength(self, password: str) -> Dict[str, Any]:
        """Analyze password strength"""
        import re
        
        strength_score = 0
        feedback = []
        
        # Length check
        if len(password) >= 12:
            strength_score += 25
        elif len(password) >= 8:
            strength_score += 15
        else:
            feedback.append("Password should be at least 8 characters")
        
        # Character variety
        if re.search(r'[a-z]', password):
            strength_score += 10
        else:
            feedback.append("Add lowercase letters")
            
        if re.search(r'[A-Z]', password):
            strength_score += 10
        else:
            feedback.append("Add uppercase letters")
            
        if re.search(r'\d', password):
            strength_score += 15
        else:
            feedback.append("Add numbers")
            
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            strength_score += 20
        else:
            feedback.append("Add special characters")
        
        # Common patterns (simple check)
        common_patterns = ['123', 'abc', 'password', 'admin']
        if any(pattern in password.lower() for pattern in common_patterns):
            strength_score -= 15
            feedback.append("Avoid common patterns")
        
        strength_score = max(0, min(100, strength_score))
        
        if strength_score >= 80:
            level = "Very Strong"
        elif strength_score >= 60:
            level = "Strong"
        elif strength_score >= 40:
            level = "Moderate"
        elif strength_score >= 20:
            level = "Weak"
        else:
            level = "Very Weak"
        
        return {
            "score": strength_score,
            "level": level,
            "feedback": feedback,
            "length": len(password)
        }
    
    def get_security_headers(self) -> Dict[str, str]:
        """Generate security headers recommendations"""
        return {
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin"
        }
    
    def generate_csp_policy(self, policy_type: str = "strict") -> str:
        """Generate Content Security Policy"""
        policies = {
            "strict": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'",
            "moderate": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:",
            "relaxed": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'"
        }
        return policies.get(policy_type, policies["strict"])

def create_response(status_code: int, body: Dict[str, Any], headers: Dict[str, str] = None) -> Dict[str, Any]:
    """Create standardized API response"""
    default_headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type,Authorization",
        "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
    }
    
    if headers:
        default_headers.update(headers)
    
    return {
        "statusCode": status_code,
        "headers": default_headers,
        "body": json.dumps(body, default=str)
    }

def lambda_handler(event, context):
    """Main Lambda handler function"""
    try:
        # Log the incoming request
        logger.info(f"Received event: {json.dumps(event, default=str)}")
        
        # Initialize security API
        security_api = SecurityAPI()
        
        # Extract HTTP method and path
        http_method = event.get('httpMethod', 'GET')
        path = event.get('path', '/')
        query_params = event.get('queryStringParameters') or {}
        
        # Handle CORS preflight requests
        if http_method == 'OPTIONS':
            return create_response(200, {"message": "CORS preflight successful"})
        
        # Route handling
        if path == '/' and http_method == 'GET':
            # API information endpoint
            response_body = {
                "service": security_api.service_name,
                "version": security_api.version,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "endpoints": {
                    "/": "API information",
                    "/token": "Generate secure token",
                    "/hash": "Hash password with salt",
                    "/password-strength": "Check password strength",
                    "/security-headers": "Get security headers",
                    "/csp": "Generate CSP policy"
                },
                "author": "Raymond Nwambuonwo",
                "purpose": "Security API for cybersecurity operations"
            }
            return create_response(200, response_body)
        
        elif path == '/token' and http_method == 'GET':
            # Generate secure token
            length = int(query_params.get('length', 32))
            if length > 128:  # Limit token length
                return create_response(400, {"error": "Token length cannot exceed 128 characters"})
            
            token = security_api.generate_secure_token(length)
            response_body = {
                "token": token,
                "length": len(token),
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "entropy_bits": len(token) * 6  # Base64 encoding entropy
            }
            return create_response(200, response_body)
        
        elif path == '/hash' and http_method == 'POST':
            # Hash password
            try:
                body = json.loads(event.get('body', '{}'))
                password = body.get('password')
                salt = body.get('salt')
                
                if not password:
                    return create_response(400, {"error": "Password is required"})
                
                hash_result = security_api.hash_password(password, salt)
                hash_result['hashed_at'] = datetime.utcnow().isoformat() + "Z"
                
                return create_response(200, hash_result)
                
            except json.JSONDecodeError:
                return create_response(400, {"error": "Invalid JSON in request body"})
        
        elif path == '/password-strength' and http_method == 'POST':
            # Check password strength
            try:
                body = json.loads(event.get('body', '{}'))
                password = body.get('password')
                
                if not password:
                    return create_response(400, {"error": "Password is required"})
                
                strength_result = security_api.check_password_strength(password)
                strength_result['analyzed_at'] = datetime.utcnow().isoformat() + "Z"
                
                return create_response(200, strength_result)
                
            except json.JSONDecodeError:
                return create_response(400, {"error": "Invalid JSON in request body"})
        
        elif path == '/security-headers' and http_method == 'GET':
            # Get security headers
            headers = security_api.get_security_headers()
            response_body = {
                "headers": headers,
                "description": "Recommended security headers for web applications",
                "generated_at": datetime.utcnow().isoformat() + "Z"
            }
            return create_response(200, response_body)
        
        elif path == '/csp' and http_method == 'GET':
            # Generate CSP policy
            policy_type = query_params.get('type', 'strict')
            csp_policy = security_api.generate_csp_policy(policy_type)
            
            response_body = {
                "csp_policy": csp_policy,
                "policy_type": policy_type,
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "available_types": ["strict", "moderate", "relaxed"]
            }
            return create_response(200, response_body)
        
        else:
            # 404 Not Found
            return create_response(404, {
                "error": "Endpoint not found",
                "path": path,
                "method": http_method,
                "available_endpoints": ["/", "/token", "/hash", "/password-strength", "/security-headers", "/csp"]
            })
    
    except Exception as e:
        # Log the error
        logger.error(f"Error processing request: {str(e)}")
        
        # Return generic error response
        return create_response(500, {
            "error": "Internal server error",
            "message": "An unexpected error occurred",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })