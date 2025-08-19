import requests
import json
import sys

class APITester:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'SecurityAPI-Tester/1.0'
        })
    
    def test_endpoint(self, method, path, data=None, params=None):
        """Test a single API endpoint"""
        url = f"{self.base_url}{path}"
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, timeout=10)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data, timeout=10)
            else:
                print(f"❌ Unsupported method: {method}")
                return None
            
            print(f"\n🧪 Testing {method} {path}")
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text[:200]}...")
            
            if response.status_code == 200:
                print(f"   ✅ Success")
            else:
                print(f"   ⚠️  Non-200 status")
            
            return response.json() if response.headers.get('content-type', '').startswith('application/json') else None
            
        except Exception as e:
            print(f"   ❌ Error: {e}")
            return None
    
    def run_all_tests(self):
        """Run comprehensive API tests"""
        print("🧪 Security API Test Suite")
        print("="*50)
        
        # Test 1: API Info
        self.test_endpoint('GET', '/')
        
        # Test 2: Token generation
        self.test_endpoint('GET', '/token')
        self.test_endpoint('GET', '/token', params={'length': 16})
        
        # Test 3: Password hashing
        self.test_endpoint('POST', '/hash', data={'password': 'testpassword123'})
        
        # Test 4: Password strength
        self.test_endpoint('POST', '/password-strength', data={'password': 'weak'})
        self.test_endpoint('POST', '/password-strength', data={'password': 'StrongP@ssw0rd123!'})
        
        # Test 5: Security headers
        self.test_endpoint('GET', '/security-headers')
        
        # Test 6: CSP policies
        self.test_endpoint('GET', '/csp')
        self.test_endpoint('GET', '/csp', params={'type': 'moderate'})
        
        # Test 7: Non-existent endpoint
        self.test_endpoint('GET', '/nonexistent')
        
        print("\n✅ Test suite completed!")

def main():
    if len(sys.argv) != 2:
        print("Usage: python test-api.py <API_URL>")
        print("Example: python test-api.py https://abc123.execute-api.us-east-1.amazonaws.com/prod")
        sys.exit(1)
    
    api_url = sys.argv[1]
    tester = APITester(api_url)
    tester.run_all_tests()

if __name__ == "__main__":
    main()