#!/usr/bin/env python3
"""
Test script for OpenAI GPT integration with SNORT AI enhancements
This script tests the GPT API integration independently
"""

import requests
import json
import sys

# OpenAI API configuration
API_KEY = "your_openai_api_key_here"
API_URL = "https://api.openai.com/v1/chat/completions"
MODEL = "gpt-3.5-turbo"

def test_openai_integration():
    """Test OpenAI API integration with a sample SNORT alert"""
    
    # Sample alert data
    alert_data = {
        "rule_id": "1000001",
        "rule_description": "Suspicious HTTP Request - Admin Access",
        "source_ip": "192.168.1.100",
        "dest_ip": "10.0.0.1",
        "source_port": 12345,
        "dest_port": 80,
        "protocol": "TCP",
        "packet_size": 1024,
        "classification": "suspicious",
        "priority": 2,
        "packet_data": "GET /admin/login.php HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0"
    }
    
    # Create prompt
    prompt = f"""Analyze this network security alert and provide a structured response:

ALERT DETAILS:
- Rule ID: {alert_data['rule_id']}
- Description: {alert_data['rule_description']}
- Source IP: {alert_data['source_ip']}:{alert_data['source_port']}
- Destination IP: {alert_data['dest_ip']}:{alert_data['dest_port']}
- Protocol: {alert_data['protocol']}
- Packet Size: {alert_data['packet_size']} bytes
- Classification: {alert_data['classification']}
- Priority: {alert_data['priority']}
- Packet Data (first 200 chars): {alert_data['packet_data'][:200]}

Please provide your analysis in the following format:
SUMMARY: [Brief summary of the alert]
ANALYSIS: [Detailed analysis of the threat level and context]
FALSE_POSITIVE: [true/false - is this likely a false positive?]
CONFIDENCE: [0.0-1.0 - confidence in your assessment]
RECOMMENDATION: [Recommended action]"""

    # Prepare API request
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}"
    }
    
    payload = {
        "model": MODEL,
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "max_tokens": 500,
        "temperature": 0.3
    }
    
    try:
        print("Testing OpenAI API integration...")
        print(f"Sending request to: {API_URL}")
        print(f"Using model: {MODEL}")
        print()
        
        # Make API request
        response = requests.post(API_URL, headers=headers, json=payload, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            
            if "choices" in result and len(result["choices"]) > 0:
                content = result["choices"][0]["message"]["content"]
                print("✅ OpenAI API integration successful!")
                print()
                print("GPT Response:")
                print("=" * 50)
                print(content)
                print("=" * 50)
                
                # Parse the response
                parse_gpt_response(content)
                
                return True
            else:
                print("❌ No choices in API response")
                print(f"Response: {result}")
                return False
        else:
            print(f"❌ API request failed with status code: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except requests.exceptions.Timeout:
        print("❌ Request timed out")
        return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def parse_gpt_response(content):
    """Parse GPT response and extract structured data"""
    print()
    print("Parsed Analysis:")
    print("-" * 30)
    
    lines = content.split('\n')
    for line in lines:
        line = line.strip()
        if line.startswith("SUMMARY:"):
            print(f"Summary: {line[8:].strip()}")
        elif line.startswith("ANALYSIS:"):
            print(f"Analysis: {line[9:].strip()}")
        elif line.startswith("FALSE_POSITIVE:"):
            fp_value = line[15:].strip().lower()
            is_fp = "true" in fp_value
            print(f"False Positive: {is_fp}")
        elif line.startswith("CONFIDENCE:"):
            try:
                confidence = float(line[11:].strip())
                print(f"Confidence: {confidence:.2f}")
            except ValueError:
                print(f"Confidence: {line[11:].strip()}")
        elif line.startswith("RECOMMENDATION:"):
            print(f"Recommendation: {line[14:].strip()}")

def test_api_key_validity():
    """Test if the API key is valid"""
    headers = {
        "Authorization": f"Bearer {API_KEY}"
    }
    
    try:
        # Simple test request
        response = requests.get("https://api.openai.com/v1/models", headers=headers, timeout=10)
        
        if response.status_code == 200:
            print("✅ API key is valid")
            return True
        elif response.status_code == 401:
            print("❌ API key is invalid or expired")
            return False
        else:
            print(f"❌ API key test failed with status code: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ API key test failed: {e}")
        return False

def main():
    """Main test function"""
    print("SNORT AI Enhancement - OpenAI Integration Test")
    print("=" * 50)
    
    # Test API key validity
    print("1. Testing API key validity...")
    if not test_api_key_validity():
        print("Cannot proceed without valid API key")
        sys.exit(1)
    
    print()
    
    # Test OpenAI integration
    print("2. Testing OpenAI integration...")
    if test_openai_integration():
        print()
        print("🎉 All tests passed! OpenAI integration is working correctly.")
        print()
        print("The GPT module is ready to be used with SNORT AI enhancements.")
        print("You can now run SNORT with --enable-gpt-filtering to use real GPT analysis.")
    else:
        print()
        print("❌ Tests failed. Please check the error messages above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
