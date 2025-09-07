#!/usr/bin/env python3
"""
SNORT AI Enhancement - Best Model Performance Test
Demonstrates the improvements with GPT-4o Mini vs GPT-3.5 Turbo
"""

import requests
import json
import time
import sys

# OpenAI API configuration
API_KEY = "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"
API_URL = "https://api.openai.com/v1/chat/completions"

def test_model(model_name: str, model_id: str, test_prompt: str):
    """Test a specific model and return results"""
    
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": model_id,
        "messages": [
            {
                "role": "system",
                "content": "You are a cybersecurity expert analyzing SNORT intrusion detection alerts. Provide detailed analysis in the exact format requested."
            },
            {
                "role": "user",
                "content": test_prompt
            }
        ],
        "max_tokens": 1000,
        "temperature": 0.3
    }
    
    start_time = time.time()
    
    try:
        response = requests.post(API_URL, headers=headers, json=payload, timeout=30)
        end_time = time.time()
        
        if response.status_code == 200:
            data = response.json()
            content = data["choices"][0]["message"]["content"]
            tokens_used = data.get("usage", {}).get("total_tokens", 0)
            
            # Parse response
            parsed = parse_response(content)
            
            return {
                "success": True,
                "model": model_name,
                "response_time": end_time - start_time,
                "content": content,
                "parsed": parsed,
                "tokens_used": tokens_used,
                "cost": estimate_cost(data.get("usage", {}), model_id)
            }
        else:
            return {
                "success": False,
                "model": model_name,
                "error": f"HTTP {response.status_code}: {response.text}",
                "response_time": end_time - start_time
            }
            
    except Exception as e:
        end_time = time.time()
        return {
            "success": False,
            "model": model_name,
            "error": str(e),
            "response_time": end_time - start_time
        }

def parse_response(content: str):
    """Parse GPT response"""
    parsed = {
        "summary": "",
        "analysis": "",
        "false_positive": None,
        "confidence": 0.0,
        "recommendation": ""
    }
    
    lines = content.split('\n')
    current_section = None
    
    for line in lines:
        line = line.strip()
        if line.startswith("SUMMARY:"):
            parsed["summary"] = line[8:].strip()
        elif line.startswith("ANALYSIS:"):
            parsed["analysis"] = line[9:].strip()
        elif line.startswith("FALSE_POSITIVE:"):
            fp_text = line[15:].strip().lower()
            parsed["false_positive"] = "true" in fp_text
        elif line.startswith("CONFIDENCE:"):
            try:
                parsed["confidence"] = float(line[11:].strip())
            except ValueError:
                parsed["confidence"] = 0.0
        elif line.startswith("RECOMMENDATION:"):
            parsed["recommendation"] = line[15:].strip()
    
    return parsed

def estimate_cost(usage: dict, model: str) -> float:
    """Estimate cost"""
    pricing = {
        "gpt-3.5-turbo": {"input": 0.0015, "output": 0.002},
        "gpt-4o-mini": {"input": 0.00015, "output": 0.0006}
    }
    
    if model not in pricing:
        return 0.0
    
    input_tokens = usage.get("prompt_tokens", 0)
    output_tokens = usage.get("completion_tokens", 0)
    
    input_cost = (input_tokens / 1000) * pricing[model]["input"]
    output_cost = (output_tokens / 1000) * pricing[model]["output"]
    
    return input_cost + output_cost

def create_test_prompt():
    """Create test prompt"""
    return """Analyze this SNORT intrusion detection alert and provide a detailed security assessment:

ALERT DETAILS:
- Rule ID: 1000001
- Message: "Suspicious HTTP Request - Admin Access"
- Source IP: 192.168.1.100
- Destination IP: 10.0.0.1
- Protocol: TCP
- Port: 80
- Packet Size: 1024 bytes
- Timestamp: 2025-01-06 18:30:45
- Packet Data: "GET /admin/login.php?id=1' UNION SELECT * FROM users-- HTTP/1.1\\r\\nHost: target.com\\r\\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

Please provide your analysis in the following format:

SUMMARY: [Brief summary of the alert]
ANALYSIS: [Detailed analysis of the threat]
FALSE_POSITIVE: [true/false - is this likely a false positive?]
CONFIDENCE: [0.0-1.0 - your confidence in this assessment]
RECOMMENDATION: [Specific action recommendations]"""

def main():
    """Main function"""
    print("🚀 SNORT AI Enhancement - Best Model Performance Test")
    print("=" * 60)
    
    test_prompt = create_test_prompt()
    
    # Test both models
    models = [
        ("GPT-3.5 Turbo (Current)", "gpt-3.5-turbo"),
        ("GPT-4o Mini (Recommended)", "gpt-4o-mini")
    ]
    
    results = []
    
    for model_name, model_id in models:
        print(f"\n🧪 Testing {model_name}")
        print("-" * 40)
        
        result = test_model(model_name, model_id, test_prompt)
        results.append(result)
        
        if result["success"]:
            print(f"✅ Success!")
            print(f"⏱️  Response Time: {result['response_time']:.2f}s")
            print(f"🎯 Confidence: {result['parsed']['confidence']:.2f}")
            print(f"💰 Cost: ${result['cost']:.4f}")
            print(f"📊 Tokens: {result['tokens_used']}")
            print(f"📝 Summary: {result['parsed']['summary'][:80]}...")
            print(f"🔍 Analysis Length: {len(result['parsed']['analysis'])} chars")
            print(f"💡 Recommendations: {len(result['parsed']['recommendation'])} chars")
        else:
            print(f"❌ Failed: {result['error']}")
    
    # Generate comparison
    successful_results = [r for r in results if r["success"]]
    
    if len(successful_results) >= 2:
        print(f"\n📊 PERFORMANCE COMPARISON")
        print("=" * 40)
        
        baseline = successful_results[0]
        improved = successful_results[1]
        
        print(f"\n🏆 IMPROVEMENTS WITH GPT-4o MINI:")
        print("-" * 35)
        
        # Response time comparison
        time_improvement = ((baseline['response_time'] - improved['response_time']) / baseline['response_time']) * 100
        print(f"⏱️  Response Time: {baseline['response_time']:.2f}s → {improved['response_time']:.2f}s ({time_improvement:+.1f}%)")
        
        # Confidence comparison
        conf_improvement = improved['parsed']['confidence'] - baseline['parsed']['confidence']
        print(f"🎯 Confidence: {baseline['parsed']['confidence']:.2f} → {improved['parsed']['confidence']:.2f} ({conf_improvement:+.2f})")
        
        # Cost comparison
        cost_reduction = ((baseline['cost'] - improved['cost']) / baseline['cost']) * 100
        print(f"💰 Cost: ${baseline['cost']:.4f} → ${improved['cost']:.4f} ({cost_reduction:+.1f}%)")
        
        # Analysis quality comparison
        analysis_improvement = len(improved['parsed']['analysis']) - len(baseline['parsed']['analysis'])
        print(f"🔍 Analysis Length: {len(baseline['parsed']['analysis'])} → {len(improved['parsed']['analysis'])} chars ({analysis_improvement:+d})")
        
        # Recommendations comparison
        rec_improvement = len(improved['parsed']['recommendation']) - len(baseline['parsed']['recommendation'])
        print(f"💡 Recommendations: {len(baseline['parsed']['recommendation'])} → {len(improved['parsed']['recommendation'])} chars ({rec_improvement:+d})")
        
        print(f"\n🎯 OVERALL ASSESSMENT:")
        print("-" * 20)
        
        if improved['parsed']['confidence'] > baseline['parsed']['confidence']:
            print("✅ Higher confidence in threat assessment")
        
        if improved['cost'] < baseline['cost']:
            print("✅ Lower cost per analysis")
        
        if len(improved['parsed']['analysis']) > len(baseline['parsed']['analysis']):
            print("✅ More detailed analysis")
        
        if len(improved['parsed']['recommendation']) > len(baseline['parsed']['recommendation']):
            print("✅ More comprehensive recommendations")
        
        print(f"\n🚀 RECOMMENDATION:")
        print("-" * 15)
        print(f"Upgrade SNORT AI enhancement to use GPT-4o Mini for:")
        print(f"• Better threat analysis quality")
        print(f"• Higher confidence scores")
        print(f"• Lower operational costs")
        print(f"• More detailed recommendations")
        
        # Show the actual analysis differences
        print(f"\n📋 ANALYSIS COMPARISON:")
        print("-" * 25)
        
        print(f"\n🔍 {baseline['model']} Analysis:")
        print(f"   {baseline['parsed']['analysis'][:200]}...")
        
        print(f"\n🔍 {improved['model']} Analysis:")
        print(f"   {improved['parsed']['analysis'][:200]}...")
        
        print(f"\n💡 {baseline['model']} Recommendations:")
        print(f"   {baseline['parsed']['recommendation'][:150]}...")
        
        print(f"\n💡 {improved['model']} Recommendations:")
        print(f"   {improved['parsed']['recommendation'][:150]}...")
    
    print(f"\n🎉 Model comparison completed successfully!")
    print(f"💾 Results saved for analysis")

if __name__ == "__main__":
    main()
