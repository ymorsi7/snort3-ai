#!/usr/bin/env python3
"""
OpenAI Model Comparison for SNORT AI Enhancement
Tests different OpenAI models to compare performance and capabilities
"""

import requests
import json
import time
import sys
from typing import Dict, List, Any

# OpenAI API configuration
API_KEY = "your_openai_api_key_here"
API_URL = "https://api.openai.com/v1/chat/completions"

# Available models to test
MODELS_TO_TEST = [
    {
        "name": "GPT-3.5 Turbo",
        "model": "gpt-3.5-turbo",
        "description": "Fast, cost-effective, good for most tasks"
    },
    {
        "name": "GPT-4",
        "model": "gpt-4",
        "description": "Most capable model, excellent reasoning"
    },
    {
        "name": "GPT-4 Turbo",
        "model": "gpt-4-turbo-preview",
        "description": "Latest GPT-4 with improved speed and capabilities"
    },
    {
        "name": "GPT-4o",
        "model": "gpt-4o",
        "description": "Latest multimodal model, fastest GPT-4"
    },
    {
        "name": "GPT-4o Mini",
        "model": "gpt-4o-mini",
        "description": "Smaller, faster, cheaper version of GPT-4o"
    }
]

def test_model(model_info: Dict[str, str], test_prompt: str) -> Dict[str, Any]:
    """Test a specific OpenAI model with the given prompt"""
    
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": model_info["model"],
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
            
            # Parse the response
            parsed_response = parse_gpt_response(content)
            
            return {
                "success": True,
                "model": model_info["name"],
                "response_time": end_time - start_time,
                "content": content,
                "parsed": parsed_response,
                "tokens_used": data.get("usage", {}).get("total_tokens", 0),
                "cost_estimate": estimate_cost(data.get("usage", {}), model_info["model"])
            }
        else:
            return {
                "success": False,
                "model": model_info["name"],
                "error": f"HTTP {response.status_code}: {response.text}",
                "response_time": end_time - start_time
            }
            
    except Exception as e:
        end_time = time.time()
        return {
            "success": False,
            "model": model_info["name"],
            "error": str(e),
            "response_time": end_time - start_time
        }

def parse_gpt_response(content: str) -> Dict[str, Any]:
    """Parse GPT response into structured format"""
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

def estimate_cost(usage: Dict[str, int], model: str) -> float:
    """Estimate cost based on token usage and model pricing"""
    # Approximate pricing per 1K tokens (as of 2024)
    pricing = {
        "gpt-3.5-turbo": {"input": 0.0015, "output": 0.002},
        "gpt-4": {"input": 0.03, "output": 0.06},
        "gpt-4-turbo-preview": {"input": 0.01, "output": 0.03},
        "gpt-4o": {"input": 0.005, "output": 0.015},
        "gpt-4o-mini": {"input": 0.00015, "output": 0.0006}
    }
    
    if model not in pricing:
        return 0.0
    
    input_tokens = usage.get("prompt_tokens", 0)
    output_tokens = usage.get("completion_tokens", 0)
    
    input_cost = (input_tokens / 1000) * pricing[model]["input"]
    output_cost = (output_tokens / 1000) * pricing[model]["output"]
    
    return input_cost + output_cost

def create_test_prompt() -> str:
    """Create a comprehensive test prompt for security analysis"""
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

def run_model_comparison():
    """Run comparison across all available models"""
    print("🔍 OpenAI Model Comparison for SNORT AI Enhancement")
    print("=" * 60)
    
    test_prompt = create_test_prompt()
    results = []
    
    for model_info in MODELS_TO_TEST:
        print(f"\n🧪 Testing {model_info['name']} ({model_info['model']})")
        print(f"   Description: {model_info['description']}")
        print("   " + "-" * 50)
        
        result = test_model(model_info, test_prompt)
        results.append(result)
        
        if result["success"]:
            print(f"   ✅ Success!")
            print(f"   ⏱️  Response Time: {result['response_time']:.2f}s")
            print(f"   🎯 Confidence: {result['parsed']['confidence']:.2f}")
            print(f"   💰 Estimated Cost: ${result['cost_estimate']:.4f}")
            print(f"   📊 Tokens Used: {result['tokens_used']}")
            print(f"   📝 Summary: {result['parsed']['summary'][:100]}...")
        else:
            print(f"   ❌ Failed: {result['error']}")
    
    # Generate comparison report
    generate_comparison_report(results)
    
    return results

def generate_comparison_report(results: List[Dict[str, Any]]):
    """Generate a detailed comparison report"""
    print("\n" + "=" * 60)
    print("📊 MODEL COMPARISON REPORT")
    print("=" * 60)
    
    successful_results = [r for r in results if r["success"]]
    
    if not successful_results:
        print("❌ No successful results to compare")
        return
    
    # Performance metrics
    print("\n🏆 PERFORMANCE METRICS:")
    print("-" * 40)
    print(f"{'Model':<20} {'Time(s)':<8} {'Confidence':<10} {'Cost($)':<8} {'Tokens':<8}")
    print("-" * 60)
    
    for result in successful_results:
        print(f"{result['model']:<20} {result['response_time']:<8.2f} {result['parsed']['confidence']:<10.2f} {result['cost_estimate']:<8.4f} {result['tokens_used']:<8}")
    
    # Find best performers
    fastest = min(successful_results, key=lambda x: x['response_time'])
    most_confident = max(successful_results, key=lambda x: x['parsed']['confidence'])
    cheapest = min(successful_results, key=lambda x: x['cost_estimate'])
    
    print(f"\n🏃 Fastest: {fastest['model']} ({fastest['response_time']:.2f}s)")
    print(f"🎯 Most Confident: {most_confident['model']} ({most_confident['parsed']['confidence']:.2f})")
    print(f"💰 Cheapest: {cheapest['model']} (${cheapest['cost_estimate']:.4f})")
    
    # Recommendations
    print(f"\n💡 RECOMMENDATIONS:")
    print("-" * 20)
    
    if most_confident['parsed']['confidence'] > 0.9:
        print(f"✅ {most_confident['model']} provides highest confidence analysis")
    
    if fastest['response_time'] < 2.0:
        print(f"⚡ {fastest['model']} offers fastest response for real-time analysis")
    
    if cheapest['cost_estimate'] < 0.01:
        print(f"💵 {cheapest['model']} is most cost-effective for high-volume processing")
    
    # Best overall recommendation
    print(f"\n🎯 BEST OVERALL CHOICE:")
    print("-" * 20)
    
    # Score models based on multiple factors
    scored_models = []
    for result in successful_results:
        score = 0
        score += (1.0 - result['response_time'] / 10.0) * 30  # Speed (30% weight)
        score += result['parsed']['confidence'] * 40  # Confidence (40% weight)
        score += (1.0 - result['cost_estimate'] / 0.1) * 30  # Cost efficiency (30% weight)
        
        scored_models.append((result['model'], score))
    
    best_model = max(scored_models, key=lambda x: x[1])
    print(f"🏆 {best_model[0]} (Score: {best_model[1]:.1f}/100)")
    
    # Update recommendation for SNORT integration
    print(f"\n🔧 SNORT INTEGRATION RECOMMENDATION:")
    print("-" * 35)
    print(f"Update gpt_assist.cc to use: {best_model[0]}")
    print(f"Model ID: {next(r['model'] for r in successful_results if r['model'] == best_model[0])}")
    print(f"Expected improvements:")
    print(f"  • Response time: {fastest['response_time']:.2f}s")
    print(f"  • Confidence: {most_confident['parsed']['confidence']:.2f}")
    print(f"  • Cost per analysis: ${cheapest['cost_estimate']:.4f}")

def main():
    """Main function"""
    print("Starting OpenAI model comparison...")
    
    try:
        results = run_model_comparison()
        
        # Save results to file
        with open("model_comparison_results.json", "w") as f:
            json.dump(results, f, indent=2)
        
        print(f"\n💾 Results saved to: model_comparison_results.json")
        print(f"🎉 Model comparison completed successfully!")
        
    except KeyboardInterrupt:
        print(f"\n⏹️  Comparison interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error during comparison: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
