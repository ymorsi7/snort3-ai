#!/usr/bin/env python3
"""
Comprehensive AI Model Comparison for SNORT Enhancement
Tests OpenAI, Claude, and Gemini models with cost analysis
"""

import requests
import json
import time
import sys
import re
from typing import Dict, List, Any

# API Keys
OPENAI_API_KEY = "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"
CLAUDE_API_KEY = "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"
GEMINI_API_KEY = "AIzaSyBe6r7-qu-8hH4XOe0GkEe4B3ll39c_t_4"

# API URLs
OPENAI_URL = "https://api.openai.com/v1/chat/completions"
CLAUDE_URL = "https://api.anthropic.com/v1/messages"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models"

# Models to test
MODELS_TO_TEST = [
    # OpenAI Models
    {
        "name": "GPT-3.5 Turbo",
        "provider": "OpenAI",
        "model": "gpt-3.5-turbo",
        "api_key": OPENAI_API_KEY,
        "url": OPENAI_URL,
        "description": "Fast, cost-effective baseline"
    },
    {
        "name": "GPT-4o",
        "provider": "OpenAI", 
        "model": "gpt-4o",
        "api_key": OPENAI_API_KEY,
        "url": OPENAI_URL,
        "description": "Latest multimodal model"
    },
    {
        "name": "GPT-4o Mini",
        "provider": "OpenAI",
        "model": "gpt-4o-mini", 
        "api_key": OPENAI_API_KEY,
        "url": OPENAI_URL,
        "description": "Smaller, faster GPT-4o"
    },
    
    # Claude Models
    {
        "name": "Claude 3 Haiku",
        "provider": "Anthropic",
        "model": "claude-3-haiku-20240307",
        "api_key": CLAUDE_API_KEY,
        "url": CLAUDE_URL,
        "description": "Fast, cost-effective Claude"
    },
    {
        "name": "Claude 3 Sonnet",
        "provider": "Anthropic",
        "model": "claude-3-sonnet-20240229",
        "api_key": CLAUDE_API_KEY,
        "url": CLAUDE_URL,
        "description": "Balanced performance Claude"
    },
    {
        "name": "Claude 3 Opus",
        "provider": "Anthropic",
        "model": "claude-3-opus-20240229",
        "api_key": CLAUDE_API_KEY,
        "url": CLAUDE_URL,
        "description": "Most capable Claude model"
    },
    
    # Gemini Models
    {
        "name": "Gemini Pro",
        "provider": "Google",
        "model": "gemini-pro",
        "api_key": GEMINI_API_KEY,
        "url": f"{GEMINI_URL}/gemini-pro:generateContent",
        "description": "Google's flagship model"
    },
    {
        "name": "Gemini Pro Vision",
        "provider": "Google",
        "model": "gemini-pro-vision",
        "api_key": GEMINI_API_KEY,
        "url": f"{GEMINI_URL}/gemini-pro-vision:generateContent",
        "description": "Multimodal Gemini model"
    }
]

def test_openai_model(model_info: Dict, prompt: str) -> Dict[str, Any]:
    """Test OpenAI model"""
    headers = {
        "Authorization": f"Bearer {model_info['api_key']}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": model_info["model"],
        "messages": [
            {"role": "system", "content": "You are a cybersecurity expert analyzing SNORT alerts."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 1000,
        "temperature": 0.3
    }
    
    start_time = time.time()
    
    try:
        response = requests.post(model_info["url"], headers=headers, json=payload, timeout=30)
        end_time = time.time()
        
        if response.status_code == 200:
            data = response.json()
            content = data["choices"][0]["message"]["content"]
            usage = data.get("usage", {})
            
            return {
                "success": True,
                "model": model_info["name"],
                "provider": model_info["provider"],
                "response_time": end_time - start_time,
                "content": content,
                "tokens_used": usage.get("total_tokens", 0),
                "cost": estimate_openai_cost(usage, model_info["model"])
            }
        else:
            return {
                "success": False,
                "model": model_info["name"],
                "provider": model_info["provider"],
                "error": f"HTTP {response.status_code}: {response.text}",
                "response_time": end_time - start_time
            }
    except Exception as e:
        end_time = time.time()
        return {
            "success": False,
            "model": model_info["name"],
            "provider": model_info["provider"],
            "error": str(e),
            "response_time": end_time - start_time
        }

def test_claude_model(model_info: Dict, prompt: str) -> Dict[str, Any]:
    """Test Claude model"""
    headers = {
        "x-api-key": model_info["api_key"],
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01"
    }
    
    payload = {
        "model": model_info["model"],
        "max_tokens": 1000,
        "temperature": 0.3,
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }
    
    start_time = time.time()
    
    try:
        response = requests.post(model_info["url"], headers=headers, json=payload, timeout=30)
        end_time = time.time()
        
        if response.status_code == 200:
            data = response.json()
            content = data["content"][0]["text"]
            usage = data.get("usage", {})
            
            return {
                "success": True,
                "model": model_info["name"],
                "provider": model_info["provider"],
                "response_time": end_time - start_time,
                "content": content,
                "tokens_used": usage.get("output_tokens", 0) + usage.get("input_tokens", 0),
                "cost": estimate_claude_cost(usage, model_info["model"])
            }
        else:
            return {
                "success": False,
                "model": model_info["name"],
                "provider": model_info["provider"],
                "error": f"HTTP {response.status_code}: {response.text}",
                "response_time": end_time - start_time
            }
    except Exception as e:
        end_time = time.time()
        return {
            "success": False,
            "model": model_info["name"],
            "provider": model_info["provider"],
            "error": str(e),
            "response_time": end_time - start_time
        }

def test_gemini_model(model_info: Dict, prompt: str) -> Dict[str, Any]:
    """Test Gemini model"""
    headers = {
        "Content-Type": "application/json"
    }
    
    payload = {
        "contents": [{
            "parts": [{"text": prompt}]
        }],
        "generationConfig": {
            "temperature": 0.3,
            "maxOutputTokens": 1000
        }
    }
    
    url = f"{model_info['url']}?key={model_info['api_key']}"
    start_time = time.time()
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        end_time = time.time()
        
        if response.status_code == 200:
            data = response.json()
            content = data["candidates"][0]["content"]["parts"][0]["text"]
            usage = data.get("usageMetadata", {})
            
            return {
                "success": True,
                "model": model_info["name"],
                "provider": model_info["provider"],
                "response_time": end_time - start_time,
                "content": content,
                "tokens_used": usage.get("totalTokenCount", 0),
                "cost": estimate_gemini_cost(usage, model_info["model"])
            }
        else:
            return {
                "success": False,
                "model": model_info["name"],
                "provider": model_info["provider"],
                "error": f"HTTP {response.status_code}: {response.text}",
                "response_time": end_time - start_time
            }
    except Exception as e:
        end_time = time.time()
        return {
            "success": False,
            "model": model_info["name"],
            "provider": model_info["provider"],
            "error": str(e),
            "response_time": end_time - start_time
        }

def estimate_openai_cost(usage: Dict, model: str) -> float:
    """Estimate OpenAI cost"""
    pricing = {
        "gpt-3.5-turbo": {"input": 0.0015, "output": 0.002},
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

def estimate_claude_cost(usage: Dict, model: str) -> float:
    """Estimate Claude cost"""
    pricing = {
        "claude-3-haiku-20240307": {"input": 0.00025, "output": 0.00125},
        "claude-3-sonnet-20240229": {"input": 0.003, "output": 0.015},
        "claude-3-opus-20240229": {"input": 0.015, "output": 0.075}
    }
    
    if model not in pricing:
        return 0.0
    
    input_tokens = usage.get("input_tokens", 0)
    output_tokens = usage.get("output_tokens", 0)
    
    input_cost = (input_tokens / 1000) * pricing[model]["input"]
    output_cost = (output_tokens / 1000) * pricing[model]["output"]
    
    return input_cost + output_cost

def estimate_gemini_cost(usage: Dict, model: str) -> float:
    """Estimate Gemini cost"""
    pricing = {
        "gemini-pro": {"input": 0.0005, "output": 0.0015},
        "gemini-pro-vision": {"input": 0.0005, "output": 0.0015}
    }
    
    if model not in pricing:
        return 0.0
    
    total_tokens = usage.get("totalTokenCount", 0)
    # Assume 70% input, 30% output for Gemini
    input_tokens = int(total_tokens * 0.7)
    output_tokens = int(total_tokens * 0.3)
    
    input_cost = (input_tokens / 1000) * pricing[model]["input"]
    output_cost = (output_tokens / 1000) * pricing[model]["output"]
    
    return input_cost + output_cost

def parse_response(content: str) -> Dict[str, Any]:
    """Parse AI response"""
    parsed = {
        "summary": "",
        "analysis": "",
        "false_positive": None,
        "confidence": 0.0,
        "recommendation": "",
        "threat_level": "",
        "attack_type": "",
        "quality_score": 0.0
    }
    
    # Extract summary
    summary_match = re.search(r"summary:\s*(.+?)(?=\n\n|\nanalysis:|$)", content, re.IGNORECASE | re.DOTALL)
    if summary_match:
        parsed["summary"] = summary_match.group(1).strip()
    
    # Extract analysis
    analysis_match = re.search(r"analysis:\s*(.+?)(?=\n\nfalse_positive:|$)", content, re.IGNORECASE | re.DOTALL)
    if analysis_match:
        parsed["analysis"] = analysis_match.group(1).strip()
    
    # Extract false positive
    fp_match = re.search(r"false_positive:\s*(.+?)(?=\n\nconfidence:|$)", content, re.IGNORECASE | re.DOTALL)
    if fp_match:
        fp_text = fp_match.group(1).strip().lower()
        parsed["false_positive"] = "true" in fp_text and "false" not in fp_text
    
    # Extract confidence
    conf_match = re.search(r"confidence:\s*([0-9.]+)", content, re.IGNORECASE)
    if conf_match:
        try:
            parsed["confidence"] = float(conf_match.group(1))
        except ValueError:
            parsed["confidence"] = 0.0
    
    # Extract recommendation
    rec_match = re.search(r"recommendation:\s*(.+?)$", content, re.IGNORECASE | re.DOTALL)
    if rec_match:
        parsed["recommendation"] = rec_match.group(1).strip()
    
    # Extract threat level
    threat_match = re.search(r"threat_level:\s*(.+?)(?=\n|$)", content, re.IGNORECASE)
    if threat_match:
        parsed["threat_level"] = threat_match.group(1).strip()
    
    # Extract attack type
    attack_match = re.search(r"attack_type:\s*(.+?)(?=\n|$)", content, re.IGNORECASE)
    if attack_match:
        parsed["attack_type"] = attack_match.group(1).strip()
    
    # Calculate quality score
    quality_score = 0.0
    if len(parsed["analysis"]) > 200:
        quality_score += 0.3
    if len(parsed["recommendation"]) > 100:
        quality_score += 0.2
    if parsed["confidence"] > 0:
        quality_score += 0.2
    if parsed["threat_level"]:
        quality_score += 0.1
    if parsed["attack_type"]:
        quality_score += 0.1
    if parsed["false_positive"] is not None:
        quality_score += 0.1
    
    parsed["quality_score"] = min(quality_score, 1.0)
    
    return parsed

def create_comprehensive_test_prompt() -> str:
    """Create comprehensive test prompt"""
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
THREAT_LEVEL: [Low/Medium/High/Critical]
ATTACK_TYPE: [Specific attack type identified]
RECOMMENDATION: [Specific action recommendations]"""

def run_comprehensive_comparison():
    """Run comprehensive comparison across all models"""
    print("🚀 Comprehensive AI Model Comparison for SNORT Enhancement")
    print("=" * 70)
    
    test_prompt = create_comprehensive_test_prompt()
    results = []
    
    for model_info in MODELS_TO_TEST:
        print(f"\n🧪 Testing {model_info['name']} ({model_info['provider']})")
        print(f"   Description: {model_info['description']}")
        print("   " + "-" * 60)
        
        # Route to appropriate test function
        if model_info["provider"] == "OpenAI":
            result = test_openai_model(model_info, test_prompt)
        elif model_info["provider"] == "Anthropic":
            result = test_claude_model(model_info, test_prompt)
        elif model_info["provider"] == "Google":
            result = test_gemini_model(model_info, test_prompt)
        else:
            result = {
                "success": False,
                "model": model_info["name"],
                "provider": model_info["provider"],
                "error": "Unknown provider"
            }
        
        results.append(result)
        
        if result["success"]:
            parsed = parse_response(result["content"])
            result["parsed"] = parsed
            
            print(f"   ✅ Success!")
            print(f"   ⏱️  Response Time: {result['response_time']:.2f}s")
            print(f"   🎯 Confidence: {parsed['confidence']:.2f}")
            print(f"   📊 Quality Score: {parsed['quality_score']:.2f}")
            print(f"   💰 Cost: ${result['cost']:.4f}")
            print(f"   📊 Tokens: {result['tokens_used']}")
            print(f"   📝 Summary: {parsed['summary'][:60]}...")
            print(f"   🔍 Analysis Length: {len(parsed['analysis'])} chars")
            print(f"   💡 Recommendations: {len(parsed['recommendation'])} chars")
        else:
            print(f"   ❌ Failed: {result['error']}")
    
    # Generate comprehensive report
    generate_comprehensive_report(results)
    
    return results

def generate_comprehensive_report(results: List[Dict[str, Any]]):
    """Generate comprehensive comparison report"""
    print("\n" + "=" * 70)
    print("📊 COMPREHENSIVE MODEL COMPARISON REPORT")
    print("=" * 70)
    
    successful_results = [r for r in results if r["success"]]
    
    if not successful_results:
        print("❌ No successful results to compare")
        return
    
    # Performance metrics
    print("\n🏆 PERFORMANCE METRICS:")
    print("-" * 60)
    print(f"{'Model':<20} {'Provider':<12} {'Time(s)':<8} {'Confidence':<10} {'Quality':<8} {'Cost($)':<8}")
    print("-" * 70)
    
    for result in successful_results:
        parsed = result["parsed"]
        print(f"{result['model']:<20} {result['provider']:<12} {result['response_time']:<8.2f} {parsed['confidence']:<10.2f} {parsed['quality_score']:<8.2f} {result['cost']:<8.4f}")
    
    # Find best performers
    fastest = min(successful_results, key=lambda x: x['response_time'])
    most_confident = max(successful_results, key=lambda x: x['parsed']['confidence'])
    highest_quality = max(successful_results, key=lambda x: x['parsed']['quality_score'])
    cheapest = min(successful_results, key=lambda x: x['cost'])
    
    print(f"\n🏃 Fastest: {fastest['model']} ({fastest['response_time']:.2f}s)")
    print(f"🎯 Most Confident: {most_confident['model']} ({most_confident['parsed']['confidence']:.2f})")
    print(f"⭐ Highest Quality: {highest_quality['model']} ({highest_quality['parsed']['quality_score']:.2f})")
    print(f"💰 Cheapest: {cheapest['model']} (${cheapest['cost']:.4f})")
    
    # Provider comparison
    print(f"\n🏢 PROVIDER COMPARISON:")
    print("-" * 30)
    
    providers = {}
    for result in successful_results:
        provider = result["provider"]
        if provider not in providers:
            providers[provider] = []
        providers[provider].append(result)
    
    for provider, provider_results in providers.items():
        avg_confidence = sum(r["parsed"]["confidence"] for r in provider_results) / len(provider_results)
        avg_quality = sum(r["parsed"]["quality_score"] for r in provider_results) / len(provider_results)
        avg_cost = sum(r["cost"] for r in provider_results) / len(provider_results)
        avg_time = sum(r["response_time"] for r in provider_results) / len(provider_results)
        
        print(f"\n{provider}:")
        print(f"  Average Confidence: {avg_confidence:.2f}")
        print(f"  Average Quality: {avg_quality:.2f}")
        print(f"  Average Cost: ${avg_cost:.4f}")
        print(f"  Average Time: {avg_time:.2f}s")
    
    # Best overall recommendation
    print(f"\n🎯 BEST OVERALL CHOICE:")
    print("-" * 20)
    
    # Score models based on multiple factors
    scored_models = []
    for result in successful_results:
        score = 0
        score += (1.0 - result['response_time'] / 10.0) * 20  # Speed (20% weight)
        score += result['parsed']['confidence'] * 30  # Confidence (30% weight)
        score += result['parsed']['quality_score'] * 30  # Quality (30% weight)
        score += (1.0 - result['cost'] / 0.1) * 20  # Cost efficiency (20% weight)
        
        scored_models.append((result['model'], result['provider'], score))
    
    best_model = max(scored_models, key=lambda x: x[2])
    print(f"🏆 {best_model[0]} ({best_model[1]}) - Score: {best_model[2]:.1f}/100")
    
    # SNORT integration recommendation
    print(f"\n🔧 SNORT INTEGRATION RECOMMENDATION:")
    print("-" * 40)
    print(f"Best Model: {best_model[0]} ({best_model[1]})")
    print(f"Expected improvements over baseline SNORT:")
    print(f"  • Response time: {fastest['response_time']:.2f}s")
    print(f"  • Confidence: {most_confident['parsed']['confidence']:.2f}")
    print(f"  • Quality score: {highest_quality['parsed']['quality_score']:.2f}")
    print(f"  • Cost per analysis: ${cheapest['cost']:.4f}")
    
    # Cost analysis for high-volume deployment
    print(f"\n💰 COST ANALYSIS FOR HIGH-VOLUME DEPLOYMENT:")
    print("-" * 50)
    
    daily_alerts = 10000  # Example: 10K alerts per day
    monthly_alerts = daily_alerts * 30
    
    for result in successful_results:
        daily_cost = result['cost'] * daily_alerts
        monthly_cost = result['cost'] * monthly_alerts
        
        print(f"{result['model']}: ${daily_cost:.2f}/day, ${monthly_cost:.2f}/month")
    
    # Show detailed analysis comparison
    print(f"\n📋 DETAILED ANALYSIS COMPARISON:")
    print("-" * 40)
    
    for result in successful_results[:3]:  # Show top 3
        parsed = result["parsed"]
        print(f"\n🔍 {result['model']} ({result['provider']}):")
        print(f"   Summary: {parsed['summary'][:100]}...")
        print(f"   Threat Level: {parsed['threat_level']}")
        print(f"   Attack Type: {parsed['attack_type']}")
        print(f"   Analysis Length: {len(parsed['analysis'])} chars")
        print(f"   Recommendations: {len(parsed['recommendation'])} chars")

def main():
    """Main function"""
    print("Starting comprehensive AI model comparison...")
    
    try:
        results = run_comprehensive_comparison()
        
        # Save results to file
        with open("comprehensive_model_comparison_results.json", "w") as f:
            json.dump(results, f, indent=2)
        
        print(f"\n💾 Results saved to: comprehensive_model_comparison_results.json")
        print(f"🎉 Comprehensive model comparison completed successfully!")
        
    except KeyboardInterrupt:
        print(f"\n⏹️  Comparison interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error during comparison: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
