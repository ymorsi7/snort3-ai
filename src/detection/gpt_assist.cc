//--------------------------------------------------------------------------
// Copyright (C) 2025 Custom SNORT AI Enhancement
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

#include "gpt_assist.h"

#include <mutex>
#include <algorithm>
#include <sstream>
#include <random>
#include <cmath>
#include <curl/curl.h>
#include <json/json.h>

#include "log/messages.h"

using namespace snort;

// OpenAI API configuration
static const std::string OPENAI_API_KEY = "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";
static const std::string OPENAI_API_URL = "https://api.openai.com/v1/chat/completions";
static const std::string OPENAI_MODEL = "gpt-4o-mini";

// Callback function for libcurl to write response data
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* response) {
    size_t totalSize = size * nmemb;
    response->append((char*)contents, totalSize);
    return totalSize;
}

// Make HTTP request to OpenAI API
std::string makeOpenAIRequest(const std::string& prompt) {
    CURL* curl;
    CURLcode res;
    std::string response;
    
    curl = curl_easy_init();
    if (!curl) {
        LogMessage("Failed to initialize CURL\n");
        return "";
    }
    
    // Prepare JSON payload
    Json::Value payload;
    payload["model"] = OPENAI_MODEL;
    payload["max_tokens"] = 500;
    payload["temperature"] = 0.3;
    
    Json::Value messages(Json::arrayValue);
    Json::Value message;
    message["role"] = "user";
    message["content"] = prompt;
    messages.append(message);
    payload["messages"] = messages;
    
    Json::StreamWriterBuilder builder;
    std::string jsonPayload = Json::writeString(builder, payload);
    
    // Set up headers
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    std::string authHeader = "Authorization: Bearer " + OPENAI_API_KEY;
    headers = curl_slist_append(headers, authHeader.c_str());
    
    // Configure CURL
    curl_easy_setopt(curl, CURLOPT_URL, OPENAI_API_URL.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonPayload.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    
    // Perform the request
    res = curl_easy_perform(curl);
    
    // Clean up
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        LogMessage("CURL request failed: %s\n", curl_easy_strerror(res));
        return "";
    }
    
    return response;
}

// Parse OpenAI API response
GPTResponse parseOpenAIResponse(const std::string& jsonResponse) {
    GPTResponse response;
    
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errors;
    
    std::istringstream jsonStream(jsonResponse);
    if (!Json::parseFromStream(builder, jsonStream, &root, &errors)) {
        LogMessage("Failed to parse OpenAI response: %s\n", errors.c_str());
        return response;
    }
    
    try {
        if (root.isMember("choices") && root["choices"].isArray() && root["choices"].size() > 0) {
            std::string content = root["choices"][0]["message"]["content"].asString();
            
            // Parse the response content
            // Expected format: "SUMMARY: ... ANALYSIS: ... FALSE_POSITIVE: true/false CONFIDENCE: 0.85"
            std::istringstream contentStream(content);
            std::string line;
            
            while (std::getline(contentStream, line)) {
                if (line.find("SUMMARY:") == 0) {
                    response.summary = line.substr(8); // Remove "SUMMARY: " prefix
                } else if (line.find("ANALYSIS:") == 0) {
                    response.analysis = line.substr(9); // Remove "ANALYSIS: " prefix
                } else if (line.find("FALSE_POSITIVE:") == 0) {
                    std::string fpStr = line.substr(15); // Remove "FALSE_POSITIVE: " prefix
                    response.is_likely_false_positive = (fpStr.find("true") != std::string::npos);
                } else if (line.find("CONFIDENCE:") == 0) {
                    std::string confStr = line.substr(11); // Remove "CONFIDENCE: " prefix
                    response.confidence_score = std::stod(confStr);
                } else if (line.find("RECOMMENDATION:") == 0) {
                    response.recommendation = line.substr(14); // Remove "RECOMMENDATION: " prefix
                }
            }
        }
    } catch (const std::exception& e) {
        LogMessage("Error parsing OpenAI response: %s\n", e.what());
    }
    
    return response;
}

GPTAssist& GPTAssist::getInstance()
{
    static GPTAssist instance;
    return instance;
}

GPTAssist::~GPTAssist()
{
    cleanup();
}

void GPTAssist::init()
{
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    // Initialize CURL
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    // Initialize stats
    stats_.total_analyses = 0;
    stats_.false_positive_detections = 0;
    stats_.true_positive_detections = 0;
    stats_.average_confidence = 0.0;
    stats_.last_analysis = std::chrono::system_clock::now();
    
    available_ = true;
    
    LogMessage("GPT Assist module initialized with OpenAI API integration\n");
}

GPTResponse GPTAssist::analyzeAlert(const AlertLog& alert_log)
{
    if (!available_)
    {
        LogMessage("GPT Assist not available\n");
        return GPTResponse{};
    }
    
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    // Create prompt for OpenAI API
    std::ostringstream prompt;
    prompt << "Analyze this network security alert and provide a structured response:\n\n";
    prompt << "ALERT DETAILS:\n";
    prompt << "- Rule ID: " << alert_log.rule_id << "\n";
    prompt << "- Description: " << alert_log.rule_description << "\n";
    prompt << "- Source IP: " << alert_log.source_ip << ":" << alert_log.source_port << "\n";
    prompt << "- Destination IP: " << alert_log.dest_ip << ":" << alert_log.dest_port << "\n";
    prompt << "- Protocol: " << alert_log.protocol << "\n";
    prompt << "- Packet Size: " << alert_log.packet_size << " bytes\n";
    prompt << "- Classification: " << alert_log.classification << "\n";
    prompt << "- Priority: " << alert_log.priority << "\n";
    prompt << "- Timestamp: " << std::chrono::duration_cast<std::chrono::seconds>(alert_log.timestamp.time_since_epoch()).count() << "\n";
    
    if (!alert_log.packet_data.empty())
    {
        prompt << "- Packet Data (first 200 chars): " << alert_log.packet_data.substr(0, 200) << "\n";
    }
    
    prompt << "\nPlease provide your analysis in the following format:\n";
    prompt << "SUMMARY: [Brief summary of the alert]\n";
    prompt << "ANALYSIS: [Detailed analysis of the threat level and context]\n";
    prompt << "FALSE_POSITIVE: [true/false - is this likely a false positive?]\n";
    prompt << "CONFIDENCE: [0.0-1.0 - confidence in your assessment]\n";
    prompt << "RECOMMENDATION: [Recommended action]\n";
    
    // Make API request
    std::string apiResponse = makeOpenAIRequest(prompt.str());
    
    GPTResponse response;
    if (!apiResponse.empty())
    {
        response = parseOpenAIResponse(apiResponse);
    }
    else
    {
        LogMessage("OpenAI API request failed, falling back to mock analysis\n");
        response = mockAnalyzeAlert(alert_log);
    }
    
    // Update statistics
    stats_.total_analyses++;
    stats_.last_analysis = std::chrono::system_clock::now();
    
    if (response.is_likely_false_positive)
        stats_.false_positive_detections++;
    else
        stats_.true_positive_detections++;
    
    // Update average confidence
    stats_.average_confidence = (stats_.average_confidence * (stats_.total_analyses - 1) + 
                                 response.confidence_score) / stats_.total_analyses;
    
    LogMessage("GPT Analysis completed for rule %s: %s (confidence: %.2f)\n",
               alert_log.rule_id.c_str(),
               response.is_likely_false_positive ? "Likely False Positive" : "Likely True Positive",
               response.confidence_score);
    
    return response;
}

std::vector<GPTResponse> GPTAssist::analyzeAlerts(const std::vector<AlertLog>& alert_logs)
{
    std::vector<GPTResponse> responses;
    responses.reserve(alert_logs.size());
    
    for (const auto& alert : alert_logs)
    {
        responses.push_back(analyzeAlert(alert));
    }
    
    return responses;
}

std::string GPTAssist::generatePatternSummary(const std::vector<AlertLog>& alert_logs)
{
    if (alert_logs.empty())
        return "No alerts to analyze.";
    
    std::ostringstream summary;
    summary << "Pattern Analysis Summary:\n";
    summary << "Total alerts analyzed: " << alert_logs.size() << "\n";
    
    // Count by rule type
    std::unordered_map<std::string, uint32_t> rule_counts;
    std::unordered_map<std::string, uint32_t> source_counts;
    std::unordered_map<std::string, uint32_t> dest_counts;
    
    for (const auto& alert : alert_logs)
    {
        rule_counts[alert.rule_id]++;
        source_counts[alert.source_ip]++;
        dest_counts[alert.dest_ip]++;
    }
    
    summary << "\nTop Rules by Frequency:\n";
    std::vector<std::pair<std::string, uint32_t>> sorted_rules(rule_counts.begin(), rule_counts.end());
    std::sort(sorted_rules.begin(), sorted_rules.end(), 
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    for (size_t i = 0; i < std::min(size_t(5), sorted_rules.size()); ++i)
    {
        summary << "  " << sorted_rules[i].first << ": " << sorted_rules[i].second << " alerts\n";
    }
    
    summary << "\nTop Source IPs:\n";
    std::vector<std::pair<std::string, uint32_t>> sorted_sources(source_counts.begin(), source_counts.end());
    std::sort(sorted_sources.begin(), sorted_sources.end(), 
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    for (size_t i = 0; i < std::min(size_t(5), sorted_sources.size()); ++i)
    {
        summary << "  " << sorted_sources[i].first << ": " << sorted_sources[i].second << " alerts\n";
    }
    
    return summary.str();
}

void GPTAssist::setApiConfig(const std::string& api_key, const std::string& endpoint)
{
    api_key_ = api_key;
    endpoint_ = endpoint;
    
    LogMessage("GPT API configuration updated (mock implementation)\n");
}

GPTAssist::Stats GPTAssist::getStats() const
{
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void GPTAssist::cleanup()
{
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    // Cleanup CURL
    curl_global_cleanup();
    
    available_ = false;
    stats_ = Stats{};
}

GPTResponse GPTAssist::mockAnalyzeAlert(const AlertLog& alert_log)
{
    GPTResponse response;
    
    response.summary = generateMockSummary(alert_log);
    response.analysis = generateMockAnalysis(alert_log);
    response.is_likely_false_positive = mockIsFalsePositive(alert_log);
    response.confidence_score = calculateMockConfidence(alert_log);
    response.recommendation = generateMockRecommendation(alert_log);
    response.suggested_actions = generateMockActions(alert_log);
    
    return response;
}

std::string GPTAssist::generateMockSummary(const AlertLog& alert_log)
{
    std::ostringstream summary;
    summary << "Alert Summary: " << alert_log.rule_description << "\n";
    summary << "Source: " << alert_log.source_ip << ":" << alert_log.source_port << "\n";
    summary << "Destination: " << alert_log.dest_ip << ":" << alert_log.dest_port << "\n";
    summary << "Protocol: " << alert_log.protocol << "\n";
    summary << "Packet Size: " << alert_log.packet_size << " bytes\n";
    summary << "Classification: " << alert_log.classification << "\n";
    summary << "Priority: " << alert_log.priority;
    
    return summary.str();
}

std::string GPTAssist::generateMockAnalysis(const AlertLog& alert_log)
{
    std::ostringstream analysis;
    
    // Mock analysis based on rule characteristics
    if (alert_log.rule_id.find("suspicious") != std::string::npos)
    {
        analysis << "This alert indicates suspicious network activity. ";
        analysis << "The pattern matches known attack signatures. ";
        analysis << "Recommend immediate investigation.";
    }
    else if (alert_log.rule_id.find("malware") != std::string::npos)
    {
        analysis << "Malware detection alert triggered. ";
        analysis << "The packet content matches known malware patterns. ";
        analysis << "High priority investigation required.";
    }
    else if (alert_log.rule_id.find("scan") != std::string::npos)
    {
        analysis << "Port scan or reconnaissance activity detected. ";
        analysis << "This could be part of a larger attack campaign. ";
        analysis << "Monitor for follow-up activities.";
    }
    else
    {
        analysis << "Generic security alert triggered. ";
        analysis << "Review packet content and context for threat assessment. ";
        analysis << "Consider correlation with other security events.";
    }
    
    return analysis.str();
}

bool GPTAssist::mockIsFalsePositive(const AlertLog& alert_log)
{
    // Mock logic to determine false positive likelihood
    // In real implementation, this would use ML models or heuristics
    
    // Factors that might indicate false positive:
    // 1. Low priority alerts
    // 2. Common source IPs (internal networks)
    // 3. Small packet sizes
    // 4. Common protocols
    
    bool likely_false_positive = false;
    
    // Check priority
    if (alert_log.priority < 3)
        likely_false_positive = true;
    
    // Check if source IP is internal (simplified)
    if (alert_log.source_ip.find("192.168.") == 0 || 
        alert_log.source_ip.find("10.") == 0 ||
        alert_log.source_ip.find("172.16.") == 0)
    {
        likely_false_positive = true;
    }
    
    // Check packet size (very small packets might be false positives)
    if (alert_log.packet_size < 64)
        likely_false_positive = true;
    
    // Add some randomness for demonstration
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_real_distribution<> dis(0.0, 1.0);
    
    if (dis(gen) < 0.3) // 30% chance of false positive
        likely_false_positive = true;
    
    return likely_false_positive;
}

double GPTAssist::calculateMockConfidence(const AlertLog& alert_log)
{
    // Mock confidence calculation
    double confidence = 0.5; // Base confidence
    
    // Adjust based on priority
    confidence += (alert_log.priority - 1) * 0.1;
    
    // Adjust based on packet size
    if (alert_log.packet_size > 1000)
        confidence += 0.1;
    else if (alert_log.packet_size < 100)
        confidence -= 0.1;
    
    // Add some randomness
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_real_distribution<> dis(-0.2, 0.2);
    
    confidence += dis(gen);
    
    // Clamp between 0 and 1
    confidence = std::max(0.0, std::min(1.0, confidence));
    
    return confidence;
}

std::string GPTAssist::generateMockRecommendation(const AlertLog& alert_log)
{
    if (alert_log.priority >= 4)
    {
        return "IMMEDIATE ACTION REQUIRED: Block source IP and investigate further.";
    }
    else if (alert_log.priority >= 3)
    {
        return "HIGH PRIORITY: Monitor source IP and review security logs.";
    }
    else if (alert_log.priority >= 2)
    {
        return "MEDIUM PRIORITY: Add to watchlist and correlate with other events.";
    }
    else
    {
        return "LOW PRIORITY: Log for future analysis and trend monitoring.";
    }
}

std::vector<std::string> GPTAssist::generateMockActions(const AlertLog& alert_log)
{
    std::vector<std::string> actions;
    
    actions.push_back("Review packet capture for additional context");
    actions.push_back("Check if source IP is on any threat intelligence feeds");
    actions.push_back("Correlate with other security events from the same time period");
    
    if (alert_log.priority >= 3)
    {
        actions.push_back("Consider blocking source IP temporarily");
        actions.push_back("Notify security team for immediate review");
    }
    
    if (alert_log.protocol == "TCP" || alert_log.protocol == "UDP")
    {
        actions.push_back("Check if destination port is commonly targeted");
        actions.push_back("Review firewall logs for related traffic");
    }
    
    return actions;
}

// Global functions for integration with SNORT
void gpt_assist_init()
{
    GPTAssist::getInstance().init();
}

void gpt_assist_cleanup()
{
    GPTAssist::getInstance().cleanup();
}

GPTResponse gptAssist(const AlertLog& alert_log)
{
    return GPTAssist::getInstance().analyzeAlert(alert_log);
}
