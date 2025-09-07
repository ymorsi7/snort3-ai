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

#ifndef GPT_ASSIST_H
#define GPT_ASSIST_H

#include <string>
#include <vector>
#include <memory>
#include <chrono>

namespace snort
{
    struct Packet;
}

struct AlertLog
{
    std::string rule_id;
    std::string rule_description;
    std::string source_ip;
    std::string dest_ip;
    uint16_t source_port;
    uint16_t dest_port;
    std::string protocol;
    std::string packet_data;
    uint32_t packet_size;
    std::chrono::system_clock::time_point timestamp;
    std::string classification;
    uint32_t priority;
};

struct GPTResponse
{
    std::string summary;
    std::string analysis;
    bool is_likely_false_positive;
    double confidence_score;
    std::string recommendation;
    std::vector<std::string> suggested_actions;
};

class GPTAssist
{
public:
    static GPTAssist& getInstance();
    
    // Initialize GPT interface
    void init();
    
    // Main function to analyze alert logs
    GPTResponse analyzeAlert(const AlertLog& alert_log);
    
    // Batch analysis for multiple alerts
    std::vector<GPTResponse> analyzeAlerts(const std::vector<AlertLog>& alert_logs);
    
    // Generate summary of alert patterns
    std::string generatePatternSummary(const std::vector<AlertLog>& alert_logs);
    
    // Check if GPT interface is available
    bool isAvailable() const { return available_; }
    
    // Set API configuration (placeholder for real implementation)
    void setApiConfig(const std::string& api_key, const std::string& endpoint);
    
    // Get statistics
    struct Stats {
        uint32_t total_analyses;
        uint32_t false_positive_detections;
        uint32_t true_positive_detections;
        double average_confidence;
        std::chrono::system_clock::time_point last_analysis;
    };
    
    Stats getStats() const;
    
    // Cleanup
    void cleanup();

private:
    GPTAssist() = default;
    ~GPTAssist();
    
    // Disable copy constructor and assignment
    GPTAssist(const GPTAssist&) = delete;
    GPTAssist& operator=(const GPTAssist&) = delete;
    
    // Internal methods
    GPTResponse mockAnalyzeAlert(const AlertLog& alert_log);
    std::string generateMockSummary(const AlertLog& alert_log);
    std::string generateMockAnalysis(const AlertLog& alert_log);
    bool mockIsFalsePositive(const AlertLog& alert_log);
    double calculateMockConfidence(const AlertLog& alert_log);
    std::string generateMockRecommendation(const AlertLog& alert_log);
    std::vector<std::string> generateMockActions(const AlertLog& alert_log);
    
    // Member variables
    bool available_{false};
    std::string api_key_;
    std::string endpoint_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    Stats stats_;
};

// Global functions for integration with SNORT
void gpt_assist_init();
void gpt_assist_cleanup();
GPTResponse gptAssist(const AlertLog& alert_log);

#endif // GPT_ASSIST_H
