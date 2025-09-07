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

#ifndef METRICS_LOGGER_H
#define METRICS_LOGGER_H

#include <string>
#include <vector>
#include <mutex>
#include <memory>
#include <chrono>
#include <fstream>
#include <unordered_map>

namespace snort
{
    struct Packet;
}

enum class RunType
{
    BASELINE,
    HYBRID_WITH_CUSTOM_RULES,
    HYBRID_WITH_GPT_FILTERING,
    HYBRID_FULL
};

struct PerformanceMetrics
{
    std::string run_id;
    RunType run_type;
    std::chrono::system_clock::time_point timestamp;
    
    // Detection metrics
    uint32_t total_alerts;
    uint32_t true_positives;
    uint32_t false_positives;
    uint32_t true_negatives;
    uint32_t false_negatives;
    
    // Calculated metrics
    double precision;
    double recall;
    double f1_score;
    double accuracy;
    
    // Performance metrics
    uint64_t packets_processed;
    double processing_time_seconds;
    double packets_per_second;
    
    // Additional metrics
    uint32_t custom_rules_loaded;
    uint32_t custom_rules_triggered;
    uint32_t gpt_analyses_performed;
    uint32_t gpt_false_positive_detections;
    
    // Configuration
    std::string dataset_name;
    std::string config_file;
    std::string rules_file;
};

class MetricsLogger
{
public:
    static MetricsLogger& getInstance();
    
    // Initialize the metrics logger
    void init(const std::string& output_dir = ".");
    
    // Start a new run
    void startRun(const std::string& run_id, RunType run_type, 
                 const std::string& dataset_name = "", 
                 const std::string& config_file = "",
                 const std::string& rules_file = "");
    
    // End current run and calculate final metrics
    void endRun();
    
    // Record detection events
    void recordAlert(const std::string& rule_id, bool is_true_positive = true);
    void recordPacketProcessed();
    void recordCustomRuleTriggered(const std::string& rule_id);
    void recordGPTAnalysis(bool detected_false_positive = false);
    
    // Set ground truth for evaluation
    void setGroundTruth(const std::string& packet_id, bool is_malicious);
    
    // Get current metrics
    PerformanceMetrics getCurrentMetrics() const;
    
    // Get all recorded metrics
    std::vector<PerformanceMetrics> getAllMetrics() const;
    
    // Export metrics to CSV
    bool exportToCSV(const std::string& filename) const;
    
    // Export metrics to JSON
    bool exportToJSON(const std::string& filename) const;
    
    // Print summary comparison
    void printComparisonSummary() const;
    
    // Get baseline metrics
    PerformanceMetrics getBaselineMetrics() const;
    
    // Get hybrid metrics
    std::vector<PerformanceMetrics> getHybridMetrics() const;
    
    // Cleanup
    void cleanup();

private:
    MetricsLogger() = default;
    ~MetricsLogger();
    
    // Disable copy constructor and assignment
    MetricsLogger(const MetricsLogger&) = delete;
    MetricsLogger& operator=(const MetricsLogger&) = delete;
    
    // Internal methods
    void calculateMetrics(PerformanceMetrics& metrics) const;
    std::string runTypeToString(RunType type) const;
    RunType stringToRunType(const std::string& str) const;
    void logToConsole(const PerformanceMetrics& metrics) const;
    
    // Member variables
    mutable std::mutex metrics_mutex_;
    std::vector<PerformanceMetrics> all_metrics_;
    PerformanceMetrics current_metrics_;
    bool run_active_{false};
    std::string output_dir_;
    
    // Ground truth data
    std::unordered_map<std::string, bool> ground_truth_;
    
    // Runtime counters
    std::chrono::system_clock::time_point run_start_time_;
    uint64_t packets_processed_count_;
    uint32_t alerts_count_;
    uint32_t true_positives_count_;
    uint32_t false_positives_count_;
    uint32_t custom_rules_triggered_count_;
    uint32_t gpt_analyses_count_;
    uint32_t gpt_false_positive_detections_count_;
};

// Global functions for integration with SNORT
void metrics_logger_init(const std::string& output_dir = ".");
void metrics_logger_cleanup();
void metrics_logger_start_run(const std::string& run_id, RunType run_type,
                             const std::string& dataset_name = "",
                             const std::string& config_file = "",
                             const std::string& rules_file = "");
void metrics_logger_end_run();
void metrics_logger_record_alert(const std::string& rule_id, bool is_true_positive = true);
void metrics_logger_record_packet();
void metrics_logger_record_custom_rule(const std::string& rule_id);
void metrics_logger_record_gpt_analysis(bool detected_false_positive = false);

#endif // METRICS_LOGGER_H
