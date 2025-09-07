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

#include "metrics_logger.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cmath>

#include "log/messages.h"

using namespace snort;

MetricsLogger& MetricsLogger::getInstance()
{
    static MetricsLogger instance;
    return instance;
}

MetricsLogger::~MetricsLogger()
{
    cleanup();
}

void MetricsLogger::init(const std::string& output_dir)
{
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    output_dir_ = output_dir;
    
    LogMessage("Metrics Logger initialized with output directory: %s\n", output_dir.c_str());
}

void MetricsLogger::startRun(const std::string& run_id, RunType run_type,
                           const std::string& dataset_name,
                           const std::string& config_file,
                           const std::string& rules_file)
{
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    if (run_active_)
    {
        LogMessage("Warning: Starting new run while previous run is still active\n");
        endRun();
    }
    
    // Initialize current metrics
    current_metrics_ = PerformanceMetrics{};
    current_metrics_.run_id = run_id;
    current_metrics_.run_type = run_type;
    current_metrics_.timestamp = std::chrono::system_clock::now();
    current_metrics_.dataset_name = dataset_name;
    current_metrics_.config_file = config_file;
    current_metrics_.rules_file = rules_file;
    
    // Reset counters
    packets_processed_count_ = 0;
    alerts_count_ = 0;
    true_positives_count_ = 0;
    false_positives_count_ = 0;
    custom_rules_triggered_count_ = 0;
    gpt_analyses_count_ = 0;
    gpt_false_positive_detections_count_ = 0;
    
    run_start_time_ = std::chrono::system_clock::now();
    run_active_ = true;
    
    LogMessage("Started metrics collection for run: %s (%s)\n", 
               run_id.c_str(), runTypeToString(run_type).c_str());
}

void MetricsLogger::endRun()
{
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    if (!run_active_)
        return;
    
    // Calculate final metrics
    auto end_time = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - run_start_time_);
    
    current_metrics_.packets_processed = packets_processed_count_;
    current_metrics_.processing_time_seconds = duration.count() / 1000.0;
    current_metrics_.packets_per_second = packets_processed_count_ / (duration.count() / 1000.0);
    
    current_metrics_.total_alerts = alerts_count_;
    current_metrics_.true_positives = true_positives_count_;
    current_metrics_.false_positives = false_positives_count_;
    current_metrics_.custom_rules_triggered = custom_rules_triggered_count_;
    current_metrics_.gpt_analyses_performed = gpt_analyses_count_;
    current_metrics_.gpt_false_positive_detections = gpt_false_positive_detections_count_;
    
    // Calculate derived metrics
    calculateMetrics(current_metrics_);
    
    // Store metrics
    all_metrics_.push_back(current_metrics_);
    
    // Log to console
    logToConsole(current_metrics_);
    
    run_active_ = false;
    
    LogMessage("Ended metrics collection for run: %s\n", current_metrics_.run_id.c_str());
}

void MetricsLogger::recordAlert(const std::string& rule_id, bool is_true_positive)
{
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    if (!run_active_)
        return;
    
    alerts_count_++;
    if (is_true_positive)
        true_positives_count_++;
    else
        false_positives_count_++;
}

void MetricsLogger::recordPacketProcessed()
{
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    if (!run_active_)
        return;
    
    packets_processed_count_++;
}

void MetricsLogger::recordCustomRuleTriggered(const std::string& rule_id)
{
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    if (!run_active_)
        return;
    
    custom_rules_triggered_count_++;
}

void MetricsLogger::recordGPTAnalysis(bool detected_false_positive)
{
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    if (!run_active_)
        return;
    
    gpt_analyses_count_++;
    if (detected_false_positive)
        gpt_false_positive_detections_count_++;
}

void MetricsLogger::setGroundTruth(const std::string& packet_id, bool is_malicious)
{
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    ground_truth_[packet_id] = is_malicious;
}

PerformanceMetrics MetricsLogger::getCurrentMetrics() const
{
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    return current_metrics_;
}

std::vector<PerformanceMetrics> MetricsLogger::getAllMetrics() const
{
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    return all_metrics_;
}

bool MetricsLogger::exportToCSV(const std::string& filename) const
{
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    std::string full_path = output_dir_ + "/" + filename;
    std::ofstream file(full_path);
    
    if (!file.is_open())
    {
        LogMessage("Failed to open CSV file for writing: %s\n", full_path.c_str());
        return false;
    }
    
    // Write header
    file << "timestamp,run_id,run_type,total_alerts,true_positives,false_positives,"
         << "precision,recall,f1_score,accuracy,packets_processed,processing_time_seconds,"
         << "packets_per_second,custom_rules_triggered,gpt_analyses_performed,"
         << "gpt_false_positive_detections,dataset_name,config_file,rules_file\n";
    
    // Write data
    for (const auto& metrics : all_metrics_)
    {
        auto time_t = std::chrono::system_clock::to_time_t(metrics.timestamp);
        file << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << ","
             << metrics.run_id << ","
             << runTypeToString(metrics.run_type) << ","
             << metrics.total_alerts << ","
             << metrics.true_positives << ","
             << metrics.false_positives << ","
             << std::fixed << std::setprecision(4) << metrics.precision << ","
             << metrics.recall << ","
             << metrics.f1_score << ","
             << metrics.accuracy << ","
             << metrics.packets_processed << ","
             << metrics.processing_time_seconds << ","
             << metrics.packets_per_second << ","
             << metrics.custom_rules_triggered << ","
             << metrics.gpt_analyses_performed << ","
             << metrics.gpt_false_positive_detections << ","
             << metrics.dataset_name << ","
             << metrics.config_file << ","
             << metrics.rules_file << "\n";
    }
    
    file.close();
    LogMessage("Exported metrics to CSV: %s\n", full_path.c_str());
    return true;
}

bool MetricsLogger::exportToJSON(const std::string& filename) const
{
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    std::string full_path = output_dir_ + "/" + filename;
    std::ofstream file(full_path);
    
    if (!file.is_open())
    {
        LogMessage("Failed to open JSON file for writing: %s\n", full_path.c_str());
        return false;
    }
    
    file << "{\n  \"metrics\": [\n";
    
    for (size_t i = 0; i < all_metrics_.size(); ++i)
    {
        const auto& metrics = all_metrics_[i];
        auto time_t = std::chrono::system_clock::to_time_t(metrics.timestamp);
        
        file << "    {\n"
             << "      \"timestamp\": \"" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << "\",\n"
             << "      \"run_id\": \"" << metrics.run_id << "\",\n"
             << "      \"run_type\": \"" << runTypeToString(metrics.run_type) << "\",\n"
             << "      \"total_alerts\": " << metrics.total_alerts << ",\n"
             << "      \"true_positives\": " << metrics.true_positives << ",\n"
             << "      \"false_positives\": " << metrics.false_positives << ",\n"
             << "      \"precision\": " << std::fixed << std::setprecision(4) << metrics.precision << ",\n"
             << "      \"recall\": " << metrics.recall << ",\n"
             << "      \"f1_score\": " << metrics.f1_score << ",\n"
             << "      \"accuracy\": " << metrics.accuracy << ",\n"
             << "      \"packets_processed\": " << metrics.packets_processed << ",\n"
             << "      \"processing_time_seconds\": " << metrics.processing_time_seconds << ",\n"
             << "      \"packets_per_second\": " << metrics.packets_per_second << ",\n"
             << "      \"custom_rules_triggered\": " << metrics.custom_rules_triggered << ",\n"
             << "      \"gpt_analyses_performed\": " << metrics.gpt_analyses_performed << ",\n"
             << "      \"gpt_false_positive_detections\": " << metrics.gpt_false_positive_detections << ",\n"
             << "      \"dataset_name\": \"" << metrics.dataset_name << "\",\n"
             << "      \"config_file\": \"" << metrics.config_file << "\",\n"
             << "      \"rules_file\": \"" << metrics.rules_file << "\"\n"
             << "    }";
        
        if (i < all_metrics_.size() - 1)
            file << ",";
        file << "\n";
    }
    
    file << "  ]\n}\n";
    
    file.close();
    LogMessage("Exported metrics to JSON: %s\n", full_path.c_str());
    return true;
}

void MetricsLogger::printComparisonSummary() const
{
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    if (all_metrics_.empty())
    {
        LogMessage("No metrics available for comparison\n");
        return;
    }
    
    LogMessage("\n=== PERFORMANCE COMPARISON SUMMARY ===\n");
    
    // Find baseline metrics
    PerformanceMetrics baseline;
    bool has_baseline = false;
    
    std::vector<PerformanceMetrics> hybrid_metrics;
    
    for (const auto& metrics : all_metrics_)
    {
        if (metrics.run_type == RunType::BASELINE)
        {
            baseline = metrics;
            has_baseline = true;
        }
        else if (metrics.run_type != RunType::BASELINE)
        {
            hybrid_metrics.push_back(metrics);
        }
    }
    
    if (!has_baseline)
    {
        LogMessage("No baseline metrics found for comparison\n");
        return;
    }
    
    // Print baseline
    LogMessage("BASELINE PERFORMANCE:\n");
    LogMessage("  Precision: %.4f\n", baseline.precision);
    LogMessage("  Recall: %.4f\n", baseline.recall);
    LogMessage("  F1-Score: %.4f\n", baseline.f1_score);
    LogMessage("  Accuracy: %.4f\n", baseline.accuracy);
    LogMessage("  Total Alerts: %u\n", baseline.total_alerts);
    LogMessage("  False Positives: %u\n", baseline.false_positives);
    LogMessage("  Packets/sec: %.2f\n", baseline.packets_per_second);
    
    // Print hybrid comparisons
    for (const auto& hybrid : hybrid_metrics)
    {
        LogMessage("\nHYBRID PERFORMANCE (%s):\n", runTypeToString(hybrid.run_type).c_str());
        LogMessage("  Precision: %.4f (%.2f%% change)\n", 
                   hybrid.precision, 
                   ((hybrid.precision - baseline.precision) / baseline.precision) * 100);
        LogMessage("  Recall: %.4f (%.2f%% change)\n", 
                   hybrid.recall, 
                   ((hybrid.recall - baseline.recall) / baseline.recall) * 100);
        LogMessage("  F1-Score: %.4f (%.2f%% change)\n", 
                   hybrid.f1_score, 
                   ((hybrid.f1_score - baseline.f1_score) / baseline.f1_score) * 100);
        LogMessage("  Accuracy: %.4f (%.2f%% change)\n", 
                   hybrid.accuracy, 
                   ((hybrid.accuracy - baseline.accuracy) / baseline.accuracy) * 100);
        LogMessage("  Total Alerts: %u (%d change)\n", 
                   hybrid.total_alerts, 
                   (int)hybrid.total_alerts - (int)baseline.total_alerts);
        LogMessage("  False Positives: %u (%d change)\n", 
                   hybrid.false_positives, 
                   (int)hybrid.false_positives - (int)baseline.false_positives);
        LogMessage("  Packets/sec: %.2f (%.2f%% change)\n", 
                   hybrid.packets_per_second, 
                   ((hybrid.packets_per_second - baseline.packets_per_second) / baseline.packets_per_second) * 100);
        
        if (hybrid.custom_rules_triggered > 0)
        {
            LogMessage("  Custom Rules Triggered: %u\n", hybrid.custom_rules_triggered);
        }
        if (hybrid.gpt_analyses_performed > 0)
        {
            LogMessage("  GPT Analyses: %u\n", hybrid.gpt_analyses_performed);
            LogMessage("  GPT False Positive Detections: %u\n", hybrid.gpt_false_positive_detections);
        }
    }
    
    LogMessage("\n=== END COMPARISON ===\n");
}

PerformanceMetrics MetricsLogger::getBaselineMetrics() const
{
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    for (const auto& metrics : all_metrics_)
    {
        if (metrics.run_type == RunType::BASELINE)
            return metrics;
    }
    
    return PerformanceMetrics{};
}

std::vector<PerformanceMetrics> MetricsLogger::getHybridMetrics() const
{
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    std::vector<PerformanceMetrics> hybrid_metrics;
    for (const auto& metrics : all_metrics_)
    {
        if (metrics.run_type != RunType::BASELINE)
            hybrid_metrics.push_back(metrics);
    }
    
    return hybrid_metrics;
}

void MetricsLogger::cleanup()
{
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    if (run_active_)
        endRun();
    
    all_metrics_.clear();
    ground_truth_.clear();
}

void MetricsLogger::calculateMetrics(PerformanceMetrics& metrics) const
{
    // Calculate precision
    if (metrics.true_positives + metrics.false_positives > 0)
    {
        metrics.precision = static_cast<double>(metrics.true_positives) / 
                           (metrics.true_positives + metrics.false_positives);
    }
    else
    {
        metrics.precision = 0.0;
    }
    
    // Calculate recall (assuming we have ground truth)
    uint32_t total_malicious = metrics.true_positives + metrics.false_negatives;
    if (total_malicious > 0)
    {
        metrics.recall = static_cast<double>(metrics.true_positives) / total_malicious;
    }
    else
    {
        metrics.recall = 0.0;
    }
    
    // Calculate F1 score
    if (metrics.precision + metrics.recall > 0)
    {
        metrics.f1_score = 2 * (metrics.precision * metrics.recall) / 
                          (metrics.precision + metrics.recall);
    }
    else
    {
        metrics.f1_score = 0.0;
    }
    
    // Calculate accuracy
    uint32_t total_predictions = metrics.true_positives + metrics.false_positives + 
                                 metrics.true_negatives + metrics.false_negatives;
    if (total_predictions > 0)
    {
        metrics.accuracy = static_cast<double>(metrics.true_positives + metrics.true_negatives) / 
                          total_predictions;
    }
    else
    {
        metrics.accuracy = 0.0;
    }
}

std::string MetricsLogger::runTypeToString(RunType type) const
{
    switch (type)
    {
        case RunType::BASELINE:
            return "BASELINE";
        case RunType::HYBRID_WITH_CUSTOM_RULES:
            return "HYBRID_WITH_CUSTOM_RULES";
        case RunType::HYBRID_WITH_GPT_FILTERING:
            return "HYBRID_WITH_GPT_FILTERING";
        case RunType::HYBRID_FULL:
            return "HYBRID_FULL";
        default:
            return "UNKNOWN";
    }
}

RunType MetricsLogger::stringToRunType(const std::string& str) const
{
    if (str == "BASELINE")
        return RunType::BASELINE;
    else if (str == "HYBRID_WITH_CUSTOM_RULES")
        return RunType::HYBRID_WITH_CUSTOM_RULES;
    else if (str == "HYBRID_WITH_GPT_FILTERING")
        return RunType::HYBRID_WITH_GPT_FILTERING;
    else if (str == "HYBRID_FULL")
        return RunType::HYBRID_FULL;
    else
        return RunType::BASELINE;
}

void MetricsLogger::logToConsole(const PerformanceMetrics& metrics) const
{
    LogMessage("\n=== RUN METRICS: %s ===\n", metrics.run_id.c_str());
    LogMessage("Run Type: %s\n", runTypeToString(metrics.run_type).c_str());
    LogMessage("Dataset: %s\n", metrics.dataset_name.c_str());
    LogMessage("Total Alerts: %u\n", metrics.total_alerts);
    LogMessage("True Positives: %u\n", metrics.true_positives);
    LogMessage("False Positives: %u\n", metrics.false_positives);
    LogMessage("Precision: %.4f\n", metrics.precision);
    LogMessage("Recall: %.4f\n", metrics.recall);
    LogMessage("F1-Score: %.4f\n", metrics.f1_score);
    LogMessage("Accuracy: %.4f\n", metrics.accuracy);
    LogMessage("Packets Processed: %lu\n", metrics.packets_processed);
    LogMessage("Processing Time: %.2f seconds\n", metrics.processing_time_seconds);
    LogMessage("Packets/Second: %.2f\n", metrics.packets_per_second);
    
    if (metrics.custom_rules_triggered > 0)
    {
        LogMessage("Custom Rules Triggered: %u\n", metrics.custom_rules_triggered);
    }
    
    if (metrics.gpt_analyses_performed > 0)
    {
        LogMessage("GPT Analyses Performed: %u\n", metrics.gpt_analyses_performed);
        LogMessage("GPT False Positive Detections: %u\n", metrics.gpt_false_positive_detections);
    }
    
    LogMessage("=== END METRICS ===\n");
}

// Global functions for integration with SNORT
void metrics_logger_init(const std::string& output_dir)
{
    MetricsLogger::getInstance().init(output_dir);
}

void metrics_logger_cleanup()
{
    MetricsLogger::getInstance().cleanup();
}

void metrics_logger_start_run(const std::string& run_id, RunType run_type,
                            const std::string& dataset_name,
                            const std::string& config_file,
                            const std::string& rules_file)
{
    MetricsLogger::getInstance().startRun(run_id, run_type, dataset_name, config_file, rules_file);
}

void metrics_logger_end_run()
{
    MetricsLogger::getInstance().endRun();
}

void metrics_logger_record_alert(const std::string& rule_id, bool is_true_positive)
{
    MetricsLogger::getInstance().recordAlert(rule_id, is_true_positive);
}

void metrics_logger_record_packet()
{
    MetricsLogger::getInstance().recordPacketProcessed();
}

void metrics_logger_record_custom_rule(const std::string& rule_id)
{
    MetricsLogger::getInstance().recordCustomRuleTriggered(rule_id);
}

void metrics_logger_record_gpt_analysis(bool detected_false_positive)
{
    MetricsLogger::getInstance().recordGPTAnalysis(detected_false_positive);
}
