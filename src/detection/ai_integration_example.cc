//--------------------------------------------------------------------------
// Copyright (C) 2025 Custom SNORT AI Enhancement
//
// Integration example showing how to integrate AI enhancements with SNORT
// This file demonstrates how to hook into SNORT's detection pipeline
//--------------------------------------------------------------------------

#include "detection/local_rule_loader.h"
#include "detection/gpt_assist.h"
#include "detection/metrics_logger.h"
#include "detection/detection_engine.h"
#include "main/snort_config.h"

using namespace snort;

// Global instances for AI enhancements
static bool ai_enhancements_enabled = false;
static bool local_rules_enabled = false;
static bool gpt_filtering_enabled = false;
static bool metrics_logging_enabled = false;

// Initialize AI enhancements
void init_ai_enhancements(SnortConfig* sc)
{
    // Initialize local rule loader
    if (local_rules_enabled)
    {
        local_rule_loader_init(sc);
        
        // Load custom rules from file
        LocalRuleLoader& loader = LocalRuleLoader::getInstance();
        loader.loadRulesFromFile("local.rules");
        
        // Start file monitoring for dynamic updates
        loader.startFileMonitoring("local.rules");
        
        LogMessage("Local rule loader initialized\n");
    }
    
    // Initialize GPT assist
    if (gpt_filtering_enabled)
    {
        gpt_assist_init();
        LogMessage("GPT assist module initialized\n");
    }
    
    // Initialize metrics logger
    if (metrics_logging_enabled)
    {
        metrics_logger_init("./metrics_output");
        LogMessage("Metrics logger initialized\n");
    }
    
    ai_enhancements_enabled = true;
}

// Process packet with AI enhancements
bool process_packet_with_ai(Packet* packet)
{
    if (!ai_enhancements_enabled || !packet)
        return false;
    
    bool alert_triggered = false;
    
    // Process with local rules
    if (local_rules_enabled)
    {
        if (local_rule_loader_process_packet(packet))
        {
            alert_triggered = true;
            
            // Record custom rule trigger
            if (metrics_logging_enabled)
            {
                metrics_logger_record_custom_rule("local_rule");
            }
        }
    }
    
    // Process with GPT filtering if alert was triggered
    if (alert_triggered && gpt_filtering_enabled)
    {
        // Create alert log from packet
        AlertLog alert_log;
        alert_log.rule_id = "local_rule";
        alert_log.rule_description = "Custom rule triggered";
        alert_log.source_ip = packet->ptrs.ip_api.get_src()->get_addr_str();
        alert_log.dest_ip = packet->ptrs.ip_api.get_dst()->get_addr_str();
        alert_log.source_port = packet->ptrs.sp;
        alert_log.dest_port = packet->ptrs.dp;
        alert_log.protocol = packet->get_ip_proto_next() == IPPROTO_TCP ? "TCP" : "UDP";
        alert_log.packet_data = std::string(reinterpret_cast<const char*>(packet->data), packet->dsize);
        alert_log.packet_size = packet->dsize;
        alert_log.timestamp = std::chrono::system_clock::now();
        alert_log.classification = "suspicious";
        alert_log.priority = 2;
        
        // Get GPT analysis
        GPTResponse response = gptAssist(alert_log);
        
        // Log GPT analysis
        LogMessage("GPT Analysis: %s\n", response.summary.c_str());
        LogMessage("Likely False Positive: %s\n", response.is_likely_false_positive ? "Yes" : "No");
        LogMessage("Confidence: %.2f\n", response.confidence_score);
        
        // Record GPT analysis
        if (metrics_logging_enabled)
        {
            metrics_logger_record_gpt_analysis(response.is_likely_false_positive);
        }
        
        // Filter out false positives
        if (response.is_likely_false_positive && response.confidence_score > 0.7)
        {
            LogMessage("Alert filtered as false positive by GPT\n");
            alert_triggered = false;
        }
    }
    
    // Record packet processing
    if (metrics_logging_enabled)
    {
        metrics_logger_record_packet();
        
        if (alert_triggered)
        {
            metrics_logger_record_alert("ai_enhanced", true); // Assume true positive for demo
        }
    }
    
    return alert_triggered;
}

// Start metrics collection for a run
void start_ai_evaluation_run(const std::string& run_id, RunType run_type,
                            const std::string& dataset_name = "",
                            const std::string& config_file = "",
                            const std::string& rules_file = "")
{
    if (metrics_logging_enabled)
    {
        metrics_logger_start_run(run_id, run_type, dataset_name, config_file, rules_file);
        LogMessage("Started AI evaluation run: %s\n", run_id.c_str());
    }
}

// End metrics collection and export results
void end_ai_evaluation_run()
{
    if (metrics_logging_enabled)
    {
        metrics_logger_end_run();
        
        // Export results
        MetricsLogger& logger = MetricsLogger::getInstance();
        logger.exportToCSV("baseline_vs_hybrid_results.csv");
        logger.exportToJSON("evaluation_results.json");
        logger.printComparisonSummary();
        
        LogMessage("AI evaluation run completed\n");
    }
}

// Cleanup AI enhancements
void cleanup_ai_enhancements()
{
    if (local_rules_enabled)
    {
        LocalRuleLoader::getInstance().cleanup();
    }
    
    if (gpt_filtering_enabled)
    {
        gpt_assist_cleanup();
    }
    
    if (metrics_logging_enabled)
    {
        metrics_logger_cleanup();
    }
    
    ai_enhancements_enabled = false;
    LogMessage("AI enhancements cleaned up\n");
}

// Configuration functions
void enable_local_rules(bool enable)
{
    local_rules_enabled = enable;
    LogMessage("Local rules %s\n", enable ? "enabled" : "disabled");
}

void enable_gpt_filtering(bool enable)
{
    gpt_filtering_enabled = enable;
    LogMessage("GPT filtering %s\n", enable ? "enabled" : "disabled");
}

void enable_metrics_logging(bool enable)
{
    metrics_logging_enabled = enable;
    LogMessage("Metrics logging %s\n", enable ? "enabled" : "disabled");
}

// Example usage in SNORT's main detection loop
void example_snort_integration(Packet* packet)
{
    // This would be called from SNORT's main packet processing loop
    
    // Process packet with standard SNORT detection
    bool standard_alert = DetectionEngine::detect(packet);
    
    // Process packet with AI enhancements
    bool ai_alert = process_packet_with_ai(packet);
    
    // Handle alerts
    if (standard_alert || ai_alert)
    {
        // Log alert
        LogMessage("Alert triggered on packet from %s to %s\n",
                   packet->ptrs.ip_api.get_src()->get_addr_str().c_str(),
                   packet->ptrs.ip_api.get_dst()->get_addr_str().c_str());
        
        // Take action (log, alert, drop, etc.)
        // This would integrate with SNORT's action system
    }
}

// Command line argument parsing example
void parse_ai_arguments(int argc, char* argv[])
{
    for (int i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], "--enable-local-rules") == 0)
        {
            enable_local_rules(true);
        }
        else if (strcmp(argv[i], "--enable-gpt-filtering") == 0)
        {
            enable_gpt_filtering(true);
        }
        else if (strcmp(argv[i], "--enable-metrics-logging") == 0)
        {
            enable_metrics_logging(true);
        }
        else if (strcmp(argv[i], "--enable-ai-enhancements") == 0)
        {
            enable_local_rules(true);
            enable_gpt_filtering(true);
            enable_metrics_logging(true);
        }
    }
}
