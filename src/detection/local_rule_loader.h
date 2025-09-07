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

#ifndef LOCAL_RULE_LOADER_H
#define LOCAL_RULE_LOADER_H

#include <string>
#include <vector>
#include <mutex>
#include <memory>
#include <thread>
#include <atomic>
#include <chrono>

namespace snort
{
    struct SnortConfig;
    struct Packet;
}

struct LocalRuleInfo
{
    std::string rule_id;
    std::string rule_content;
    std::string description;
    std::chrono::system_clock::time_point loaded_time;
    bool is_active;
    uint32_t hit_count;
};

class LocalRuleLoader
{
public:
    static LocalRuleLoader& getInstance();
    
    // Initialize the rule loader
    void init(snort::SnortConfig* sc);
    
    // Load rules from local.rules file
    bool loadRulesFromFile(const std::string& filepath);
    
    // Add a single rule dynamically
    bool addRule(const std::string& rule_id, const std::string& rule_content, 
                 const std::string& description = "");
    
    // Remove a rule by ID
    bool removeRule(const std::string& rule_id);
    
    // Reload rules from file
    bool reloadRules();
    
    // Check if a rule exists
    bool hasRule(const std::string& rule_id) const;
    
    // Get rule information
    LocalRuleInfo* getRuleInfo(const std::string& rule_id);
    
    // Get all loaded rules
    std::vector<LocalRuleInfo> getAllRules() const;
    
    // Start file monitoring for dynamic reloading
    void startFileMonitoring(const std::string& filepath);
    
    // Stop file monitoring
    void stopFileMonitoring();
    
    // Check if file monitoring is active
    bool isMonitoring() const { return monitoring_active_; }
    
    // Process packet against local rules
    bool processPacket(snort::Packet* packet);
    
    // Get statistics
    struct Stats {
        uint32_t total_rules_loaded;
        uint32_t active_rules;
        uint32_t total_hits;
        std::chrono::system_clock::time_point last_reload;
    };
    
    Stats getStats() const;
    
    // Cleanup
    void cleanup();

private:
    LocalRuleLoader() = default;
    ~LocalRuleLoader();
    
    // Disable copy constructor and assignment
    LocalRuleLoader(const LocalRuleLoader&) = delete;
    LocalRuleLoader& operator=(const LocalRuleLoader&) = delete;
    
    // Internal methods
    void monitorFile();
    bool parseRuleLine(const std::string& line, std::string& rule_id, 
                      std::string& rule_content, std::string& description);
    void logRuleHit(const std::string& rule_id, snort::Packet* packet);
    
    // Member variables
    mutable std::mutex rules_mutex_;
    std::unordered_map<std::string, std::unique_ptr<LocalRuleInfo>> rules_;
    std::string rules_file_path_;
    std::atomic<bool> monitoring_active_{false};
    std::thread monitoring_thread_;
    snort::SnortConfig* config_{nullptr};
    
    // Statistics
    mutable std::mutex stats_mutex_;
    Stats stats_;
};

// Global functions for integration with SNORT
void local_rule_loader_init(snort::SnortConfig* sc);
void local_rule_loader_cleanup();
bool local_rule_loader_process_packet(snort::Packet* packet);

#endif // LOCAL_RULE_LOADER_H
