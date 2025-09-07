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

#include "local_rule_loader.h"

#include <fstream>
#include <sstream>
#include <iostream>
#include <sys/inotify.h>
#include <unistd.h>
#include <regex>

#include "log/messages.h"
#include "main/snort_config.h"
#include "parser/parse_conf.h"
#include "detection/detection_engine.h"

using namespace snort;

LocalRuleLoader& LocalRuleLoader::getInstance()
{
    static LocalRuleLoader instance;
    return instance;
}

LocalRuleLoader::~LocalRuleLoader()
{
    stopFileMonitoring();
}

void LocalRuleLoader::init(SnortConfig* sc)
{
    std::lock_guard<std::mutex> lock(rules_mutex_);
    config_ = sc;
    
    // Initialize stats
    stats_.total_rules_loaded = 0;
    stats_.active_rules = 0;
    stats_.total_hits = 0;
    stats_.last_reload = std::chrono::system_clock::now();
    
    LogMessage("LocalRuleLoader initialized\n");
}

bool LocalRuleLoader::loadRulesFromFile(const std::string& filepath)
{
    std::ifstream file(filepath);
    if (!file.is_open())
    {
        LogMessage("Failed to open local rules file: %s\n", filepath.c_str());
        return false;
    }
    
    std::lock_guard<std::mutex> lock(rules_mutex_);
    
    // Clear existing rules
    rules_.clear();
    stats_.total_rules_loaded = 0;
    stats_.active_rules = 0;
    
    std::string line;
    int line_number = 0;
    
    while (std::getline(file, line))
    {
        line_number++;
        
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#')
            continue;
            
        std::string rule_id, rule_content, description;
        if (parseRuleLine(line, rule_id, rule_content, description))
        {
            auto rule_info = std::make_unique<LocalRuleInfo>();
            rule_info->rule_id = rule_id;
            rule_info->rule_content = rule_content;
            rule_info->description = description;
            rule_info->loaded_time = std::chrono::system_clock::now();
            rule_info->is_active = true;
            rule_info->hit_count = 0;
            
            rules_[rule_id] = std::move(rule_info);
            stats_.total_rules_loaded++;
            stats_.active_rules++;
            
            LogMessage("Loaded local rule: %s - %s\n", rule_id.c_str(), description.c_str());
        }
        else
        {
            LogMessage("Failed to parse rule at line %d: %s\n", line_number, line.c_str());
        }
    }
    
    stats_.last_reload = std::chrono::system_clock::now();
    LogMessage("Loaded %u local rules from %s\n", stats_.total_rules_loaded, filepath.c_str());
    
    return true;
}

bool LocalRuleLoader::addRule(const std::string& rule_id, const std::string& rule_content, 
                             const std::string& description)
{
    std::lock_guard<std::mutex> lock(rules_mutex_);
    
    auto rule_info = std::make_unique<LocalRuleInfo>();
    rule_info->rule_id = rule_id;
    rule_info->rule_content = rule_content;
    rule_info->description = description;
    rule_info->loaded_time = std::chrono::system_clock::now();
    rule_info->is_active = true;
    rule_info->hit_count = 0;
    
    rules_[rule_id] = std::move(rule_info);
    stats_.total_rules_loaded++;
    stats_.active_rules++;
    
    LogMessage("Added dynamic local rule: %s - %s\n", rule_id.c_str(), description.c_str());
    return true;
}

bool LocalRuleLoader::removeRule(const std::string& rule_id)
{
    std::lock_guard<std::mutex> lock(rules_mutex_);
    
    auto it = rules_.find(rule_id);
    if (it != rules_.end())
    {
        rules_.erase(it);
        stats_.active_rules--;
        LogMessage("Removed local rule: %s\n", rule_id.c_str());
        return true;
    }
    
    return false;
}

bool LocalRuleLoader::reloadRules()
{
    if (rules_file_path_.empty())
    {
        LogMessage("No rules file path set for reload\n");
        return false;
    }
    
    return loadRulesFromFile(rules_file_path_);
}

bool LocalRuleLoader::hasRule(const std::string& rule_id) const
{
    std::lock_guard<std::mutex> lock(rules_mutex_);
    return rules_.find(rule_id) != rules_.end();
}

LocalRuleInfo* LocalRuleLoader::getRuleInfo(const std::string& rule_id)
{
    std::lock_guard<std::mutex> lock(rules_mutex_);
    auto it = rules_.find(rule_id);
    return (it != rules_.end()) ? it->second.get() : nullptr;
}

std::vector<LocalRuleInfo> LocalRuleLoader::getAllRules() const
{
    std::lock_guard<std::mutex> lock(rules_mutex_);
    std::vector<LocalRuleInfo> result;
    
    for (const auto& pair : rules_)
    {
        result.push_back(*pair.second);
    }
    
    return result;
}

void LocalRuleLoader::startFileMonitoring(const std::string& filepath)
{
    if (monitoring_active_)
    {
        stopFileMonitoring();
    }
    
    rules_file_path_ = filepath;
    monitoring_active_ = true;
    monitoring_thread_ = std::thread(&LocalRuleLoader::monitorFile, this);
    
    LogMessage("Started monitoring local rules file: %s\n", filepath.c_str());
}

void LocalRuleLoader::stopFileMonitoring()
{
    if (monitoring_active_)
    {
        monitoring_active_ = false;
        if (monitoring_thread_.joinable())
        {
            monitoring_thread_.join();
        }
        LogMessage("Stopped monitoring local rules file\n");
    }
}

void LocalRuleLoader::monitorFile()
{
    int fd = inotify_init();
    if (fd < 0)
    {
        LogMessage("Failed to initialize inotify for file monitoring\n");
        return;
    }
    
    int wd = inotify_add_watch(fd, rules_file_path_.c_str(), IN_MODIFY | IN_MOVE_SELF);
    if (wd < 0)
    {
        LogMessage("Failed to add watch for file: %s\n", rules_file_path_.c_str());
        close(fd);
        return;
    }
    
    char buffer[4096];
    
    while (monitoring_active_)
    {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);
        
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int result = select(fd + 1, &readfds, nullptr, nullptr, &timeout);
        
        if (result > 0 && FD_ISSET(fd, &readfds))
        {
            ssize_t length = read(fd, buffer, sizeof(buffer));
            if (length > 0)
            {
                LogMessage("Local rules file modified, reloading...\n");
                reloadRules();
            }
        }
    }
    
    inotify_rm_watch(fd, wd);
    close(fd);
}

bool LocalRuleLoader::processPacket(Packet* packet)
{
    if (!packet)
        return false;
    
    std::lock_guard<std::mutex> lock(rules_mutex_);
    
    // Simple pattern matching for demonstration
    // In a real implementation, this would integrate with SNORT's detection engine
    for (auto& pair : rules_)
    {
        LocalRuleInfo* rule = pair.second.get();
        if (!rule->is_active)
            continue;
            
        // Simple content matching (this is a placeholder)
        // Real implementation would use SNORT's pattern matching engine
        if (packet->data && packet->dsize > 0)
        {
            std::string packet_data(reinterpret_cast<const char*>(packet->data), packet->dsize);
            
            // Check if rule content matches packet data
            if (packet_data.find(rule->rule_content) != std::string::npos)
            {
                rule->hit_count++;
                stats_.total_hits++;
                logRuleHit(rule->rule_id, packet);
                return true;
            }
        }
    }
    
    return false;
}

bool LocalRuleLoader::parseRuleLine(const std::string& line, std::string& rule_id, 
                                   std::string& rule_content, std::string& description)
{
    // Simple parsing for demonstration
    // Format: RULE_ID:CONTENT:DESCRIPTION
    std::istringstream iss(line);
    std::string token;
    
    if (!std::getline(iss, token, ':'))
        return false;
    rule_id = token;
    
    if (!std::getline(iss, token, ':'))
        return false;
    rule_content = token;
    
    if (!std::getline(iss, token))
        return false;
    description = token;
    
    return !rule_id.empty() && !rule_content.empty();
}

void LocalRuleLoader::logRuleHit(const std::string& rule_id, Packet* packet)
{
    LogMessage("Local rule hit: %s on packet from %s to %s, size: %u\n",
               rule_id.c_str(),
               packet->ptrs.ip_api.get_src()->get_addr_str().c_str(),
               packet->ptrs.ip_api.get_dst()->get_addr_str().c_str(),
               packet->dsize);
}

LocalRuleLoader::Stats LocalRuleLoader::getStats() const
{
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void LocalRuleLoader::cleanup()
{
    stopFileMonitoring();
    
    std::lock_guard<std::mutex> lock(rules_mutex_);
    rules_.clear();
    stats_ = Stats{};
}

// Global functions for integration with SNORT
void local_rule_loader_init(SnortConfig* sc)
{
    LocalRuleLoader::getInstance().init(sc);
}

void local_rule_loader_cleanup()
{
    LocalRuleLoader::getInstance().cleanup();
}

bool local_rule_loader_process_packet(Packet* packet)
{
    return LocalRuleLoader::getInstance().processPacket(packet);
}
