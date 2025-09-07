#!/usr/bin/env python3
"""
Generate sample PCAP data for SNORT AI enhancement testing
This creates a simple text file that simulates PCAP data for testing
"""

import os
import random
import time

def generate_sample_pcap():
    """Generate sample PCAP-like data for testing"""
    
    # Create sample traffic data
    sample_traffic = []
    
    # Generate 100 sample packets
    for i in range(100):
        packet_id = f"packet_{i:06d}"
        
        # Randomly assign malicious or normal traffic
        is_malicious = (i % 5) == 0  # 20% malicious
        
        if is_malicious:
            # Generate malicious traffic patterns
            attack_types = [
                "sql_injection",
                "port_scan", 
                "malware_signature",
                "brute_force",
                "xss_attack",
                "directory_traversal",
                "command_injection",
                "ddos_attack",
                "crypto_mining",
                "data_exfiltration"
            ]
            attack_type = random.choice(attack_types)
            
            # Generate suspicious packet data
            if attack_type == "sql_injection":
                packet_data = f"GET /login.php?id=1' UNION SELECT * FROM users-- HTTP/1.1"
            elif attack_type == "port_scan":
                packet_data = f"SYN packet to port {random.randint(1, 65535)}"
            elif attack_type == "malware_signature":
                packet_data = "MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff"
            elif attack_type == "brute_force":
                packet_data = f"POST /login HTTP/1.1\r\nContent-Length: 50\r\n\r\nusername=admin&password=password123"
            elif attack_type == "xss_attack":
                packet_data = f"GET /search?q=<script>alert('xss')</script> HTTP/1.1"
            else:
                packet_data = f"Suspicious {attack_type} activity detected"
        else:
            # Generate normal traffic
            packet_data = f"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0"
        
        # Generate IP addresses
        source_ip = f"192.168.1.{random.randint(100, 200)}"
        dest_ip = f"10.0.0.{random.randint(1, 50)}"
        
        # Generate ports
        source_port = random.randint(1024, 65535)
        dest_port = random.choice([80, 443, 22, 25, 53, 8080])
        
        # Generate protocol
        protocol = random.choice(["TCP", "UDP"])
        
        packet_info = {
            "id": packet_id,
            "is_malicious": is_malicious,
            "attack_type": attack_type if is_malicious else "normal_traffic",
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "source_port": source_port,
            "dest_port": dest_port,
            "protocol": protocol,
            "packet_data": packet_data,
            "timestamp": time.time()
        }
        
        sample_traffic.append(packet_info)
    
    return sample_traffic

def create_sample_pcap_file():
    """Create a sample PCAP file for testing"""
    
    traffic_data = generate_sample_pcap()
    
    # Create a simple text-based PCAP representation
    pcap_content = "# Sample PCAP data for SNORT AI enhancement testing\n"
    pcap_content += "# Format: timestamp,source_ip:port,dest_ip:port,protocol,packet_data\n"
    
    for packet in traffic_data:
        pcap_content += f"{packet['timestamp']:.6f},{packet['source_ip']}:{packet['source_port']},{packet['dest_ip']}:{packet['dest_port']},{packet['protocol']},{packet['packet_data']}\n"
    
    # Write to file
    with open("sample_traffic.pcap", "w") as f:
        f.write(pcap_content)
    
    print(f"Created sample_traffic.pcap with {len(traffic_data)} packets")
    print(f"Malicious packets: {sum(1 for p in traffic_data if p['is_malicious'])}")
    print(f"Normal packets: {sum(1 for p in traffic_data if not p['is_malicious'])}")

def create_sample_snort_config():
    """Create a sample SNORT configuration file"""
    
    config_content = """# SNORT Configuration for AI Enhancement Testing
config daq: pcap
config daq_dir: /usr/lib/x86_64-linux-gnu/daq/
config daq_mode: read-file

# AI Enhancement Configuration
config enable_local_rules: true
config enable_gpt_filtering: true
config enable_metrics_logging: true

# Include custom rules
include local.rules

# Output configuration
output alert_csv: file:./results/alerts.csv
output log_tcpdump: ./results/traffic.pcap

# Performance tuning
config pcre_match_limit: 1500
config pcre_match_limit_recursion: 1500

# Basic rules for testing
alert tcp any any -> any 80 (msg:"HTTP Traffic Detected"; content:"GET"; http_method; sid:1; rev:1;)
alert tcp any any -> any 22 (msg:"SSH Traffic Detected"; content:"SSH"; sid:2; rev:1;)
alert tcp any any -> any 443 (msg:"HTTPS Traffic Detected"; content:"CONNECT"; http_method; sid:3; rev:1;)
"""
    
    with open("snort.conf", "w") as f:
        f.write(config_content)
    
    print("Created snort.conf configuration file")

if __name__ == "__main__":
    print("Generating sample data for SNORT AI enhancement testing...")
    
    # Create sample data
    create_sample_pcap_file()
    create_sample_snort_config()
    
    print("\nSample data created successfully!")
    print("You can now run:")
    print("  python evaluate.py --dataset ./datasets/cicids2017/ --config ./snort.conf --pcap ./sample_traffic.pcap")
