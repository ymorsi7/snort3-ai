#!/usr/bin/env python3
"""
Create a real PCAP file for SNORT testing
"""

from scapy.all import *
import random

def create_test_pcap():
    """Create a test PCAP file with various network traffic"""
    
    packets = []
    
    # Create some TCP packets to different ports
    for i in range(10):
        # SSH traffic
        pkt = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(dport=22, sport=random.randint(1024, 65535))
        packets.append(pkt)
        
        # HTTP traffic
        pkt = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(dport=80, sport=random.randint(1024, 65535))
        packets.append(pkt)
        
        # HTTPS traffic
        pkt = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(dport=443, sport=random.randint(1024, 65535))
        packets.append(pkt)
    
    # Write packets to PCAP file
    wrpcap("test_real.pcap", packets)
    print(f"Created test_real.pcap with {len(packets)} packets")

if __name__ == "__main__":
    create_test_pcap()
