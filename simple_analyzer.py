
# simple_analyzer.py - Basic packet analysis
from scapy.all import sniff, IP, TCP, UDP, ICMP
import datetime

def analyze_packet(packet):
    print(f"\n[{datetime.datetime.now().strftime('%H:%M:%S')}] Packet:")
    print("-" * 50)
    
    # Basic IP info
    if packet.haslayer(IP):
        ip = packet[IP]
        print(f"IP: {ip.src} -> {ip.dst}")
        print(f"Protocol: {ip.proto} | TTL: {ip.ttl}")
        
        # Protocol analysis
        if ip.proto == 6:  # TCP
            tcp = packet[TCP]
            print(f"TCP: {tcp.sport} -> {tcp.dport}")
            print(f"Flags: {tcp.flags}")
            
        elif ip.proto == 17:  # UDP
            udp = packet[UDP]
            print(f"UDP: {udp.sport} -> {udp.dport}")
            
        elif ip.proto == 1:  # ICMP
            icmp = packet[ICMP]
            print(f"ICMP: Type {icmp.type}")
    
    print("-" * 50)

print("Simple Packet Analyzer - Capturing 5 packets")
print("Run 'ping google.com' in another window!")
sniff(count=5, prn=analyze_packet, store=False)
print("Analysis completed!")