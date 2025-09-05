# explicit_sniffer.py - Debug version
from scapy.all import sniff, IP, TCP, UDP, ICMP
import time

def packet_callback(packet):
    print(f"\nPacket captured at {time.time()}")
    if packet.haslayer(IP):
        ip = packet[IP]
        print(f"IP: {ip.src} -> {ip.dst}")
    else:
        print("No IP layer found")

print("DEBUG: Starting sniffer...")
print("Make sure to run as Administrator!")
try:
    # Try with explicit parameters
    sniff(count=3, 
          prn=packet_callback, 
          store=False,
          timeout=10)  # Stop after 10 seconds if no packets
    print("Sniffing completed")
except Exception as e:
    print(f"Error: {e}")