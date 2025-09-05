
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Ether
from collections import Counter
import datetime

class PacketAnalyzer:
    def __init__(self):
        self.packet_count = 0
        self.protocol_stats = Counter()
        self.conversations = Counter()
    
    def analyze_packet(self, packet):
        self.packet_count += 1
        print(f"\n{'='*60}")
        print(f"📦 Packet #{self.packet_count} - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*60}")
        
        
        if packet.haslayer(Ether):
            eth = packet[Ether]
            print(f"🔗 MAC: {eth.src} -> {eth.dst}")
        
        
        if packet.haslayer(IP):
            ip = packet[IP]
            print(f"🌐 IP: {ip.src} -> {ip.dst}")
            print(f"   Protocol: {self.get_protocol_name(ip.proto)} | TTL: {ip.ttl}")
            
            
            conv = f"{ip.src} ↔ {ip.dst}"
            self.conversations[conv] += 1
            
            
            if packet.haslayer(TCP):
                self.analyze_tcp(packet)
            elif packet.haslayer(UDP):
                self.analyze_udp(packet)
            elif packet.haslayer(ICMP):
                self.analyze_icmp(packet)
        
        
        self.analyze_payload(packet)
        
        print(f"{'-'*60}")
    
    def analyze_tcp(self, packet):
        tcp = packet[TCP]
        print(f"🔗 TCP: {tcp.sport} -> {tcp.dport}")
        print(f"   Flags: {tcp.flags} | Seq: {tcp.seq}")
        print(f"   Service: {self.get_service_name(tcp.dport, 'tcp')}")
        self.protocol_stats['TCP'] += 1
    
    def analyze_udp(self, packet):
        udp = packet[UDP]
        print(f"🔗 UDP: {udp.sport} -> {udp.dport}")
        print(f"   Length: {udp.len} bytes")
        print(f"   Service: {self.get_service_name(udp.dport, 'udp')}")
        self.protocol_stats['UDP'] += 1
    
    def analyze_icmp(self, packet):
        icmp = packet[ICMP]
        print(f"📶 ICMP: Type {icmp.type}, Code {icmp.code}")
        self.protocol_stats['ICMP'] += 1
    
    def analyze_payload(self, packet):
        if packet.haslayer(Raw):
            raw = packet[Raw]
            payload = raw.load
            print(f"📄 Payload: {len(payload)} bytes")
            
            # Show text preview if possible
            try:
                text = payload.decode('utf-8', errors='ignore')[:50]
                if text.strip():
                    print(f"   Text: {text}...")
            except:
                hex_preview = payload[:20].hex()
                print(f"   Hex: {hex_preview}...")
    
    def get_protocol_name(self, proto_num):
        protocols = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP"}
        return protocols.get(proto_num, f"Unknown ({proto_num})")
    
    def get_service_name(self, port, protocol):
        services = {
            53: "DNS", 80: "HTTP", 443: "HTTPS", 25: "SMTP",
            110: "POP3", 143: "IMAP", 67: "DHCP Server", 68: "DHCP Client"
        }
        return services.get(port, f"Unknown {protocol.upper()} service")
    
    def show_stats(self):
        print(f"\n{'='*60}")
        print("📊 CAPTURE SUMMARY")
        print(f"{'='*60}")
        print(f"Total packets: {self.packet_count}")
        print("\nProtocols:")
        for proto, count in self.protocol_stats.items():
            print(f"  {proto}: {count}")
        print("\nTop Conversations:")
        for conv, count in self.conversations.most_common(3):
            print(f"  {conv}: {count} packets")


if __name__ == "__main__":
    print("🛰️  ADVANCED PACKET ANALYZER")
    print("=" * 60)
    print("Capturing network traffic...")
    print("Generate traffic with: ping google.com")
    print("=" * 60)
    
    analyzer = PacketAnalyzer()
    
    try:
        
        sniff(prn=analyzer.analyze_packet, count=10, store=False)
    except KeyboardInterrupt:
        print("\nCapture stopped by user")
    finally:

        analyzer.show_stats()
