
echo from scapy.all import sniff, IP, TCP, UDP, ICMP > clean_sniffer.py
echo import datetime >> clean_sniffer.py
echo. >> clean_sniffer.py
echo def packet_callback(packet): >> clean_sniffer.py
echo     print(f"\n[{datetime.datetime.now().strftime('%%H:%%M:%%S')}] Packet captured!") >> clean_sniffer.py
echo     print("-" * 50) >> clean_sniffer.py
echo. >> clean_sniffer.py
echo     if packet.haslayer(IP): >> clean_sniffer.py
echo         ip = packet[IP] >> clean_sniffer.py
echo         print(f"IP: {ip.src} -> {ip.dst}") >> clean_sniffer.py
echo         print(f"Protocol: {ip.proto} | TTL: {ip.ttl}") >> clean_sniffer.py
echo. >> clean_sniffer.py
echo     if packet.haslayer(TCP): >> clean_sniffer.py
echo         tcp = packet[TCP] >> clean_sniffer.py
echo         print(f"TCP: {tcp.sport} -> {tcp.dport}") >> clean_sniffer.py
echo         print(f"Flags: {tcp.flags}") >> clean_sniffer.py
echo. >> clean_sniffer.py
echo     elif packet.haslayer(UDP): >> clean_sniffer.py
echo         udp = packet[UDP] >> clean_sniffer.py
echo         print(f"UDP: {udp.sport} -> {udp.dport}") >> clean_sniffer.py
echo. >> clean_sniffer.py
echo     elif packet.haslayer(ICMP): >> clean_sniffer.py
echo         icmp = packet[ICMP] >> clean_sniffer.py
echo         print(f"ICMP: Type {icmp.type}, Code {icmp.code}") >> clean_sniffer.py
echo. >> clean_sniffer.py
echo     print("-" * 50) >> clean_sniffer.py
echo. >> clean_sniffer.py
echo print("🐍 Network Packet Sniffer - Working!") >> clean_sniffer.py
echo print("=" * 60) >> clean_sniffer.py
echo print("Capturing 3 packets...") >> clean_sniffer.py
echo print("Run 'ping google.com' in another window!") >> clean_sniffer.py
echo print("=" * 60) >> clean_sniffer.py
echo sniff(count=3, prn=packet_callback, store=False) >> clean_sniffer.py
echo print("✅ Capture completed successfully!") >> clean_sniffer.py