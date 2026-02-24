from scapy.all import rdpcap, TCP, IP
from collections import defaultdict
from datetime import datetime 
import sys
from utils.detection_rules import PORT_SCAN_THRESHOLD

def load_pcap(file_path):
    """
    """
    print(f"[+] Loading PCAP file: {file_path}")
    return rdpcap(file_path)

def detect_port_scan(packets):
    """ 

    """
    print("[+] Analyzing for port scanning...")

    ip_port_map = defaultdict(set)

    for pack in packets:
        if pack.haslayer(TCP) and pack.haslayer(IP):
            src_ip = pack[IP].src
            dst_port = pack[TCP].dport
            ip_port_map[src_ip].add(dst_port)
    
    suspicious_ip_addresses = [] #making a new array to store the suspicious IP addresses

    for ip, ports in ip_port_map.items():
        if len(ports) > PORT_SCAN_THRESHOLD:
            suspicious_ip_addresses.append((ip, len(ports)))
        
    return suspicious_ip_addresses 

def detect_syn_flood(packets):
    """
    Detects whether or not an SYN flood has taken place. A SYN flood is a type of DDoS attack that exploits the TCP 3-way handshake, sending a rapid stream of SYN packets, to overwhelm a target's server.

    Parameters:

    Returns:

    (int) syn_count: 
    
    """
    syn_count = defaultdict(int)

    for packet in packets:
        if packet.haslayer(TCP) and packet.haslayer(IP):
            if packet[TCP].flags == "S": 
                src_ip = packet[IP].src
                syn_count[src_ip] += 1
    return syn_count

def main():
    if len(sys.argv) != 2:
        print("Usage: python analyzer.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    packets = load_pcap(pcap_file)
    print (f"[+] Total packets loaded: {len(packets)}")

    port_scan_results = detect_port_scan(packets)
    syn_results = detect_syn_flood(packets)

    print("\n=== Port Scan Detection ===")
    if port_scan_results:
        for ip, port_count in port_scan_results:
            print(f"[!] Suspicious IP: {ip} scanned {port_count} ports")
    else:
        print("No port scanning detected.")

    print("\n=== SYN Packet Analysis ===")
    for ip, count in syn_results.items():
        if count > 50:
            print(f"[!] High SYN count from {ip}: {count}")

if __name__ == "__main__":
    main()

