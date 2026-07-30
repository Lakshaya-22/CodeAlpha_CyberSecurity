"""
Basic Network Sniffer
CodeAlpha Cyber Security Internship - Task 1

Captures live network packets and displays useful information:
source/destination IP, protocol, and payload.

Requirements:
    pip install scapy

Run with admin/root privileges (packet capture needs raw socket access):
    Linux/Mac : sudo python3 network_sniffer.py
    Windows   : run terminal as Administrator (Npcap must be installed - https://npcap.com)
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime


def process_packet(packet):
    """Callback function run for every captured packet."""
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto_num = ip_layer.proto

        # Map protocol number to name
        if TCP in packet:
            proto_name = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            port_info = f"  Src Port: {sport}  Dst Port: {dport}"
        elif UDP in packet:
            proto_name = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            port_info = f"  Src Port: {sport}  Dst Port: {dport}"
        elif ICMP in packet:
            proto_name = "ICMP"
            port_info = "  (no ports - ICMP)"
        else:
            proto_name = f"Other (proto={proto_num})"
            port_info = ""

        timestamp = datetime.now().strftime("%H:%M:%S")

        print("-" * 70)
        print(f"[{timestamp}] {proto_name} Packet")
        print(f"  Source IP:      {src_ip}")
        print(f"  Destination IP: {dst_ip}")
        print(port_info)

        # Show a preview of the payload if present
        if Raw in packet:
            payload = bytes(packet[Raw].load)
            preview = payload[:50]
            print(f"  Payload (first 50 bytes): {preview}")


def main():
    print("=" * 70)
    print(" Basic Network Sniffer - CodeAlpha Cyber Security Internship")
    print(" Press Ctrl+C to stop capturing")
    print("=" * 70)

    # count=0 means capture indefinitely until Ctrl+C
    # Change 'iface' to your network interface name if needed, e.g. iface="eth0"
    sniff(prn=process_packet, store=False, count=0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except PermissionError:
        print("\nPermission denied. Run this script as Administrator/root.")
