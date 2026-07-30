# Task 1: Basic Network Sniffer

**CodeAlpha Cyber Security Internship**

## About

A simple Python-based network sniffer that captures live network traffic
and displays key packet details such as source/destination IP addresses,
protocol type (TCP/UDP/ICMP), port numbers, and a preview of the payload.

This project demonstrates how data flows across a network and the basics
of common network protocols.

## Tech Used

- Python 3
- [Scapy](https://scapy.net/) - for packet capturing and parsing

## Setup

```bash
pip install scapy
```

**Windows users:** also install [Npcap](https://npcap.com) (required by Scapy for packet capture).

## How to Run

Packet capturing needs elevated privileges since it accesses raw sockets.

```bash
# Linux / macOS
sudo python3 network_sniffer.py

# Windows (run terminal as Administrator)
python network_sniffer.py
```

Press `Ctrl+C` to stop the capture.

## Sample Output

```
----------------------------------------------------------------------
[14:32:10] TCP Packet
  Source IP:      192.168.1.5
  Destination IP: 142.250.183.14
  Src Port: 51322  Dst Port: 443
  Payload (first 50 bytes): b'\x17\x03\x03\x00\xa1...'
```

## What I Learned

- How network packets are structured (IP header, transport layer header, payload)
- The difference between TCP, UDP, and ICMP traffic
- How to use Scapy to capture and parse live traffic
- Why raw packet capture requires elevated OS permissions

## Disclaimer

This tool is for educational purposes only. Only capture traffic on networks
you own or have explicit permission to monitor.
