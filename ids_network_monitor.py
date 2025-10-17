import logging
import subprocess
import platform
import configparser
from collections import defaultdict
from scapy.all import *

# Global Variables
syn_counts = defaultdict(int)
port_scan_tracker = defaultdict(set)

# Load configuration
def load_config():
    config = configparser.ConfigParser()
    config.read('config.ini')
    return config

CONFIG = load_config()

# Setup logging
def setup_logging():
    logging.basicConfig(
        filename=CONFIG['logging']['log_file'],
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

# Block IP based on OS
def block_ip(ip_address):
    os_type = platform.system()
    logging.info(f"Attempting to block IP: {ip_address} on {os_type}")

    try:
        if os_type == "Windows":
            command = f"netsh advfirewall firewall add rule name='Blocked by IDS: {ip_address}' dir=in action=block remoteip={ip_address}"
            subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        elif os_type == "Linux":
            command = f"iptables -A INPUT -s {ip_address} -j DROP"
            subprocess.run(command, shell=True, check=True, capture_output=True, text=True)

        logging.info(f"Successfully blocked IP address: {ip_address}")

    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to block IP {ip_address}. Error: {e.stderr}. Ensure you are running with root/admin privileges.")
    except Exception as e:
        logging.error(f"An unexpected error occurred during IP blocking: {e}")

# Alert function
def send_alert(message):
    print(f"CRITICAL ALERT: {message}")
    logging.critical(f"ALERT: {message}")

# Packet analysis logic
def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    packet_size = len(packet)

    # Large Packet Detection
    if packet_size > int(CONFIG['detection_rules']['max_packet_size']):
        log_message = f"Large Packet Detected: Size {packet_size} bytes from {ip_src} to {ip_dst}."
        logging.warning(log_message)

    if packet.haslayer(TCP):
        tcp_sport = packet[TCP].sport
        tcp_dport = packet[TCP].dport
        tcp_flags = packet[TCP].flags

        # SYN Flood Detection
        if tcp_flags == 'S':
            syn_counts[ip_src] += 1
            if syn_counts[ip_src] > int(CONFIG['detection_rules']['syn_flood_threshold']):
                alert_message = f"Potential SYN Flood Attack Detected from {ip_src} (Count: {syn_counts[ip_src]})."
                send_alert(alert_message)
                block_ip(ip_src)
                syn_counts[ip_src] = 0

        # Port Scanning Detection
        ports_to_monitor = [int(p) for p in CONFIG['settings']['ports_to_monitor'].split(',')]
        if tcp_dport in ports_to_monitor:
            port_scan_tracker[ip_src].add(tcp_dport)
            if len(port_scan_tracker[ip_src]) > int(CONFIG['detection_rules']['port_scan_threshold']):
                alert_message = f"Potential Port Scan Detected from {ip_src}. Scanned ports: {sorted(list(port_scan_tracker[ip_src]))}"
                send_alert(alert_message)
                block_ip(ip_src)
                port_scan_tracker[ip_src].clear()

# Main function
def main():
    setup_logging()
    logging.info("Intrusion Detection System started.")
    print("IDS is running... Press Ctrl+C to stop.")

    try:
        sniff(prn=packet_callback, store=0)
    except Exception as e:
        logging.error(f"An error occurred during sniffing: {e}")
    finally:
        logging.info("Intrusion Detection System stopped.")
        print("\nIDS has been stopped.")

if __name__ == "__main__":
    main()
