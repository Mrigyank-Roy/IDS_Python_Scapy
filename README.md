# Python Intrusion Detection System

## Description

This is a network Intrusion Detection System (IDS) built in Python using the Scapy library. It monitors network traffic in real-time to detect and respond to potential security threats. The system can identify large packets, SYN flood attacks, and port scanning activities. When a threat is detected, it sends an alert and can automatically block the source IP address using firewall rules for both Windows and Linux operating systems.

## Features

* **SYN Flood Detection:** Monitors for an excessive number of SYN packets from a single source and blocks the IP if it exceeds a configurable threshold.
* **Port Scanning Detection:** Tracks connection attempts to a predefined list of ports from a single IP and blocks the IP if the number of scanned ports exceeds a threshold.
* **Large Packet Detection:** Logs a warning if a packet larger than a specified size is detected.
* **Cross-Platform IP Blocking:** Automatically adds firewall rules to block malicious IP addresses on both Windows (`netsh advfirewall`) and Linux (`iptables`).
* **Configurable:** All detection thresholds, monitored ports, and logging settings can be easily configured in the `config.ini` file.
* **Logging:** Logs all significant events, including system start/stop, warnings, and critical alerts, to a log file (`ids_advanced_logs.log`).

## How It Works

The script uses the Scapy library to sniff network packets. Each packet is analyzed by the `packet_callback` function, which checks for various threat patterns:

1.  **Large Packets:** The size of each packet is compared against the `max_packet_size` in the configuration. If it's larger, a warning is logged.
2.  **SYN Floods:** The script counts TCP packets with the SYN flag set for each source IP. If the count exceeds the `syn_flood_threshold`, it triggers an alert and blocks the IP.
3.  **Port Scanning:** For a list of `ports_to_monitor`, the script keeps track of which ports are being accessed by each source IP. If an IP attempts to connect to more ports than the `port_scan_threshold`, it's flagged as a port scanner, an alert is raised, and the IP is blocked.

When a threat is detected, the `send_alert` function prints a critical message to the console, and the `block_ip` function executes a system command to add a firewall rule to block the offending IP address.

## Configuration

The IDS is configured through the `config.ini` file, which has the following sections:

* **[detection\_rules]**
    * `max_packet_size`: The maximum packet size in bytes before a warning is logged.
    * `syn_flood_threshold`: The number of SYN packets from a single IP before it's considered a SYN flood attack.
    * `port_scan_threshold`: The number of monitored ports an IP can scan before being blocked.
* **[settings]**
    * `ports_to_monitor`: A comma-separated list of ports to monitor for scanning activity.
* **[logging]**
    * `log_file`: The name of the file where logs will be stored.
* **[alerting]**
    * `enable_email_alerts`: A boolean to enable or disable email alerts.
    * `email_recipient`: The email address to send alerts to.

## Dependencies

* Python 3
* Scapy
* WinPcap (on Windows) or libpcap (on Linux)

## Usage

1.  Install the required dependencies:
    ```bash
    pip install scapy
    ```
2.  (Windows) Install Npcap from the official website.
3.  Customize the `config.ini` file to suit your needs.
4.  Run the script with administrative/root privileges:
    ```bash
    sudo python ids_network_monitor.py
    ```
    or on Windows with an Administrator Command Prompt:
    ```bash
    python ids_network_monitor.py
    ```
5.  Press `Ctrl+C` to stop the IDS.

## Logs

The `ids_advanced_logs.log` file provides a record of the IDS's activity. It logs when the system starts and stops, any errors that occur, and any detected threats.
