# ARPDefender

Advanced ARP Spoofing Detection & Network Security Monitor

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

---

## ⚠️ Legal Notice

**This tool is for AUTHORIZED SECURITY MONITORING ONLY.**

- You MUST own the network or have EXPLICIT PERMISSION to monitor it
- Unauthorized network monitoring is ILLEGAL in most jurisdictions
- Run this tool only on networks you OWN or have AUTHORIZATION for
- The developers are NOT responsible for misuse

See [DISCLAIMER.md](DISCLAIMER.md) for complete legal terms.

---

## What is ARPDefender?

ARPDefender is a comprehensive network security monitoring solution that:

- **Captures network packets** in real-time using Scapy
- **Detects ARP spoofing attacks** by monitoring IP-to-MAC mappings
- **Analyzes network traffic** and provides detailed statistics
- **Alerts on suspicious activity** via console, logs, and notifications
- **Exports captures** to PCAP format for forensic analysis

### How ARP Spoofing Detection Works

```
Normal ARP Flow:
  Host A: "Who has 192.168.1.1? Tell 192.168.1.100"
  Router: "192.168.1.1 is at AA:BB:CC:DD:EE:FF"

Attack Detection:
  1. Monitor all ARP requests/replies
  2. Track IP-to-MAC mappings
  3. Detect anomalies:
     - Same IP claiming different MACs
     - Same MAC claiming multiple IPs
     - Gratuitous ARP without request
     - Repeated MAC changes
  4. Alert on suspicious activity
```

---

## Features

### Core Features
- Real-time packet capture and display
- ARP spoofing detection with confidence scoring
- IP-to-MAC mapping tracking
- Traffic statistics and analysis
- PCAP file export
- Log management with SQLite

### Advanced Features
- Discord/Telegram notification integration
- MAC vendor identification
- Network topology ASCII visualization
- Rate limiting for alerts
- Historical data analysis
- Color-coded console output

### Safety Features
- Legal disclaimer on startup
- `--accept-terms` flag required
- No attack capabilities (detection only)
- Local data storage only
- Opt-in notifications

---

## Installation

### Prerequisites

- Python 3.8 or higher
- Administrator/root privileges (for packet capture)

### Steps

1. **Clone or download the project:**
   ```bash
   cd ARPDefender
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation:**
   ```bash
   python sniffer.py --list-interfaces
   ```

---

## Usage

### Basic Usage

```bash
# Run with auto-detected interface
python sniffer.py --accept-terms

# Specify interface
python sniffer.py --accept-terms --interface "Wi-Fi"

# ARP detection only
python sniffer.py --accept-terms --arp-only
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `--accept-terms` | Accept legal terms (required) |
| `--interface NAME` | Network interface to monitor |
| `--arp-only` | Only run ARP spoofing detection |
| `--save FILENAME` | Save captures to PCAP file |
| `--config FILE` | Path to config file |
| `--verbose` | Show detailed packet info |
| `--quiet` | Suppress console output |
| `--list-interfaces` | List available interfaces |

### Examples

**Example 1: Basic monitoring**
```bash
python sniffer.py --accept-terms --interface "Ethernet"
```

**Example 2: ARP detection with save**
```bash
python sniffer.py --accept-terms --arp-only --save capture.pcap
```

**Example 3: Verbose mode with custom config**
```bash
python sniffer.py --accept-terms --verbose --config config.yaml
```

---

## Configuration

Edit `config.yaml` to customize behavior:

```yaml
# Network Settings
network:
  interface: "auto"
  capture_filters: ""
  max_packets: 0
  promiscuous: true

# ARP Detection Settings
arp_detection:
  enabled: true
  monitor_interval: 1
  alert_threshold: 3
  whitelist: []

# Logging Settings
logging:
  console: true
  file: true
  sqlite: true
  log_dir: "logs"
  capture_dir: "captures"

# Notification Settings (Opt-In)
notifications:
  discord:
    enabled: false
    webhook_url: ""
  telegram:
    enabled: false
    bot_token: ""
    chat_id: ""
```

### Whitelist Trusted Devices

Add trusted IP-MAC pairs to prevent false positives:

```yaml
arp_detection:
  whitelist:
    - ip: "192.168.1.1"
      mac: "AA:BB:CC:DD:EE:FF"
      description: "Router"
    - ip: "192.168.1.100"
      mac: "11:22:33:44:55:66"
      description: "My Laptop"
```

### Enable Notifications

**Discord:**
1. Create a webhook in your Discord server
2. Add the webhook URL to config.yaml
3. Enable the discord notification

**Telegram:**
1. Create a bot via @BotFather
2. Get your chat ID
3. Add bot token and chat ID to config.yaml

---

## Project Structure

```
ARPDefender/
├── sniffer.py                  # Main entry point
├── requirements.txt            # Dependencies
├── config.yaml                 # Configuration
├── LICENSE                     # MIT License
├── DISCLAIMER.md               # Legal disclaimer
├── README.md                   # This file
├── modules/
│   ├── __init__.py
│   ├── packet_capture.py       # Scapy packet capture
│   ├── arp_detector.py         # ARP spoofing detection
│   ├── network_monitor.py      # Traffic analysis
│   ├── logger.py               # Logging & notifications
│   └── utils.py                # Network utilities
├── logs/                       # Log files
└── captures/                   # PCAP files
```

---

## How It Works

### Packet Capture

The tool uses Scapy to capture network packets in real-time:

1. Selects network interface (auto-detect or manual)
2. Starts packet capture with optional BPF filters
3. Parses each packet for relevant information
4. Logs packets to console, file, and SQLite database

### ARP Spoofing Detection

The ARP detector maintains a table of IP-to-MAC mappings:

1. Monitors all ARP requests and replies
2. Tracks IP-to-MAC associations
3. Detects anomalies:
   - Same IP claiming different MACs
   - Same MAC claiming multiple IPs
   - Gratuitous ARP without request
   - Repeated MAC changes
4. Generates alerts with confidence scores

### Traffic Analysis

The network monitor tracks:

- Total packets and bytes
- Protocol distribution (TCP, UDP, ICMP, ARP)
- Top talkers by traffic volume
- Bandwidth usage over time
- Port activity

---

## Troubleshooting

### Common Issues

**"Permission denied" error:**
```bash
# Windows: Run as Administrator
# Linux/Mac: Use sudo
sudo python sniffer.py --accept-terms
```

**"No interface found":**
```bash
# List available interfaces
python sniffer.py --list-interfaces
```

**"Scapy not installed":**
```bash
pip install scapy
```

**"PyYAML not installed":**
```bash
pip install pyyaml
```

### Windows-Specific Notes

- Run Command Prompt or PowerShell as Administrator
- Some features require Npcap or WinPcap
- Download Npcap from: https://npcap.com/

### Linux-Specific Notes

- Requires root privileges for packet capture
- May need to install additional packages:
  ```bash
  sudo apt-get install python3-scapy
  ```

---

## Ethical Use Guidelines

This tool is designed for legitimate security purposes:

1. **Home Network Monitoring**
   - Monitor your own home network
   - Detect unauthorized devices
   - Identify potential security threats

2. **Authorized Penetration Testing**
   - Use only with written authorization
   - Document all testing activities
   - Follow responsible disclosure

3. **Educational Purposes**
   - Learn about network security
   - Understand ARP protocol
   - Practice in controlled environments

4. **Security Research**
   - Conduct ethical research
   - Follow institutional guidelines
   - Publish findings responsibly

---

## Contributing

Contributions are welcome! Please:

1. Follow ethical guidelines
2. Do not add attack capabilities
3. Maintain the authorized-use-only focus
4. Update documentation as needed

---

## License

This project is licensed under the MIT License with Ethical Use Clause.

See [LICENSE](LICENSE) for details.

---

## Disclaimer

This software is provided for **authorized security monitoring only**. Users are responsible for complying with all applicable laws. See [DISCLAIMER.md](DISCLAIMER.md) for full details.

---

## Support

For issues or questions:
- Check the troubleshooting section
- Review the documentation
- Open an issue on GitHub

---

**Remember: Only use this tool on networks you own or have authorization to monitor!**
