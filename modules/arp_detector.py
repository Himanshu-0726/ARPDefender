"""
ARP Spoofing Detector Module
============================

Detects ARP spoofing attacks by monitoring IP-to-MAC mappings.
"""

import time
import threading
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict

from .utils import normalize_mac, validate_mac_address, validate_ip_address, get_mac_vendor


class ARPTable:
    """
    Maintains IP-to-MAC address mappings.
    """
    
    def __init__(self):
        """Initialize the ARP table."""
        # Main mapping: IP -> MAC
        self.ip_to_mac: Dict[str, str] = {}
        
        # Reverse mapping: MAC -> IPs
        self.mac_to_ips: Dict[str, Set[str]] = defaultdict(set)
        
        # History of changes: IP -> [(timestamp, old_mac, new_mac)]
        self.history: Dict[str, List[Tuple[datetime, str, str]]] = defaultdict(list)
        
        # Timestamps: IP -> first_seen, last_seen
        self.timestamps: Dict[str, Dict] = {}
        
        # Lock for thread safety
        self.lock = threading.Lock()
    
    def add_entry(self, ip: str, mac: str, is_gratuitous: bool = False) -> Optional[Dict]:
        """
        Add or update an IP-MAC mapping.
        
        Args:
            ip: IP address
            mac: MAC address
            is_gratuitous: Whether this was a gratuitous ARP
            
        Returns:
            Alert information if suspicious, None otherwise
        """
        if not validate_ip_address(ip) or not validate_mac_address(mac):
            return None
        
        normalized_mac = normalize_mac(mac)
        
        alerts = []
        
        with self.lock:
            current_time = datetime.now()
            
            # Check if IP already has a different MAC
            if ip in self.ip_to_mac:
                old_mac = self.ip_to_mac[ip]
                
                if old_mac.lower() != normalized_mac.lower():
                    # MAC change detected!
                    alerts.append({
                        'type': 'mac_change',
                        'ip': ip,
                        'old_mac': old_mac,
                        'new_mac': normalized_mac,
                        'timestamp': current_time,
                        'severity': 'HIGH'
                    })
                    
                    # Record history
                    self.history[ip].append((current_time, old_mac, normalized_mac))
                    
                    # Remove IP from old MAC's reverse mapping
                    for mac_key in list(self.mac_to_ips.keys()):
                        if mac_key.lower() == old_mac.lower():
                            self.mac_to_ips[mac_key].discard(ip)
                            break
            
            # Check if MAC is associated with multiple IPs
            existing_mac_key = None
            for m in self.mac_to_ips.keys():
                if m.lower() == normalized_mac.lower():
                    existing_mac_key = m
                    break
            
            if existing_mac_key:
                existing_ips = self.mac_to_ips[existing_mac_key]
                if ip not in existing_ips and len(existing_ips) > 0:
                    # MAC is now associated with a new IP
                    alerts.append({
                        'type': 'mac_multiple_ips',
                        'ip': ip,
                        'mac': normalized_mac,
                        'existing_ips': list(existing_ips),
                        'timestamp': current_time,
                        'severity': 'MEDIUM'
                    })
            
            # Update mappings
            self.ip_to_mac[ip] = normalized_mac
            
            # Update reverse mapping
            if existing_mac_key:
                self.mac_to_ips[existing_mac_key].add(ip)
            else:
                self.mac_to_ips[normalized_mac].add(ip)
            
            # Update timestamps
            if ip not in self.timestamps:
                self.timestamps[ip] = {
                    'first_seen': current_time,
                    'last_seen': current_time
                }
            else:
                self.timestamps[ip]['last_seen'] = current_time
        
        # Return first alert (most severe) or None
        return alerts[0] if alerts else None
    
    def get_mac(self, ip: str) -> Optional[str]:
        """Get MAC address for an IP."""
        with self.lock:
            return self.ip_to_mac.get(ip)
    
    def get_ips(self, mac: str) -> List[str]:
        """Get all IPs associated with a MAC."""
        with self.lock:
            normalized_mac = normalize_mac(mac)
            for m in self.mac_to_ips.keys():
                if m.lower() == normalized_mac.lower():
                    return list(self.mac_to_ips[m])
            return []
    
    def get_all_entries(self) -> List[Dict]:
        """Get all IP-MAC entries."""
        with self.lock:
            entries = []
            for ip, mac in self.ip_to_mac.items():
                entry = {
                    'ip': ip,
                    'mac': mac,
                    'vendor': get_mac_vendor(mac),
                    'first_seen': self.timestamps.get(ip, {}).get('first_seen'),
                    'last_seen': self.timestamps.get(ip, {}).get('last_seen')
                }
                entries.append(entry)
            return entries
    
    def get_history(self, ip: str) -> List[Tuple[datetime, str, str]]:
        """Get MAC change history for an IP."""
        with self.lock:
            return self.history.get(ip, [])
    
    def remove_entry(self, ip: str):
        """Remove an IP-MAC mapping."""
        with self.lock:
            if ip in self.ip_to_mac:
                mac = self.ip_to_mac[ip]
                del self.ip_to_mac[ip]
                
                # Remove from reverse mapping
                for m in self.mac_to_ips.keys():
                    if m.lower() == mac.lower():
                        self.mac_to_ips[m].discard(ip)
                        break
                
                if ip in self.timestamps:
                    del self.timestamps[ip]
    
    def clear(self):
        """Clear the entire ARP table."""
        with self.lock:
            self.ip_to_mac.clear()
            self.mac_to_ips.clear()
            self.history.clear()
            self.timestamps.clear()
    
    def get_suspicious_entries(self, threshold: int = 3) -> List[Dict]:
        """
        Get entries that may be suspicious.
        
        Args:
            threshold: Number of MAC changes to flag as suspicious
            
        Returns:
            List of suspicious entries
        """
        suspicious = []
        
        with self.lock:
            for ip, changes in self.history.items():
                if len(changes) >= threshold:
                    suspicious.append({
                        'ip': ip,
                        'current_mac': self.ip_to_mac.get(ip),
                        'change_count': len(changes),
                        'changes': changes[-5:]  # Last 5 changes
                    })
            
            # Check for MACs with multiple IPs
            for mac, ips in self.mac_to_ips.items():
                if len(ips) > 1:
                    suspicious.append({
                        'type': 'mac_multiple_ips',
                        'mac': mac,
                        'ips': list(ips),
                        'vendor': get_mac_vendor(mac)
                    })
        
        return suspicious


class ARPDetector:
    """
    Detects ARP spoofing attacks by monitoring ARP traffic.
    """
    
    def __init__(self, config: Dict = None, logger=None):
        """
        Initialize ARP detector.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config or {}
        self.arp_config = self.config.get('arp_detection', {})
        self.logger = logger
        
        # ARP table
        self.arp_table = ARPTable()
        
        # Whitelist
        self.whitelist = self._load_whitelist()
        
        # Detection settings
        self.monitor_interval = self.arp_config.get('monitor_interval', 1)
        self.alert_threshold = self.arp_config.get('alert_threshold', 3)
        self.enabled = self.arp_config.get('enabled', True)
        
        # Suspicious tracking
        self.suspicious_sources: Dict[str, int] = defaultdict(int)
        self.alert_counts: Dict[str, int] = defaultdict(int)
        
        # Monitoring thread
        self.monitor_thread = None
        self.is_monitoring = False
    
    def _load_whitelist(self) -> List[Dict]:
        """Load whitelist from config."""
        whitelist = self.arp_config.get('whitelist', [])
        
        # Normalize MAC addresses in whitelist
        normalized_whitelist = []
        for entry in whitelist:
            ip = entry.get('ip', '')
            mac = entry.get('mac', '')
            # Skip entries with empty IP or MAC
            if not ip or not mac:
                continue
            normalized_entry = {
                'ip': ip,
                'mac': normalize_mac(mac),
                'description': entry.get('description', '')
            }
            normalized_whitelist.append(normalized_entry)
        
        return normalized_whitelist
    
    def is_whitelisted(self, ip: str, mac: str) -> bool:
        """
        Check if an IP-MAC pair is whitelisted.
        
        Args:
            ip: IP address
            mac: MAC address
            
        Returns:
            True if whitelisted
        """
        normalized_mac = normalize_mac(mac)
        
        for entry in self.whitelist:
            if entry['ip'] == ip and entry['mac'] == normalized_mac:
                return True
        
        return False
    
    def process_arp_packet(self, packet_info: Dict) -> Optional[Dict]:
        """
        Process a captured ARP packet.
        
        Args:
            packet_info: Packet information dictionary
            
        Returns:
            Alert information if suspicious, None otherwise
        """
        if not self.enabled:
            return None
        
        # Extract ARP information
        src_ip = packet_info.get('source_ip')
        src_mac = packet_info.get('source_mac')
        dst_ip = packet_info.get('destination_ip')
        dst_mac = packet_info.get('destination_mac')
        
        if not src_ip or not src_mac:
            return None
        
        # Check if whitelisted
        if self.is_whitelisted(src_ip, src_mac):
            return None
        
        # Determine ARP type from info
        info = packet_info.get('info', '')
        # Gratuitous ARP: source IP equals destination IP (unsolicited announcement)
        # Normal replies like "X is at Y" don't contain "Tell" but are NOT gratuitous
        is_gratuitous = (src_ip == dst_ip)
        
        # Check for gratuitous ARP BEFORE updating the table
        alert = None
        if is_gratuitous:
            alert = self._check_gratuitous_arp(src_ip, src_mac)
        
        # Update ARP table
        table_alert = self.arp_table.add_entry(src_ip, src_mac, is_gratuitous)
        
        if table_alert:
            self._handle_alert(table_alert, packet_info)
            alert = table_alert
        elif alert:
            self._handle_alert(alert, packet_info)
        
        return alert
    
    def _check_gratuitous_arp(self, ip: str, mac: str) -> Optional[Dict]:
        """
        Check for suspicious gratuitous ARP.
        
        Args:
            ip: Source IP
            mac: Source MAC
            
        Returns:
            Alert information if suspicious, None otherwise
        """
        # Check if this IP was recently claimed by a different MAC
        previous_mac = self.arp_table.get_mac(ip)
        
        if previous_mac and previous_mac.lower() != mac.lower():
            # Track suspicious activity
            self.suspicious_sources[ip] += 1
            
            if self.suspicious_sources[ip] >= self.alert_threshold:
                return {
                    'type': 'gratuitous_arp_suspicious',
                    'ip': ip,
                    'mac': mac,
                    'previous_mac': previous_mac,
                    'severity': 'HIGH',
                    'confidence': min(0.9, 0.3 + (self.suspicious_sources[ip] * 0.1))
                }
        
        return None
    
    def _handle_alert(self, alert: Dict, packet_info: Dict):
        """
        Handle a detected alert.
        
        Args:
            alert: Alert information
            packet_info: Original packet information
        """
        alert_type = alert.get('type', 'unknown')
        severity = alert.get('severity', 'MEDIUM')
        ip = alert.get('ip', 'N/A')
        mac = alert.get('mac', 'N/A')
        
        # Generate message
        message = self._generate_alert_message(alert)
        
        # Log alert
        if self.logger:
            self.logger.log_alert(
                alert_type=f"arp_{alert_type}",
                severity=severity,
                message=message,
                source_ip=ip,
                details=alert
            )
            
            # Log to ARP table
            self.logger.log_arp_entry(
                ip=ip,
                mac=mac,
                is_suspicious=True,
                alert_type=alert_type,
                details=message
            )
    
    def _generate_alert_message(self, alert: Dict) -> str:
        """
        Generate a human-readable alert message.
        
        Args:
            alert: Alert information
            
        Returns:
            Alert message string
        """
        alert_type = alert.get('type', 'unknown')
        ip = alert.get('ip', 'N/A')
        
        if alert_type == 'mac_change':
            old_mac = alert.get('old_mac', 'N/A')
            new_mac = alert.get('new_mac', 'N/A')
            vendor = get_mac_vendor(new_mac)
            return f"IP {ip} changed MAC from {old_mac} to {new_mac} ({vendor})"
        
        elif alert_type == 'mac_multiple_ips':
            mac = alert.get('mac', 'N/A')
            ips = alert.get('ips', [])
            return f"MAC {mac} is now claiming multiple IPs: {', '.join(ips)}"
        
        elif alert_type == 'gratuitous_arp_suspicious':
            mac = alert.get('mac', 'N/A')
            prev_mac = alert.get('previous_mac', 'N/A')
            confidence = alert.get('confidence', 0)
            return f"Suspicious gratuitous ARP from {ip} ({mac}), was previously {prev_mac} (confidence: {confidence:.0%})"
        
        elif alert_type == 'arp_without_request':
            mac = alert.get('mac', 'N/A')
            return f"ARP reply from {ip} ({mac}) without prior request"
        
        else:
            return f"Suspicious ARP activity detected from {ip}"
    
    def start_monitoring(self):
        """Start ARP monitoring in background thread."""
        if self.is_monitoring:
            print("ARP monitoring already active")
            return
        
        self.is_monitoring = True
        
        def monitor_thread():
            while self.is_monitoring:
                # Periodic checks
                self._periodic_checks()
                time.sleep(self.monitor_interval)
        
        self.monitor_thread = threading.Thread(target=monitor_thread, daemon=True)
        self.monitor_thread.start()
        
        print("Started ARP spoofing detection")
    
    def stop_monitoring(self):
        """Stop ARP monitoring."""
        self.is_monitoring = False
        print("Stopped ARP spoofing detection")
    
    def _periodic_checks(self):
        """Perform periodic security checks."""
        current_time = datetime.now()
        
        # Check for stale entries (optional)
        # Could implement aging of ARP entries here
        
        # Check for suspicious patterns
        suspicious = self.arp_table.get_suspicious_entries(self.alert_threshold)
        
        for entry in suspicious:
            if 'change_count' in entry:
                ip = entry['ip']
                if self.alert_counts[ip] < entry['change_count']:
                    # New alert needed
                    self.alert_counts[ip] = entry['change_count']
                    
                    alert = {
                        'type': 'repeated_mac_changes',
                        'ip': ip,
                        'change_count': entry['change_count'],
                        'severity': 'HIGH'
                    }
                    
                    message = f"IP {ip} has changed MAC address {entry['change_count']} times - possible ARP spoofing attack"
                    
                    if self.logger:
                        self.logger.log_alert(
                            alert_type='arp_repeated_changes',
                            severity='HIGH',
                            message=message,
                            source_ip=ip,
                            details=entry
                        )
    
    def get_arp_table(self) -> List[Dict]:
        """Get current ARP table entries."""
        return self.arp_table.get_all_entries()
    
    def get_suspicious_entries(self) -> List[Dict]:
        """Get suspicious ARP entries."""
        return self.arp_table.get_suspicious_entries()
    
    def get_statistics(self) -> Dict:
        """Get ARP detection statistics."""
        return {
            'enabled': self.enabled,
            'is_monitoring': self.is_monitoring,
            'total_entries': len(self.arp_table.ip_to_mac),
            'suspicious_sources': dict(self.suspicious_sources),
            'alert_counts': dict(self.alert_counts),
            'whitelist_count': len(self.whitelist)
        }
    
    def print_arp_table(self):
        """Print the current ARP table."""
        entries = self.get_arp_table()
        
        print("\n" + "="*70)
        print("  ARP TABLE")
        print("="*70)
        print(f"  {'IP Address':<20} {'MAC Address':<20} {'Vendor':<20}")
        print("-"*70)
        
        for entry in entries:
            ip = entry.get('ip', 'N/A')
            mac = entry.get('mac', 'N/A')
            vendor = entry.get('vendor', 'Unknown')
            
            print(f"  {ip:<20} {mac:<20} {vendor:<20}")
        
        print("="*70 + "\n")
    
    def print_suspicious(self):
        """Print suspicious ARP entries."""
        suspicious = self.get_suspicious_entries()
        
        if not suspicious:
            print("\n  No suspicious ARP entries detected.\n")
            return
        
        print("\n" + "="*70)
        print("  SUSPICIOUS ARP ENTRIES")
        print("="*70)
        
        for entry in suspicious:
            if 'ip' in entry:
                print(f"\n  IP: {entry['ip']}")
                print(f"  Current MAC: {entry.get('current_mac', 'N/A')}")
                print(f"  Change Count: {entry.get('change_count', 0)}")
                print(f"  Changes: {entry.get('changes', [])}")
            elif 'mac' in entry:
                print(f"\n  MAC: {entry['mac']}")
                print(f"  Associated IPs: {entry.get('ips', [])}")
                print(f"  Vendor: {entry.get('vendor', 'Unknown')}")
        
        print("\n" + "="*70 + "\n")
