"""
Network Monitor Module
======================

Real-time traffic analysis and statistics.
"""

import time
import threading
from datetime import datetime
from typing import Dict, List, Optional, Set
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class TrafficStats:
    """Traffic statistics for a specific endpoint."""
    ip: str
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    protocols: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    ports: Set[int] = field(default_factory=set)


class NetworkMonitor:
    """
    Real-time network traffic monitoring and analysis.
    """
    
    def __init__(self, config: Dict = None, logger=None):
        """
        Initialize network monitor.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config or {}
        self.monitor_config = self.config.get('monitoring', {})
        self.logger = logger
        
        # Thread safety lock
        self._lock = threading.Lock()
        
        # Traffic statistics
        self.traffic_stats: Dict[str, TrafficStats] = {}
        
        # Protocol counts
        self.protocol_counts: Dict[str, int] = defaultdict(int)
        
        # Port activity
        self.port_activity: Dict[int, int] = defaultdict(int)
        
        # Bandwidth tracking
        self.bandwidth_samples: List[Dict] = []
        self.total_bytes = 0
        self.total_packets = 0
        self._last_bytes = 0
        self._last_packets = 0
        
        # Time tracking
        self.start_time = datetime.now()
        self.last_update = datetime.now()
        
        # Monitoring settings
        self.bandwidth_interval = self.monitor_config.get('bandwidth_interval', 5)
        self.enabled = self.monitor_config.get('traffic_stats', True)
        
        # Monitoring thread
        self.monitor_thread = None
        self.is_monitoring = False
    
    def process_packet(self, packet_info: Dict):
        """
        Process a captured packet for statistics.
        
        Args:
            packet_info: Packet information dictionary
        """
        if not self.enabled:
            return
        
        src_ip = packet_info.get('source_ip')
        dst_ip = packet_info.get('destination_ip')
        protocol = packet_info.get('protocol', 'Unknown')
        size = packet_info.get('size', 0)
        
        with self._lock:
            # Update total counts
            self.total_packets += 1
            self.total_bytes += size
            
            # Update protocol counts
            self.protocol_counts[protocol] += 1
            
            # Update traffic stats for source IP
            if src_ip:
                self._update_ip_stats(src_ip, 'sent', size, protocol)
            
            # Update traffic stats for destination IP
            if dst_ip:
                self._update_ip_stats(dst_ip, 'received', size, protocol)
            
            # Update port activity
            src_port = packet_info.get('source_port')
            dst_port = packet_info.get('destination_port')
            
            if src_port:
                self.port_activity[src_port] += 1
            if dst_port:
                self.port_activity[dst_port] += 1
    
    def _update_ip_stats(self, ip: str, direction: str, size: int, protocol: str):
        """
        Update statistics for a specific IP.
        
        Args:
            ip: IP address
            direction: 'sent' or 'received'
            size: Packet size in bytes
            protocol: Protocol name
        """
        if ip not in self.traffic_stats:
            self.traffic_stats[ip] = TrafficStats(ip=ip)
        
        stats = self.traffic_stats[ip]
        stats.last_seen = datetime.now()
        stats.protocols[protocol] += 1
        
        if direction == 'sent':
            stats.packets_sent += 1
            stats.bytes_sent += size
        else:
            stats.packets_received += 1
            stats.bytes_received += size
    
    def get_statistics(self) -> Dict:
        """
        Get current traffic statistics.
        
        Returns:
            Dictionary with traffic statistics
        """
        with self._lock:
            elapsed_time = (datetime.now() - self.start_time).total_seconds()
            
            # Calculate bandwidth
            bytes_per_second = self.total_bytes / elapsed_time if elapsed_time > 0 else 0
            packets_per_second = self.total_packets / elapsed_time if elapsed_time > 0 else 0
            
            # Protocol breakdown
            protocol_percentages = {}
            for proto, count in self.protocol_counts.items():
                protocol_percentages[proto] = (count / self.total_packets * 100) if self.total_packets > 0 else 0
            
            # Top talkers (by total traffic)
            top_talkers = sorted(
                self.traffic_stats.values(),
                key=lambda s: s.bytes_sent + s.bytes_received,
                reverse=True
            )[:10]
            
            # Top ports
            top_ports = sorted(
                self.port_activity.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
            
            stats = {
                'total_packets': self.total_packets,
                'total_bytes': self.total_bytes,
                'bytes_per_second': bytes_per_second,
                'packets_per_second': packets_per_second,
                'protocol_counts': dict(self.protocol_counts),
                'protocol_percentages': protocol_percentages,
                'unique_ips': len(self.traffic_stats),
                'uptime_seconds': elapsed_time,
                'top_talkers': [
                    {
                        'ip': t.ip,
                        'bytes_sent': t.bytes_sent,
                        'bytes_received': t.bytes_received,
                        'total_bytes': t.bytes_sent + t.bytes_received,
                        'packets_sent': t.packets_sent,
                        'packets_received': t.packets_received
                    }
                    for t in top_talkers
                ],
                'top_ports': [{'port': port, 'count': count} for port, count in top_ports]
            }
            
            # Add protocol-specific counts
            stats['tcp_packets'] = self.protocol_counts.get('TCP', 0)
            stats['udp_packets'] = self.protocol_counts.get('UDP', 0)
            stats['icmp_packets'] = self.protocol_counts.get('ICMP', 0)
            stats['arp_packets'] = self.protocol_counts.get('ARP', 0)
            stats['other_packets'] = self.total_packets - (
                stats['tcp_packets'] + stats['udp_packets'] + 
                stats['icmp_packets'] + stats['arp_packets']
            )
            
            return stats
    
    def get_ip_statistics(self, ip: str) -> Optional[Dict]:
        """
        Get statistics for a specific IP.
        
        Args:
            ip: IP address
            
        Returns:
            Statistics for the IP or None
        """
        if ip not in self.traffic_stats:
            return None
        
        stats = self.traffic_stats[ip]
        
        return {
            'ip': stats.ip,
            'packets_sent': stats.packets_sent,
            'packets_received': stats.packets_received,
            'bytes_sent': stats.bytes_sent,
            'bytes_received': stats.bytes_received,
            'total_bytes': stats.bytes_sent + stats.bytes_received,
            'protocols': dict(stats.protocols),
            'first_seen': stats.first_seen.isoformat(),
            'last_seen': stats.last_seen.isoformat()
        }
    
    def get_top_talkers(self, limit: int = 10) -> List[Dict]:
        """
        Get top talkers by traffic volume.
        
        Args:
            limit: Number of results to return
            
        Returns:
            List of top talkers
        """
        sorted_talkers = sorted(
            self.traffic_stats.values(),
            key=lambda s: s.bytes_sent + s.bytes_received,
            reverse=True
        )[:limit]
        
        return [
            {
                'ip': t.ip,
                'total_bytes': t.bytes_sent + t.bytes_received,
                'packets': t.packets_sent + t.packets_received
            }
            for t in sorted_talkers
        ]
    
    def get_protocol_distribution(self) -> Dict[str, Dict]:
        """
        Get protocol distribution with percentages.
        
        Returns:
            Dictionary of protocol statistics
        """
        distribution = {}
        
        for protocol, count in self.protocol_counts.items():
            distribution[protocol] = {
                'count': count,
                'percentage': (count / self.total_packets * 100) if self.total_packets > 0 else 0
            }
        
        return distribution
    
    def get_port_activity(self, limit: int = 20) -> List[Dict]:
        """
        Get most active ports.
        
        Args:
            limit: Number of results to return
            
        Returns:
            List of port activity
        """
        sorted_ports = sorted(
            self.port_activity.items(),
            key=lambda x: x[1],
            reverse=True
        )[:limit]
        
        return [{'port': port, 'count': count} for port, count in sorted_ports]
    
    def start_monitoring(self):
        """Start background monitoring thread."""
        if self.is_monitoring:
            print("Network monitoring already active")
            return
        
        self.is_monitoring = True
        self.start_time = datetime.now()
        
        def monitor_thread():
            while self.is_monitoring:
                # Record bandwidth sample
                self._record_bandwidth_sample()
                time.sleep(self.bandwidth_interval)
        
        self.monitor_thread = threading.Thread(target=monitor_thread, daemon=True)
        self.monitor_thread.start()
        
        print("Started network monitoring")
    
    def stop_monitoring(self):
        """Stop background monitoring."""
        self.is_monitoring = False
        print("Stopped network monitoring")
    
    def _record_bandwidth_sample(self):
        """Record a bandwidth sample for trend analysis."""
        current_time = datetime.now()
        
        with self._lock:
            elapsed = (current_time - self.last_update).total_seconds()
            
            if elapsed > 0:
                sample = {
                    'timestamp': current_time.isoformat(),
                    'total_bytes': self.total_bytes,
                    'total_packets': self.total_packets,
                    'bytes_per_second': (self.total_bytes - self._last_bytes) / elapsed,
                    'packets_per_second': (self.total_packets - self._last_packets) / elapsed
                }
                
                self.bandwidth_samples.append(sample)
                
                # Keep only last 100 samples
                if len(self.bandwidth_samples) > 100:
                    self.bandwidth_samples = self.bandwidth_samples[-100:]
            
            self._last_bytes = self.total_bytes
            self._last_packets = self.total_packets
            self.last_update = current_time
    
    def get_bandwidth_history(self) -> List[Dict]:
        """Get bandwidth history samples."""
        return self.bandwidth_samples
    
    def clear_statistics(self):
        """Clear all statistics."""
        with self._lock:
            self.traffic_stats.clear()
            self.protocol_counts.clear()
            self.port_activity.clear()
            self.bandwidth_samples.clear()
            self.total_bytes = 0
            self.total_packets = 0
            self._last_bytes = 0
            self._last_packets = 0
            self.start_time = datetime.now()
        print("Cleared network statistics")
    
    def print_statistics(self):
        """Print current traffic statistics."""
        stats = self.get_statistics()
        
        print("\n" + "="*70)
        print("  NETWORK TRAFFIC STATISTICS")
        print("="*70)
        print(f"  Uptime: {stats['uptime_seconds']:.0f} seconds")
        print(f"  Total Packets: {stats['total_packets']:,}")
        print(f"  Total Bytes: {stats['total_bytes']:,}")
        print(f"  Bandwidth: {stats['bytes_per_second']:,.2f} bytes/sec")
        print(f"  Packets/sec: {stats['packets_per_second']:.2f}")
        print("-"*70)
        
        print("  Protocol Distribution:")
        for proto, count in sorted(stats['protocol_counts'].items(), 
                                   key=lambda x: x[1], reverse=True):
            percentage = stats['protocol_percentages'].get(proto, 0)
            print(f"    {proto:<10} {count:>10,} ({percentage:>5.1f}%)")
        
        print("-"*70)
        print("  Top Talkers:")
        for talker in stats['top_talkers'][:5]:
            print(f"    {talker['ip']:<20} {talker['total_bytes']:>10,} bytes")
        
        print("="*70 + "\n")
    
    def print_top_talkers(self, limit: int = 10):
        """Print top talkers."""
        talkers = self.get_top_talkers(limit)
        
        print("\n" + "="*70)
        print("  TOP TALKERS (by traffic volume)")
        print("="*70)
        print(f"  {'IP Address':<20} {'Total Bytes':>12} {'Packets':>10}")
        print("-"*70)
        
        for talker in talkers:
            print(f"  {talker['ip']:<20} {talker['total_bytes']:>12,} {talker['packets']:>10,}")
        
        print("="*70 + "\n")
    
    def print_protocol_distribution(self):
        """Print protocol distribution."""
        distribution = self.get_protocol_distribution()
        
        print("\n" + "="*70)
        print("  PROTOCOL DISTRIBUTION")
        print("="*70)
        
        for protocol, stats in sorted(distribution.items(), 
                                      key=lambda x: x[1]['count'], reverse=True):
            count = stats['count']
            percentage = stats['percentage']
            bar_length = int(percentage / 2)  # Scale bar
            bar = '█' * bar_length
            
            print(f"  {protocol:<10} {count:>8,} ({percentage:>5.1f}%) {bar}")
        
        print("="*70 + "\n")
