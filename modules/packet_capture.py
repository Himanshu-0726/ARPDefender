"""
Packet Capture Module
=====================

Core packet capture functionality using Scapy library.
"""

import os
import threading
from datetime import datetime
from typing import Dict, List, Optional, Callable
from pathlib import Path

try:
    from scapy.all import (
        sniff, wrpcap, rdpcap,
        IP, IPv6, TCP, UDP, ICMP, ARP,
        DNS, DNSQR, DNSRR,
        Ether, Raw
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not installed. Install with: pip install scapy")

from .utils import (
    get_interfaces, get_default_interface, validate_interface,
    get_protocol_name, get_port_service, get_mac_vendor
)

MAX_CAPTURED_PACKETS = 100000


class PacketCapture:
    """
    Network packet capture using Scapy.
    """
    
    def __init__(self, config: Dict = None, logger=None):
        """
        Initialize packet capture.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config or {}
        self.capture_config = self.config.get('network', {})
        self.logger = logger
        
        # Capture state
        self.is_capturing = False
        self.captured_packets = []
        self.packet_count = 0
        self.capture_thread = None
        self._sniff_stop_event = threading.Event()
        
        # Callbacks
        self.packet_callback = None
        
        # Interface
        self.interface = None
        
        # PCAP storage
        self.capture_dir = self.config.get('logging', {}).get('capture_dir', 'captures')
        Path(self.capture_dir).mkdir(parents=True, exist_ok=True)
    
    def set_interface(self, interface: str = None):
        """
        Set the network interface for capture.
        
        Args:
            interface: Interface name (None for auto-detect)
        """
        if interface:
            if validate_interface(interface):
                self.interface = interface
            else:
                raise ValueError(f"Invalid interface: {interface}")
        else:
            self.interface = get_default_interface()
            if not self.interface:
                raise RuntimeError("No network interface found")
    
    def get_interfaces(self) -> List[Dict]:
        """Get list of available network interfaces."""
        return get_interfaces()
    
    def set_packet_callback(self, callback: Callable):
        """
        Set callback function for captured packets.
        
        Args:
            callback: Function to call with packet info dictionary
        """
        self.packet_callback = callback
    
    def _parse_packet(self, packet) -> Optional[Dict]:
        """
        Parse a Scapy packet into a dictionary.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Parsed packet dictionary or None
        """
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'size': len(packet),
            'source_ip': None,
            'destination_ip': None,
            'source_mac': None,
            'destination_mac': None,
            'protocol': None,
            'source_port': None,
            'destination_port': None,
            'info': None,
            'raw_packet': packet
        }
        
        try:
            # Ethernet layer
            if packet.haslayer(Ether):
                ether = packet[Ether]
                packet_info['source_mac'] = ether.src
                packet_info['destination_mac'] = ether.dst
            
            # IP layer
            if packet.haslayer(IP):
                ip = packet[IP]
                packet_info['source_ip'] = ip.src
                packet_info['destination_ip'] = ip.dst
                packet_info['protocol'] = get_protocol_name(ip.proto)
                
            # IPv6 layer
            elif packet.haslayer(IPv6):
                ipv6 = packet[IPv6]
                packet_info['source_ip'] = ipv6.src
                packet_info['destination_ip'] = ipv6.dst
                packet_info['protocol'] = get_protocol_name(ipv6.nh)
            
            # ARP layer
            if packet.haslayer(ARP):
                arp = packet[ARP]
                packet_info['protocol'] = 'ARP'
                
                if arp.op == 1:  # ARP Request
                    packet_info['info'] = f"Who has {arp.pdst}? Tell {arp.psrc}"
                elif arp.op == 2:  # ARP Reply
                    packet_info['info'] = f"{arp.psrc} is at {arp.hwsrc}"
                
                packet_info['source_ip'] = arp.psrc
                packet_info['destination_ip'] = arp.pdst
                packet_info['source_mac'] = arp.hwsrc
                packet_info['destination_mac'] = arp.hwdst
            
            # TCP layer
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                packet_info['source_port'] = tcp.sport
                packet_info['destination_port'] = tcp.dport
                
                # Get service name
                src_service = get_port_service(tcp.sport, 'tcp')
                dst_service = get_port_service(tcp.dport, 'tcp')
                
                # TCP flags
                flags = []
                if tcp.flags & 0x02: flags.append('SYN')
                if tcp.flags & 0x10: flags.append('ACK')
                if tcp.flags & 0x01: flags.append('FIN')
                if tcp.flags & 0x04: flags.append('RST')
                if tcp.flags & 0x08: flags.append('PSH')
                if tcp.flags & 0x20: flags.append('URG')
                
                packet_info['info'] = f"TCP {','.join(flags)} {src_service}->{dst_service}"
            
            # UDP layer
            if packet.haslayer(UDP):
                udp = packet[UDP]
                packet_info['source_port'] = udp.sport
                packet_info['destination_port'] = udp.dport
                
                # Get service name
                src_service = get_port_service(udp.sport, 'udp')
                dst_service = get_port_service(udp.dport, 'udp')
                
                packet_info['info'] = f"UDP {src_service}->{dst_service}"
            
            # ICMP layer
            if packet.haslayer(ICMP):
                icmp = packet[ICMP]
                
                icmp_types = {
                    0: 'Echo Reply',
                    3: 'Destination Unreachable',
                    5: 'Redirect',
                    8: 'Echo Request',
                    11: 'Time Exceeded'
                }
                
                icmp_type = icmp_types.get(icmp.type, f'Type {icmp.type}')
                packet_info['info'] = f"ICMP {icmp_type} (Code: {icmp.code})"
            
            # DNS layer
            if packet.haslayer(DNS):
                dns = packet[DNS]
                
                if dns.qr == 0:  # DNS Query
                    if packet.haslayer(DNSQR):
                        query = packet[DNSQR]
                        qname = query.qname
                        if isinstance(qname, bytes):
                            qname = qname.decode(errors='replace')
                        packet_info['info'] = f"DNS Query: {qname}"
                else:  # DNS Response
                    if packet.haslayer(DNSRR):
                        rr = packet[DNSRR]
                        rrname = rr.rrname
                        if isinstance(rrname, bytes):
                            rrname = rrname.decode(errors='replace')
                        rdata = rr.rdata
                        if isinstance(rdata, bytes):
                            rdata = rdata.decode(errors='replace')
                        packet_info['info'] = f"DNS Response: {rrname} -> {rdata}"
            
            # Raw data
            if packet.haslayer(Raw):
                raw = packet[Raw]
                packet_info['info'] = f"Raw Data ({len(raw.load)} bytes)"
            
            return packet_info
            
        except Exception as e:
            packet_info['info'] = f"Parse Error: {str(e)}"
            return packet_info
    
    def _packet_handler(self, packet):
        """
        Handle captured packets.
        
        Args:
            packet: Scapy packet object
        """
        self.packet_count += 1
        
        # Parse packet
        packet_info = self._parse_packet(packet)
        
        if packet_info:
            # Store packet (with memory limit)
            if len(self.captured_packets) < MAX_CAPTURED_PACKETS:
                self.captured_packets.append(packet_info)
            
            # Log packet
            if self.logger:
                self.logger.log_packet(packet_info)
            
            # Call callback
            if self.packet_callback:
                self.packet_callback(packet_info)
    
    def start_capture(self, interface: str = None, filter_str: str = None,
                     max_packets: int = 0, promiscuous: bool = True):
        """
        Start packet capture in a background thread.
        
        Args:
            interface: Network interface (None for current interface)
            filter_str: BPF filter string
            max_packets: Maximum packets to capture (0 = unlimited)
            promiscuous: Enable promiscuous mode
        """
        if self.is_capturing:
            print("Already capturing packets")
            return
        
        if not SCAPY_AVAILABLE:
            print("Scapy is not installed. Cannot capture packets.")
            return
        
        # Use specified interface or current interface
        iface = interface or self.interface
        if not iface:
            raise RuntimeError("No interface specified. Use set_interface() first.")
        
        # Build capture arguments
        capture_args = {
            'iface': iface,
            'prn': self._packet_handler,
            'store': False,
            'stop_filter': lambda p: self._sniff_stop_event.is_set()
        }
        
        # Only add filter if non-empty
        if filter_str and filter_str.strip():
            capture_args['filter'] = filter_str
        
        if max_packets > 0:
            capture_args['count'] = max_packets
        
        if promiscuous:
            capture_args['promisc'] = True
        
        # Start capture in background thread
        self.is_capturing = True
        self._sniff_stop_event.clear()
        
        # Don't clear previous packets - preserve them for restart scenarios
        
        def capture_thread():
            try:
                sniff(**capture_args)
            except Exception as e:
                print(f"Capture error: {e}")
            finally:
                self.is_capturing = False
        
        self.capture_thread = threading.Thread(target=capture_thread, daemon=True)
        self.capture_thread.start()
        
        print(f"Started packet capture on {iface}")
    
    def stop_capture(self):
        """Stop packet capture."""
        self._sniff_stop_event.set()
        self.is_capturing = False
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
        print(f"Stopped packet capture. Captured {self.packet_count} packets.")
    
    def save_to_pcap(self, filename: str = None, packets: List = None) -> str:
        """
        Save captured packets to PCAP file.
        
        Args:
            filename: Output filename (None for auto-generated)
            packets: List of packets to save (None for all captured)
            
        Returns:
            Path to saved PCAP file
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is not installed")
        
        # Use provided packets or all captured
        packets_to_save = packets or self.captured_packets
        
        if not packets_to_save:
            print("No packets to save")
            return None
        
        # Generate filename if not provided
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"capture_{timestamp}.pcap"
        
        # Ensure .pcap extension
        if not filename.endswith('.pcap'):
            filename += '.pcap'
        
        # Full path
        filepath = os.path.join(self.capture_dir, filename)
        
        # Extract raw Scapy packets
        raw_packets = []
        for pkt_info in packets_to_save:
            if 'raw_packet' in pkt_info and pkt_info['raw_packet']:
                raw_packets.append(pkt_info['raw_packet'])
        
        if raw_packets:
            wrpcap(filepath, raw_packets)
            print(f"Saved {len(raw_packets)} packets to {filepath}")
            return filepath
        else:
            print("No raw packets to save")
            return None
    
    def load_from_pcap(self, filename: str) -> List[Dict]:
        """
        Load packets from a PCAP file.
        
        Args:
            filename: Path to PCAP file
            
        Returns:
            List of parsed packet dictionaries
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is not installed")
        
        if not os.path.exists(filename):
            raise FileNotFoundError(f"PCAP file not found: {filename}")
        
        try:
            packets = rdpcap(filename)
            parsed_packets = []
            
            for packet in packets:
                packet_info = self._parse_packet(packet)
                if packet_info:
                    parsed_packets.append(packet_info)
            
            print(f"Loaded {len(parsed_packets)} packets from {filename}")
            return parsed_packets
            
        except Exception as e:
            print(f"Error loading PCAP: {e}")
            return []
    
    def get_capture_stats(self) -> Dict:
        """Get capture statistics."""
        stats = {
            'is_capturing': self.is_capturing,
            'packet_count': self.packet_count,
            'captured_packets': len(self.captured_packets),
            'interface': self.interface
        }
        
        # Protocol breakdown
        protocol_counts = {}
        for pkt in self.captured_packets:
            proto = pkt.get('protocol', 'Unknown')
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
        
        stats['protocol_counts'] = protocol_counts
        
        return stats
    
    def clear_captured_packets(self):
        """Clear all captured packets from memory."""
        self.captured_packets.clear()
        self.packet_count = 0
        print("Cleared captured packets")
    
    def filter_packets(self, protocol: str = None, src_ip: str = None,
                      dst_ip: str = None, port: int = None) -> List[Dict]:
        """
        Filter captured packets.
        
        Args:
            protocol: Filter by protocol (TCP, UDP, ICMP, ARP)
            src_ip: Filter by source IP
            dst_ip: Filter by destination IP
            port: Filter by port number
            
        Returns:
            List of filtered packet dictionaries
        """
        filtered = self.captured_packets.copy()
        
        if protocol:
            filtered = [p for p in filtered if p.get('protocol', '').upper() == protocol.upper()]
        
        if src_ip:
            filtered = [p for p in filtered if p.get('source_ip') == src_ip]
        
        if dst_ip:
            filtered = [p for p in filtered if p.get('destination_ip') == dst_ip]
        
        if port:
            filtered = [p for p in filtered if 
                       p.get('source_port') == port or p.get('destination_port') == port]
        
        return filtered
