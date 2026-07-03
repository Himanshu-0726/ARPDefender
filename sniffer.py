#!/usr/bin/env python3
"""
ARPDefender - Advanced ARP Spoofing Detection & Network Security Monitor
========================================================================

A comprehensive network security monitoring tool for authorized use only.

This tool captures network packets, analyzes traffic, and detects ARP spoofing
attacks by monitoring IP-to-MAC address mappings.

IMPORTANT: This tool is for authorized security monitoring only.
Unauthorized use against networks you do not own is illegal and prohibited.

Usage:
    python sniffer.py --accept-terms [options]

Options:
    --accept-terms      Accept legal terms (required to run)
    --interface NAME    Network interface to monitor
    --arp-only          Only run ARP spoofing detection
    --save FILENAME     Save captured packets to PCAP file
    --config FILE       Path to config file
    --verbose           Show detailed packet information
    --quiet             Suppress console output
    --list-interfaces   List available network interfaces
"""

import os
import sys
import signal
import argparse
import time
from datetime import datetime
from typing import Dict

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    print("Warning: PyYAML not installed. Using default config. Install with: pip install pyyaml")

from modules.packet_capture import PacketCapture
from modules.arp_detector import ARPDetector
from modules.network_monitor import NetworkMonitor
from modules.logger import Logger


class PacketSniffer:
    """
    Main application class for the Packet Sniffer + ARP Spoofing Detector.
    """
    
    def __init__(self, config: dict = None):
        """
        Initialize the packet sniffer.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.running = False
        self._stopped = False
        
        # Initialize components
        self.logger = Logger(self.config)
        self.capture = PacketCapture(self.config, self.logger)
        self.arp_detector = ARPDetector(self.config, self.logger)
        self.network_monitor = NetworkMonitor(self.config, self.logger)
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        print("\n\nShutting down gracefully...")
        self.running = False
        self.stop()
        sys.exit(0)
    
    def _packet_callback(self, packet_info: Dict):
        """
        Callback for captured packets.
        
        Args:
            packet_info: Packet information dictionary
        """
        # Process packet for network statistics
        self.network_monitor.process_packet(packet_info)
        
        # Check if this is an ARP packet
        if packet_info.get('protocol') == 'ARP':
            self.arp_detector.process_arp_packet(packet_info)
        
        # Print packet if verbose mode
        if self.config.get('verbose', False):
            self.logger.print_packet(packet_info)
    
    def list_interfaces(self):
        """List available network interfaces."""
        interfaces = self.capture.get_interfaces()
        
        print("\nAvailable Network Interfaces:")
        print("-" * 50)
        
        for iface in interfaces:
            status = "UP" if iface.get('is_up') else "DOWN"
            ipv4 = iface.get('ipv4', 'N/A')
            mac = iface.get('mac', 'N/A')
            
            print(f"\n  Interface: {iface['name']}")
            print(f"  Status: {status}")
            print(f"  IPv4: {ipv4}")
            print(f"  MAC: {mac}")
        
        print("\n" + "-" * 50 + "\n")
    
    def start(self, interface: str = None,
             save_file: str = None, verbose: bool = False, quiet: bool = False):
        """
        Start packet capture and monitoring.
        
        Args:
            interface: Network interface name (None for auto-detect)
            save_file: Save captured packets to this file
            verbose: Show detailed packet information
            quiet: Suppress console output
        """
        # Update config
        self.config['verbose'] = verbose
        self.config['quiet'] = quiet
        
        # Print legal notice
        self.logger.print_legal_notice()
        
        try:
            # Set interface
            self.capture.set_interface(interface)
            interface_name = self.capture.interface
            
            # Print banner
            self.logger.print_banner(interface_name)
            
            # Set packet callback
            self.capture.set_packet_callback(self._packet_callback)
            
            # Start ARP monitoring
            self.arp_detector.start_monitoring()
            
            # Start network monitoring
            self.network_monitor.start_monitoring()
            
            # Start packet capture
            self.capture.start_capture(
                    interface=interface_name,
                    filter_str=self.config.get('network', {}).get('capture_filters', ''),
                    max_packets=self.config.get('network', {}).get('max_packets', 0),
                    promiscuous=self.config.get('network', {}).get('promiscuous', True)
                )
            
            self.running = True
            
            print(f"\nMonitoring started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("Press Ctrl+C to stop...\n")
            
            # Main loop
            self._main_loop(save_file)
            
        except Exception as e:
            print(f"Error starting packet sniffer: {e}")
            self.stop()
            raise
    
    def _main_loop(self, save_file: str = None):
        """
        Main application loop.
        
        Args:
            save_file: Save captured packets to this file on exit
        """
        refresh_rate = self.config.get('display', {}).get('refresh_rate', 5)
        
        try:
            while self.running:
                time.sleep(refresh_rate)
                
                # Show ARP table if configured
                if self.config.get('display', {}).get('show_arp_table', False):
                    self.arp_detector.print_arp_table()
                
                # Show statistics if configured
                if self.config.get('display', {}).get('show_stats', True):
                    stats = self.network_monitor.get_statistics()
                    self.logger.print_stats(stats)
                
                # Show suspicious entries
                suspicious = self.arp_detector.get_suspicious_entries()
                if suspicious:
                    self.arp_detector.print_suspicious()
                    
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
            
            # Save captures if requested
            if save_file:
                self.capture.save_to_pcap(save_file)
    
    def stop(self):
        """Stop all monitoring and capture."""
        if self._stopped:
            return
        self._stopped = True
        self.running = False
        
        # Stop packet capture
        if self.capture.is_capturing:
            self.capture.stop_capture()
        
        # Stop ARP monitoring
        if self.arp_detector.is_monitoring:
            self.arp_detector.stop_monitoring()
        
        # Stop network monitoring
        if self.network_monitor.is_monitoring:
            self.network_monitor.stop_monitoring()
        
        # Print final statistics
        print("\n" + "="*60)
        print("  FINAL STATISTICS")
        print("="*60)
        
        stats = self.network_monitor.get_statistics()
        print(f"  Total Packets: {stats['total_packets']:,}")
        print(f"  Total Bytes: {stats['total_bytes']:,}")
        print(f"  Uptime: {stats['uptime_seconds']:.0f} seconds")
        
        arp_stats = self.arp_detector.get_statistics()
        print(f"  ARP Entries: {arp_stats['total_entries']}")
        print(f"  Suspicious Sources: {len(arp_stats['suspicious_sources'])}")
        
        print("="*60)
        
        # Close logger
        self.logger.close()
        
        print("\nPacket sniffer stopped.")
    
    def run_arp_detection_only(self, interface: str = None):
        """
        Run only ARP spoofing detection.
        
        Args:
            interface: Network interface name
        """
        print("\nRunning ARP spoofing detection only...")
        print("This mode monitors ARP traffic for suspicious activity.\n")
        
        # Set interface
        self.capture.set_interface(interface)
        interface_name = self.capture.interface
        
        # Print banner
        self.logger.print_banner(interface_name)
        
        # Start ARP monitoring
        self.arp_detector.start_monitoring()
        
        # Start network monitoring
        self.network_monitor.start_monitoring()
        
        # Start packet capture with ARP filter
        self.capture.set_packet_callback(self._packet_callback)
        self.capture.start_capture(
            interface=interface_name,
            filter_str='arp',
            promiscuous=True
        )
        
        self.running = True
        
        print(f"\nARP monitoring started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("Press Ctrl+C to stop...\n")
        
        try:
            while self.running:
                time.sleep(5)
                
                # Show ARP table
                self.arp_detector.print_arp_table()
                
                # Show suspicious entries
                suspicious = self.arp_detector.get_suspicious_entries()
                if suspicious:
                    self.arp_detector.print_suspicious()
                
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()


def load_config(config_path: str) -> dict:
    """
    Load configuration from YAML file.
    
    Args:
        config_path: Path to config file
        
    Returns:
        Configuration dictionary
    """
    if not YAML_AVAILABLE:
        return {}
    
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        print(f"Config file not found: {config_path}")
        return {}
    except Exception as e:
        print(f"Error loading config: {e}")
        return {}


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Advanced Packet Sniffer + ARP Spoofing Detector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage (auto-detect interface)
  python sniffer.py --accept-terms
  
  # Specify interface
  python sniffer.py --accept-terms --interface "Wi-Fi"
  
  # ARP detection only
  python sniffer.py --accept-terms --arp-only
  
  # Save captures to PCAP file
  python sniffer.py --accept-terms --save capture.pcap
  
  # Verbose mode
  python sniffer.py --accept-terms --verbose
  
  # Use custom config
  python sniffer.py --accept-terms --config my_config.yaml
        """
    )
    
    parser.add_argument('--accept-terms', action='store_true',
                       help='Accept legal terms (required to run)')
    
    parser.add_argument('--interface', '-i', type=str,
                       help='Network interface to monitor')
    
    parser.add_argument('--arp-only', action='store_true',
                       help='Only run ARP spoofing detection')
    
    parser.add_argument('--save', '-s', type=str,
                       help='Save captured packets to PCAP file')
    
    parser.add_argument('--config', '-c', type=str,
                       help='Path to config file')
    
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed packet information')
    
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Suppress console output')
    
    parser.add_argument('--list-interfaces', '-l', action='store_true',
                       help='List available network interfaces')
    
    args = parser.parse_args()
    
    # Check for terms acceptance
    if not args.accept_terms:
        print("\n" + "="*60)
        print("  ERROR: You must accept the legal terms to run this tool.")
        print("="*60)
        print("\n  Usage: python sniffer.py --accept-terms [options]")
        print("\n  This tool is for AUTHORIZED SECURITY MONITORING ONLY.")
        print("  Unauthorized use is illegal and prohibited.")
        print("\n  Run with --help for more information.")
        print("="*60 + "\n")
        sys.exit(1)
    
    # Load configuration
    config = {}
    if args.config:
        config = load_config(args.config)
    else:
        # Try default config locations
        default_configs = ['config.yaml', 'config.yml']
        for config_file in default_configs:
            if os.path.exists(config_file):
                config = load_config(config_file)
                break
    
    # Initialize sniffer
    sniffer = PacketSniffer(config)
    
    # List interfaces if requested
    if args.list_interfaces:
        sniffer.list_interfaces()
        sys.exit(0)
    
    # Run sniffer
    try:
        if args.arp_only:
            sniffer.run_arp_detection_only(args.interface)
        else:
            sniffer.start(
                interface=args.interface,
                save_file=args.save,
                verbose=args.verbose,
                quiet=args.quiet
            )
    except Exception as e:
        print(f"\nFatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
