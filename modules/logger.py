"""
Logging and Notification Module
===============================

Handles console output, file logging, SQLite storage, and notifications.
"""

import os
import sys
import time
import json
import sqlite3
import logging
import threading
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Dict, List, Optional, Any
from pathlib import Path

DB_COMMIT_BATCH_SIZE = 50
DB_COMMIT_INTERVAL = 2.0


class Color:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    # Basic colors
    BLACK = '\033[30m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    # Bright versions
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Background colors
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'


class Logger:
    """
    Comprehensive logging system with console, file, SQLite, and notification support.
    """
    
    def __init__(self, config: Dict = None):
        """
        Initialize the logger.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.log_config = self.config.get('logging', {})
        self.notif_config = self.config.get('notifications', {})
        
        # Setup directories
        self.log_dir = self.log_config.get('log_dir', 'logs')
        self.capture_dir = self.log_config.get('capture_dir', 'captures')
        self._ensure_directories()
        
        # SQLite thread safety
        self._db_lock = threading.Lock()
        self._pending_commits = 0
        self._last_commit_time = time.time()
        
        # Setup logging
        self._setup_file_logger()
        self._setup_sqlite()
        
        # Notification rate limiting
        self._last_notification = {}
        self._notification_rate_limit = self.notif_config.get('rate_limit', 60)
        
        # Statistics
        self.stats = {
            'packets_captured': 0,
            'arp_requests': 0,
            'arp_replies': 0,
            'suspicious_arps': 0,
            'alerts': 0,
            'start_time': datetime.now()
        }
    
    def _ensure_directories(self):
        """Create log and capture directories if they don't exist."""
        Path(self.log_dir).mkdir(parents=True, exist_ok=True)
        Path(self.capture_dir).mkdir(parents=True, exist_ok=True)
    
    def _setup_file_logger(self):
        """Setup rotating file logger."""
        self.file_logger = logging.getLogger('ARPDefender')
        self.file_logger.setLevel(getattr(logging, self.log_config.get('log_level', 'INFO').upper()))
        self.file_logger.propagate = False
        
        # Clear all handlers to prevent duplicates on re-init
        self.file_logger.handlers.clear()
        
        # File handler with rotation
        log_file = os.path.join(self.log_dir, 'ARPDefender.log')
        max_bytes = self.log_config.get('max_log_size', 10) * 1024 * 1024  # Convert MB to bytes
        backup_count = self.log_config.get('max_log_files', 5)
        
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        self.file_logger.addHandler(file_handler)
        
        # Console handler
        if self.log_config.get('console', True):
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            self.file_logger.addHandler(console_handler)
    
    def _setup_sqlite(self):
        """Setup SQLite database for historical data."""
        self.db_enabled = self.log_config.get('sqlite', True)
        
        if self.db_enabled:
            db_path = os.path.join(self.log_dir, 'ARPDefender.db')
            self.conn = sqlite3.connect(db_path, check_same_thread=False)
            self.cursor = self.conn.cursor()
            
            # Create tables
            self._create_tables()
    
    def _create_tables(self):
        """Create SQLite tables if they don't exist."""
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                protocol TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                size INTEGER,
                source_mac TEXT,
                destination_mac TEXT,
                info TEXT
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS arp_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                mac_address TEXT NOT NULL,
                is_suspicious INTEGER DEFAULT 0,
                alert_type TEXT,
                details TEXT
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                message TEXT NOT NULL,
                details TEXT
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                interface TEXT,
                total_packets INTEGER,
                total_bytes INTEGER,
                tcp_packets INTEGER,
                udp_packets INTEGER,
                icmp_packets INTEGER,
                arp_packets INTEGER,
                other_packets INTEGER
            )
        ''')
        
        self.conn.commit()
    
    def _batch_commit(self, force: bool = False):
        """Commit pending DB changes, batching for performance."""
        self._pending_commits += 1
        current_time = time.time()
        elapsed = current_time - self._last_commit_time
        
        if force or self._pending_commits >= DB_COMMIT_BATCH_SIZE or elapsed >= DB_COMMIT_INTERVAL:
            with self._db_lock:
                try:
                    self.conn.commit()
                    self._pending_commits = 0
                    self._last_commit_time = current_time
                except Exception as e:
                    self.file_logger.error(f"Database commit error: {e}")
    
    def log_packet(self, packet_info: Dict):
        """
        Log a captured packet.
        
        Args:
            packet_info: Dictionary containing packet details
        """
        self.stats['packets_captured'] += 1
        
        # Log to file
        if self.log_config.get('file', True):
            self.file_logger.info(f"Packet: {packet_info.get('source_ip')} -> {packet_info.get('destination_ip')} "
                                 f"[{packet_info.get('protocol')}] {packet_info.get('size')} bytes")
        
        # Log to SQLite
        if self.db_enabled:
            with self._db_lock:
                self.cursor.execute('''
                    INSERT INTO packets (timestamp, source_ip, destination_ip, protocol, 
                                        source_port, destination_port, size, source_mac, 
                                        destination_mac, info)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    datetime.now().isoformat(),
                    packet_info.get('source_ip'),
                    packet_info.get('destination_ip'),
                    packet_info.get('protocol'),
                    packet_info.get('source_port'),
                    packet_info.get('destination_port'),
                    packet_info.get('size'),
                    packet_info.get('source_mac'),
                    packet_info.get('destination_mac'),
                    packet_info.get('info')
                ))
            self._batch_commit()
    
    def log_arp_entry(self, ip: str, mac: str, is_suspicious: bool = False, 
                     alert_type: str = None, details: str = None):
        """
        Log an ARP entry.
        
        Args:
            ip: IP address
            mac: MAC address
            is_suspicious: Whether this entry is suspicious
            alert_type: Type of alert (if suspicious)
            details: Additional details
        """
        if is_suspicious:
            self.stats['suspicious_arps'] += 1
        
        # Log to SQLite
        if self.db_enabled:
            with self._db_lock:
                self.cursor.execute('''
                    INSERT INTO arp_entries (timestamp, ip_address, mac_address, 
                                            is_suspicious, alert_type, details)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    datetime.now().isoformat(),
                    ip,
                    mac,
                    1 if is_suspicious else 0,
                    alert_type,
                    details
                ))
            self._batch_commit()
    
    def log_alert(self, alert_type: str, severity: str, message: str,
                 source_ip: str = None, destination_ip: str = None, 
                 details: Dict = None):
        """
        Log a security alert.
        
        Args:
            alert_type: Type of alert (arp_suspicious, arp_critical, intrusion, etc.)
            severity: Alert severity (LOW, MEDIUM, HIGH, CRITICAL)
            message: Alert message
            source_ip: Source IP address
            destination_ip: Destination IP address
            details: Additional details
        """
        self.stats['alerts'] += 1
        
        # Console output with color
        if self.log_config.get('console', True):
            self._print_alert(alert_type, severity, message, source_ip, destination_ip)
        
        # Log to file
        self.file_logger.warning(f"ALERT [{severity}] {alert_type}: {message}")
        
        # Log to SQLite
        if self.db_enabled:
            with self._db_lock:
                self.cursor.execute('''
                    INSERT INTO alerts (timestamp, alert_type, severity, source_ip, 
                                       destination_ip, message, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    datetime.now().isoformat(),
                    alert_type,
                    severity,
                    source_ip,
                    destination_ip,
                    message,
                    json.dumps(details) if details else None
                ))
            self._batch_commit()
        
        # Send notifications
        self._send_notifications(alert_type, severity, message, source_ip, 
                               destination_ip, details)
    
    def _print_alert(self, alert_type: str, severity: str, message: str,
                    source_ip: str = None, destination_ip: str = None):
        """Print alert to console with color coding."""
        if not self.log_config.get('colors', True):
            # Plain text output
            alert_line = f"[{severity}] {alert_type}: {message}"
            if source_ip:
                alert_line += f" (Source: {source_ip})"
            if destination_ip:
                alert_line += f" -> {destination_ip}"
            print(alert_line)
            return
        
        # Color-coded output
        color = Color.RESET
        if severity == 'CRITICAL':
            color = Color.BG_RED + Color.BRIGHT_WHITE
        elif severity == 'HIGH':
            color = Color.RED
        elif severity == 'MEDIUM':
            color = Color.YELLOW
        elif severity == 'LOW':
            color = Color.CYAN
        
        print(f"\n{color}{'='*60}{Color.RESET}")
        print(f"{color}  ALERT: {alert_type.upper()}{Color.RESET}")
        print(f"{color}  Severity: {severity}{Color.RESET}")
        print(f"{color}  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Color.RESET}")
        if source_ip:
            print(f"{color}  Source: {source_ip}{Color.RESET}")
        if destination_ip:
            print(f"{color}  Destination: {destination_ip}{Color.RESET}")
        print(f"{color}  Message: {message}{Color.RESET}")
        print(f"{color}{'='*60}{Color.RESET}\n")
    
    def _send_notifications(self, alert_type: str, severity: str, message: str,
                          source_ip: str = None, destination_ip: str = None,
                          details: Dict = None):
        """Send notifications via Discord/Telegram if configured."""
        # Check if notification is needed for this alert type
        discord_config = self.notif_config.get('discord', {})
        telegram_config = self.notif_config.get('telegram', {})
        
        # Check rate limiting
        current_time = time.time()
        last_time = self._last_notification.get(alert_type, 0)
        if current_time - last_time < self._notification_rate_limit:
            return
        
        # Send Discord notification
        if discord_config.get('enabled', False):
            if alert_type in discord_config.get('alert_types', []):
                self._send_discord_notification(
                    discord_config.get('webhook_url'),
                    alert_type, severity, message, source_ip, destination_ip, details
                )
                self._last_notification[alert_type] = current_time
        
        # Send Telegram notification
        if telegram_config.get('enabled', False):
            if alert_type in telegram_config.get('alert_types', []):
                self._send_telegram_notification(
                    telegram_config.get('bot_token'),
                    telegram_config.get('chat_id'),
                    alert_type, severity, message, source_ip, destination_ip, details
                )
                self._last_notification[alert_type] = current_time
    
    def _send_discord_notification(self, webhook_url: str, alert_type: str,
                                 severity: str, message: str, source_ip: str = None,
                                 destination_ip: str = None, details: Dict = None):
        """Send notification via Discord webhook."""
        if not webhook_url:
            return
        
        try:
            import requests
            
            # Color mapping
            color_map = {
                'CRITICAL': 0xFF0000,  # Red
                'HIGH': 0xFF6600,      # Orange
                'MEDIUM': 0xFFFF00,    # Yellow
                'LOW': 0x00FF00        # Green
            }
            
            embed = {
                'title': f'🚨 Security Alert: {alert_type.upper()}',
                'description': message,
                'color': color_map.get(severity, 0x808080),
                'fields': [
                    {'name': 'Severity', 'value': severity, 'inline': True},
                    {'name': 'Time', 'value': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'inline': True}
                ],
                'footer': {'text': 'ARPDefender'}
            }
            
            if source_ip:
                embed['fields'].append({'name': 'Source IP', 'value': source_ip, 'inline': True})
            if destination_ip:
                embed['fields'].append({'name': 'Destination IP', 'value': destination_ip, 'inline': True})
            
            payload = {'embeds': [embed]}
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            if response.status_code != 204:
                self.file_logger.error(f"Failed to send Discord notification: {response.status_code}")
                
        except Exception as e:
            self.file_logger.error(f"Error sending Discord notification: {e}")
    
    def _send_telegram_notification(self, bot_token: str, chat_id: str,
                                  alert_type: str, severity: str, message: str,
                                  source_ip: str = None, destination_ip: str = None,
                                  details: Dict = None):
        """Send notification via Telegram bot."""
        if not bot_token or not chat_id:
            return
        
        try:
            import requests
            
            text = f"🚨 *Security Alert: {alert_type.upper()}*\n\n"
            text += f"*Severity:* {severity}\n"
            text += f"*Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            if source_ip:
                text += f"*Source IP:* {source_ip}\n"
            if destination_ip:
                text += f"*Destination IP:* {destination_ip}\n"
            text += f"\n*Message:* {message}\n"
            
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            payload = {
                'chat_id': chat_id,
                'text': text,
                'parse_mode': 'Markdown'
            }
            
            response = requests.post(url, json=payload, timeout=10)
            if response.status_code != 200:
                self.file_logger.error(f"Failed to send Telegram notification: {response.status_code}")
                
        except Exception as e:
            self.file_logger.error(f"Error sending Telegram notification: {e}")
    
    def log_statistics(self, interface: str, stats: Dict):
        """
        Log traffic statistics.
        
        Args:
            interface: Network interface name
            stats: Statistics dictionary
        """
        if self.db_enabled:
            with self._db_lock:
                self.cursor.execute('''
                    INSERT INTO traffic_stats (timestamp, interface, total_packets, total_bytes,
                                             tcp_packets, udp_packets, icmp_packets, 
                                             arp_packets, other_packets)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    datetime.now().isoformat(),
                    interface,
                    stats.get('total_packets', 0),
                    stats.get('total_bytes', 0),
                    stats.get('tcp_packets', 0),
                    stats.get('udp_packets', 0),
                    stats.get('icmp_packets', 0),
                    stats.get('arp_packets', 0),
                    stats.get('other_packets', 0)
                ))
            self._batch_commit(force=True)
    
    def get_statistics(self) -> Dict:
        """Get current statistics."""
        return {
            **self.stats,
            'uptime': str(datetime.now() - self.stats['start_time'])
        }
    
    def get_arp_entries(self, hours: int = 24, suspicious_only: bool = False) -> List[Dict]:
        """
        Get ARP entries from the database.
        
        Args:
            hours: Number of hours to look back
            suspicious_only: Only return suspicious entries
            
        Returns:
            List of ARP entry dictionaries
        """
        if not self.db_enabled:
            return []
        
        query = "SELECT * FROM arp_entries WHERE timestamp >= datetime('now', ?)"
        params = [f'-{hours} hours']
        
        if suspicious_only:
            query += " AND is_suspicious = 1"
        
        query += " ORDER BY timestamp DESC"
        
        with self._db_lock:
            self.cursor.execute(query, params)
            columns = [description[0] for description in self.cursor.description]
            rows = self.cursor.fetchall()
        
        return [dict(zip(columns, row)) for row in rows]
    
    def get_alerts(self, hours: int = 24, severity: str = None) -> List[Dict]:
        """
        Get alerts from the database.
        
        Args:
            hours: Number of hours to look back
            severity: Filter by severity level
            
        Returns:
            List of alert dictionaries
        """
        if not self.db_enabled:
            return []
        
        query = "SELECT * FROM alerts WHERE timestamp >= datetime('now', ?)"
        params = [f'-{hours} hours']
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        query += " ORDER BY timestamp DESC"
        
        with self._db_lock:
            self.cursor.execute(query, params)
            columns = [description[0] for description in self.cursor.description]
            rows = self.cursor.fetchall()
        
        return [dict(zip(columns, row)) for row in rows]
    
    def print_banner(self, interface: str):
        """Print the application banner."""
        banner = f"""
{Color.CYAN}{Color.BOLD}
╔══════════════════════════════════════════════════════════════════╗
║                     ARPDefender - Version 1.0.0                  ║
║          Advanced ARP Spoofing Detection & Network Monitor       ║
╠══════════════════════════════════════════════════════════════════╣
║  For authorized security monitoring only.                       ║
║  Unauthorized use is illegal and prohibited.                    ║
╚══════════════════════════════════════════════════════════════════╝
{Color.RESET}
{Color.GREEN}Interface: {interface}{Color.RESET}
{Color.YELLOW}Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Color.RESET}
"""
        print(banner)
    
    def print_legal_notice(self):
        """Print legal notice and require acceptance."""
        notice = f"""
{Color.BG_YELLOW}{Color.BLACK}{Color.BOLD}
╔══════════════════════════════════════════════════════════════════╗
║                        LEGAL NOTICE                             ║
╠══════════════════════════════════════════════════════════════════╣
║  This tool is for AUTHORIZED SECURITY MONITORING ONLY.          ║
║                                                                  ║
║  - You MUST own the network or have EXPLICIT PERMISSION         ║
║  - Unauthorized network monitoring is ILLEGAL                   ║
║  - Run this tool only on networks you OWN or have AUTHORIZATION  ║
║  - The developers are NOT responsible for misuse                 ║
║                                                                  ║
║  By using this tool, you agree to comply with all applicable     ║
║  laws and regulations in your jurisdiction.                      ║
╚══════════════════════════════════════════════════════════════════╝
{Color.RESET}
"""
        print(notice)
    
    def print_packet(self, packet_info: Dict):
        """Print packet information to console."""
        if not self.log_config.get('console', True):
            return
        
        src_ip = packet_info.get('source_ip', 'N/A')
        dst_ip = packet_info.get('destination_ip', 'N/A')
        protocol = packet_info.get('protocol', 'N/A')
        size = packet_info.get('size', 0)
        src_port = packet_info.get('source_port', '')
        dst_port = packet_info.get('destination_port', '')
        
        # Color based on protocol
        color = Color.WHITE
        if protocol == 'ARP':
            color = Color.MAGENTA
        elif protocol == 'TCP':
            color = Color.CYAN
        elif protocol == 'UDP':
            color = Color.GREEN
        elif protocol == 'ICMP':
            color = Color.YELLOW
        
        # Format port info
        port_info = ''
        if src_port and dst_port:
            port_info = f" :{src_port}->{dst_port}"
        
        print(f"{color}[{protocol}]{Color.RESET} {src_ip} -> {dst_ip}{port_info} ({size} bytes)")
    
    def print_stats(self, stats: Dict):
        """Print statistics to console."""
        if not self.log_config.get('console', True):
            return
        
        print(f"\n{Color.CYAN}{'='*60}{Color.RESET}")
        print(f"{Color.CYAN}  STATISTICS{Color.RESET}")
        print(f"{Color.CYAN}{'='*60}{Color.RESET}")
        print(f"  Packets: {stats.get('total_packets', 0)}")
        print(f"  Bytes: {stats.get('total_bytes', 0):,}")
        print(f"  TCP: {stats.get('tcp_packets', 0)}")
        print(f"  UDP: {stats.get('udp_packets', 0)}")
        print(f"  ICMP: {stats.get('icmp_packets', 0)}")
        print(f"  ARP: {stats.get('arp_packets', 0)}")
        print(f"{Color.CYAN}{'='*60}{Color.RESET}\n")
    
    def close(self):
        """Close database connection."""
        if self.db_enabled:
            # Flush any pending commits
            self._batch_commit(force=True)
            with self._db_lock:
                self.conn.close()
