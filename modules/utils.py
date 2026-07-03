"""
Network Utilities Module
========================

Helper functions for network interface detection, validation, and MAC vendor lookup.
"""

import re
import socket
import platform
from typing import Optional, Dict, List


def get_interfaces() -> List[Dict]:
    """
    Get all available network interfaces with their details.
    
    Returns:
        List of dictionaries containing interface information
    """
    interfaces = []
    
    try:
        import psutil
        
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        
        for iface_name, addr_list in addrs.items():
            iface_info = {
                'name': iface_name,
                'addresses': {},
                'mac': None,
                'is_up': False,
                'ipv4': None,
                'ipv6': None,
                'netmask': None,
                'broadcast': None
            }
            
            # Check if interface is up
            if iface_name in stats:
                iface_info['is_up'] = stats[iface_name].isup
            
            # Parse addresses
            import psutil._common as _psutil_common
            for addr in addr_list:
                if addr.family == _psutil_common.AF_LINK or (hasattr(_psutil_common, 'AF_PACKET') and addr.family == _psutil_common.AF_PACKET):
                    iface_info['mac'] = addr.address
                elif addr.family == socket.AF_INET:
                    iface_info['ipv4'] = addr.address
                    iface_info['netmask'] = addr.netmask
                    iface_info['broadcast'] = addr.broadcast
                    iface_info['addresses']['ipv4'] = {'addr': addr.address, 'netmask': addr.netmask, 'broadcast': addr.broadcast}
                elif addr.family == socket.AF_INET6:
                    iface_info['ipv6'] = addr.address
                    iface_info['addresses']['ipv6'] = {'addr': addr.address}
            
            interfaces.append(iface_info)
            
    except ImportError:
        interfaces = _get_interfaces_fallback()
    
    return interfaces


def _get_interfaces_fallback() -> List[Dict]:
    """
    Fallback method to get interfaces without netifaces.
    
    Returns:
        List of interface dictionaries
    """
    interfaces = []
    
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        
        interfaces.append({
            'name': 'default',
            'addresses': {'ipv4': {'addr': ip}},
            'mac': None,
            'is_up': True,
            'ipv4': ip,
            'ipv6': None,
            'netmask': None,
            'broadcast': None
        })
    except Exception:
        pass
    
    return interfaces


def get_default_interface() -> Optional[str]:
    """
    Get the default network interface name.
    
    Returns:
        Interface name or None
    """
    try:
        import psutil
        import psutil._common as _psutil_common
        
        # Get default route via scapy or system command
        # psutil doesn't directly expose gateway info, so use subprocess fallback
        system = platform.system()
        
        if system == "Windows":
            # Parse route print for default gateway interface
            import subprocess
            result = subprocess.run(['route', 'print', '0.0.0.0'], capture_output=True, text=True, timeout=5)
            # Find the interface with the default route
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for line in result.stdout.split('\n'):
                match = re.search(r'0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    gateway_ip = match.group(1)
                    # Find which interface has this gateway's network
                    for iface_name in stats:
                        if stats[iface_name].isup and iface_name in addrs:
                            for addr in addrs[iface_name]:
                                if addr.family == socket.AF_INET and addr.address:
                                    return iface_name
        
        elif system == "Linux":
            import subprocess
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if 'dev' in line:
                    match = re.search(r'dev\s+(\S+)', line)
                    if match:
                        return match.group(1)
        
        elif system == "Darwin":
            import subprocess
            result = subprocess.run(['route', '-n', 'get', 'default'], 
                                  capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if 'interface:' in line:
                    match = re.search(r'interface:\s*(\S+)', line)
                    if match:
                        return match.group(1)
        
        # Fallback: first non-loopback interface that is up
        stats = psutil.net_if_stats()
        for iface_name, stat in stats.items():
            if stat.isup and iface_name not in ('lo', 'lo0', 'loopback'):
                return iface_name
                
    except Exception:
        pass
    
    return None


def validate_interface(interface_name: str) -> bool:
    """
    Validate that an interface exists and is usable.
    
    Args:
        interface_name: Name of the interface to validate
        
    Returns:
        True if interface is valid
    """
    interfaces = get_interfaces()
    interface_names = [iface['name'] for iface in interfaces]
    return interface_name in interface_names


def validate_mac_address(mac: str) -> bool:
    """
    Validate a MAC address format.
    
    Args:
        mac: MAC address string to validate
        
    Returns:
        True if MAC address is valid
    """
    if not mac:
        return False
    
    # Common MAC address formats
    mac_patterns = [
        r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',  # XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
        r'^([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4})$',      # XXXX.XXXX.XXXX
        r'^[0-9A-Fa-f]{12}$'                              # XXXXXXXXXXXX
    ]
    
    return any(re.match(pattern, mac) for pattern in mac_patterns)


def validate_ip_address(ip: str) -> bool:
    """
    Validate an IPv4 address format.
    
    Args:
        ip: IP address string to validate
        
    Returns:
        True if IP address is valid
    """
    if not ip:
        return False
    
    try:
        # Check if it's a valid IPv4 address
        socket.inet_aton(ip)
        
        # Additional validation: check octets
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        for part in parts:
            if not 0 <= int(part) <= 255:
                return False
        
        return True
    except socket.error:
        return False


def normalize_mac(mac: str) -> str:
    """
    Normalize a MAC address to uppercase colon-separated format.
    
    Args:
        mac: MAC address in any format
        
    Returns:
        Normalized MAC address (XX:XX:XX:XX:XX:XX)
    """
    if not mac:
        return ""
    
    # Remove separators and convert to uppercase
    clean = re.sub(r'[:-\.\s]', '', mac).upper()
    
    # Format as XX:XX:XX:XX:XX:XX
    if len(clean) == 12:
        return ':'.join(clean[i:i+2] for i in range(0, 12, 2))
    
    return mac.upper()


def get_mac_vendor(mac: str) -> str:
    """
    Look up the vendor/manufacturer from a MAC address.
    
    Args:
        mac: MAC address
        
    Returns:
        Vendor name or "Unknown"
    """
    if not mac:
        return "Unknown"
    
    # Extract OUI (first 3 bytes)
    normalized = normalize_mac(mac)
    if not normalized:
        return "Unknown"
    
    oui = normalized[:8]
    
    # Common OUI database (partial)
    vendors = {
        # Major manufacturers
        '00:00:00': 'Xerox',
        '00:00:0C': 'Cisco',
        '00:00:0E': 'Fujitsu',
        '00:00:1A': 'AT&T',
        '00:00:1B': 'Cisco',
        '00:00:21': 'SCM Microsystems',
        '00:00:24': 'Cisco',
        '00:00:25': 'DEC',
        '00:00:27': 'Novell',
        '00:00:29': 'Metaphor',
        '00:00:2A': 'Trw',
        '00:00:2E': 'Symmetric Computer Systems',
        '00:00:2F': 'Western Digital',
        '00:00:30': 'Versatech',
        '00:00:31': 'Databus',
        '00:00:32': 'Matsushita',
        '00:00:33': 'Matsushita',
        '00:00:34': 'Matsushita',
        '00:00:35': 'Matsushita',
        '00:00:36': 'Matsushita',
        '00:00:37': 'Oxford Instruments',
        '00:00:38': 'CSS Labs',
        '00:00:39': 'Tulip Computers',
        '00:00:3A': 'AT&T',
        '00:00:3B': 'AT&T',
        '00:00:3C': 'AT&T',
        '00:00:3D': 'AT&T',
        '00:00:3E': 'AT&T',
        '00:00:3F': 'AT&T',
        '00:00:40': 'Balfour',
        '00:00:41': 'ICE',
        '00:00:42': 'Metier',
        '00:00:43': 'Plexus',
        '00:00:44': 'Castelle',
        '00:00:45': 'Ameristar',
        '00:00:46': 'Omniscience',
        '00:00:47': 'Tadiran',
        '00:00:48': 'Epson',
        '00:00:49': 'Siemens',
        '00:00:4A': 'Amdax',
        '00:00:4B': 'Nokia',
        '00:00:4C': 'Nokia',
        '00:00:4D': 'Nokia',
        '00:00:4E': 'Nokia',
        '00:00:4F': 'Nokia',
        '00:00:50': 'Nokia',
        '00:00:51': 'Nokia',
        '00:00:52': 'Nokia',
        '00:00:53': 'Nokia',
        '00:00:54': 'Nokia',
        '00:00:55': 'Nokia',
        '00:00:56': 'Nokia',
        '00:00:57': 'Nokia',
        '00:00:58': 'Nokia',
        '00:00:59': 'Nokia',
        '00:00:5A': 'Nokia',
        '00:00:5B': 'Nokia',
        '00:00:5C': 'Nokia',
        '00:00:5D': 'Nokia',
        '00:00:5E': 'Nokia',
        '00:00:5F': 'Nokia',
        '00:00:60': 'Nokia',
        '00:00:61': 'Nokia',
        '00:00:62': 'Nokia',
        '00:00:63': 'Nokia',
        '00:00:64': 'Nokia',
        '00:00:65': 'Nokia',
        '00:00:66': 'Nokia',
        '00:00:67': 'Nokia',
        '00:00:68': 'Nokia',
        '00:00:69': 'Nokia',
        '00:00:6A': 'Nokia',
        '00:00:6B': 'Nokia',
        '00:00:6C': 'Nokia',
        '00:00:6D': 'Nokia',
        '00:00:6E': 'Nokia',
        '00:00:6F': 'Nokia',
        '00:00:70': 'Nokia',
        '00:00:71': 'Nokia',
        '00:00:72': 'Nokia',
        '00:00:73': 'Nokia',
        '00:00:74': 'Nokia',
        '00:00:75': 'Nokia',
        '00:00:76': 'Nokia',
        '00:00:77': 'Nokia',
        '00:00:78': 'Nokia',
        '00:00:79': 'Nokia',
        '00:00:7A': 'Nokia',
        '00:00:7B': 'Nokia',
        '00:00:7C': 'Nokia',
        '00:00:7D': 'Nokia',
        '00:00:7E': 'Nokia',
        '00:00:7F': 'Nokia',
        '00:00:80': 'Nokia',
        '00:00:81': 'Nokia',
        '00:00:82': 'Nokia',
        '00:00:83': 'Nokia',
        '00:00:84': 'Nokia',
        '00:00:85': 'Nokia',
        '00:00:86': 'Nokia',
        '00:00:87': 'Nokia',
        '00:00:88': 'Nokia',
        '00:00:89': 'Nokia',
        '00:00:8A': 'Nokia',
        '00:00:8B': 'Nokia',
        '00:00:8C': 'Nokia',
        '00:00:8D': 'Nokia',
        '00:00:8E': 'Nokia',
        '00:00:8F': 'Nokia',
        '00:00:90': 'Nokia',
        '00:00:91': 'Nokia',
        '00:00:92': 'Nokia',
        '00:00:93': 'Nokia',
        '00:00:94': 'Nokia',
        '00:00:95': 'Nokia',
        '00:00:96': 'Nokia',
        '00:00:97': 'Nokia',
        '00:00:98': 'Nokia',
        '00:00:99': 'Nokia',
        '00:00:9A': 'Nokia',
        '00:00:9B': 'Nokia',
        '00:00:9C': 'Nokia',
        '00:00:9D': 'Nokia',
        '00:00:9E': 'Nokia',
        '00:00:9F': 'Nokia',
        '00:00:A0': 'Nokia',
        '00:00:A1': 'Nokia',
        '00:00:A2': 'Nokia',
        '00:00:A3': 'Nokia',
        '00:00:A4': 'Nokia',
        '00:00:A5': 'Nokia',
        '00:00:A6': 'Nokia',
        '00:00:A7': 'Nokia',
        '00:00:A8': 'Nokia',
        '00:00:A9': 'Nokia',
        '00:00:AA': 'Nokia',
        '00:00:AB': 'Nokia',
        '00:00:AC': 'Nokia',
        '00:00:AD': 'Nokia',
        '00:00:AE': 'Nokia',
        '00:00:AF': 'Nokia',
        '00:00:B0': 'Nokia',
        '00:00:B1': 'Nokia',
        '00:00:B2': 'Nokia',
        '00:00:B3': 'Nokia',
        '00:00:B4': 'Nokia',
        '00:00:B5': 'Nokia',
        '00:00:B6': 'Nokia',
        '00:00:B7': 'Nokia',
        '00:00:B8': 'Nokia',
        '00:00:B9': 'Nokia',
        '00:00:BA': 'Nokia',
        '00:00:BB': 'Nokia',
        '00:00:BC': 'Nokia',
        '00:00:BD': 'Nokia',
        '00:00:BE': 'Nokia',
        '00:00:BF': 'Nokia',
        '00:00:C0': 'Nokia',
        '00:00:C1': 'Nokia',
        '00:00:C2': 'Nokia',
        '00:00:C3': 'Nokia',
        '00:00:C4': 'Nokia',
        '00:00:C5': 'Nokia',
        '00:00:C6': 'Nokia',
        '00:00:C7': 'Nokia',
        '00:00:C8': 'Nokia',
        '00:00:C9': 'Nokia',
        '00:00:CA': 'Nokia',
        '00:00:CB': 'Nokia',
        '00:00:CC': 'Nokia',
        '00:00:CD': 'Nokia',
        '00:00:CE': 'Nokia',
        '00:00:CF': 'Nokia',
        '00:00:D0': 'Nokia',
        '00:00:D1': 'Nokia',
        '00:00:D2': 'Nokia',
        '00:00:D3': 'Nokia',
        '00:00:D4': 'Nokia',
        '00:00:D5': 'Nokia',
        '00:00:D6': 'Nokia',
        '00:00:D7': 'Nokia',
        '00:00:D8': 'Nokia',
        '00:00:D9': 'Nokia',
        '00:00:DA': 'Nokia',
        '00:00:DB': 'Nokia',
        '00:00:DC': 'Nokia',
        '00:00:DD': 'Nokia',
        '00:00:DE': 'Nokia',
        '00:00:DF': 'Nokia',
        '00:00:E0': 'Nokia',
        '00:00:E1': 'Nokia',
        '00:00:E2': 'Nokia',
        '00:00:E3': 'Nokia',
        '00:00:E4': 'Nokia',
        '00:00:E5': 'Nokia',
        '00:00:E6': 'Nokia',
        '00:00:E7': 'Nokia',
        '00:00:E8': 'Nokia',
        '00:00:E9': 'Nokia',
        '00:00:EA': 'Nokia',
        '00:00:EB': 'Nokia',
        '00:00:EC': 'Nokia',
        '00:00:ED': 'Nokia',
        '00:00:EE': 'Nokia',
        '00:00:EF': 'Nokia',
        '00:00:F0': 'Nokia',
        '00:00:F1': 'Nokia',
        '00:00:F2': 'Nokia',
        '00:00:F3': 'Nokia',
        '00:00:F4': 'Nokia',
        '00:00:F5': 'Nokia',
        '00:00:F6': 'Nokia',
        '00:00:F7': 'Nokia',
        '00:00:F8': 'Nokia',
        '00:00:F9': 'Nokia',
        '00:00:FA': 'Nokia',
        '00:00:FB': 'Nokia',
        '00:00:FC': 'Nokia',
        '00:00:FD': 'Nokia',
        '00:00:FE': 'Nokia',
        '00:00:FF': 'Nokia',
        # Common vendors
        '00:01:02': 'IBM',
        '00:01:42': 'Cisco',
        '00:02:01': 'AMD',
        '00:03:6B': 'Cisco',
        '00:04:5A': 'Cisco',
        '00:06:52': 'Cisco',
        '00:07:0C': 'Cisco',
        '00:08:21': 'Cisco',
        '00:09:11': 'Cisco',
        '00:0A:41': 'Cisco',
        '00:0B:05': 'Cisco',
        '00:0C:07': 'Cisco',
        '00:0D:BC': 'Cisco',
        '00:0E:38': 'Cisco',
        '00:0F:F7': 'Cisco',
        '00:10:11': 'Cisco',
        '00:11:21': 'Cisco',
        '00:12:00': 'Cisco',
        '00:13:19': 'Cisco',
        '00:14:6A': 'Cisco',
        '00:15:5F': 'Cisco',
        '00:16:46': 'Cisco',
        '00:17:0E': 'Cisco',
        '00:18:73': 'Cisco',
        '00:19:2F': 'Cisco',
        '00:1A:2F': 'Cisco',
        '00:1B:0C': 'Cisco',
        '00:1C:0E': 'Cisco',
        '00:1D:45': 'Cisco',
        '00:1E:13': 'Cisco',
        '00:1F:27': 'Cisco',
        '00:21:55': 'Cisco',
        '00:22:55': 'Cisco',
        '00:23:04': 'Cisco',
        '00:24:13': 'Cisco',
        '00:25:45': 'Cisco',
        '00:26:0A': 'Cisco',
        '00:27:0C': 'Cisco',
        '00:28:F8': 'Cisco',
        '00:29:26': 'Cisco',
        '00:2A:10': 'Cisco',
        '00:2B:2C': 'Cisco',
        '00:2C:0C': 'Cisco',
        '00:2D:0C': 'Cisco',
        '00:2E:0C': 'Cisco',
        '00:2F:0C': 'Cisco',
        '00:30:71': 'Cisco',
        '00:40:96': 'Cisco',
        '00:50:56': 'VMware',
        '00:0C:29': 'VMware',
        '00:05:69': 'VMware',
        '00:1C:14': 'VMware',
        '00:0F:4B': 'VirtualBox',
        '08:00:27': 'VirtualBox',
        '52:54:00': 'QEMU/KVM',
        '00:16:3E': 'Xen',
        '00:15:5D': 'Hyper-V',
        '00:18:51': 'Hyper-V',
        # Apple
        '00:03:93': 'Apple',
        '00:06:0B': 'Apple',
        '00:07:09': 'Apple',
        '00:08:00': 'Apple',
        '00:09:6A': 'Apple',
        '00:0A:95': 'Apple',
        '00:0B:12': 'Apple',
        '00:0D:93': 'Apple',
        '00:0E:58': 'Apple',
        '00:10:FA': 'Apple',
        '00:11:24': 'Apple',
        '00:12:00': 'Apple',
        '00:13:00': 'Apple',
        '00:14:51': 'Apple',
        '00:15:30': 'Apple',
        '00:16:CB': 'Apple',
        '00:17:88': 'Apple',
        '00:18:B9': 'Apple',
        '00:19:E3': 'Apple',
        '00:1A:11': 'Apple',
        '00:1B:63': 'Apple',
        '00:1C:B3': 'Apple',
        '00:1D:4F': 'Apple',
        '00:1E:52': 'Apple',
        '00:1F:5B': 'Apple',
        '00:21:E9': 'Apple',
        '00:22:41': 'Apple',
        '00:23:12': 'Apple',
        '00:24:36': 'Apple',
        '00:25:00': 'Apple',
        '00:26:08': 'Apple',
        '00:27:10': 'Apple',
        '00:28:98': 'Apple',
        '00:29:43': 'Apple',
        '00:2A:86': 'Apple',
        '00:2B:C2': 'Apple',
        '00:2C:5D': 'Apple',
        '00:2D:4E': 'Apple',
        '00:2E:3A': 'Apple',
        '00:2F:D7': 'Apple',
        # Microsoft
        '00:0D:3A': 'Microsoft',
        '00:12:5A': 'Microsoft',
        '00:15:5D': 'Microsoft',
        '00:17:FA': 'Microsoft',
        '00:1A:11': 'Microsoft',
        '00:1B:21': 'Microsoft',
        '00:1C:42': 'Microsoft',
        '00:1D:37': 'Microsoft',
        '00:1E:C2': 'Microsoft',
        '00:1F:3B': 'Microsoft',
        '28:18:78': 'Microsoft',
        '30:59:B7': 'Microsoft',
        '58:82:A8': 'Microsoft',
        '60:45:BD': 'Microsoft',
        '7C:1E:52': 'Microsoft',
        'B8:31:B5': 'Microsoft',
        'C8:3F:26': 'Microsoft',
        'DC:B4:C4': 'Microsoft',
        # Google
        '3C:5A:B4': 'Google',
        '54:60:09': 'Google',
        'A4:77:33': 'Google',
        'F4:F5:D8': 'Google',
        # Samsung
        '00:07:AB': 'Samsung',
        '00:21:D1': 'Samsung',
        '00:22:58': 'Samsung',
        '00:23:39': 'Samsung',
        '00:24:54': 'Samsung',
        '00:25:66': 'Samsung',
        '00:26:37': 'Samsung',
        '00:26:5D': 'Samsung',
        # Intel
        '00:02:02': 'Intel',
        '00:02:03': 'Intel',
        '00:02:04': 'Intel',
        '00:02:05': 'Intel',
        '00:02:06': 'Intel',
        '00:02:07': 'Intel',
        '00:02:08': 'Intel',
        '00:02:09': 'Intel',
        '00:02:0A': 'Intel',
        '00:02:0B': 'Intel',
        '00:02:0C': 'Intel',
        '00:02:0D': 'Intel',
        '00:02:0E': 'Intel',
        '00:02:0F': 'Intel',
        '00:11:22': 'Intel',
        '00:13:02': 'Intel',
        '00:15:17': 'Intel',
        '00:16:EA': 'Intel',
        '00:18:8B': 'Intel',
        '00:19:D1': 'Intel',
        '00:1C:23': 'Intel',
        '00:1D:E5': 'Intel',
        '00:1E:65': 'Intel',
        '00:20:21': 'Intel',
        '00:21:5A': 'Intel',
        '00:22:FA': 'Intel',
        '00:23:24': 'Intel',
        '00:24:D6': 'Intel',
        '00:25:AC': 'Intel',
        '00:26:C7': 'Intel',
        '00:27:0F': 'Intel',
        # Dell
        '00:06:5B': 'Dell',
        '00:08:74': 'Dell',
        '00:0A:01': 'Dell',
        '00:0B:DB': 'Dell',
        '00:0C:76': 'Dell',
        '00:0D:56': 'Dell',
        '00:0E:17': 'Dell',
        '00:0F:1F': 'Dell',
        '00:11:43': 'Dell',
        '00:12:3F': 'Dell',
        '00:13:72': 'Dell',
        '00:14:22': 'Dell',
        '00:15:C5': 'Dell',
        '00:16:35': 'Dell',
        '00:17:31': 'Dell',
        '00:19:99': 'Dell',
        '00:1A:A0': 'Dell',
        '00:1B:24': 'Dell',
        '00:1C:43': 'Dell',
        '00:1D:09': 'Dell',
        '00:1E:4F': 'Dell',
        '00:1F:16': 'Dell',
        '00:21:70': 'Dell',
        '00:22:19': 'Dell',
        '00:23:18': 'Dell',
        '00:24:E8': 'Dell',
        '00:26:B9': 'Dell',
        # HP
        '00:02:00': 'HP',
        '00:03:00': 'HP',
        '00:04:00': 'HP',
        '00:05:00': 'HP',
        '00:06:00': 'HP',
        '00:07:00': 'HP',
        '00:08:00': 'HP',
        '00:09:00': 'HP',
        '00:0A:00': 'HP',
        '00:0B:00': 'HP',
        '00:0C:00': 'HP',
        '00:0D:00': 'HP',
        '00:0E:00': 'HP',
        '00:0F:00': 'HP',
        '00:10:00': 'HP',
        '00:11:00': 'HP',
        '00:12:00': 'HP',
        '00:13:00': 'HP',
        '00:14:00': 'HP',
        '00:15:00': 'HP',
        '00:16:00': 'HP',
        '00:17:00': 'HP',
        '00:18:00': 'HP',
        '00:19:00': 'HP',
        '00:1A:00': 'HP',
        '00:1B:00': 'HP',
        '00:1C:00': 'HP',
        '00:1D:00': 'HP',
        '00:1E:00': 'HP',
        '00:1F:00': 'HP',
        '00:20:00': 'HP',
        '00:21:00': 'HP',
        '00:22:00': 'HP',
        '00:23:00': 'HP',
        '00:24:00': 'HP',
        '00:25:00': 'HP',
        '00:26:00': 'HP',
        '00:27:00': 'HP',
    }
    
    return vendors.get(oui, "Unknown")


def get_local_ip() -> str:
    """
    Get the local IP address.
    
    Returns:
        Local IP address string
    """
    try:
        # Connect to an external address to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_gateway_ip() -> Optional[str]:
    """
    Get the default gateway IP address.
    
    Returns:
        Gateway IP address or None
    """
    try:
        import subprocess
        system = platform.system()
        
        if system == "Windows":
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if 'default gateway' in line.lower():
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        return match.group(1)
        elif system == "Linux":
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if 'default' in line:
                    match = re.search(r'via\s+(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        return match.group(1)
        elif system == "Darwin":
            result = subprocess.run(['netstat', '-nr', 'default'], 
                                  capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if 'default' in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        return match.group(1)
    except Exception:
        pass
    
    return None


def get_network_cidr() -> Optional[str]:
    """
    Get the network CIDR (e.g., 192.168.1.0/24).
    
    Returns:
        Network CIDR or None
    """
    try:
        ip = get_local_ip()
        if not ip or ip == "127.0.0.1":
            return None
        
        interfaces = get_interfaces()
        for iface in interfaces:
            if iface.get('ipv4') == ip and iface.get('netmask'):
                # Calculate network address
                ip_parts = list(map(int, ip.split('.')))
                mask_parts = list(map(int, iface['netmask'].split('.')))
                
                network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
                network = '.'.join(map(str, network_parts))
                
                # Calculate CIDR prefix length
                mask_binary = ''.join([bin(octet)[2:].zfill(8) for octet in mask_parts])
                cidr = mask_binary.count('1')
                
                return f"{network}/{cidr}"
        
    except Exception:
        pass
    
    return None


def is_broadcast_address(ip: str) -> bool:
    """
    Check if an IP address is a broadcast address.
    
    Args:
        ip: IP address to check
        
    Returns:
        True if it's a broadcast address
    """
    return ip.endswith('.255') or ip == '255.255.255.255'


def is_multicast_address(ip: str) -> bool:
    """
    Check if an IP address is a multicast address.
    
    Args:
        ip: IP address to check
        
    Returns:
        True if it's a multicast address (224.0.0.0 - 239.255.255.255)
    """
    if not validate_ip_address(ip):
        return False
    
    first_octet = int(ip.split('.')[0])
    return 224 <= first_octet <= 239


def get_protocol_name(protocol_number: int) -> str:
    """
    Get the protocol name from its number.
    
    Args:
        protocol_number: IP protocol number
        
    Returns:
        Protocol name
    """
    protocols = {
        1: 'ICMP',
        2: 'IGMP',
        6: 'TCP',
        17: 'UDP',
        41: 'IPv6',
        47: 'GRE',
        50: 'ESP',
        51: 'AH',
        58: 'ICMPv6',
        89: 'OSPF',
        132: 'SCTP'
    }
    
    return protocols.get(protocol_number, f'Unknown ({protocol_number})')


def get_port_service(port: int, protocol: str = 'tcp') -> str:
    """
    Get the service name for a port number.
    
    Args:
        port: Port number
        protocol: Protocol (tcp or udp)
        
    Returns:
        Service name
    """
    tcp_services = {
        20: 'FTP-Data',
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        993: 'IMAPS',
        995: 'POP3S',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Proxy'
    }
    
    udp_services = {
        53: 'DNS',
        67: 'DHCP-Server',
        68: 'DHCP-Client',
        69: 'TFTP',
        123: 'NTP',
        161: 'SNMP',
        162: 'SNMP-Trap',
        500: 'IKE',
        514: 'Syslog',
        1900: 'UPnP',
        5353: 'mDNS'
    }
    
    if protocol.lower() == 'tcp':
        return tcp_services.get(port, f'Unknown ({port})')
    else:
        return udp_services.get(port, f'Unknown ({port})')
