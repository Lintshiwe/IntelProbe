"""Utility functions for IntelProbe.

Common utilities, validation, formatting, and helper functions
used throughout the application.

Author: Lintshiwe Slade (@lintshiwe)
GitHub: https://github.com/lintshiwe/IntelProbe
License: MIT License
"""

import logging
import ipaddress
import re
import time
import socket
from typing import Optional, Union, List, Dict, Any
from pathlib import Path
import json
import os
import sys

def setup_logging(config) -> None:
    """
    Setup logging configuration for IntelProbe
    
    Args:
        config: Configuration manager instance
    """
    try:
        output_config = config.get_output_config()
        
        # Create logs directory
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        # Configure logging level
        log_level = getattr(logging, output_config['log_level'].upper(), logging.INFO)
        
        # Configure handlers
        handlers = []
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        handlers.append(console_handler)
        
        # File handler if enabled
        if output_config['log_to_file']:
            log_file = log_dir / f"intelprobe_{int(time.time())}.log"
            file_handler = logging.FileHandler(log_file)
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
            )
            file_handler.setFormatter(file_formatter)
            handlers.append(file_handler)
        
        # Configure root logger
        logging.basicConfig(
            level=log_level,
            handlers=handlers,
            force=True  # Override any existing configuration
        )
        
        # Suppress noisy third-party loggers
        logging.getLogger('scapy').setLevel(logging.WARNING)
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('requests').setLevel(logging.WARNING)
        
        logger = logging.getLogger(__name__)
        logger.info("Logging configured successfully")
        
    except Exception as e:
        print(f"Warning: Failed to setup logging: {e}")
        # Fallback to basic config
        logging.basicConfig(level=logging.INFO)

def validate_ip(ip_address: str) -> bool:
    """
    Validate IP address format
    
    Args:
        ip_address: IP address string to validate
        
    Returns:
        True if valid IP address
    """
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

def validate_network(network: str) -> bool:
    """
    Validate network CIDR notation
    
    Args:
        network: Network in CIDR notation (e.g., 192.168.1.0/24)
        
    Returns:
        True if valid network
    """
    try:
        ipaddress.ip_network(network, strict=False)
        return True
    except ValueError:
        return False

def validate_mac(mac_address: str) -> bool:
    """
    Validate MAC address format
    
    Args:
        mac_address: MAC address string to validate
        
    Returns:
        True if valid MAC address
    """
    # Common MAC address patterns
    patterns = [
        r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',  # xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx
        r'^([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4})$',     # xxxx.xxxx.xxxx
        r'^([0-9A-Fa-f]{12})$'                           # xxxxxxxxxxxx
    ]
    
    return any(re.match(pattern, mac_address) for pattern in patterns)

def validate_port_range(port_range: str) -> bool:
    """
    Validate port range format
    
    Args:
        port_range: Port range string (e.g., "80", "1-1000", "80,443,8080")
        
    Returns:
        True if valid port range
    """
    try:
        # Handle single port
        if port_range.isdigit():
            port = int(port_range)
            return 1 <= port <= 65535
        
        # Handle comma-separated ports
        if ',' in port_range:
            ports = port_range.split(',')
            for port in ports:
                if '-' in port:
                    start, end = map(int, port.split('-', 1))
                    if not (1 <= start <= end <= 65535):
                        return False
                else:
                    port_num = int(port)
                    if not (1 <= port_num <= 65535):
                        return False
            return True
        
        # Handle range
        if '-' in port_range:
            start, end = map(int, port_range.split('-', 1))
            return 1 <= start <= end <= 65535
        
        return False
        
    except ValueError:
        return False

def normalize_mac_address(mac_address: str) -> str:
    """
    Normalize MAC address to standard format (xx:xx:xx:xx:xx:xx)
    
    Args:
        mac_address: MAC address in any common format
        
    Returns:
        Normalized MAC address
    """
    # Remove all separators and convert to uppercase
    mac_clean = re.sub(r'[:-.]', '', mac_address.upper())
    
    # Add colons every 2 characters
    if len(mac_clean) == 12:
        return ':'.join(mac_clean[i:i+2] for i in range(0, 12, 2))
    
    return mac_address  # Return original if can't normalize

def format_time(seconds: float) -> str:
    """
    Format time duration in human-readable format
    
    Args:
        seconds: Time duration in seconds
        
    Returns:
        Formatted time string
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"

def format_bytes(bytes_count: int) -> str:
    """
    Format byte count in human-readable format
    
    Args:
        bytes_count: Number of bytes
        
    Returns:
        Formatted byte string
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.1f} PB"

def get_local_ip() -> Optional[str]:
    """
    Get local IP address
    
    Returns:
        Local IP address or None if not found
    """
    try:
        # Connect to a remote address to determine local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return None

def get_network_interfaces() -> List[str]:
    """
    Get list of available network interfaces with fallback methods
    
    Returns:
        List of interface names
    """
    interfaces = []
    
    try:
        # Try netifaces first (most reliable)
        import netifaces
        interfaces = netifaces.interfaces()
        
        # Filter out loopback and virtual interfaces
        filtered_interfaces = []
        for iface in interfaces:
            if iface != 'lo' and not any(x in iface.lower() for x in ['docker', 'veth', 'br-']):
                filtered_interfaces.append(iface)
        
        return filtered_interfaces
        
    except ImportError:
        # Fallback to local implementation
        try:
            from . import netifaces_fallback as netifaces
            interfaces = netifaces.interfaces()
            
            # Filter out loopback and virtual interfaces
            filtered_interfaces = []
            for iface in interfaces:
                if iface != 'lo' and not any(x in iface.lower() for x in ['docker', 'veth', 'br-']):
                    filtered_interfaces.append(iface)
            
            return filtered_interfaces
        except ImportError:
            pass
        # Fallback 1: Use psutil (cross-platform)
        try:
            import psutil
            net_if = psutil.net_if_addrs()
            for iface, addrs in net_if.items():
                if iface != 'lo' and not any(x in iface.lower() for x in ['docker', 'veth', 'br-']):
                    # Check if interface has valid IP
                    for addr in addrs:
                        if addr.family == 2:  # AF_INET
                            interfaces.append(iface)
                            break
            return interfaces
        except ImportError:
            pass
        
        # Fallback 2: Platform-specific methods
        if sys.platform == "win32":
            import subprocess
            try:
                result = subprocess.run(['wmic', 'path', 'win32_networkadapter', 'where', 'NetEnabled=true', 'get', 'NetConnectionID'], 
                                      capture_output=True, text=True, timeout=10)
                lines = result.stdout.split('\n')
                for line in lines:
                    line = line.strip()
                    if line and line != 'NetConnectionID' and line != '':
                        interfaces.append(line)
            except:
                # Final fallback for Windows
                try:
                    result = subprocess.run(['netsh', 'interface', 'show', 'interface'], 
                                          capture_output=True, text=True, timeout=10)
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'Connected' in line and 'Dedicated' in line:
                            parts = line.split()
                            if len(parts) >= 4:
                                interfaces.append(' '.join(parts[3:]))
                except:
                    # Hardcoded common Windows interfaces
                    interfaces = ['Wi-Fi', 'Ethernet', 'Local Area Connection']
        else:
            # Linux/Unix fallback
            try:
                import subprocess
                result = subprocess.run(['ip', 'link', 'show'], 
                                      capture_output=True, text=True, timeout=10)
                lines = result.stdout.split('\n')
                for line in lines:
                    match = re.match(r'\d+: ([^:]+):', line)
                    if match:
                        iface = match.group(1)
                        if iface != 'lo' and not iface.startswith('docker'):
                            interfaces.append(iface)
            except:
                # Final fallback - check /sys/class/net
                try:
                    net_path = Path('/sys/class/net')
                    if net_path.exists():
                        for iface_dir in net_path.iterdir():
                            iface = iface_dir.name
                            if iface != 'lo' and not iface.startswith('docker'):
                                interfaces.append(iface)
                except:
                    # Ultimate fallback
                    interfaces = ['eth0', 'wlan0', 'enp0s3']
    
    # If no interfaces found, return common defaults
    if not interfaces:
        if sys.platform == "win32":
            interfaces = ['Wi-Fi', 'Ethernet']
        else:
            interfaces = ['eth0', 'wlan0']
    
    return interfaces

def is_private_ip(ip_address: str) -> bool:
    """
    Check if IP address is private/internal
    
    Args:
        ip_address: IP address to check
        
    Returns:
        True if IP is private
    """
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private
    except ValueError:
        return False

def is_multicast_ip(ip_address: str) -> bool:
    """
    Check if IP address is multicast
    
    Args:
        ip_address: IP address to check
        
    Returns:
        True if IP is multicast
    """
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_multicast
    except ValueError:
        return False

def get_vendor_from_mac(mac_address: str) -> str:
    """
    Get vendor from MAC address OUI (first 3 octets)
    
    Args:
        mac_address: MAC address
        
    Returns:
        Vendor name or "Unknown"
    """
    # Basic OUI database (subset)
    oui_database = {
        "00:1B:44": "Cisco Systems",
        "00:50:56": "VMware",
        "08:00:27": "Oracle VirtualBox",
        "00:0C:29": "VMware",
        "00:15:5D": "Microsoft Hyper-V",
        "00:16:3E": "Xen",
        "52:54:00": "QEMU/KVM",
        "00:1C:42": "Parallels",
        "DC:A6:32": "Raspberry Pi",
        "B8:27:EB": "Raspberry Pi Foundation",
        "E4:5F:01": "Raspberry Pi Trading",
        "00:22:4D": "Apple",
        "AC:DE:48": "Apple",
        "40:6C:8F": "Apple",
        "00:1F:5B": "Apple"
    }
    
    try:
        # Extract OUI (first 3 octets)
        mac_normalized = normalize_mac_address(mac_address)
        oui = mac_normalized[:8].upper()  # First 3 octets with colons
        
        return oui_database.get(oui, "Unknown")
        
    except Exception:
        return "Unknown"

def save_json_report(data: Dict[str, Any], filename: str, directory: str = "reports") -> bool:
    """
    Save data as JSON report
    
    Args:
        data: Data to save
        filename: Output filename
        directory: Output directory
        
    Returns:
        True if successful
    """
    try:
        # Create directory if it doesn't exist
        Path(directory).mkdir(parents=True, exist_ok=True)
        
        # Full file path
        file_path = Path(directory) / filename
        
        # Add metadata
        report_data = {
            "metadata": {
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "generator": "IntelProbe v2.0",
                "format_version": "1.0"
            },
            "data": data
        }
        
        # Save to file
        with open(file_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        return True
        
    except Exception as e:
        logging.error(f"Failed to save JSON report: {e}")
        return False

def load_json_report(filename: str, directory: str = "reports") -> Optional[Dict[str, Any]]:
    """
    Load JSON report from file
    
    Args:
        filename: Input filename
        directory: Input directory
        
    Returns:
        Loaded data or None if failed
    """
    try:
        file_path = Path(directory) / filename
        
        if not file_path.exists():
            return None
        
        with open(file_path, 'r') as f:
            report_data = json.load(f)
        
        return report_data.get("data", report_data)
        
    except Exception as e:
        logging.error(f"Failed to load JSON report: {e}")
        return None

def create_directory_structure() -> None:
    """Create necessary directory structure for IntelProbe"""
    directories = [
        "reports",
        "logs", 
        "sessions",
        "alerts",
        "models",
        "cache"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)

def check_dependencies() -> Dict[str, bool]:
    """
    Check if required dependencies are available
    
    Returns:
        Dictionary with dependency status
    """
    dependencies = {
        'scapy': False,
        'pandas': False,
        'requests': False,
        'rich': False,
        'click': False,
        'numpy': False,
        'sklearn': False,
        'nmap': False,
        'netifaces': False,
        'openai': False
    }
    
    for dep in dependencies:
        try:
            __import__(dep)
            dependencies[dep] = True
        except ImportError:
            pass
    
    return dependencies

def check_permissions() -> Dict[str, bool]:
    """
    Check if required permissions are available
    
    Returns:
        Dictionary with permission status
    """
    permissions = {
        'raw_sockets': False,
        'network_interfaces': False,
        'file_write': False
    }
    
    # Check raw socket permissions (required for packet capture)
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.close()
        permissions['raw_sockets'] = True
    except (OSError, PermissionError):
        pass
    
    # Check network interface access
    try:
        interfaces = get_network_interfaces()
        permissions['network_interfaces'] = len(interfaces) > 0
    except Exception:
        pass
    
    # Check file write permissions
    try:
        test_file = Path("test_write_permission.tmp")
        test_file.write_text("test")
        test_file.unlink()
        permissions['file_write'] = True
    except Exception:
        pass
    
    return permissions

def get_system_info() -> Dict[str, Any]:
    """
    Get system information
    
    Returns:
        System information dictionary
    """
    import platform
    
    info = {
        'platform': platform.system(),
        'platform_version': platform.version(),
        'architecture': platform.machine(),
        'python_version': platform.python_version(),
        'hostname': socket.gethostname(),
        'local_ip': get_local_ip(),
        'interfaces': get_network_interfaces()
    }
    
    return info

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe file operations
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove or replace invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Remove leading/trailing spaces and dots
    filename = filename.strip(' .')
    
    # Limit length
    if len(filename) > 255:
        filename = filename[:255]
    
    return filename

def generate_session_id() -> str:
    """
    Generate unique session ID
    
    Returns:
        Session ID string
    """
    import hashlib
    import random
    
    # Combine timestamp and random data
    data = f"{time.time()}_{random.randint(1000, 9999)}_{socket.gethostname()}"
    return hashlib.md5(data.encode()).hexdigest()[:16]

def parse_port_list(port_range: str) -> List[int]:
    """
    Parse port range string into list of ports
    
    Args:
        port_range: Port range string (e.g., "80", "1-1000", "80,443,8080")
        
    Returns:
        List of port numbers
    """
    ports = []
    
    try:
        for part in port_range.split(','):
            part = part.strip()
            
            if '-' in part:
                start, end = map(int, part.split('-', 1))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        
        # Remove duplicates and sort
        return sorted(set(ports))
        
    except ValueError:
        return []

def chunk_list(data: List[Any], chunk_size: int) -> List[List[Any]]:
    """
    Split list into chunks
    
    Args:
        data: List to split
        chunk_size: Size of each chunk
        
    Returns:
        List of chunks
    """
    chunks = []
    for i in range(0, len(data), chunk_size):
        chunks.append(data[i:i + chunk_size])
    return chunks

def retry_on_failure(func, max_retries: int = 3, delay: float = 1.0):
    """
    Retry function on failure
    
    Args:
        func: Function to retry
        max_retries: Maximum number of retries
        delay: Delay between retries in seconds
        
    Returns:
        Function result or raises last exception
    """
    last_exception = None
    
    for attempt in range(max_retries + 1):
        try:
            return func()
        except Exception as e:
            last_exception = e
            if attempt < max_retries:
                time.sleep(delay)
                delay *= 2  # Exponential backoff
            else:
                raise last_exception

def safe_json_loads(json_str: str, default: Any = None) -> Any:
    """
    Safely load JSON with fallback
    
    Args:
        json_str: JSON string to parse
        default: Default value if parsing fails
        
    Returns:
        Parsed JSON or default value
    """
    try:
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError):
        return default

def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Truncate string to maximum length
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add when truncated
        
    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix

# Color constants for console output
class Colors:
    """ANSI color codes for console output"""
    RED = '\\033[91m'
    GREEN = '\\033[92m'
    YELLOW = '\\033[93m'
    BLUE = '\\033[94m'
    MAGENTA = '\\033[95m'
    CYAN = '\\033[96m'
    WHITE = '\\033[97m'
    BOLD = '\\033[1m'
    UNDERLINE = '\\033[4m'
    END = '\\033[0m'

def colorize(text: str, color: str) -> str:
    """
    Colorize text for console output
    
    Args:
        text: Text to colorize
        color: Color name or ANSI code
        
    Returns:
        Colorized text
    """
    color_map = {
        'red': Colors.RED,
        'green': Colors.GREEN,
        'yellow': Colors.YELLOW,
        'blue': Colors.BLUE,
        'magenta': Colors.MAGENTA,
        'cyan': Colors.CYAN,
        'white': Colors.WHITE,
        'bold': Colors.BOLD,
        'underline': Colors.UNDERLINE
    }
    
    color_code = color_map.get(color.lower(), color)
    return f"{color_code}{text}{Colors.END}"
