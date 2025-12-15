"""
Enhanced Scanner Module
Advanced network scanning with multi-threading and AI integration
Based on netspionage core with significant enhancements

Author: Lintshiwe Slade (@lintshiwe)
GitHub: https://github.com/lintshiwe/IntelProbe
License: MIT License
Copyright (c) 2025 Lintshiwe Slade
"""

# Core Python imports
import socket
import threading
import time
import json
import ipaddress
import concurrent.futures
from typing import List, Dict, Any, Optional, Tuple
import logging
from dataclasses import dataclass, field
from pathlib import Path

# Try to import optional dependencies with graceful fallback
try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, ICMP, TCP, UDP
    from scapy.layers.l2 import ARP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Some advanced scanning features will be disabled.")

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    print("Warning: Pandas not available. Data analysis features will be limited.")

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("Warning: python-nmap not available. Nmap integration will be disabled.")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("Warning: psutil not available. System monitoring features will be limited.")

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False
    print("Warning: netifaces not available. Network interface detection will be limited.")

@dataclass
class ScanResult:
    """Data class for network scan results.
    
    Attributes:
        ip: IP address of the discovered host.
        mac: MAC address of the host.
        hostname: Resolved hostname.
        os: Detected operating system.
        ports: List of open ports.
        services: Dictionary mapping ports to service names.
        response_time: Time to receive response in seconds.
        timestamp: When the scan was performed.
    """
    ip: str
    mac: str = ""
    hostname: str = ""
    os: str = ""
    ports: List[int] = field(default_factory=list)
    services: Dict[str, str] = field(default_factory=dict)
    response_time: float = 0.0
    timestamp: str = ""
    
    def __post_init__(self) -> None:
        """Initialize default timestamp if not provided."""
        if not self.timestamp:
            self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

@dataclass
class WifiNetwork:
    """Data class for discovered WiFi networks.
    
    Attributes:
        bssid: MAC address of the access point.
        ssid: Network name.
        channel: WiFi channel number.
        encryption: Encryption type (WPA2, WPA3, WEP, Open).
        signal_strength: Signal strength in dBm.
        timestamp: When the network was discovered.
    """
    bssid: str
    ssid: str
    channel: int
    encryption: str
    signal_strength: int
    timestamp: str = ""
    
    def __post_init__(self) -> None:
        """Initialize default timestamp if not provided."""
        if not self.timestamp:
            self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

class EnhancedScanner:
    """Enhanced network scanner with multi-threading and AI integration.
    
    Provides comprehensive network scanning capabilities including host
    discovery, port scanning, service detection, OS fingerprinting,
    and WiFi enumeration.
    
    Attributes:
        config: Configuration manager instance.
        results: List of scan results.
        wifi_networks: DataFrame or list of discovered WiFi networks.
        nm: Nmap scanner instance (if available).
    """
    
    def __init__(self, config) -> None:
        """Initialize the enhanced scanner.
        
        Args:
            config: Configuration manager instance.
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.results: List[ScanResult] = []
        self._scapy_available = SCAPY_AVAILABLE
        self._nmap_available = NMAP_AVAILABLE
        
        # Initialize WiFi networks DataFrame if pandas is available
        if PANDAS_AVAILABLE:
            self.wifi_networks = pd.DataFrame(columns=["BSSID", "SSID", "Channel", "Encryption", "Signal"])
            self.wifi_networks.set_index("BSSID", inplace=True)
        else:
            self.wifi_networks: List[WifiNetwork] = []
        
        # Initialize nmap scanner if available
        if NMAP_AVAILABLE:
            try:
                self.nm = nmap.PortScanner()
            except Exception as e:
                self.logger.warning("Nmap executable not found in PATH - using fallback scanning methods")
                self.nm = None
        else:
            self.nm = None
    
    def scan_network(self, target: str, threads: int = 50, timeout: int = 5) -> List[ScanResult]:
        """
        Perform comprehensive network discovery scan
        
        Args:
            target: Target network (e.g., 192.168.1.0/24)
            threads: Number of threads to use
            timeout: Timeout for each host
            
        Returns:
            List of ScanResult objects
        """
        self.logger.info(f"Starting network scan of {target}")
        start_time = time.time()
        
        try:
            # Parse network
            network = ipaddress.ip_network(target, strict=False)
            hosts = list(network.hosts())
            
            self.logger.info(f"Scanning {len(hosts)} hosts with {threads} threads")
            
            # Multi-threaded ARP scanning
            results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_ip = {
                    executor.submit(self._scan_host_arp, str(ip), timeout): str(ip) 
                    for ip in hosts
                }
                
                for future in concurrent.futures.as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        result = future.result()
                        if result:
                            results.append(result)
                            self.logger.debug(f"Found host: {result.ip}")
                    except Exception as e:
                        self.logger.debug(f"Error scanning {ip}: {e}")
            
            # Enhanced scanning for discovered hosts
            if results:
                self.logger.info(f"Performing enhanced scan on {len(results)} discovered hosts")
                enhanced_results = []
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=min(threads, len(results))) as executor:
                    future_to_result = {
                        executor.submit(self._enhance_host_info, result): result 
                        for result in results
                    }
                    
                    for future in concurrent.futures.as_completed(future_to_result):
                        try:
                            enhanced_result = future.result()
                            enhanced_results.append(enhanced_result)
                        except Exception as e:
                            self.logger.debug(f"Error enhancing host info: {e}")
                
                results = enhanced_results
            
            scan_time = time.time() - start_time
            self.logger.info(f"Network scan completed in {scan_time:.2f} seconds")
            self.logger.info(f"Discovered {len(results)} active hosts")
            
            self.results.extend(results)
            return results
            
        except Exception as e:
            self.logger.error(f"Network scan failed: {e}")
            return []
    
    def _scan_host_arp(self, ip: str, timeout: int) -> Optional[ScanResult]:
        """Scan single host using ARP"""
        if not SCAPY_AVAILABLE:
            # Fallback to ping-based detection when scapy is not available
            return self._scan_host_ping(ip, timeout)
        
        try:
            start_time = time.time()
            
            # Create ARP request
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send request and get response
            answered_list = scapy.srp(arp_request_broadcast, timeout=timeout, verbose=False)[0]
            
            if answered_list:
                response = answered_list[0][1]
                response_time = time.time() - start_time
                
                return ScanResult(
                    ip=response.psrc,
                    mac=response.hwsrc,
                    response_time=response_time
                )
                
        except Exception as e:
            self.logger.debug(f"ARP scan error for {ip}: {e}")
        
        return None
    
    def _scan_host_ping(self, ip: str, timeout: int) -> Optional[ScanResult]:
        """Fallback ping-based host detection when scapy is not available"""
        try:
            import subprocess
            import platform
            
            start_time = time.time()
            
            # Determine ping command based on OS
            system = platform.system().lower()
            if system == "windows":
                cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
            else:
                cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 1)
            response_time = time.time() - start_time
            
            if result.returncode == 0:
                return ScanResult(
                    ip=ip,
                    mac="Unknown",  # Can't get MAC without ARP
                    response_time=response_time
                )
                
        except Exception as e:
            self.logger.debug(f"Ping scan error for {ip}: {e}")
        
        return None
    
    def _enhance_host_info(self, result: ScanResult) -> ScanResult:
        """Enhance host information with OS detection and hostname resolution"""
        try:
            # Enhanced OS Detection
            result.os = self._detect_os_enhanced(result.ip, result.mac)
            
            # Hostname resolution
            try:
                result.hostname = socket.gethostbyaddr(result.ip)[0]
            except:
                result.hostname = "Unknown"
            
            return result
            
        except Exception as e:
            self.logger.debug(f"Error enhancing {result.ip}: {e}")
            return result

    def _detect_os_enhanced(self, ip: str, mac: str = None) -> str:
        """Enhanced OS detection using multiple methods with confidence scoring"""
        
        detection_results = []
        
        # Method 1: Check if it's localhost (highest confidence)
        if ip in ["127.0.0.1", "localhost"] or ip == socket.gethostbyname(socket.gethostname()):
            try:
                import platform
                system = platform.system().lower()
                if 'windows' in system:
                    detection_results.append(("Windows", 95, "Platform Detection"))
                elif 'darwin' in system:
                    detection_results.append(("macOS", 95, "Platform Detection"))
                elif 'linux' in system:
                    detection_results.append(("Linux", 95, "Platform Detection"))
                else:
                    detection_results.append((platform.system(), 90, "Platform Detection"))
            except:
                pass
        
        # Method 2: Enhanced MAC address vendor analysis (medium-high confidence)
        if mac:
            mac_prefix = mac[:8].upper()
            vendor_os_hints = {
                # VMware (typically Windows hosts)
                "00:50:56": "Windows", "00:0C:29": "Windows", "00:1C:14": "Windows",
                # VirtualBox (mixed, but often Linux)
                "08:00:27": "Linux", "0A:00:27": "Linux",
                # QEMU/KVM (Linux)
                "52:54:00": "Linux", "52:55:0A": "Linux",
                # Parallels (macOS host)
                "00:1C:42": "macOS",
                # Apple devices
                "AC:DE:48": "macOS", "28:CF:E9": "macOS", "3C:07:54": "macOS",
                "A4:B1:C1": "macOS", "B8:17:C2": "macOS", "BC:52:B7": "macOS",
                "F0:18:98": "macOS", "64:A3:CB": "macOS", "98:01:A7": "macOS",
                # Microsoft Surface/Windows devices
                "AC:81:12": "Windows", "54:27:1E": "Windows", "48:45:20": "Windows",
                # Dell (typically Windows)
                "D4:BE:D9": "Windows", "18:03:73": "Windows", "B8:CA:3A": "Windows",
                # HP (typically Windows)
                "70:5A:0F": "Windows", "A0:48:1C": "Windows", "98:E7:43": "Windows",
                # Lenovo ThinkPad (typically Windows/Linux)
                "00:21:CC": "Windows", "54:EE:75": "Windows", "4C:80:93": "Linux",
                # Raspberry Pi (Linux)
                "B8:27:EB": "Linux", "DC:A6:32": "Linux", "E4:5F:01": "Linux",
                # Docker containers
                "02:42:AC": "Linux"
            }
            
            for prefix, os_type in vendor_os_hints.items():
                if mac_prefix.startswith(prefix):
                    detection_results.append((os_type, 75, "MAC Vendor"))
        
        # Method 3: TTL-based detection (medium confidence)
        ttl_os = self._detect_os_ttl(ip)
        if ttl_os != "Unknown":
            detection_results.append((ttl_os, 60, "TTL Analysis"))
        
        # Select best result based on confidence
        if detection_results:
            # Sort by confidence score (highest first)
            detection_results.sort(key=lambda x: x[1], reverse=True)
            best_result = detection_results[0]
            return f"{best_result[0]} ({best_result[2]}: {best_result[1]}%)"
        
        # Method 3 fallback: TTL-based detection (improved)
        return self._detect_os_ttl(ip)
    
    def _detect_os_ttl(self, ip: str) -> str:
        """Detect OS based on TTL values and additional fingerprinting"""
        
        # First try platform detection for localhost
        if ip == "127.0.0.1" or ip == "localhost":
            try:
                import platform
                system = platform.system().lower()
                if 'windows' in system:
                    return "Windows"
                elif 'darwin' in system:
                    return "macOS"
                elif 'linux' in system:
                    return "Linux"
                else:
                    return f"{platform.system()}"
            except:
                pass
        
        # TTL-based detection for remote hosts
        ttl_signatures = {
            # Windows TTL values
            32: "Windows", 128: "Windows", 
            # Linux/Unix TTL values  
            64: "Linux", 255: "Linux",
            # macOS TTL values
            60: "macOS", 64: "macOS"
        }
        
        try:
            if SCAPY_AVAILABLE:
                # Send ICMP ping using scapy
                response = scapy.sr1(
                    IP(dst=ip) / ICMP(),
                    timeout=3,
                    verbose=False
                )
                
                if response and hasattr(response, 'ttl'):
                    ttl = response.ttl
                    
                    # Enhanced OS detection based on TTL ranges
                    if ttl <= 32:
                        return "Windows"
                    elif ttl <= 64 and ttl > 32:
                        if ttl == 60:
                            return "macOS"
                        else:
                            return "Linux"
                    elif ttl <= 128 and ttl > 64:
                        return "Windows"
                    elif ttl > 128:
                        return "Linux"
                    else:
                        return f"Unknown (TTL: {ttl})"
            else:
                # Fallback: try to get TTL using system ping command
                import subprocess
                import platform
                import re
                
                system = platform.system().lower()
                if system == "windows":
                    cmd = ["ping", "-n", "1", ip]
                else:
                    cmd = ["ping", "-c", "1", ip]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # Try to extract TTL from ping output
                    ttl_match = re.search(r'ttl=(\d+)', result.stdout.lower())
                    if ttl_match:
                        ttl = int(ttl_match.group(1))
                        if ttl <= 32:
                            return "Windows"
                        elif ttl <= 64 and ttl > 32:
                            return "Linux/macOS"
                        elif ttl <= 128 and ttl > 64:
                            return "Windows"
                        else:
                            return f"Unknown (TTL: {ttl})"
            
        except Exception as e:
            self.logger.debug(f"TTL-based OS detection failed for {ip}: {e}")
        
        # Fallback: Advanced socket-based detection with multiple methods
        try:
            os_indicators = {"windows": 0, "linux": 0, "macos": 0}
            
            # Test multiple Windows-specific services
            windows_ports = [135, 139, 445, 1433, 3389, 5985]  # RPC, NetBIOS, SMB, SQL, RDP, WinRM
            for port in windows_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    if sock.connect_ex((ip, port)) == 0:
                        os_indicators["windows"] += 2
                    sock.close()
                except:
                    pass
            
            # Test Linux/Unix services
            linux_ports = [22, 25, 53, 80, 443, 993, 995]  # SSH, SMTP, DNS, HTTP, HTTPS, IMAPS, POP3S
            for port in linux_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    if sock.connect_ex((ip, port)) == 0:
                        os_indicators["linux"] += 1
                    sock.close()
                except:
                    pass
            
            # Test macOS specific services
            macos_ports = [548, 631, 5353]  # AFP, CUPS, mDNS
            for port in macos_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    if sock.connect_ex((ip, port)) == 0:
                        os_indicators["macos"] += 3
                    sock.close()
                except:
                    pass
            
            # Determine OS based on service fingerprint
            if os_indicators["windows"] > 0:
                return f"Windows (Service Detection)"
            elif os_indicators["macos"] > 0:
                return f"macOS (Service Detection)"
            elif os_indicators["linux"] > 0:
                return f"Linux (Service Detection)"
                
        except Exception as e:
            self.logger.debug(f"Advanced service detection failed for {ip}: {e}")
        
        # Final fallback - make educated guess based on network context
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            return "Windows"  # Most common in home/office networks
        
        return "Unknown"
    
    def scan_ports(self, target: str, port_range: str = "1-1000", 
                   service_detection: bool = True, threads: int = 100) -> Dict[str, Any]:
        """
        Advanced port scanning with service detection
        
        Args:
            target: Target host or network
            port_range: Port range to scan (e.g., "1-1000" or "80,443,22")
            service_detection: Enable service detection
            threads: Number of concurrent scans
            
        Returns:
            Dictionary with scan results
        """
        self.logger.info(f"Starting port scan of {target}")
        start_time = time.time()
        
        try:
            # Parse port range
            ports = self._parse_port_range(port_range)
            
            # Check if target is a single host or network
            if '/' in target:
                # Network scanning
                network = ipaddress.ip_network(target, strict=False)
                hosts = [str(ip) for ip in network.hosts()]
            else:
                hosts = [target]
            
            results = {}
            
            for host in hosts:
                self.logger.info(f"Scanning {host} - {len(ports)} ports")
                host_results = self._scan_host_ports(host, ports, threads, service_detection)
                if host_results['open_ports']:
                    results[host] = host_results
            
            scan_time = time.time() - start_time
            self.logger.info(f"Port scan completed in {scan_time:.2f} seconds")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Port scan failed: {e}")
            return {}
    
    def _parse_port_range(self, port_range: str) -> List[int]:
        """Parse port range string into list of ports"""
        ports = []
        
        for part in port_range.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        
        return sorted(set(ports))
    
    def _scan_host_ports(self, host: str, ports: List[int], 
                        threads: int, service_detection: bool) -> Dict[str, Any]:
        """Scan ports on a single host"""
        open_ports = []
        services = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_port = {
                executor.submit(self._check_port, host, port): port 
                for port in ports
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(port)
                        if service_detection:
                            service = self._detect_service(host, port)
                            if service:
                                services[port] = service
                except Exception as e:
                    self.logger.debug(f"Error checking port {port}: {e}")
        
        return {
            'open_ports': sorted(open_ports),
            'services': services,
            'total_scanned': len(ports)
        }
    
    def _check_port(self, host: str, port: int, timeout: float = 1.0) -> bool:
        """Check if a port is open"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                return result == 0
        except:
            return False
    
    def _detect_service(self, host: str, port: int) -> Optional[str]:
        """Detect service running on port"""
        common_services = {
            21: "FTP",
            22: "SSH", 
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S"
        }
        
        # Check common services first
        if port in common_services:
            return common_services[port]
        
        # Try banner grabbing
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(3)
                sock.connect((host, port))
                sock.send(b"\\r\\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                
                if banner:
                    # Simple service detection based on banner
                    banner_lower = banner.lower()
                    if 'ssh' in banner_lower:
                        return f"SSH ({banner})"
                    elif 'http' in banner_lower:
                        return f"HTTP ({banner})"
                    elif 'ftp' in banner_lower:
                        return f"FTP ({banner})"
                    else:
                        return f"Unknown ({banner[:50]})"
                        
        except:
            pass
        
        return "Unknown"
    
    def scan_wifi(self, interface: str = None, duration: int = 30) -> List[WifiNetwork]:
        """
        WiFi network scanning
        
        Args:
            interface: WiFi interface to use
            duration: Scan duration in seconds
            
        Returns:
            List of discovered WiFi networks
        """
        if not interface:
            interface = self._get_default_wifi_interface()
        
        if not interface:
            self.logger.error("No WiFi interface available")
            return []
        
        self.logger.info(f"📡 Starting WiFi scan on {interface} for {duration} seconds")
        
        try:
            # Start packet capture in background
            stop_event = threading.Event()
            networks = []
            
            def packet_handler(packet):
                if stop_event.is_set():
                    return
                
                try:
                    if packet.haslayer(scapy.Dot11Beacon):
                        self._extract_wifi_info(packet, networks)
                except Exception as e:
                    self.logger.debug(f"Error processing WiFi packet: {e}")
            
            # Start sniffing
            sniff_thread = threading.Thread(
                target=lambda: scapy.sniff(
                    iface=interface,
                    prn=packet_handler,
                    timeout=duration,
                    store=False
                )
            )
            sniff_thread.start()
            
            # Wait for completion
            sniff_thread.join(timeout=duration + 5)
            stop_event.set()
            
            self.logger.info(f"WiFi scan completed. Found {len(networks)} networks")
            return networks
            
        except Exception as e:
            self.logger.error(f"WiFi scan failed: {e}")
            return []
    
    def _get_default_wifi_interface(self) -> Optional[str]:
        """Get default WiFi interface"""
        try:
            if NETIFACES_AVAILABLE:
                # Get all network interfaces using netifaces
                interfaces = netifaces.interfaces()
                
                for iface in interfaces:
                    # Check if interface is wireless
                    if any(keyword in iface.lower() for keyword in ['wlan', 'wifi', 'wireless']):
                        return iface
                
                # Fallback to first available interface
                if interfaces:
                    return interfaces[0]
            else:
                # Fallback method without netifaces - try common interface names
                import os
                import subprocess
                
                # Try common WiFi interface names
                common_wifi_interfaces = ['wlan0', 'wlan1', 'wifi0', 'wlp2s0', 'wlp3s0']
                
                for iface in common_wifi_interfaces:
                    try:
                        # Check if interface exists (Linux/macOS)
                        if os.path.exists(f'/sys/class/net/{iface}'):
                            return iface
                    except:
                        pass
                
                # Try to get interfaces from system commands
                try:
                    if os.name == 'posix':  # Linux/macOS
                        result = subprocess.run(['ip', 'link'], capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            for line in result.stdout.split('\n'):
                                if 'wlan' in line or 'wifi' in line:
                                    parts = line.split(':')
                                    if len(parts) > 1:
                                        return parts[1].strip()
                except:
                    pass
                
                # Return None if no interface found
                return None
                    
        except Exception as e:
            self.logger.debug(f"Error getting WiFi interface: {e}")
        
        return None
    
    def _extract_wifi_info(self, packet, networks: List[WifiNetwork]) -> None:
        """Extract WiFi network information from packet"""
        try:
            if packet.haslayer(scapy.Dot11Beacon):
                # Extract network information
                bssid = packet[scapy.Dot11].addr2
                ssid = packet[scapy.Dot11Elt].info.decode('utf-8', errors='ignore')
                
                # Skip hidden networks
                if not ssid.strip():
                    return
                
                # Get signal strength
                try:
                    signal_strength = packet.dBm_AntSignal
                except:
                    signal_strength = -100
                
                # Get network stats
                try:
                    stats = packet[scapy.Dot11Beacon].network_stats()
                    channel = stats.get("channel", 0)
                    encryption = stats.get("crypto", "Unknown")
                except:
                    channel = 0
                    encryption = "Unknown"
                
                # Check if already discovered
                for network in networks:
                    if network.bssid == bssid:
                        return
                
                # Add new network
                wifi_network = WifiNetwork(
                    bssid=bssid,
                    ssid=ssid,
                    channel=channel,
                    encryption=encryption,
                    signal_strength=signal_strength
                )
                
                networks.append(wifi_network)
                self.logger.debug(f"📡 Found WiFi: {ssid} ({bssid})")
                
        except Exception as e:
            self.logger.debug(f"Error extracting WiFi info: {e}")
    
    def export_results(self, filename: str, format: str = "json") -> bool:
        """
        Export scan results to file
        
        Args:
            filename: Output filename
            format: Export format (json, csv, html)
            
        Returns:
            True if export successful
        """
        try:
            if format.lower() == "json":
                data = {
                    'scan_results': [
                        {
                            'ip': r.ip,
                            'mac': r.mac,
                            'hostname': r.hostname,
                            'os': r.os,
                            'ports': r.ports,
                            'services': r.services,
                            'response_time': r.response_time,
                            'timestamp': r.timestamp
                        }
                        for r in self.results
                    ],
                    'metadata': {
                        'scan_count': len(self.results),
                        'export_time': time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                }
                
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
                    
            elif format.lower() == "csv":
                df = pd.DataFrame([
                    {
                        'IP': r.ip,
                        'MAC': r.mac,
                        'Hostname': r.hostname,
                        'OS': r.os,
                        'Ports': ','.join(map(str, r.ports)),
                        'Response_Time': r.response_time,
                        'Timestamp': r.timestamp
                    }
                    for r in self.results
                ])
                df.to_csv(filename, index=False)
                
            self.logger.info(f"Results exported to {filename}")
            return True
            
        except Exception as e:
            self.logger.error(f"Export failed: {e}")
            return False
    
    def get_scan_summary(self) -> Dict[str, Any]:
        """Get summary of scan results"""
        if not self.results:
            return {"message": "No scan results available"}
        
        os_counts = {}
        total_ports = 0
        
        for result in self.results:
            # Count OS types
            os_type = result.os.split(' ')[0] if result.os else "Unknown"
            os_counts[os_type] = os_counts.get(os_type, 0) + 1
            total_ports += len(result.ports)
        
        return {
            'total_hosts': len(self.results),
            'os_distribution': os_counts,
            'total_open_ports': total_ports,
            'average_response_time': sum(r.response_time for r in self.results) / len(self.results),
            'scan_timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
        }

class NetworkScanner(EnhancedScanner):
    """Backward compatibility wrapper for legacy imports.
    Older code expects NetworkScanner; this subclass preserves the public API
    of EnhancedScanner without modification.
    """
    pass
