#!/usr/bin/env python3
"""
IntelProbe Quick Start Utilities
Easy-to-use convenience functions for common operations

Author: Lintshiwe Slade (@lintshiwe)
GitHub: https://github.com/lintshiwe/IntelProbe
License: MIT License
"""

import sys
import os
import asyncio
from pathlib import Path
from typing import List, Dict, Optional, Union

# Add parent directory to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

__all__ = [
    'quick_scan', 
    'full_scan', 
    'discover_hosts', 
    'port_scan',
    'get_network_info',
    'setup_ai',
    'check_setup',
    'IntelProbe'
]


def quick_scan(target: str, ports: str = "top20") -> Dict:
    """
    Perform a quick network scan
    
    Args:
        target: IP address, hostname, or CIDR network
        ports: Port preset (top20, common, full) or range (1-1000)
    
    Returns:
        Dictionary with scan results
    
    Example:
        >>> results = quick_scan("192.168.1.1")
        >>> results = quick_scan("192.168.1.0/24", ports="common")
    """
    try:
        from core.super_scanner import SuperScanner, ScanSpeed
        scanner = SuperScanner()
        scanner.set_speed(ScanSpeed.FAST)
        
        # Get port list
        if ports in scanner.port_presets:
            port_list = scanner.port_presets[ports]
        elif '-' in str(ports):
            start, end = map(int, str(ports).split('-'))
            port_list = list(range(start, end + 1))
        else:
            port_list = scanner.port_presets['top20']
        
        results = scanner.scan_network(target, port_list)
        return {
            'success': True,
            'target': target,
            'hosts_found': len(results),
            'results': [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]
        }
    except ImportError:
        from core.scanner import Scanner
        scanner = Scanner()
        results = scanner.scan(target)
        return {
            'success': True,
            'target': target,
            'results': results
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'target': target
        }


def full_scan(target: str, ai_analysis: bool = True) -> Dict:
    """
    Perform a comprehensive full network scan with AI analysis
    
    Args:
        target: IP address, hostname, or CIDR network
        ai_analysis: Whether to include AI-powered analysis
    
    Returns:
        Dictionary with comprehensive scan results
    
    Example:
        >>> results = full_scan("192.168.1.1")
        >>> results = full_scan("192.168.1.0/24", ai_analysis=True)
    """
    try:
        from run import IntelProbeRunner
        runner = IntelProbeRunner(quiet=True)
        return runner.scan(target, ports="full", ai_analysis=ai_analysis)
    except ImportError:
        # Fallback
        return quick_scan(target, ports="full")


def discover_hosts(network: str) -> List[str]:
    """
    Discover live hosts on a network
    
    Args:
        network: Network in CIDR notation (e.g., "192.168.1.0/24")
    
    Returns:
        List of discovered IP addresses
    
    Example:
        >>> hosts = discover_hosts("192.168.1.0/24")
        >>> print(f"Found {len(hosts)} hosts")
    """
    try:
        from core.super_scanner import SuperScanner
        scanner = SuperScanner()
        results = scanner.discover_hosts(network)
        return results
    except ImportError:
        import ipaddress
        import socket
        
        hosts = []
        try:
            net = ipaddress.ip_network(network, strict=False)
            for ip in list(net.hosts())[:255]:  # Limit to first 255
                try:
                    socket.setdefaulttimeout(0.5)
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    result = s.connect_ex((str(ip), 80))
                    if result == 0 or result == 111:
                        hosts.append(str(ip))
                    s.close()
                except:
                    pass
        except:
            pass
        return hosts


def port_scan(host: str, ports: Union[str, List[int]] = "common") -> Dict:
    """
    Scan ports on a specific host
    
    Args:
        host: IP address or hostname
        ports: Port preset, range string, or list of ports
    
    Returns:
        Dictionary with open ports and services
    
    Example:
        >>> results = port_scan("192.168.1.1")
        >>> results = port_scan("192.168.1.1", ports=[22, 80, 443])
        >>> results = port_scan("192.168.1.1", ports="1-1000")
    """
    try:
        from core.super_scanner import SuperScanner
        scanner = SuperScanner()
        
        if isinstance(ports, list):
            port_list = ports
        elif isinstance(ports, str) and '-' in ports:
            start, end = map(int, ports.split('-'))
            port_list = list(range(start, end + 1))
        elif ports in scanner.port_presets:
            port_list = scanner.port_presets[ports]
        else:
            port_list = scanner.port_presets['common']
        
        results = scanner.scan_network(host, port_list)
        
        if results:
            result = results[0]
            return {
                'host': host,
                'open_ports': result.open_ports if hasattr(result, 'open_ports') else [],
                'services': result.services if hasattr(result, 'services') else {},
                'os_type': result.os_type if hasattr(result, 'os_type') else 'Unknown'
            }
        return {'host': host, 'open_ports': [], 'services': {}}
        
    except ImportError:
        import socket
        open_ports = []
        port_list = list(range(1, 1025)) if ports == "common" else ports
        
        for port in port_list:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                result = s.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                s.close()
            except:
                pass
        
        return {'host': host, 'open_ports': open_ports, 'services': {}}


def get_network_info() -> Dict:
    """
    Get information about the local network
    
    Returns:
        Dictionary with network information
    
    Example:
        >>> info = get_network_info()
        >>> print(f"Your IP: {info['local_ip']}")
    """
    import socket
    
    info = {
        'hostname': socket.gethostname(),
        'local_ip': None,
        'network': None,
        'gateway': None
    }
    
    try:
        # Get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info['local_ip'] = s.getsockname()[0]
        s.close()
        
        # Calculate network
        ip_parts = info['local_ip'].split('.')
        info['network'] = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        info['gateway'] = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
        
    except Exception as e:
        info['error'] = str(e)
    
    # Try to get more info with netifaces
    try:
        import netifaces
        gws = netifaces.gateways()
        if 'default' in gws and netifaces.AF_INET in gws['default']:
            info['gateway'] = gws['default'][netifaces.AF_INET][0]
            info['interface'] = gws['default'][netifaces.AF_INET][1]
    except ImportError:
        pass
    
    return info


def setup_ai(api_key: str = None, provider: str = "gemini") -> bool:
    """
    Configure AI for enhanced analysis
    
    Args:
        api_key: API key for the AI provider (or set GEMINI_API_KEY env var)
        provider: AI provider ("gemini" or "openai")
    
    Returns:
        True if setup successful
    
    Example:
        >>> setup_ai("your-api-key-here")
        >>> # Or set environment variable:
        >>> # export GEMINI_API_KEY="your-api-key"
        >>> setup_ai()
    """
    import json
    
    if not api_key:
        api_key = os.environ.get('GEMINI_API_KEY') or os.environ.get('OPENAI_API_KEY')
    
    if not api_key:
        print("❌ No API key provided. Set GEMINI_API_KEY environment variable or pass key directly.")
        return False
    
    config_dir = Path("config")
    config_dir.mkdir(exist_ok=True)
    
    config = {
        "gemini_enabled": provider == "gemini",
        "gemini_api_key": api_key if provider == "gemini" else "",
        "gemini_model": "gemini-1.5-flash",
        "openai_enabled": provider == "openai",
        "openai_api_key": api_key if provider == "openai" else "",
        "openai_model": "gpt-3.5-turbo"
    }
    
    config_file = config_dir / "ai_config.json"
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"✅ AI configured successfully ({provider})")
    return True


def check_setup() -> Dict:
    """
    Check IntelProbe setup and dependencies
    
    Returns:
        Dictionary with setup status
    
    Example:
        >>> status = check_setup()
        >>> if status['ready']:
        ...     print("IntelProbe is ready!")
    """
    status = {
        'ready': True,
        'core_modules': {},
        'optional_modules': {},
        'ai_status': {},
        'warnings': []
    }
    
    # Check core modules
    core_modules = ['socket', 'threading', 'asyncio', 'json', 'logging']
    for mod in core_modules:
        try:
            __import__(mod)
            status['core_modules'][mod] = True
        except ImportError:
            status['core_modules'][mod] = False
            status['ready'] = False
    
    # Check optional modules
    optional_modules = {
        'rich': 'Rich console output',
        'scapy': 'Advanced packet analysis',
        'netifaces': 'Network interface detection',
        'numpy': 'Numerical operations',
        'sklearn': 'Machine learning (scikit-learn)'
    }
    
    for mod, desc in optional_modules.items():
        try:
            __import__(mod)
            status['optional_modules'][mod] = True
        except ImportError:
            status['optional_modules'][mod] = False
            status['warnings'].append(f"{mod} not installed - {desc} unavailable")
    
    # Check AI configuration
    try:
        import google.generativeai
        status['ai_status']['gemini_available'] = True
    except ImportError:
        status['ai_status']['gemini_available'] = False
    
    try:
        import openai
        status['ai_status']['openai_available'] = True
    except ImportError:
        status['ai_status']['openai_available'] = False
    
    # Check for API keys
    status['ai_status']['gemini_key_set'] = bool(os.environ.get('GEMINI_API_KEY'))
    status['ai_status']['openai_key_set'] = bool(os.environ.get('OPENAI_API_KEY'))
    
    # Check config file
    config_file = Path("config/ai_config.json")
    status['ai_status']['config_exists'] = config_file.exists()
    
    return status


class IntelProbe:
    """
    Main IntelProbe class for programmatic access
    
    Example:
        >>> probe = IntelProbe()
        >>> results = probe.scan("192.168.1.1")
        >>> probe.analyze(results)
    """
    
    def __init__(self, ai_enabled: bool = True, verbose: bool = False):
        """Initialize IntelProbe instance"""
        self.ai_enabled = ai_enabled
        self.verbose = verbose
        self._scanner = None
        self._ai_engine = None
    
    @property
    def scanner(self):
        """Get scanner instance"""
        if self._scanner is None:
            try:
                from core.super_scanner import SuperScanner
                self._scanner = SuperScanner()
            except ImportError:
                from core.scanner import Scanner
                self._scanner = Scanner()
        return self._scanner
    
    @property
    def ai_engine(self):
        """Get AI engine instance"""
        if self._ai_engine is None and self.ai_enabled:
            try:
                from core.ai_engine import AIEngine
                from core.config import ConfigManager
                config = ConfigManager()
                self._ai_engine = AIEngine(config)
            except ImportError:
                pass
        return self._ai_engine
    
    def scan(self, target: str, ports: str = "common", speed: str = "fast") -> Dict:
        """
        Scan a target
        
        Args:
            target: IP, hostname, or CIDR network
            ports: Port preset or range
            speed: Scan speed preset
        
        Returns:
            Scan results dictionary
        """
        return quick_scan(target, ports)
    
    def analyze(self, scan_results: Dict) -> Dict:
        """
        Analyze scan results with AI
        
        Args:
            scan_results: Results from scan()
        
        Returns:
            Analysis results
        """
        if not self.ai_engine:
            return {'analysis': 'AI analysis not available'}
        
        try:
            results_list = scan_results.get('results', [])
            analysis = self.ai_engine.analyze_network_scan(results_list)
            return {
                'threat_level': analysis.threat_level,
                'threats': analysis.threats,
                'recommendations': analysis.recommendations,
                'analysis': analysis.analysis
            }
        except Exception as e:
            return {'error': str(e)}
    
    def discover(self, network: str) -> List[str]:
        """Discover hosts on a network"""
        return discover_hosts(network)
    
    def full_scan(self, target: str) -> Dict:
        """Perform a full scan with AI analysis"""
        scan_results = self.scan(target, ports="full")
        analysis = self.analyze(scan_results)
        return {
            'scan': scan_results,
            'analysis': analysis
        }


# Print usage when run directly
if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════╗
║           IntelProbe Quick Start Utilities                       ║
╚══════════════════════════════════════════════════════════════════╝

Available Functions:
────────────────────
• quick_scan(target)      - Fast scan of target
• full_scan(target)       - Comprehensive scan with AI
• discover_hosts(network) - Find live hosts
• port_scan(host, ports)  - Scan specific ports
• get_network_info()      - Local network information
• setup_ai(api_key)       - Configure AI analysis
• check_setup()           - Verify installation

Example Usage:
──────────────
>>> from utils import quick_scan, get_network_info
>>> info = get_network_info()
>>> results = quick_scan(info['network'])

Class-based Usage:
──────────────────
>>> from utils import IntelProbe
>>> probe = IntelProbe()
>>> results = probe.scan("192.168.1.0/24")
>>> analysis = probe.analyze(results)

For more info, visit: https://github.com/lintshiwe/IntelProbe
""")
