#!/usr/bin/env python3
"""IntelProbe - AI-Powered Network Forensics CLI.

Enhanced version of netspionage with AI capabilities and modern features.
Provides network scanning, OSINT gathering, attack detection, and AI analysis.

Usage:
    python intelprobe.py                    # Interactive mode
    python intelprobe.py scan network <target>
    python intelprobe.py --help

Author: Lintshiwe Slade (@lintshiwe)
GitHub: https://github.com/lintshiwe/IntelProbe
License: MIT License
"""

import sys
import os
import argparse
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def main():
    """Main entry point for IntelProbe"""
    
    # Check Python version
    if sys.version_info[0] < 3 or sys.version_info[1] < 8:
        print("❌ IntelProbe requires Python 3.8 or higher")
        print(f"   Current version: {sys.version}")
        sys.exit(1)
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="IntelProbe - AI-Powered Network Forensics CLI",
        epilog="For interactive mode, run without arguments"
    )
    
    parser.add_argument(
        '--version', 
        action='version', 
        version='IntelProbe v2.0.0 (Enhanced netspionage)'
    )
    
    parser.add_argument(
        '--config', 
        type=str, 
        default='config.ini',
        help='Configuration file path (default: config.ini)'
    )
    
    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Disable banner display'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan commands
    scan_parser = subparsers.add_parser('scan', help='Network scanning operations')
    scan_subparsers = scan_parser.add_subparsers(dest='scan_type')
    
    # Network scan
    network_parser = scan_subparsers.add_parser('network', help='Network discovery scan')
    network_parser.add_argument('target', help='Target network (e.g., 192.168.1.0/24)')
    network_parser.add_argument('--threads', type=int, default=50, help='Number of threads')
    network_parser.add_argument('--timeout', type=int, default=5, help='Scan timeout in seconds')
    
    # Port scan
    port_parser = scan_subparsers.add_parser('ports', help='Port scanning')
    port_parser.add_argument('target', help='Target host or network')
    port_parser.add_argument('--range', default='1-1000', help='Port range (e.g., 1-1000)')
    port_parser.add_argument('--service-detection', action='store_true', help='Enable service detection')
    
    # WiFi scan
    wifi_parser = scan_subparsers.add_parser('wifi', help='WiFi network scanning')
    wifi_parser.add_argument('--interface', help='WiFi interface (e.g., wlan0)')
    wifi_parser.add_argument('--duration', type=int, default=30, help='Scan duration in seconds')
    
    # OSINT commands
    osint_parser = subparsers.add_parser('osint', help='OSINT and intelligence gathering')
    osint_subparsers = osint_parser.add_subparsers(dest='osint_type')
    
    # MAC lookup
    mac_parser = osint_subparsers.add_parser('mac', help='MAC address intelligence')
    mac_parser.add_argument('address', help='MAC address to lookup')
    
    # IP lookup
    ip_parser = osint_subparsers.add_parser('ip', help='IP address intelligence')
    ip_parser.add_argument('address', help='IP address to lookup')
    
    # Detection commands
    detect_parser = subparsers.add_parser('detect', help='Attack detection and monitoring')
    detect_subparsers = detect_parser.add_subparsers(dest='detect_type')
    
    # ARP spoofing detection
    arp_parser = detect_subparsers.add_parser('arp', help='ARP spoofing detection')
    arp_parser.add_argument('network', help='Target network to monitor')
    arp_parser.add_argument('--interface', help='Network interface')
    
    # DDoS detection
    ddos_parser = detect_subparsers.add_parser('ddos', help='DDoS attack detection')
    ddos_parser.add_argument('--interface', help='Network interface to monitor')
    ddos_parser.add_argument('--threshold', type=int, default=100, help='Packet threshold')
    
    # AI commands
    ai_parser = subparsers.add_parser('ai', help='AI-powered analysis and insights')
    ai_subparsers = ai_parser.add_subparsers(dest='ai_type')
    
    # AI analysis
    analyze_parser = ai_subparsers.add_parser('analyze', help='AI network analysis')
    analyze_parser.add_argument('data', help='Data to analyze or scan ID')
    
    # AI report generation
    report_parser = ai_subparsers.add_parser('report', help='Generate AI-powered reports')
    report_parser.add_argument('scan_id', help='Scan ID for report generation')
    report_parser.add_argument('--format', choices=['json', 'html', 'pdf'], default='json')
    
    args = parser.parse_args()
    
    try:
        # Import core modules after argument parsing to avoid import errors
        from core.interface import IntelProbeInterface
        from core.config import ConfigManager
        from core.utils import setup_logging
        
        # Initialize configuration
        config = ConfigManager(args.config)
        
        # Setup logging
        setup_logging(config)
        
        # Initialize the main interface
        interface = IntelProbeInterface(config, args)
        
        if args.command:
            # Command-line mode
            interface.execute_command(args)
        else:
            # Interactive mode
            interface.interactive_mode()
            
    except KeyboardInterrupt:
        print("\n🛑 IntelProbe interrupted by user. Goodbye!")
        sys.exit(0)
    except ImportError as e:
        print(f"❌ Missing dependencies: {e}")
        print("💡 Install dependencies:")
        print("   pip install -r requirements-simple.txt")
        print("\n🚀 For a quick demo without dependencies, try:")
        print("   python quick-start.py")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        print("\n🚀 For a quick demo without dependencies, try:")
        print("   python quick-start.py")
        sys.exit(1)

if __name__ == '__main__':
    main()
