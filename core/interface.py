"""Main Interface Module for IntelProbe
Handles command-line interface, interactive mode, and orchestrates all components
"""

import sys
import os
import time
import json
import asyncio
from typing import Dict, List, Any, Optional
import logging
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich import print as rprint
import click
from datetime import datetime

from .config import ConfigManager
from .utils import setup_logging, format_time, validate_ip, validate_network
from .scanner import EnhancedScanner
from .forensics import ForensicsEngine
from .pentester import PenTester
from .ai_engine import AIEngine

class IntelProbeInterface:
    """Main interface for IntelProbe CLI"""
    
    def __init__(self, config: ConfigManager, args: Any = None):
        """Initialize IntelProbe interface"""
        self.config = config
        self.args = args or {}
        self.console = Console()
        
        # Set up logging
        self._setup_logging()
        
    def _validate_network(self, target: str) -> bool:
        """Validate network target format"""
        # Basic format validation
        if not target:
            return False
            
        # Allow IP with CIDR
        if "/" in target:
            try:
                ip, cidr = target.split("/")
                if not (0 <= int(cidr) <= 32):
                    return False
            except:
                return False
                
        # Validate IP format
        try:
            parts = target.split(".")
            if len(parts) != 4:
                return False
            return all(0 <= int(p) <= 255 for p in parts)
        except:
            return False
        
        # Initialize engines
        self.scanner = EnhancedScanner(config)
        self.ai_engine = AIEngine(config)
        self.forensics = ForensicsEngine(config, self.ai_engine)
        self.pentester = PenTester(config, self.ai_engine)
        
        # Analysis state
        self.active_scan = None
        self.active_forensics = None
        self.active_pentest = None
        
        # Results storage
        self.scan_results = []
        self.forensic_cases = []
        self.pentest_results = []

    def _setup_logging(self) -> None:
        """Configure logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('intelprobe.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Initialize scanner with enhanced OS detection
        try:
            self.scanner = EnhancedScanner(self.config)
            self.logger.info("Enhanced scanner initialized")
        except ImportError:
            try:
                from .production_scanner import ProductionScanner
                self.scanner = ProductionScanner(self.config)
                self.logger.info("Using production scanner")
            except ImportError:
                self.scanner = None
                self.logger.error("No scanner available")
        
        # Initialize AI engine
        try:
            self.ai_engine = AIEngine(self.config)
        except ImportError:
            self.ai_engine = None
            self.logger.warning("AI engine not available")
        
        # Initialize forensics and pentester engines
        try:
            self.forensics = ForensicsEngine(self.config, self.ai_engine)
            self.pentester = PenTester(self.config, self.ai_engine)
        except ImportError:
            self.forensics = None
            self.pentester = None
            self.logger.warning("Forensics/Pentester engines not available")
        
        # Initialize detection engine
        try:
            from .detection import AttackDetector
            self.detector = AttackDetector(self.config)
        except ImportError:
            self.detector = None
            self.logger.warning("Attack detector not available")
        
        # Initialize OSINT engine
        try:
            from .osint import OSINTGatherer
            self.osint = OSINTGatherer(self.config)
        except ImportError:
            self.osint = None
            self.logger.warning("OSINT module not available")
        
        # Session data
        self.session_data = {
            'scan_results': [],
            'osint_data': {},
            'detection_alerts': [],
            'ai_analyses': [],
            'session_start': time.time()
        }
        
        # Display banner unless disabled
        if not getattr(self.args, 'no_banner', False):
            self._display_banner()
    
    def _display_banner(self) -> None:
        """Display IntelProbe banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║     ██╗███╗   ██╗████████╗███████╗██╗     ██████╗ ██████╗  ██████╗ ██████╗ ███████╗    ║
║     ██║████╗  ██║╚══██╔══╝██╔════╝██║     ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝    ║
║     ██║██╔██╗ ██║   ██║   █████╗  ██║     ██████╔╝██████╔╝██║   ██║██████╔╝█████╗      ║
║     ██║██║╚██╗██║   ██║   ██╔══╝  ██║     ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝      ║
║     ██║██║ ╚████║   ██║   ███████╗███████╗██║     ██║  ██║╚██████╔╝██████╔╝███████╗    ║
║     ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝    ║
║                                                                               ║
║                    🔍 AI-Powered Network Forensics CLI v2.0                   ║
║                                                                               ║
║                     Enhanced with netspionage core technology                 ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
        
        self.console.print(banner, style="bold cyan")
        self.console.print("🚀 Welcome to IntelProbe - Where Network Forensics Meets AI", style="bold green")
        self.console.print("⚡ Ready to analyze, detect, and secure your network", style="yellow")
        self.console.print()
    
    def interactive_mode(self) -> None:
        """Run IntelProbe in interactive mode"""
        self.console.print("🎯 Starting Interactive Mode", style="bold blue")
        self.console.print("Type 'help' for available commands or 'exit' to quit\\n")
        
        while True:
            try:
                # Get user input
                user_input = self.console.input("[bold green]IntelProbe[/bold green] [cyan]>>[/cyan] ").strip()
                
                if not user_input:
                    continue
                    
                if user_input.lower() in ['exit', 'quit', 'q']:
                    self._handle_exit()
                    break
                    
                elif user_input.lower() in ['help', '?']:
                    self._show_help()
                    
                elif user_input.lower() == 'status':
                    self._show_status()
                    
                elif user_input.lower() == 'clear':
                    os.system('cls' if os.name == 'nt' else 'clear')
                    self._display_banner()
                    
                else:
                    # Parse and execute command
                    self._parse_interactive_command(user_input)
                    
            except KeyboardInterrupt:
                self.console.print("\\n🛑 Use 'exit' to quit IntelProbe")
                continue
            except EOFError:
                break
            except Exception as e:
                self.console.print(f"❌ Error: {e}", style="red")
    
    def _parse_interactive_command(self, command: str) -> None:
        """Parse and execute interactive command"""
        parts = command.split()
        if not parts:
            return
        
        cmd = parts[0].lower()
        
        try:
            if cmd == 'scan':
                self._handle_interactive_scan(parts[1:])
            elif cmd == 'osint':
                self._handle_interactive_osint(parts[1:])
            elif cmd == 'detect':
                self._handle_interactive_detect(parts[1:])
            elif cmd == 'ai':
                self._handle_interactive_ai(parts[1:])
            elif cmd == 'report':
                self._handle_interactive_report(parts[1:])
            elif cmd == 'config':
                self._handle_interactive_config(parts[1:])
            else:
                self.console.print(f"❌ Unknown command: {cmd}. Type 'help' for available commands.", style="red")
                
        except Exception as e:
            self.console.print(f"❌ Command execution failed: {e}", style="red")
    
    def _handle_interactive_scan(self, args: List[str]) -> None:
        """Handle interactive scan commands"""
        if not args:
            self.console.print("📋 Available scan types:", style="bold")
            self.console.print("  • scan network <target>     - Network discovery")
            self.console.print("  • scan ports <target>       - Port scanning")
            self.console.print("  • scan wifi                 - WiFi enumeration")
            return
            
        scan_type = args[0].lower()
        
        if scan_type == 'network':
            if len(args) < 2:
                target = self.console.input("🎯 Enter target network (e.g., 192.168.1.0/24): ")
            else:
                target = args[1]
                
            if not self._validate_network(target):
                self.console.print("❌ Invalid network format", style="red")
                return
                
            self._run_network_scan(target)
            
        elif scan_type == 'ports':
            if len(args) < 2:
                target = self.console.input("🎯 Enter target host/network: ")
            else:
                target = args[1]
                
            port_range = args[2] if len(args) > 2 else "1-1000"
            self._run_port_scan(target, port_range)
            
        elif scan_type == 'wifi':
            duration = int(args[1]) if len(args) > 1 else 30
            self._run_wifi_scan(duration)
            
        else:
            self.console.print(f"❌ Unknown scan type: {scan_type}", style="red")
    
    def _run_network_scan(self, target: str) -> None:
        """Run network discovery scan"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("🔍 Scanning network...", total=None)
            
            try:
                results = self.scanner.scan_network(target)
                progress.update(task, description="✅ Network scan completed")
                
                if results:
                    self.session_data['scan_results'].extend(results)
                    self._display_scan_results(results)
                    
                    # AI analysis if enabled
                    if self.config.get_ai_config()['enabled']:
                        self._run_ai_analysis(results)
                else:
                    self.console.print("ℹ️ No hosts discovered", style="yellow")
                    
            except Exception as e:
                self.console.print(f"❌ Network scan failed: {e}", style="red")
    
    def _run_port_scan(self, target: str, port_range: str) -> None:
        """Run port scan"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("🔍 Scanning ports...", total=None)
            
            try:
                # Run port scan with service detection enabled
                results = self.scanner.scan_ports(
                    target, 
                    port_range=port_range,
                    service_detection=True,
                    threads=100
                )
                progress.update(task, description="✅ Port scan completed")
                
                if results:
                    self._display_port_scan_results(results)
                    # Store results in session data
                    if not isinstance(self.session_data['scan_results'], list):
                        self.session_data['scan_results'] = []
                    self.session_data['scan_results'].append({
                        'timestamp': time.time(),
                        'target': target,
                        'port_data': results
                    })
                else:
                    self.console.print("ℹ️ No open ports found", style="yellow")
                    
            except Exception as e:
                self.console.print(f"❌ Port scan failed: {e}", style="red")
    
    def _run_wifi_scan(self, duration: int) -> None:
        """Run WiFi scan"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task(f"📡 Scanning WiFi networks for {duration}s...", total=None)
            
            try:
                # Run WiFi scan
                networks = self.scanner.scan_wifi(duration=duration)
                progress.update(task, description="✅ WiFi scan completed")
                
                if networks:
                    self._display_wifi_results(networks)
                    # Store results in session data
                    self.session_data['scan_results'].append({
                        'timestamp': time.time(),
                        'type': 'wifi',
                        'duration': duration,
                        'networks': [
                            {
                                'ssid': n.ssid,
                                'bssid': n.bssid,
                                'channel': n.channel,
                                'encryption': n.encryption,
                                'signal_strength': n.signal_strength
                            }
                            for n in networks
                        ]
                    })
                else:
                    self.console.print("ℹ️ No WiFi networks discovered", style="yellow")
                    
            except Exception as e:
                self.console.print(f"❌ WiFi scan failed: {e}", style="red")
                
            finally:
                # Cleanup and disable monitor mode if needed
                try:
                    if hasattr(self.scanner, '_cleanup_wifi'):
                        self.scanner._cleanup_wifi()
                except:
                    pass
    
    def _display_scan_results(self, results) -> None:
        """Display network scan results in a table"""
        table = Table(title="🔍 Network Scan Results")
        table.add_column("IP Address", style="cyan")
        table.add_column("MAC Address", style="magenta")
        table.add_column("Hostname", style="green")
        table.add_column("OS", style="yellow")
        table.add_column("Response Time", style="blue")
        
        for result in results:
            table.add_row(
                result.ip,
                result.mac,
                result.hostname or "N/A",
                result.os or "Unknown",
                f"{result.response_time:.3f}s"
            )
        
        self.console.print(table)
        self.console.print(f"\\n📊 Discovered {len(results)} active hosts")
    
    def _display_port_scan_results(self, results: Dict[str, Any]) -> None:
        """Display port scan results"""
        for host, data in results.items():
            panel_content = []
            panel_content.append(f"🎯 Host: {host}")
            panel_content.append(f"📊 Open Ports: {len(data['open_ports'])}")
            panel_content.append(f"🔍 Total Scanned: {data['total_scanned']}")
            
            if data['open_ports']:
                panel_content.append("\\n🟢 Open Ports:")
                for port in data['open_ports'][:10]:  # Show first 10
                    service = data['services'].get(port, 'Unknown')
                    panel_content.append(f"  • {port}/tcp - {service}")
                
                if len(data['open_ports']) > 10:
                    panel_content.append(f"  ... and {len(data['open_ports']) - 10} more")
            
            self.console.print(Panel("\\n".join(panel_content), title=f"Port Scan - {host}"))
    
    def _display_wifi_results(self, networks) -> None:
        """Display WiFi scan results"""
        table = Table(title="📡 WiFi Networks")
        table.add_column("SSID", style="cyan")
        table.add_column("BSSID", style="magenta")
        table.add_column("Channel", style="green")
        table.add_column("Encryption", style="yellow")
        table.add_column("Signal", style="blue")
        
        for network in networks:
            table.add_row(
                network.ssid,
                network.bssid,
                str(network.channel),
                network.encryption,
                f"{network.signal_strength} dBm"
            )
        
        self.console.print(table)
    
    def _run_ai_analysis(self, scan_results) -> None:
        """Run AI analysis on scan results"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("🤖 Running AI analysis...", total=None)
            
            try:
                # Convert scan results to dict format for AI
                results_dict = [
                    {
                        'ip': r.ip,
                        'mac': r.mac,
                        'hostname': r.hostname,
                        'os': r.os,
                        'ports': r.ports,
                        'services': r.services,
                        'response_time': r.response_time
                    }
                    for r in scan_results
                ]
                
                analysis = self.ai_engine.analyze_network_scan(results_dict)
                progress.update(task, description="✅ AI analysis completed")
                
                self.session_data['ai_analyses'].append(analysis)
                self._display_ai_analysis(analysis)
                
            except Exception as e:
                self.console.print(f"❌ AI analysis failed: {e}", style="red")
    
    def _display_ai_analysis(self, analysis) -> None:
        """Display AI analysis results"""
        # Threat level color mapping
        level_colors = {
            'low': 'green',
            'medium': 'yellow',
            'high': 'red',
            'critical': 'bright_red'
        }
        
        color = level_colors.get(analysis.threat_level, 'white')
        
        panel_content = []
        panel_content.append(f"🎯 Threat Level: [{color}]{analysis.threat_level.upper()}[/{color}]")
        panel_content.append(f"🎯 Confidence: {analysis.confidence:.2%}")
        panel_content.append(f"⚠️ Threats Found: {len(analysis.threats)}")
        
        if analysis.threats:
            panel_content.append("\\n🚨 Key Threats:")
            for threat in analysis.threats[:5]:  # Show top 5
                panel_content.append(f"  • {threat}")
        
        if analysis.recommendations:
            panel_content.append("\\n💡 Recommendations:")
            for rec in analysis.recommendations[:5]:  # Show top 5
                panel_content.append(f"  • {rec}")
        
        if analysis.analysis:
            panel_content.append(f"\\n🤖 AI Analysis:\\n{analysis.analysis}")
        
        self.console.print(Panel("\\n".join(panel_content), title="🤖 AI Security Analysis"))
    
    def _handle_interactive_osint(self, args: List[str]) -> None:
        """Handle interactive OSINT commands"""
        if not args:
            self.console.print("📋 Available OSINT commands:", style="bold")
            self.console.print("  • osint mac <address>       - MAC address lookup")
            self.console.print("  • osint ip <address>        - IP intelligence")
            self.console.print("  • osint domain <domain>     - Domain analysis")
            return
        
        osint_type = args[0].lower()
        
        if osint_type == 'mac':
            if len(args) < 2:
                mac = self.console.input("🔍 Enter MAC address: ")
            else:
                mac = args[1]
            
            self._run_mac_lookup(mac)
            
        elif osint_type == 'ip':
            if len(args) < 2:
                ip = self.console.input("🔍 Enter IP address: ")
            else:
                ip = args[1]
            
            if not validate_ip(ip):
                self.console.print("❌ Invalid IP address format", style="red")
                return
            
            self._run_ip_lookup(ip)
            
        elif osint_type == 'domain':
            if len(args) < 2:
                domain = self.console.input("🔍 Enter domain name: ")
            else:
                domain = args[1]
            
            self._run_domain_analysis(domain)
            
        else:
            self.console.print(f"❌ Unknown OSINT type: {osint_type}", style="red")
    
    def _run_mac_lookup(self, mac: str) -> None:
        """Run MAC address lookup"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("🔍 Looking up MAC address...", total=None)
            
            try:
                vendor_info = self.osint.lookup_mac_address(mac)
                progress.update(task, description="✅ MAC lookup completed")
                
                self._display_mac_info(vendor_info)
                
            except Exception as e:
                self.console.print(f"❌ MAC lookup failed: {e}", style="red")
    
    def _run_ip_lookup(self, ip: str) -> None:
        """Run IP address intelligence lookup"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("🌐 Analyzing IP address...", total=None)
            
            try:
                ip_intel = self.osint.lookup_ip_address(ip)
                progress.update(task, description="✅ IP analysis completed")
                
                self._display_ip_intel(ip_intel)
                
            except Exception as e:
                self.console.print(f"❌ IP lookup failed: {e}", style="red")
    
    def _run_domain_analysis(self, domain: str) -> None:
        """Run domain analysis"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("🌍 Analyzing domain...", total=None)
            
            try:
                domain_intel = self.osint.analyze_domain(domain)
                progress.update(task, description="✅ Domain analysis completed")
                
                self._display_domain_intel(domain_intel)
                
            except Exception as e:
                self.console.print(f"❌ Domain analysis failed: {e}", style="red")
    
    def _display_mac_info(self, vendor_info) -> None:
        """Display MAC address vendor information"""
        panel_content = []
        panel_content.append(f"🔍 MAC Address: {vendor_info.mac_address}")
        panel_content.append(f"🏢 Vendor: {vendor_info.vendor}")
        panel_content.append(f"🏪 Company: {vendor_info.company}")
        
        if vendor_info.address:
            panel_content.append(f"📍 Address: {vendor_info.address}")
        if vendor_info.country:
            panel_content.append(f"🌍 Country: {vendor_info.country}")
        if vendor_info.block_type:
            panel_content.append(f"📋 Block Type: {vendor_info.block_type}")
        
        self.console.print(Panel("\\n".join(panel_content), title="🔍 MAC Address Intelligence"))
    
    def _display_ip_intel(self, ip_intel) -> None:
        """Display IP intelligence information"""
        panel_content = []
        panel_content.append(f"🌐 IP Address: {ip_intel.ip_address}")
        panel_content.append(f"🏠 Hostname: {ip_intel.hostname}")
        panel_content.append(f"🌍 Location: {ip_intel.city}, {ip_intel.country}")
        panel_content.append(f"🏢 Organization: {ip_intel.organization}")
        panel_content.append(f"📡 ISP: {ip_intel.isp}")
        
        if ip_intel.threat_level != 'unknown':
            threat_color = 'red' if ip_intel.is_malicious else 'green'
            panel_content.append(f"⚠️ Threat Level: [{threat_color}]{ip_intel.threat_level.upper()}[/{threat_color}]")
        
        if ip_intel.vpn_detected:
            panel_content.append("🔒 VPN/Proxy: Detected")
        
        self.console.print(Panel("\\n".join(panel_content), title="🌐 IP Intelligence"))
    
    def _display_domain_intel(self, domain_intel) -> None:
        """Display domain intelligence information"""
        panel_content = []
        panel_content.append(f"🌍 Domain: {domain_intel.domain}")
        
        if domain_intel.ip_addresses:
            panel_content.append(f"📍 IP Addresses: {', '.join(domain_intel.ip_addresses[:3])}")
        
        if domain_intel.nameservers:
            panel_content.append(f"🌐 Nameservers: {', '.join(domain_intel.nameservers[:2])}")
        
        if domain_intel.registrar:
            panel_content.append(f"📋 Registrar: {domain_intel.registrar}")
        
        if domain_intel.reputation_score > 0:
            score_color = 'red' if domain_intel.is_suspicious else 'green'
            panel_content.append(f"⭐ Reputation: [{score_color}]{domain_intel.reputation_score:.1f}/100[/{score_color}]")
        
        self.console.print(Panel("\\n".join(panel_content), title="🌍 Domain Intelligence"))
    
    def _handle_interactive_detect(self, args: List[str]) -> None:
        """Handle interactive detection commands"""
        if not args:
            self.console.print("📋 Available detection commands:", style="bold")
            self.console.print("  • detect start [interface]  - Start monitoring")
            self.console.print("  • detect stop               - Stop monitoring") 
            self.console.print("  • detect arp <network>      - ARP spoofing detection")
            self.console.print("  • detect status             - Detection status")
            return
        
        detect_cmd = args[0].lower()
        
        if detect_cmd == 'start':
            interface = args[1] if len(args) > 1 else None
            duration = int(args[2]) if len(args) > 2 else 0
            self._start_detection(interface, duration)
            
        elif detect_cmd == 'stop':
            self._stop_detection()
            
        elif detect_cmd == 'arp':
            if len(args) < 2:
                network = self.console.input("🎯 Enter network to monitor: ")
            else:
                network = args[1]
            
            duration = int(args[2]) if len(args) > 2 else 60
            self._detect_arp_spoofing(network, duration)
            
        elif detect_cmd == 'status':
            self._show_detection_status()
            
        else:
            self.console.print(f"❌ Unknown detection command: {detect_cmd}", style="red")
    
    def _start_detection(self, interface: str = None, duration: int = 0) -> None:
        """Start attack detection monitoring"""
        self.console.print("🛡️ Starting attack detection monitoring...")
        
        try:
            success = self.detector.start_monitoring(interface, duration)
            if success:
                self.console.print("✅ Attack detection started", style="green")
                if duration > 0:
                    self.console.print(f"⏱️ Monitoring for {duration} seconds")
                else:
                    self.console.print("🔄 Monitoring indefinitely (use 'detect stop' to stop)")
            else:
                self.console.print("❌ Failed to start detection", style="red")
                
        except Exception as e:
            self.console.print(f"❌ Detection startup failed: {e}", style="red")
    
    def _stop_detection(self) -> None:
        """Stop attack detection monitoring"""
        try:
            self.detector.stop_monitoring()
            self.console.print("✅ Attack detection stopped", style="green")
            
            # Show summary
            summary = self.detector.get_detection_summary()
            self._display_detection_summary(summary)
            
        except Exception as e:
            self.console.print(f"❌ Failed to stop detection: {e}", style="red")
    
    def _detect_arp_spoofing(self, network: str, duration: int) -> None:
        """Run dedicated ARP spoofing detection"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task(f"🛡️ Monitoring for ARP spoofing ({duration}s)...", total=None)
            
            try:
                alerts = self.detector.detect_arp_spoofing(network, duration=duration)
                progress.update(task, description="✅ ARP spoofing detection completed")
                
                if alerts:
                    self.console.print(f"🚨 Found {len(alerts)} ARP spoofing alerts:", style="red")
                    for alert in alerts:
                        self.console.print(f"  • {alert.description}")
                else:
                    self.console.print("✅ No ARP spoofing detected", style="green")
                    
            except Exception as e:
                self.console.print(f"❌ ARP spoofing detection failed: {e}", style="red")
    
    def _show_detection_status(self) -> None:
        """Show detection status"""
        summary = self.detector.get_detection_summary()
        self._display_detection_summary(summary)
    
    def _display_detection_summary(self, summary: Dict[str, Any]) -> None:
        """Display detection summary"""
        panel_content = []
        panel_content.append(f"📊 Status: {summary['monitoring_status'].upper()}")
        panel_content.append(f"⏱️ Runtime: {format_time(summary['runtime_seconds'])}")
        panel_content.append(f"📦 Packets Analyzed: {summary['packets_analyzed']:,}")
        panel_content.append(f"🚨 Total Alerts: {summary['total_alerts']}")
        
        if summary['alerts_by_severity']:
            panel_content.append("\\n⚠️ Alerts by Severity:")
            for severity, count in summary['alerts_by_severity'].items():
                panel_content.append(f"  • {severity.title()}: {count}")
        
        if summary['recent_alerts']:
            panel_content.append("\\n🕒 Recent Alerts:")
            for alert in summary['recent_alerts']:
                panel_content.append(f"  • [{alert['severity']}] {alert['type']}: {alert['description'][:50]}...")
        
        self.console.print(Panel("\\n".join(panel_content), title="🛡️ Attack Detection Status"))
    
    def _handle_interactive_ai(self, args: List[str]) -> None:
        """Handle interactive AI commands"""
        if not args:
            self.console.print("📋 Available AI commands:", style="bold")
            self.console.print("  • ai analyze                - Analyze current data")
            self.console.print("  • ai predict                - Generate threat predictions")
            self.console.print("  • ai report                 - Generate comprehensive report")
            return
        
        ai_cmd = args[0].lower()
        
        if ai_cmd == 'analyze':
            self._run_ai_analysis_interactive()
            
        elif ai_cmd == 'predict':
            self._run_ai_predictions()
            
        elif ai_cmd == 'report':
            self._generate_ai_report()
            
        else:
            self.console.print(f"❌ Unknown AI command: {ai_cmd}", style="red")
    
    def _run_ai_analysis_interactive(self) -> None:
        """Run AI analysis on current session data"""
        if not self.session_data['scan_results']:
            self.console.print("⚠️ No scan data available for analysis. Run a scan first.", style="yellow")
            return
        
        self._run_ai_analysis(self.session_data['scan_results'])
    
    def _run_ai_predictions(self) -> None:
        """Run AI threat predictions"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("🔮 Generating threat predictions...", total=None)
            
            try:
                network_data = {'scan_results': self.session_data['scan_results']}
                predictions = self.ai_engine.predict_threats(network_data)
                progress.update(task, description="✅ Predictions generated")
                
                if predictions:
                    self._display_ai_predictions(predictions)
                else:
                    self.console.print("ℹ️ No specific threats predicted", style="yellow")
                    
            except Exception as e:
                self.console.print(f"❌ Threat prediction failed: {e}", style="red")
    
    def _display_ai_predictions(self, predictions) -> None:
        """Display AI threat predictions"""
        panel_content = []
        panel_content.append(f"🔮 Generated {len(predictions)} threat predictions:")
        
        for i, prediction in enumerate(predictions, 1):
            panel_content.append(f"\\n{i}. {prediction.insight_type.title()}")
            panel_content.append(f"   📋 Description: {prediction.description}")
            panel_content.append(f"   💥 Impact: {prediction.impact}")
            panel_content.append(f"   💡 Recommendation: {prediction.recommendation}")
            panel_content.append(f"   🎯 Confidence: {prediction.confidence:.2%}")
        
        self.console.print(Panel("\\n".join(panel_content), title="🔮 AI Threat Predictions"))
    
    def _generate_ai_report(self) -> None:
        """Generate comprehensive AI report"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("📊 Generating AI report...", total=None)
            
            try:
                # Use latest analysis or create new one
                if self.session_data['ai_analyses']:
                    analysis = self.session_data['ai_analyses'][-1]
                else:
                    # Create analysis from current data
                    results_dict = [
                        {
                            'ip': r.ip,
                            'mac': r.mac,
                            'hostname': r.hostname,
                            'os': r.os,
                            'ports': r.ports,
                            'services': r.services
                        }
                        for r in self.session_data['scan_results']
                    ]
                    analysis = self.ai_engine.analyze_network_scan(results_dict)
                
                report = self.ai_engine.generate_report(self.session_data, analysis)
                progress.update(task, description="✅ Report generated")
                
                # Save report
                timestamp = int(time.time())
                report_file = f"reports/ai_report_{timestamp}.json"
                
                os.makedirs("reports", exist_ok=True)
                with open(report_file, 'w') as f:
                    json.dump(report, f, indent=2)
                
                self.console.print(f"✅ AI report saved: {report_file}", style="green")
                self._display_report_summary(report)
                
            except Exception as e:
                self.console.print(f"❌ Report generation failed: {e}", style="red")
    
    def _display_report_summary(self, report: Dict[str, Any]) -> None:
        """Display report summary"""
        executive = report.get('executive_summary', {})
        
        panel_content = []
        panel_content.append(f"🎯 Threat Level: {executive.get('threat_level', 'unknown').upper()}")
        panel_content.append(f"🎯 Confidence: {executive.get('confidence', 0):.2%}")
        panel_content.append(f"⚠️ Total Threats: {executive.get('total_threats', 0)}")
        
        if 'ai_summary' in executive:
            panel_content.append(f"\\n🤖 Executive Summary:\\n{executive['ai_summary']}")
        
        self.console.print(Panel("\\n".join(panel_content), title="📊 AI Security Report"))
    
    def _show_help(self) -> None:
        """Show help information"""
        help_text = """
[bold cyan]IntelProbe Commands:[/bold cyan]

[bold yellow]Network Scanning:[/bold yellow]
  scan network <target>     - Network discovery (e.g., 192.168.1.0/24)
  scan ports <target>       - Port scanning
  scan wifi [duration]      - WiFi network enumeration

[bold yellow]OSINT & Intelligence:[/bold yellow]
  osint mac <address>       - MAC address vendor lookup
  osint ip <address>        - IP address intelligence
  osint domain <domain>     - Domain analysis

[bold yellow]Attack Detection:[/bold yellow]
  detect start [interface]  - Start monitoring for attacks
  detect stop               - Stop attack monitoring
  detect arp <network>      - ARP spoofing detection
  detect status             - Show detection status

[bold yellow]AI Features:[/bold yellow]
  ai analyze                - AI analysis of current data
  ai predict                - Generate threat predictions
  ai report                 - Create comprehensive AI report

[bold yellow]General:[/bold yellow]
  status                    - Show session status
  clear                     - Clear screen
  help                      - Show this help
  exit                      - Quit IntelProbe
        """
        
        self.console.print(Panel(help_text, title="📚 IntelProbe Help"))
    
    def _show_status(self) -> None:
        """Show current session status"""
        runtime = time.time() - self.session_data['session_start']
        
        panel_content = []
        panel_content.append(f"⏱️ Session Runtime: {format_time(runtime)}")
        panel_content.append(f"🔍 Scan Results: {len(self.session_data['scan_results'])}")
        panel_content.append(f"🕵️ OSINT Lookups: {len(self.session_data['osint_data'])}")
        panel_content.append(f"🚨 Detection Alerts: {len(self.session_data['detection_alerts'])}")
        panel_content.append(f"🤖 AI Analyses: {len(self.session_data['ai_analyses'])}")
        
        # Show latest scan summary if available
        if self.session_data['scan_results']:
            scan_summary = self.scanner.get_scan_summary()
            panel_content.append(f"\\n📊 Latest Scan Summary:")
            panel_content.append(f"  • Total Hosts: {scan_summary.get('total_hosts', 0)}")
            panel_content.append(f"  • Open Ports: {scan_summary.get('total_open_ports', 0)}")
        
        # Show detection status if monitoring
        if self.detector.is_monitoring:
            panel_content.append("\\n🛡️ Attack Detection: ACTIVE")
        
        self.console.print(Panel("\\n".join(panel_content), title="📊 Session Status"))
    
    def _handle_exit(self) -> None:
        """Handle graceful exit"""
        self.console.print("\\n🛑 Shutting down IntelProbe...")
        
        # Stop any active monitoring
        if self.detector.is_monitoring:
            self.detector.stop_monitoring()
        
        # Save session data if needed
        if self.session_data['scan_results'] or self.session_data['ai_analyses']:
            save = self.console.input("💾 Save session data? (y/N): ").lower().strip()
            if save == 'y':
                self._save_session_data()
        
        self.console.print("👋 Thank you for using IntelProbe!", style="bold green")
    
    def _save_session_data(self) -> None:
        """Save session data to file"""
        try:
            timestamp = int(time.time())
            session_file = f"sessions/session_{timestamp}.json"
            
            os.makedirs("sessions", exist_ok=True)
            
            # Convert scan results to serializable format
            serializable_data = {
                'session_start': self.session_data['session_start'],
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
                    for r in self.session_data['scan_results']
                ],
                'osint_data': self.session_data['osint_data'],
                'ai_analyses': [a.__dict__ for a in self.session_data['ai_analyses']]
            }
            
            with open(session_file, 'w') as f:
                json.dump(serializable_data, f, indent=2)
            
            self.console.print(f"✅ Session saved: {session_file}", style="green")
            
        except Exception as e:
            self.console.print(f"❌ Failed to save session: {e}", style="red")
    
    def execute_command(self, args) -> None:
        """Execute command-line arguments"""
        try:
            if args.command == 'scan':
                self._execute_scan_command(args)
            elif args.command == 'osint':
                self._execute_osint_command(args)
            elif args.command == 'detect':
                self._execute_detect_command(args)
            elif args.command == 'ai':
                self._execute_ai_command(args)
            else:
                self.console.print(f"❌ Unknown command: {args.command}", style="red")
                
        except Exception as e:
            self.console.print(f"❌ Command execution failed: {e}", style="red")
            sys.exit(1)
    
    def _execute_scan_command(self, args) -> None:
        """Execute scan command from CLI"""
        if args.scan_type == 'network':
            results = self.scanner.scan_network(
                args.target, 
                threads=getattr(args, 'threads', 50),
                timeout=getattr(args, 'timeout', 5)
            )
            if results:
                self._display_scan_results(results)
                
        elif args.scan_type == 'ports':
            results = self.scanner.scan_ports(
                args.target,
                port_range=getattr(args, 'range', '1-1000'),
                service_detection=getattr(args, 'service_detection', False)
            )
            if results:
                self._display_port_scan_results(results)
                
        elif args.scan_type == 'wifi':
            networks = self.scanner.scan_wifi(
                interface=getattr(args, 'interface', None),
                duration=getattr(args, 'duration', 30)
            )
            if networks:
                self._display_wifi_results(networks)
    
    def _execute_osint_command(self, args) -> None:
        """Execute OSINT command from CLI"""
        if args.osint_type == 'mac':
            vendor_info = self.osint.lookup_mac_address(args.address)
            self._display_mac_info(vendor_info)
            
        elif args.osint_type == 'ip':
            ip_intel = self.osint.lookup_ip_address(args.address)
            
    def _run_comprehensive_analysis(self, target: str, scan_results: List[Dict[str, Any]]) -> None:
        """Run comprehensive analysis including forensics and pentesting"""
        try:
            analysis_ids = {}
            
            # Store scan results
            self.scan_results.append(scan_results)
            
            # Start forensic analysis
            target_data = {
                'target': target,
                'scan_results': scan_results
            }
            case_id = self.forensics.start_forensic_analysis(target_data)
            analysis_ids['case_id'] = case_id
            
            # Start penetration testing
            test_id = self.pentester.start_pentest(target)
            analysis_ids['test_id'] = test_id
            
            # Generate and display progress panel
            self._display_analysis_progress(analysis_ids)
            
            # Wait for initial results
            time.sleep(10)  # Allow time for initial analysis
            
            # Generate reports
            reports = self.generate_reports(analysis_ids)
            
            # Display results
            self.display_results(reports)
            
        except Exception as e:
            self.logger.error(f"Comprehensive analysis failed: {e}")
            self.console.print("❌ Analysis failed", style="red")

    def generate_reports(self, analysis_ids: Dict[str, str]) -> Dict[str, Path]:
        """Generate comprehensive analysis reports"""
        reports = {}
        
        try:
            self.console.print("\n📊 Generating analysis reports...")
            
            # Forensic analysis report
            if 'case_id' in analysis_ids:
                forensic_report = self.forensics.generate_forensic_report(analysis_ids['case_id'])
                reports['forensics'] = forensic_report
            
            # Penetration test report
            if 'test_id' in analysis_ids:
                pentest_report = self.pentester.generate_pentest_report(analysis_ids['test_id'])
                reports['pentest'] = pentest_report
            
            # Generate AI-enhanced summary
            if reports:
                summary = self._generate_executive_summary(reports)
                reports['summary'] = summary
            
            return reports
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            raise

    def _display_analysis_progress(self, analysis_ids: Dict[str, str]) -> None:
        """Display real-time analysis progress"""
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                # Create progress tasks
                forensics_task = progress.add_task("🔬 Forensic Analysis...", total=None)
                pentest_task = progress.add_task("🎯 Penetration Testing...", total=None)
                
                while True:
                    # Update forensics progress
                    if self.forensics and not self.forensics.stop_event.is_set():
                        progress.update(
                            forensics_task,
                            description=f"🔬 Forensic Analysis: {len(self.forensics.evidence_collection)} items found"
                        )
                    else:
                        progress.update(forensics_task, description="✅ Forensic Analysis Complete")
                    
                    # Update pentest progress
                    if self.pentester and not self.pentester.stop_event.is_set():
                        progress.update(
                            pentest_task,
                            description=f"🎯 Pentest: {len(self.pentester.discovered_vulns)} vulnerabilities, "
                                      f"{len(self.pentester.successful_exploits)} successful exploits"
                        )
                    else:
                        progress.update(pentest_task, description="✅ Penetration Testing Complete")
                    
                    # Check if both are complete
                    if (self.forensics.stop_event.is_set() and 
                        self.pentester.stop_event.is_set()):
                        break
                    
                    time.sleep(1)
                
        except Exception as e:
            self.logger.error(f"Progress display failed: {e}")

    def _generate_executive_summary(self, reports: Dict[str, Any]) -> Path:
        """Generate executive summary of all analysis results"""
        try:
            # Create summary data
            summary = {
                'timestamp': datetime.now().isoformat(),
                'overview': {
                    'total_hosts': len(self.scan_results[-1] if self.scan_results else []),
                    'total_vulnerabilities': len(reports.get('pentest', {}).get('vulnerabilities', [])),
                    'risk_level': reports.get('pentest', {}).get('risk_level', 'unknown'),
                    'successful_exploits': len(reports.get('pentest', {}).get('successful_exploits', [])),
                    'evidence_items': len(reports.get('forensics', {}).get('evidence_items', []))
                },
                'key_findings': self._extract_key_findings(reports),
                'recommendations': self._compile_recommendations(reports)
            }
            
            # Generate AI-enhanced analysis
            if self.ai_engine:
                summary['ai_analysis'] = self.ai_engine.analyze_network_scan(
                    summary['overview']
                )
            
            # Save summary
            summary_path = Path("reports/summary.json")
            summary_path.parent.mkdir(exist_ok=True)
            
            with open(summary_path, 'w') as f:
                json.dump(summary, f, indent=2)
            
            return summary_path
            
        except Exception as e:
            self.logger.error(f"Summary generation failed: {e}")
            raise

    def _extract_key_findings(self, reports: Dict[str, Any]) -> List[str]:
        """Extract key findings from all reports"""
        findings = []
        
        try:
            # Add forensic findings
            if 'forensics' in reports:
                high_confidence = [
                    e for e in reports['forensics'].get('evidence_items', [])
                    if e.confidence >= 0.8
                ]
                for evidence in high_confidence:
                    findings.append(
                        f"[FORENSIC] {evidence.description}"
                    )
            
            # Add pentest findings
            if 'pentest' in reports:
                # Add successful exploits
                for exploit in reports['pentest'].get('successful_exploits', []):
                    findings.append(
                        f"[EXPLOIT] {exploit.get('exploit')} on "
                        f"{exploit.get('vulnerability', {}).get('name', 'unknown target')}"
                    )
                
                # Add critical vulnerabilities
                for vuln in reports['pentest'].get('vulnerabilities', []):
                    if vuln.get('severity') == 'critical':
                        findings.append(
                            f"[CRITICAL] {vuln.get('description', 'Unknown vulnerability')}"
                        )
            
        except Exception as e:
            self.logger.error(f"Failed to extract findings: {e}")
            findings.append("Error: Some findings could not be processed")
            
        return findings

    def _compile_recommendations(self, reports: Dict[str, Any]) -> List[str]:
        """Compile security recommendations from all reports"""
        recommendations = set()
        
        try:
            # Add forensic recommendations
            if 'forensics' in reports:
                recommendations.update(
                    reports['forensics'].get('recommendations', [])
                )
            
            # Add pentest recommendations
            if 'pentest' in reports:
                recommendations.update(
                    reports['pentest'].get('recommendations', [])
                )
            
            # Prioritize and deduplicate
            return list(recommendations)
            
        except Exception as e:
            self.logger.error(f"Failed to compile recommendations: {e}")
            return ["Error: Some recommendations could not be processed"]

    def display_results(self, reports: Dict[str, Path]) -> None:
        """Display analysis results in the console"""
        try:
            # Load summary
            with open(reports['summary']) as f:
                summary = json.load(f)
            
            # Create results table
            table = Table(title="🔍 Analysis Results")
            
            table.add_column("Category", style="cyan")
            table.add_column("Finding", style="green")
            table.add_column("Impact", style="yellow")
            
            # Add overview
            table.add_row(
                "Overview",
                f"Analyzed {summary['overview']['total_hosts']} hosts",
                f"Risk Level: {summary['overview']['risk_level'].upper()}"
            )
            
            # Add key findings
            for finding in summary['key_findings']:
                table.add_row(
                    "Finding",
                    finding,
                    "High"
                )
            
            # Add top recommendations
            for rec in summary['recommendations'][:5]:
                table.add_row(
                    "Recommendation",
                    rec,
                    "Action Required"
                )
            
            # Display table
            self.console.print("\n")
            self.console.print(table)
            
            # Show report locations
            self.console.print("\n📋 Detailed reports saved:")
            for report_type, path in reports.items():
                self.console.print(f"  - {report_type}: {path}")
            
        except Exception as e:
            self.logger.error(f"Results display failed: {e}")
            self.console.print("❌ Error displaying results", style="red")
            self._display_ip_intel(ip_intel)
    
    def _execute_detect_command(self, args) -> None:
        """Execute detection command from CLI"""
        if args.detect_type == 'arp':
            alerts = self.detector.detect_arp_spoofing(
                args.network,
                interface=getattr(args, 'interface', None)
            )
            
            if alerts:
                self.console.print(f"🚨 Found {len(alerts)} ARP spoofing alerts:", style="red")
                for alert in alerts:
                    self.console.print(f"  • {alert.description}")
            else:
                self.console.print("✅ No ARP spoofing detected", style="green")
    
    def _execute_ai_command(self, args) -> None:
        """Execute AI command from CLI"""
        if args.ai_type == 'analyze':
            # This would require pre-existing scan data
            self.console.print("❌ AI analysis requires interactive mode with scan data", style="red")
            
        elif args.ai_type == 'report':
            # This would require pre-existing data
            self.console.print("❌ AI report generation requires interactive mode with scan data", style="red")
