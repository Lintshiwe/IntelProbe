#!/usr/bin/env python3
"""
IntelProbe - Ultimate Network Security Platform
The most powerful AI-driven network reconnaissance and security assessment tool

Author: Lintshiwe Slade (@lintshiwe)
GitHub: https://github.com/lintshiwe/IntelProbe
License: MIT License
Copyright (c) 2025 Lintshiwe Slade

Features:
- Ultra-fast async network scanning
- AI-powered threat analysis (Gemini/OpenAI)
- Real-time vulnerability detection
- OSINT intelligence gathering
- Beautiful Rich CLI interface
- Multiple output formats (JSON, HTML, PDF)
- Stealth and speed modes
"""

import sys
import os
import time
import json
import asyncio
import argparse
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Any

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

# Rich imports for beautiful output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.live import Live
    from rich.layout import Layout
    from rich.text import Text
    from rich import print as rprint
    from rich.markdown import Markdown
    from rich.syntax import Syntax
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("⚠️ Rich not available. Install with: pip install rich")

# Version info
__version__ = "2.0.0"
__author__ = "Lintshiwe Slade"
__email__ = "lintshiwe.slade@intelprobe.dev"


class IntelProbeRunner:
    """
    Main IntelProbe orchestration class
    Coordinates all scanning, analysis, and reporting components
    """
    
    def __init__(self, verbose: bool = False, quiet: bool = False):
        self.verbose = verbose
        self.quiet = quiet
        self.console = Console() if RICH_AVAILABLE else None
        self.start_time = time.time()
        
        # Initialize logging
        log_level = logging.DEBUG if verbose else logging.WARNING if quiet else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler('intelprobe.log'),
                logging.StreamHandler() if not quiet else logging.NullHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Initialize components lazily
        self._scanner = None
        self._ai_engine = None
        self._vuln_scanner = None
        self._config = None
        
        # Results storage
        self.results = {
            'scan_results': [],
            'ai_analysis': None,
            'vulnerabilities': [],
            'recommendations': [],
            'metadata': {
                'version': __version__,
                'timestamp': datetime.now().isoformat(),
                'author': __author__
            }
        }
    
    @property
    def scanner(self):
        """Lazy load SuperScanner"""
        if self._scanner is None:
            try:
                from core.super_scanner import SuperScanner
                self._scanner = SuperScanner()
                self.logger.info("SuperScanner loaded")
            except ImportError:
                try:
                    from core.production_scanner import ProductionScanner
                    self._scanner = ProductionScanner()
                    self.logger.info("ProductionScanner loaded")
                except ImportError:
                    self.logger.error("No scanner available")
        return self._scanner
    
    @property
    def ai_engine(self):
        """Lazy load AI Engine"""
        if self._ai_engine is None:
            try:
                from core.ai_engine import AIEngine
                from core.config import ConfigManager
                config = ConfigManager()
                self._ai_engine = AIEngine(config)
                if self._ai_engine.ai_provider:
                    self.logger.info(f"AI Engine loaded ({self._ai_engine.ai_provider})")
                else:
                    self.logger.info("AI Engine loaded (no provider)")
            except ImportError as e:
                self.logger.warning(f"AI Engine not available: {e}")
        return self._ai_engine
    
    @property
    def vuln_scanner(self):
        """Lazy load Vulnerability Scanner"""
        if self._vuln_scanner is None:
            try:
                from core.vuln_scanner import VulnerabilityScanner
                self._vuln_scanner = VulnerabilityScanner()
                self.logger.info("VulnerabilityScanner loaded")
            except ImportError as e:
                self.logger.warning(f"VulnerabilityScanner not available: {e}")
        return self._vuln_scanner
    
    def show_banner(self):
        """Display the IntelProbe banner"""
        if self.quiet:
            return
        
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██╗███╗   ██╗████████╗███████╗██╗     ██████╗ ██████╗  ██████╗ ██████╗ ███████╗   ║
║   ██║████╗  ██║╚══██╔══╝██╔════╝██║     ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝   ║
║   ██║██╔██╗ ██║   ██║   █████╗  ██║     ██████╔╝██████╔╝██║   ██║██████╔╝█████╗     ║
║   ██║██║╚██╗██║   ██║   ██╔══╝  ██║     ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝     ║
║   ██║██║ ╚████║   ██║   ███████╗███████╗██║     ██║  ██║╚██████╔╝██████╔╝███████╗   ║
║   ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝   ║
║                                                                              ║
║            🔍 AI-Powered Network Forensics & Security Platform v2.0         ║
║                      Created by: Lintshiwe Slade (@lintshiwe)               ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
        if self.console:
            self.console.print(banner, style="bold cyan")
            self.console.print("  🚀 Ready to scan, analyze, and secure your network!", style="bold green")
            self.console.print()
        else:
            print(banner)
    
    def scan(self, target: str, ports: str = "common", speed: str = "fast", 
             ai_analysis: bool = True) -> Dict:
        """
        Execute a comprehensive network scan
        
        Args:
            target: IP, hostname, or CIDR network to scan
            ports: Port preset or range (top20, common, full, or 1-1000)
            speed: Scan speed (insane, fast, normal, stealth, paranoid)
            ai_analysis: Whether to perform AI analysis on results
        
        Returns:
            Dictionary containing scan results and analysis
        """
        if not self.scanner:
            self.logger.error("No scanner available")
            return {'error': 'No scanner available'}
        
        # Configure scanner speed
        from core.super_scanner import ScanSpeed
        speed_map = {
            'insane': ScanSpeed.INSANE,
            'fast': ScanSpeed.FAST,
            'normal': ScanSpeed.NORMAL,
            'stealth': ScanSpeed.STEALTH,
            'paranoid': ScanSpeed.PARANOID
        }
        self.scanner.set_speed(speed_map.get(speed.lower(), ScanSpeed.FAST))
        
        # Determine port list
        if hasattr(self.scanner, 'port_presets') and ports in self.scanner.port_presets:
            port_list = self.scanner.port_presets[ports]
        elif '-' in ports:
            start, end = map(int, ports.split('-'))
            port_list = list(range(start, end + 1))
        else:
            port_list = self.scanner.port_presets.get('common', list(range(1, 1025)))
        
        # Show progress
        if self.console and not self.quiet:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                task = progress.add_task(f"[cyan]Scanning {target}...", total=100)
                
                # Set progress callback
                def update_progress(msg, pct):
                    progress.update(task, completed=pct, description=f"[cyan]{msg}")
                
                self.scanner.progress_callback = update_progress
                
                # Execute scan
                scan_results = self.scanner.scan_network(target, port_list)
                progress.update(task, completed=100)
        else:
            scan_results = self.scanner.scan_network(target, port_list)
        
        # Store results
        self.results['scan_results'] = [r.to_dict() if hasattr(r, 'to_dict') else r for r in scan_results]
        
        # AI Analysis
        if ai_analysis and self.ai_engine and scan_results:
            if not self.quiet:
                self._print("Running AI threat analysis...", style="bold yellow")
            
            try:
                analysis = self.ai_engine.analyze_network_scan(
                    [r.to_dict() if hasattr(r, 'to_dict') else r for r in scan_results]
                )
                self.results['ai_analysis'] = analysis
            except Exception as e:
                self.logger.warning(f"AI analysis failed: {e}")
        
        return self.results
    
    def deep_vuln_scan(self, target: str, ports: List[int] = None, aggressive: bool = True) -> Dict:
        """
        Perform deep vulnerability scanning with CVE identification
        
        Args:
            target: Target IP or hostname
            ports: List of ports to scan (auto-discovers if None)
            aggressive: Whether to perform aggressive scanning
        
        Returns:
            Dictionary containing vulnerability results
        """
        if not self.vuln_scanner:
            self.logger.error("Vulnerability scanner not available")
            return {'error': 'Vulnerability scanner not available'}
        
        if not self.quiet:
            self._print("Deep Vulnerability Scan - CVE Identification Mode", style="bold cyan")
        
        # If no ports specified and we have scan results, use those
        if ports is None and self.results.get('scan_results'):
            for host in self.results['scan_results']:
                if host.get('ip') == target or host.get('hostname') == target:
                    ports = host.get('open_ports', [])
                    break
        
        # Show progress
        if self.console and not self.quiet:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                task = progress.add_task(f"[red]Deep scanning {target} for vulnerabilities...", total=100)
                
                # Execute vulnerability scan
                progress.update(task, completed=30, description="[red]Scanning ports and services...")
                vuln_results = self.vuln_scanner.deep_scan(target, ports, aggressive)
                
                progress.update(task, completed=60, description="[red]Analyzing CVEs and exploits...")
                # Generate comprehensive report
                report = self.vuln_scanner.generate_report(vuln_results)
                
                progress.update(task, completed=100, description="[green]Vulnerability scan complete!")
        else:
            vuln_results = self.vuln_scanner.deep_scan(target, ports, aggressive)
            report = self.vuln_scanner.generate_report(vuln_results)
        
        # Store vulnerability results
        self.results['vulnerabilities'] = [
            {
                'host': r.host,
                'port': r.port,
                'service': r.service,
                'vulnerabilities': [
                    {
                        'cve_id': v.cve_id,
                        'severity': v.severity,
                        'cvss_score': v.cvss_score,
                        'description': v.description,
                        'exploit_tools': v.exploit_tools,
                        'mitigation': v.mitigation
                    } for v in r.vulnerabilities
                ],
                'risk_level': r.risk_level,
                'banner': r.banner
            } for r in vuln_results
        ]
        
        return {
            'results': self.results['vulnerabilities'],
            'report': report
        }
    
    def display_vuln_results(self, vuln_data: Dict = None):
        """Display vulnerability scan results with CVE details"""
        if vuln_data is None:
            vuln_data = {'results': self.results.get('vulnerabilities', [])}
        
        results = vuln_data.get('results', [])
        if not results:
            self._print("No vulnerabilities found or scan not performed", style="yellow")
            return
        
        if not self.console:
            print(json.dumps(results, indent=2, default=str))
            return
        
        # Count vulnerabilities by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        all_cves = []
        all_tools = set()
        
        for result in results:
            for vuln in result.get('vulnerabilities', []):
                sev = vuln.get('severity', 'INFO').upper()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                all_cves.append(vuln)
                all_tools.update(vuln.get('exploit_tools', []))
        
        # Summary panel
        total_vulns = sum(severity_counts.values())
        summary = f"""
**DEEP VULNERABILITY SCAN RESULTS**

| Severity | Count |
|----------|-------|
| CRITICAL | {severity_counts['CRITICAL']} |
| HIGH     | {severity_counts['HIGH']} |
| MEDIUM   | {severity_counts['MEDIUM']} |
| LOW      | {severity_counts['LOW']} |
| INFO     | {severity_counts['INFO']} |

**Total Vulnerabilities: {total_vulns}**
**Unique CVEs Found: {len(set(v['cve_id'] for v in all_cves))}**
**Exploit Tools Available: {len(all_tools)}**
"""
        self.console.print(Panel(Markdown(summary), title="VULNERABILITY SUMMARY", border_style="red"))
        
        # CVE Details Table
        if all_cves:
            cve_table = Table(title="CVE DETAILS", show_header=True, header_style="bold red")
            cve_table.add_column("CVE ID", style="cyan", width=18)
            cve_table.add_column("Severity", width=10)
            cve_table.add_column("CVSS", style="yellow", width=6)
            cve_table.add_column("Service", style="green", width=12)
            cve_table.add_column("Description", width=40)
            
            seen_cves = set()
            for result in results:
                service = result.get('service', 'unknown')
                for vuln in result.get('vulnerabilities', []):
                    cve_id = vuln.get('cve_id', 'N/A')
                    if cve_id in seen_cves:
                        continue
                    seen_cves.add(cve_id)
                    
                    severity = vuln.get('severity', 'INFO')
                    cvss = vuln.get('cvss_score', 0.0)
                    desc = vuln.get('description', '')[:38] + '...' if len(vuln.get('description', '')) > 40 else vuln.get('description', '')
                    
                    sev_style = {
                        'CRITICAL': 'bold white on red',
                        'HIGH': 'bold red',
                        'MEDIUM': 'bold yellow',
                        'LOW': 'green',
                        'INFO': 'blue'
                    }.get(severity.upper(), 'white')
                    
                    cve_table.add_row(
                        cve_id,
                        Text(severity, style=sev_style),
                        f"{cvss:.1f}",
                        service,
                        desc
                    )
            
            self.console.print(cve_table)
        
        # Exploit Tools Table
        if all_tools:
            from core.vuln_scanner import CVEDatabase
            EXPLOIT_TOOLS = CVEDatabase.EXPLOIT_TOOLS
            
            tools_table = Table(title="AVAILABLE EXPLOIT TOOLS", show_header=True, header_style="bold magenta")
            tools_table.add_column("Tool", style="cyan", width=15)
            tools_table.add_column("Type", style="yellow", width=12)
            tools_table.add_column("Description", width=35)
            tools_table.add_column("Demo Command", style="green", width=45)
            
            for tool_name in sorted(all_tools):
                # Try to find tool in database (case-insensitive match)
                tool_info = None
                tool_key = tool_name.lower().replace(" ", "").replace("-", "").replace("_", "")
                for key, info in EXPLOIT_TOOLS.items():
                    if key in tool_key or tool_key in key:
                        tool_info = info
                        break
                
                if tool_info:
                    tools_table.add_row(
                        tool_name,
                        tool_info.get('type', 'Exploit'),
                        tool_info.get('description', '')[:33],
                        tool_info.get('usage', 'See documentation')
                    )
                else:
                    # Show tool even if not in our database
                    tools_table.add_row(
                        tool_name,
                        "Exploit",
                        "Security testing tool",
                        f"{tool_name.lower()} --help"
                    )
            
            self.console.print(tools_table)
        
        # Recommendations Panel
        if vuln_data.get('report'):
            report = vuln_data['report']
            if isinstance(report, dict):
                # Format dictionary report as readable text
                report_text = "**SECURITY RECOMMENDATIONS**\n\n"
                
                if report.get('summary'):
                    s = report['summary']
                    report_text += f"**Scan Summary:**\n"
                    report_text += f"- Total Ports Scanned: {s.get('total_ports_scanned', 0)}\n"
                    report_text += f"- Unique CVEs Found: {s.get('unique_cves_found', 0)}\n"
                    report_text += f"- Exploitable Vulnerabilities: {s.get('exploitable_vulnerabilities', 0)}\n\n"
                
                if report.get('critical_vulnerabilities'):
                    report_text += "**CRITICAL VULNERABILITIES TO ADDRESS:**\n"
                    for i, crit in enumerate(report['critical_vulnerabilities'][:5], 1):
                        report_text += f"{i}. **{crit.get('cve_id')}** (CVSS: {crit.get('cvss_score', 0)})\n"
                        report_text += f"   - {crit.get('description', '')}\n"
                        report_text += f"   - Mitigation: {crit.get('mitigation', 'N/A')}\n"
                
                if report.get('exploit_suggestions', {}).get('attack_vectors'):
                    report_text += "\n**TOP ATTACK VECTORS:**\n"
                    seen_targets = set()
                    for av in report['exploit_suggestions']['attack_vectors'][:8]:
                        target = av.get('target', '')
                        if target not in seen_targets:
                            seen_targets.add(target)
                            report_text += f"- {target}: {av.get('vulnerability')} using {', '.join(av.get('tools', [])[:2])}\n"
                
                self.console.print(Panel(
                    Markdown(report_text),
                    title="SECURITY RECOMMENDATIONS",
                    border_style="yellow"
                ))
            else:
                self.console.print(Panel(
                    str(report),
                    title="SECURITY RECOMMENDATIONS",
                    border_style="yellow"
                ))
    
    def display_results(self, results: Dict = None):
        """Display scan results in a beautiful format"""
        if results is None:
            results = self.results
        
        if not results.get('scan_results'):
            self._print("❌ No results to display", style="red")
            return
        
        if not self.console:
            # Fallback to plain text
            print(json.dumps(results, indent=2, default=str))
            return
        
        # Summary panel
        scan_results = results['scan_results']
        total_hosts = len(scan_results)
        total_ports = sum(len(r.get('open_ports', [])) for r in scan_results)
        
        summary = f"""
🎯 **Scan Summary**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Hosts Discovered: **{total_hosts}**
• Total Open Ports: **{total_ports}**
• Scan Duration: **{time.time() - self.start_time:.2f}s**
"""
        self.console.print(Panel(Markdown(summary), title="📊 IntelProbe Results", border_style="green"))
        
        # Results table
        table = Table(title="🖥️ Discovered Hosts", show_header=True, header_style="bold magenta")
        table.add_column("IP Address", style="cyan", width=15)
        table.add_column("Hostname", style="green", width=25)
        table.add_column("OS", style="yellow", width=20)
        table.add_column("Ports", style="blue", width=30)
        table.add_column("Risk", style="red", width=10)
        
        for host in scan_results:
            ip = host.get('ip', 'Unknown')
            hostname = host.get('hostname', '-')[:24]
            os_type = f"{host.get('os_type', 'Unknown')} {host.get('os_version', '')}".strip()[:19]
            ports = ', '.join(map(str, host.get('open_ports', [])[:8]))
            if len(host.get('open_ports', [])) > 8:
                ports += f"... (+{len(host['open_ports']) - 8})"
            
            risk = host.get('threat_level', 'INFO')
            if isinstance(risk, dict):
                risk = risk.get('name', 'INFO')
            
            risk_style = {
                'CRITICAL': 'bold red',
                'HIGH': 'red',
                'MEDIUM': 'yellow',
                'LOW': 'green',
                'INFO': 'blue'
            }.get(str(risk).upper(), 'white')
            
            table.add_row(ip, hostname, os_type, ports, Text(str(risk), style=risk_style))
        
        self.console.print(table)
        
        # AI Analysis
        if results.get('ai_analysis'):
            ai_panel = Panel(
                Markdown(f"**AI Threat Analysis**\n\n{results['ai_analysis']}"),
                title="🤖 Gemini AI Insights",
                border_style="purple"
            )
            self.console.print(ai_panel)
    
    def save_report(self, filename: str = None, format: str = "json"):
        """Save scan results to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"reports/intelprobe_report_{timestamp}.{format}"
        
        # Ensure directory exists
        Path(filename).parent.mkdir(parents=True, exist_ok=True)
        
        if format == "json":
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
        elif format == "txt":
            with open(filename, 'w') as f:
                f.write(f"IntelProbe Scan Report\n")
                f.write(f"Generated: {datetime.now().isoformat()}\n")
                f.write("=" * 60 + "\n\n")
                
                for host in self.results.get('scan_results', []):
                    f.write(f"Host: {host.get('ip')}\n")
                    f.write(f"  Hostname: {host.get('hostname', '-')}\n")
                    f.write(f"  OS: {host.get('os_type', 'Unknown')}\n")
                    f.write(f"  Ports: {host.get('open_ports', [])}\n")
                    f.write(f"  Risk: {host.get('threat_level', 'INFO')}\n\n")
                
                if self.results.get('ai_analysis'):
                    f.write("\n" + "=" * 60 + "\n")
                    f.write("AI ANALYSIS\n")
                    f.write("=" * 60 + "\n")
                    f.write(str(self.results['ai_analysis']))
        
        self._print(f"📄 Report saved: {filename}", style="green")
        return filename
    
    def _print(self, message: str, style: str = None):
        """Print message with optional styling"""
        if self.quiet:
            return
        if self.console and style:
            self.console.print(message, style=style)
        else:
            print(message)
    
    def interactive_mode(self):
        """Run interactive mode with command prompt"""
        self.show_banner()
        self._print("🎮 Interactive Mode - Type 'help' for commands, 'exit' to quit\n", style="bold green")
        
        while True:
            try:
                if self.console:
                    cmd = self.console.input("[bold cyan]IntelProbe[/] [green]>[/] ").strip()
                else:
                    cmd = input("IntelProbe > ").strip()
                
                if not cmd:
                    continue
                
                if cmd.lower() in ['exit', 'quit', 'q']:
                    self._print("👋 Goodbye!", style="bold blue")
                    break
                
                elif cmd.lower() == 'help':
                    self._show_help()
                
                elif cmd.lower().startswith('scan '):
                    target = cmd[5:].strip()
                    self.scan(target)
                    self.display_results()
                
                elif cmd.lower().startswith('vuln '):
                    target = cmd[5:].strip()
                    vuln_results = self.deep_vuln_scan(target)
                    self.display_vuln_results(vuln_results)
                
                elif cmd.lower() == 'vulns':
                    self.display_vuln_results()
                
                elif cmd.lower() == 'results':
                    self.display_results()
                
                elif cmd.lower().startswith('save'):
                    parts = cmd.split()
                    filename = parts[1] if len(parts) > 1 else None
                    self.save_report(filename)
                
                elif cmd.lower() == 'clear':
                    os.system('cls' if os.name == 'nt' else 'clear')
                    self.show_banner()
                
                elif cmd.lower() == 'status':
                    self._show_status()
                
                else:
                    self._print(f"❌ Unknown command: {cmd}. Type 'help' for available commands.", style="red")
                    
            except KeyboardInterrupt:
                self._print("\n⚠️ Use 'exit' to quit", style="yellow")
            except Exception as e:
                self._print(f"❌ Error: {e}", style="red")
    
    def _show_help(self):
        """Display help information"""
        help_text = """
**IntelProbe Commands**

**Scanning:**
  `scan <target>`        Scan a target (IP, hostname, or CIDR)
  `scan 192.168.1.0/24`  Scan entire subnet

**Vulnerability Analysis:**
  `vuln <target>`        Deep CVE scan with exploit tools
  `vulns`                Display last vulnerability results

**Results:**
  `results`              Display last scan results
  `save [filename]`      Save report to file

**General:**
  `status`               Show system status
  `clear`                Clear screen
  `help`                 Show this help
  `exit`                 Exit IntelProbe

**Examples:**
  scan 192.168.1.1
  vuln 192.168.1.1
  scan 192.168.1.0/24
  scan example.com
"""
        if self.console:
            self.console.print(Markdown(help_text))
        else:
            print(help_text)
    
    def _show_status(self):
        """Show system status"""
        status = f"""
🔧 **System Status**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Version: **{__version__}**
• Scanner: **{'✅ Ready' if self.scanner else '❌ Not Available'}**
• AI Engine: **{'✅ ' + (self.ai_engine.ai_provider or 'No Provider') if self.ai_engine else '❌ Not Available'}**
• Session Time: **{time.time() - self.start_time:.0f}s**
• Results Cached: **{len(self.results.get('scan_results', []))} hosts**
"""
        if self.console:
            self.console.print(Panel(Markdown(status), title="📊 Status", border_style="blue"))
        else:
            print(status)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="IntelProbe - AI-Powered Network Security Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan 192.168.1.1              Quick scan a single host
  %(prog)s scan 192.168.1.0/24           Scan entire subnet
  %(prog)s scan 192.168.1.1 -p full      Full port scan
  %(prog)s scan 192.168.1.1 --speed fast Fast scan mode
  %(prog)s -i                            Interactive mode
  %(prog)s --version                     Show version

Created by Lintshiwe Slade (@lintshiwe)
GitHub: https://github.com/lintshiwe/IntelProbe
"""
    )
    
    parser.add_argument('command', nargs='?', choices=['scan', 'vuln', 'osint', 'detect'],
                        help='Command to execute (scan, vuln, osint, detect)')
    parser.add_argument('target', nargs='?', help='Target to scan')
    
    parser.add_argument('-p', '--ports', default='common',
                        help='Port preset or range (top20, common, full, 1-1000)')
    parser.add_argument('-s', '--speed', default='fast',
                        choices=['insane', 'fast', 'normal', 'stealth', 'paranoid'],
                        help='Scan speed preset')
    parser.add_argument('--no-ai', action='store_true',
                        help='Disable AI analysis')
    
    parser.add_argument('-o', '--output', help='Output file for report')
    parser.add_argument('-f', '--format', default='json',
                        choices=['json', 'txt', 'html'],
                        help='Output format')
    
    parser.add_argument('-i', '--interactive', action='store_true',
                        help='Run in interactive mode')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Quiet mode (minimal output)')
    
    parser.add_argument('--version', action='version',
                        version=f'IntelProbe {__version__}')
    
    args = parser.parse_args()
    
    # Create runner
    runner = IntelProbeRunner(verbose=args.verbose, quiet=args.quiet)
    
    # Interactive mode
    if args.interactive or (not args.command and not args.target):
        runner.interactive_mode()
        return
    
    # Command mode
    runner.show_banner()
    
    if args.command == 'scan' or (args.target and args.command != 'vuln'):
        target = args.target or args.command
        if not target or target == 'scan':
            print("Please specify a target to scan")
            parser.print_help()
            return
        
        # Execute scan
        results = runner.scan(
            target=target,
            ports=args.ports,
            speed=args.speed,
            ai_analysis=not args.no_ai
        )
        
        # Display results
        runner.display_results(results)
        
        # Save report if requested
        if args.output:
            runner.save_report(args.output, args.format)
    
    elif args.command == 'vuln':
        target = args.target
        if not target:
            print("Please specify a target for vulnerability scan")
            parser.print_help()
            return
        
        # Execute vulnerability scan
        vuln_results = runner.deep_vuln_scan(target)
        
        # Display vulnerability results
        runner.display_vuln_results(vuln_results)
        
        # Save report if requested
        if args.output:
            runner.save_report(args.output, args.format)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
