#!/usr/bin/env python3
"""
IntelProbe Real-World Network Scanner Demo
Military-grade network reconnaissance with exploitation intelligence

Author: Lintshiwe Slade (@lintshiwe)
Enhanced from netspionage framework with AI-powered capabilities
"""

import time
import json
import os
import sys

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

try:
    from core.enhanced_scanner import EnhancedNetworkScanner
    ENHANCED_SCANNER_AVAILABLE = True
except ImportError:
    ENHANCED_SCANNER_AVAILABLE = False
    try:
        from core.production_scanner import ProductionScanner
        PRODUCTION_SCANNER_AVAILABLE = True
    except ImportError:
        PRODUCTION_SCANNER_AVAILABLE = False

if RICH_AVAILABLE:
    console = Console()
else:
    class SimpleConsole:
        def print(self, *args, **kwargs):
            print(*args)
        def clear(self):
            os.system('cls' if os.name == 'nt' else 'clear')
    console = SimpleConsole()

def display_banner():
    """Display the military-grade banner"""
    banner = Panel(
        Text.assemble(
            ("🎖️ INTELPROBE REAL-WORLD NETWORK SCANNER 🎖️\n", "bold red"),
            ("Military-Grade Network Reconnaissance & Exploitation Intelligence\n", "bold white"),
            ("Enhanced from netspionage framework with AI capabilities\n", "dim"),
            ("Developed by: Lintshiwe Slade (@lintshiwe)", "bold cyan")
        ),
        title="MILITARY INTELLIGENCE",
        border_style="red",
        padding=(1, 2)
    )
    console.print(banner)

def scan_local_networks():
    """Perform comprehensive local network scanning"""
    scanner = EnhancedNetworkScanner()
    
    console.print("\n[bold yellow]🌐 PHASE 1: NETWORK DISCOVERY[/bold yellow]")
    console.print("Discovering available network interfaces and subnets...")
    
    # Discover network interfaces
    interfaces = scanner.discover_network_interfaces()
    
    if not interfaces:
        console.print("[red]❌ No network interfaces discovered[/red]")
        return
    
    # Display discovered networks
    interface_table = Table(title="Discovered Network Interfaces")
    interface_table.add_column("Interface", style="cyan")
    interface_table.add_column("Local IP", style="green")
    interface_table.add_column("Network", style="yellow")
    
    for iface in interfaces:
        interface_table.add_row(
            iface["interface"],
            iface["ip"],
            iface["network"]
        )
    
    console.print(interface_table)
    
    console.print("\n[bold yellow]🔍 PHASE 2: COMPREHENSIVE NETWORK SCANNING[/bold yellow]")
    all_devices = []
    
    for iface in interfaces:
        network = iface["network"]
        console.print(f"\n[cyan]Scanning network: {network}[/cyan]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task(f"Scanning {network}...", total=None)
            
            devices = scanner.scan_network_range(network, max_hosts=50)
            progress.update(task, completed=True)
        
        if devices:
            console.print(f"[green]✅ Found {len(devices)} active devices on {network}[/green]")
            all_devices.extend(devices)
            
            # Display device summary
            for device in devices:
                console.print(f"  📡 {device.ip} ({device.hostname or 'Unknown'})")
                console.print(f"     OS: {device.os_type or 'Unknown'}")
                console.print(f"     Open Ports: {', '.join(map(str, device.open_ports))}")
                console.print(f"     Risk Score: {device.risk_score}/100")
        else:
            console.print(f"[dim]No active devices found on {network}[/dim]")
    
    if not all_devices:
        console.print("[red]❌ No active devices discovered across all networks[/red]")
        return
    
    console.print(f"\n[bold green]📊 PHASE 3: NETWORK INTELLIGENCE ANALYSIS[/bold green]")
    console.print(f"Total active devices discovered: {len(all_devices)}")
    
    # Generate detailed analysis
    generate_device_analysis(all_devices)
    generate_vulnerability_analysis(all_devices)
    generate_exploitation_intelligence(all_devices)
    
    # Save comprehensive report
    report = scanner.generate_detailed_report(all_devices)
    report_file = f"reports/comprehensive_network_scan_{int(time.time())}.json"
    os.makedirs("reports", exist_ok=True)
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    console.print(f"\n[bold cyan]📄 COMPREHENSIVE REPORT SAVED: {report_file}[/bold cyan]")

def generate_device_analysis(devices):
    """Generate detailed device analysis"""
    console.print("\n[bold]🖥️  DEVICE ANALYSIS[/bold]")
    
    device_table = Table(title="Discovered Network Devices")
    device_table.add_column("IP Address", style="cyan")
    device_table.add_column("Hostname", style="green")
    device_table.add_column("OS Type", style="yellow")
    device_table.add_column("Open Ports", style="blue")
    device_table.add_column("Risk Score", style="red")
    
    for device in sorted(devices, key=lambda d: d.risk_score, reverse=True):
        ports_str = ', '.join(map(str, device.open_ports[:5]))
        if len(device.open_ports) > 5:
            ports_str += f" (+{len(device.open_ports) - 5} more)"
        
        risk_color = "red" if device.risk_score >= 70 else "yellow" if device.risk_score >= 40 else "green"
        
        device_table.add_row(
            device.ip,
            device.hostname or "Unknown",
            device.os_type or "Unknown",
            ports_str,
            f"[{risk_color}]{device.risk_score}/100[/{risk_color}]"
        )
    
    console.print(device_table)

def generate_vulnerability_analysis(devices):
    """Generate vulnerability analysis"""
    console.print("\n[bold]🛡️  VULNERABILITY ANALYSIS[/bold]")
    
    high_risk = [d for d in devices if d.risk_score >= 70]
    medium_risk = [d for d in devices if 40 <= d.risk_score < 70]
    low_risk = [d for d in devices if d.risk_score < 40]
    
    risk_table = Table(title="Network Risk Assessment")
    risk_table.add_column("Risk Level", style="bold")
    risk_table.add_column("Device Count", style="cyan")
    risk_table.add_column("Percentage", style="yellow")
    risk_table.add_column("Devices", style="dim")
    
    total = len(devices)
    
    risk_table.add_row(
        "[red]🔴 HIGH RISK[/red]",
        str(len(high_risk)),
        f"{len(high_risk)/total*100:.1f}%",
        ", ".join([d.ip for d in high_risk[:3]]) + ("..." if len(high_risk) > 3 else "")
    )
    
    risk_table.add_row(
        "[yellow]🟡 MEDIUM RISK[/yellow]",
        str(len(medium_risk)),
        f"{len(medium_risk)/total*100:.1f}%",
        ", ".join([d.ip for d in medium_risk[:3]]) + ("..." if len(medium_risk) > 3 else "")
    )
    
    risk_table.add_row(
        "[green]🟢 LOW RISK[/green]",
        str(len(low_risk)),
        f"{len(low_risk)/total*100:.1f}%",
        ", ".join([d.ip for d in low_risk[:3]]) + ("..." if len(low_risk) > 3 else "")
    )
    
    console.print(risk_table)

def generate_exploitation_intelligence(devices):
    """Generate exploitation intelligence"""
    console.print("\n[bold]⚔️  EXPLOITATION INTELLIGENCE[/bold]")
    
    # Collect all unique exploits
    all_exploits = {}
    for device in devices:
        for exploit in device.exploits:
            key = f"{exploit.service}:{exploit.vulnerability}"
            if key not in all_exploits:
                all_exploits[key] = {
                    "exploit": exploit,
                    "affected_devices": []
                }
            all_exploits[key]["affected_devices"].append(device.ip)
    
    if not all_exploits:
        console.print("[dim]No specific exploitation vectors identified[/dim]")
        return
    
    # Sort by severity and device count
    sorted_exploits = sorted(
        all_exploits.values(),
        key=lambda x: (
            {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}.get(x["exploit"].severity, 0),
            len(x["affected_devices"])
        ),
        reverse=True
    )
    
    exploit_table = Table(title="Exploitation Opportunities")
    exploit_table.add_column("Service", style="cyan")
    exploit_table.add_column("Vulnerability", style="yellow")
    exploit_table.add_column("Severity", style="red")
    exploit_table.add_column("Affected", style="blue")
    exploit_table.add_column("Tools", style="green")
    
    for item in sorted_exploits[:10]:  # Top 10 exploits
        exploit = item["exploit"]
        affected_count = len(item["affected_devices"])
        
        severity_color = {
            "CRITICAL": "red",
            "HIGH": "orange1", 
            "MEDIUM": "yellow"
        }.get(exploit.severity, "white")
        
        tools_str = ", ".join(exploit.exploit_tools[:3])
        if len(exploit.exploit_tools) > 3:
            tools_str += "..."
        
        exploit_table.add_row(
            exploit.service,
            exploit.vulnerability[:50] + ("..." if len(exploit.vulnerability) > 50 else ""),
            f"[{severity_color}]{exploit.severity}[/{severity_color}]",
            str(affected_count),
            tools_str
        )
    
    console.print(exploit_table)
    
    # Display critical recommendations
    console.print("\n[bold red]🚨 CRITICAL SECURITY RECOMMENDATIONS[/bold red]")
    
    critical_exploits = [item for item in sorted_exploits if item["exploit"].severity == "CRITICAL"]
    if critical_exploits:
        for item in critical_exploits[:5]:
            exploit = item["exploit"]
            console.print(f"• [red]{exploit.service}[/red]: {exploit.description}")
            console.print(f"  Affected devices: {len(item['affected_devices'])}")
            console.print(f"  Recommended tools: {', '.join(exploit.exploit_tools[:3])}")
            console.print()

def demonstrate_specific_scanning():
    """Demonstrate specific scanning capabilities"""
    console.print("\n[bold yellow]🎯 PHASE 4: TARGETED SCANNING DEMONSTRATION[/bold yellow]")
    
    scanner = EnhancedNetworkScanner()
    
    # Scan localhost with detailed analysis
    console.print("[cyan]Performing detailed localhost analysis...[/cyan]")
    
    device = scanner.scan_host("127.0.0.1")
    if device:
        console.print(f"[green]✅ Localhost analysis complete[/green]")
        console.print(f"  IP: {device.ip}")
        console.print(f"  Hostname: {device.hostname}")
        console.print(f"  OS: {device.os_type}")
        console.print(f"  Open Ports: {device.open_ports}")
        console.print(f"  Risk Score: {device.risk_score}/100")
        
        if device.exploits:
            console.print(f"  Potential Exploits: {len(device.exploits)}")
            for exploit in device.exploits[:3]:
                console.print(f"    • {exploit.vulnerability} ({exploit.severity})")
    
    # Demonstrate router/gateway scanning
    console.print("\n[cyan]Attempting gateway/router discovery...[/cyan]")
    common_gateways = ["192.168.1.1", "192.168.0.1", "10.0.0.1", "172.16.0.1", "192.168.137.1"]
    
    for gateway in common_gateways:
        device = scanner.scan_host(gateway)
        if device and device.open_ports:
            console.print(f"[green]✅ Gateway found: {gateway}[/green]")
            console.print(f"  Open Ports: {device.open_ports}")
            console.print(f"  Services: {list(device.services.values())}")
            break
    else:
        console.print("[dim]No common gateways accessible[/dim]")

def main():
    """Main demonstration function"""
    console.clear()
    display_banner()
    
    console.print("\n[bold green]🎖️ REAL-WORLD NETWORK RECONNAISSANCE DEMONSTRATION[/bold green]")
    console.print("[dim]This demonstration will perform actual network scanning on your local networks[/dim]")
    console.print("[dim]All scanning is performed on networks you have authorized access to[/dim]\n")
    
    try:
        # Phase 1-3: Comprehensive network scanning
        scan_local_networks()
        
        # Phase 4: Targeted demonstration
        demonstrate_specific_scanning()
        
        console.print("\n[bold green]🎯 RECONNAISSANCE MISSION COMPLETE[/bold green]")
        console.print("[bold]IntelProbe has successfully demonstrated real-world network scanning capabilities[/bold]")
        console.print("[dim]Author: Lintshiwe Slade | GitHub: @lintshiwe[/dim]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Scan interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]❌ Error during scanning: {e}[/red]")

if __name__ == "__main__":
    main()
