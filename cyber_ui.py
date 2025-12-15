#!/usr/bin/env python3
"""
IntelProbe Terminal UI - Cyberpunk AI-Powered Interface
Super catchy terminal interface with real-time AI analysis display
"""

import os
import sys
import time
import json
import threading
import random
from datetime import datetime
from pathlib import Path
import asyncio

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Terminal styling and colors
class TerminalColors:
    """Cyberpunk color scheme for terminal"""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    # Neon colors
    NEON_GREEN = '\033[38;5;46m'
    NEON_BLUE = '\033[38;5;51m'
    NEON_PINK = '\033[38;5;198m'
    NEON_YELLOW = '\033[38;5;226m'
    NEON_PURPLE = '\033[38;5;135m'
    NEON_ORANGE = '\033[38;5;208m'
    
    # Background colors
    BG_BLACK = '\033[40m'
    BG_DARK_BLUE = '\033[48;5;17m'
    
    # Matrix-style green
    MATRIX_GREEN = '\033[38;5;40m'
    DARK_GREEN = '\033[38;5;22m'
    
    # Warning colors
    RED = '\033[31m'
    YELLOW = '\033[33m'
    
    # Gradients
    CYBER_GRADIENT = ['\033[38;5;51m', '\033[38;5;45m', '\033[38;5;39m', '\033[38;5;33m']

class CyberUI:
    """Cyberpunk-style terminal UI for IntelProbe"""
    
    def __init__(self):
        self.width = 120
        self.height = 40
        self.ai_active = False
        self.scan_active = False
        self.matrix_rain = []
        self.ai_thoughts = []
        self.scan_results = []
        self.threat_level = "LOW"
        self.targets_found = 0
        self.ai_analyzing = False
        
        # Initialize matrix rain
        self.init_matrix_rain()
        
    def init_matrix_rain(self):
        """Initialize matrix-style background effect"""
        for i in range(20):
            self.matrix_rain.append({
                'x': random.randint(0, self.width - 1),
                'y': random.randint(-10, 0),
                'speed': random.randint(1, 3),
                'char': random.choice('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()'),
                'color': random.choice([TerminalColors.DARK_GREEN, TerminalColors.MATRIX_GREEN])
            })
    
    def clear_screen(self):
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def draw_border(self, char='═', color=TerminalColors.NEON_BLUE):
        """Draw cyberpunk border"""
        return f"{color}{char * self.width}{TerminalColors.RESET}"
    
    def center_text(self, text, width=None, color=TerminalColors.NEON_GREEN):
        """Center text with color"""
        if width is None:
            width = self.width
        spaces = (width - len(text)) // 2
        return f"{' ' * spaces}{color}{text}{TerminalColors.RESET}"
    
    def draw_header(self):
        """Draw the main header with AI status"""
        header = f"""
{TerminalColors.NEON_BLUE}╔{'═' * (self.width - 2)}╗{TerminalColors.RESET}
{TerminalColors.NEON_BLUE}║{TerminalColors.RESET}{self.center_text('🛡️  INTELLIPROBE CYBER DEFENSE MATRIX  🛡️', self.width - 2, TerminalColors.NEON_GREEN)}{TerminalColors.NEON_BLUE}║{TerminalColors.RESET}
{TerminalColors.NEON_BLUE}║{TerminalColors.RESET}{self.center_text('⚡ AI-POWERED NETWORK RECONNAISSANCE SYSTEM ⚡', self.width - 2, TerminalColors.NEON_YELLOW)}{TerminalColors.NEON_BLUE}║{TerminalColors.RESET}
{TerminalColors.NEON_BLUE}║{TerminalColors.RESET}{self.center_text('Created by: Lintshiwe Slade (@lintshiwe)', self.width - 2, TerminalColors.NEON_PINK)}{TerminalColors.NEON_BLUE}║{TerminalColors.RESET}
{TerminalColors.NEON_BLUE}╠{'═' * (self.width - 2)}╣{TerminalColors.RESET}
"""
        return header
    
    def draw_ai_status(self):
        """Draw AI status panel"""
        ai_emoji = "🤖" if self.ai_active else "💤"
        ai_status = "ONLINE" if self.ai_active else "OFFLINE"
        ai_color = TerminalColors.NEON_GREEN if self.ai_active else TerminalColors.RED
        
        analyzing_text = " 🧠 ANALYZING..." if self.ai_analyzing else ""
        
        status_panel = f"""
{TerminalColors.NEON_BLUE}║{TerminalColors.RESET} {TerminalColors.NEON_PURPLE}🔮 GEMINI AI STATUS:{TerminalColors.RESET} {ai_emoji} {ai_color}{ai_status}{TerminalColors.RESET}{TerminalColors.NEON_YELLOW}{analyzing_text}{TerminalColors.RESET}{' ' * (self.width - 50)}{TerminalColors.NEON_BLUE}║{TerminalColors.RESET}
{TerminalColors.NEON_BLUE}║{TerminalColors.RESET} {TerminalColors.NEON_ORANGE}⚡ THREAT LEVEL:{TerminalColors.RESET} {self.get_threat_color()}{self.threat_level}{TerminalColors.RESET} | {TerminalColors.NEON_BLUE}🎯 TARGETS:{TerminalColors.RESET} {TerminalColors.NEON_GREEN}{self.targets_found}{TerminalColors.RESET}{' ' * (self.width - 45)}{TerminalColors.NEON_BLUE}║{TerminalColors.RESET}
{TerminalColors.NEON_BLUE}╠{'═' * (self.width - 2)}╣{TerminalColors.RESET}
"""
        return status_panel
    
    def get_threat_color(self):
        """Get color based on threat level"""
        if self.threat_level == "LOW":
            return TerminalColors.NEON_GREEN
        elif self.threat_level == "MEDIUM":
            return TerminalColors.NEON_YELLOW
        elif self.threat_level == "HIGH":
            return TerminalColors.NEON_ORANGE
        elif self.threat_level == "CRITICAL":
            return TerminalColors.RED
        return TerminalColors.NEON_BLUE
    
    def draw_scan_panel(self):
        """Draw real-time scanning panel"""
        scan_emoji = "🔍" if self.scan_active else "⏸️"
        scan_status = "SCANNING" if self.scan_active else "STANDBY"
        scan_color = TerminalColors.NEON_GREEN if self.scan_active else TerminalColors.YELLOW
        
        panel = f"""
{TerminalColors.NEON_BLUE}║{TerminalColors.RESET} {TerminalColors.NEON_PURPLE}📡 NETWORK SCANNER:{TerminalColors.RESET} {scan_emoji} {scan_color}{scan_status}{TerminalColors.RESET}{' ' * (self.width - 35)}{TerminalColors.NEON_BLUE}║{TerminalColors.RESET}
"""
        
        # Show recent scan results
        if self.scan_results:
            for i, result in enumerate(self.scan_results[-3:]):  # Show last 3 results
                ip = result.get('ip', 'Unknown')
                os_type = result.get('os', 'Unknown')
                status = result.get('status', 'Found')
                
                status_emoji = "✅" if status == "Found" else "❌"
                panel += f"""{TerminalColors.NEON_BLUE}║{TerminalColors.RESET} {status_emoji} {TerminalColors.NEON_GREEN}{ip}{TerminalColors.RESET} | {TerminalColors.NEON_YELLOW}{os_type}{TerminalColors.RESET}{' ' * (self.width - 25 - len(ip) - len(os_type))}{TerminalColors.NEON_BLUE}║{TerminalColors.RESET}
"""
        
        panel += f"{TerminalColors.NEON_BLUE}╠{'═' * (self.width - 2)}╣{TerminalColors.RESET}\n"
        return panel
    
    def draw_ai_thoughts(self):
        """Draw AI analysis thoughts panel"""
        panel = f"""
{TerminalColors.NEON_BLUE}║{TerminalColors.RESET} {TerminalColors.NEON_PURPLE}🧠 AI NEURAL ANALYSIS:{TerminalColors.RESET}{' ' * (self.width - 30)}{TerminalColors.NEON_BLUE}║{TerminalColors.RESET}
"""
        
        if self.ai_thoughts:
            for thought in self.ai_thoughts[-4:]:  # Show last 4 thoughts
                # Truncate long thoughts
                display_thought = thought[:self.width - 10] + "..." if len(thought) > self.width - 10 else thought
                panel += f"""{TerminalColors.NEON_BLUE}║{TerminalColors.RESET} {TerminalColors.NEON_PINK}▶{TerminalColors.RESET} {TerminalColors.NEON_YELLOW}{display_thought}{TerminalColors.RESET}{' ' * (self.width - 5 - len(display_thought))}{TerminalColors.NEON_BLUE}║{TerminalColors.RESET}
"""
        else:
            panel += f"""{TerminalColors.NEON_BLUE}║{TerminalColors.RESET} {TerminalColors.DIM}🤖 AI awaiting scan data for analysis...{TerminalColors.RESET}{' ' * (self.width - 45)}{TerminalColors.NEON_BLUE}║{TerminalColors.RESET}
"""
        
        panel += f"{TerminalColors.NEON_BLUE}╠{'═' * (self.width - 2)}╣{TerminalColors.RESET}\n"
        return panel
    
    def draw_matrix_background(self):
        """Draw matrix-style background effect"""
        matrix_lines = []
        for drop in self.matrix_rain[:5]:  # Show only a few for performance
            if 0 <= drop['y'] < 5:  # Only show in certain areas
                line = ' ' * drop['x'] + f"{drop['color']}{drop['char']}{TerminalColors.RESET}"
                matrix_lines.append(line)
        
        return '\n'.join(matrix_lines) if matrix_lines else ""
    
    def draw_footer(self):
        """Draw footer with controls"""
        footer = f"""
{TerminalColors.NEON_BLUE}║{TerminalColors.RESET} {TerminalColors.NEON_GREEN}[SPACE]{TerminalColors.RESET} Start/Stop Scan | {TerminalColors.NEON_GREEN}[A]{TerminalColors.RESET} Toggle AI | {TerminalColors.NEON_GREEN}[Q]{TerminalColors.RESET} Quit | {TerminalColors.NEON_GREEN}[R]{TerminalColors.RESET} Reset{' ' * (self.width - 65)}{TerminalColors.NEON_BLUE}║{TerminalColors.RESET}
{TerminalColors.NEON_BLUE}╚{'═' * (self.width - 2)}╝{TerminalColors.RESET}
"""
        return footer
    
    def draw_complete_interface(self):
        """Draw the complete interface"""
        interface = ""
        interface += self.draw_header()
        interface += self.draw_ai_status()
        interface += self.draw_scan_panel()
        interface += self.draw_ai_thoughts()
        interface += self.draw_footer()
        
        return interface
    
    def update_matrix_rain(self):
        """Update matrix rain animation"""
        for drop in self.matrix_rain:
            drop['y'] += drop['speed']
            if drop['y'] > 10:
                drop['y'] = random.randint(-10, 0)
                drop['x'] = random.randint(0, self.width - 1)
                drop['char'] = random.choice('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()')
    
    def add_ai_thought(self, thought):
        """Add AI analysis thought"""
        self.ai_thoughts.append(f"🤖 {thought}")
        # Keep only last 10 thoughts
        if len(self.ai_thoughts) > 10:
            self.ai_thoughts = self.ai_thoughts[-10:]
    
    def add_scan_result(self, ip, os_type="Unknown", status="Found"):
        """Add scan result"""
        self.scan_results.append({
            'ip': ip,
            'os': os_type,
            'status': status,
            'timestamp': datetime.now().strftime("%H:%M:%S")
        })
        self.targets_found = len(self.scan_results)
        
        # Update threat level based on findings
        if len(self.scan_results) > 20:
            self.threat_level = "HIGH"
        elif len(self.scan_results) > 10:
            self.threat_level = "MEDIUM"
        else:
            self.threat_level = "LOW"
    
    def simulate_ai_analysis(self):
        """Simulate AI analysis thoughts"""
        ai_thoughts = [
            "Analyzing network topology patterns...",
            "Detecting anomalous traffic signatures...",
            "Cross-referencing threat intelligence database...",
            "Evaluating port scan behavior patterns...",
            "Assessing device fingerprint uniqueness...",
            "Correlating temporal access patterns...",
            "Scanning for known vulnerability signatures...",
            "Processing network segmentation analysis...",
            "Evaluating encryption protocol strength...",
            "Detecting potential lateral movement paths...",
            "Analyzing DNS query patterns...",
            "Assessing firewall rule effectiveness...",
            "Processing machine learning threat models...",
            "Correlating geolocation data points...",
            "Detecting zero-day exploitation vectors..."
        ]
        
        return random.choice(ai_thoughts)
    
    def simulate_scan_data(self):
        """Simulate incoming scan data"""
        ips = [f"192.168.1.{i}" for i in range(1, 255)]
        os_types = ["Windows 10", "Linux Ubuntu", "macOS", "Windows Server", "Android", "iOS", "Unknown"]
        
        ip = random.choice(ips)
        os_type = random.choice(os_types)
        
        return ip, os_type

class IntelProbeUI:
    """Main UI controller for IntelProbe"""
    
    def __init__(self):
        self.ui = CyberUI()
        self.running = False
        self.ai_engine = None
        self.scanner = None
        
        # Try to initialize actual components
        self.init_components()
    
    def init_components(self):
        """Initialize actual IntelProbe components"""
        try:
            # Load configuration
            with open('config/ai_config.json', 'r') as f:
                config_data = json.load(f)
            
            # Create config wrapper
            class ConfigWrapper:
                def __init__(self, data):
                    self.data = data
                def get_ai_config(self):
                    return self.data.get('ai_config', {})
            
            config = ConfigWrapper(config_data)
            
            # Initialize AI Engine
            from core.ai_engine import AIEngine
            self.ai_engine = AIEngine(config)
            self.ui.ai_active = True
            
            # Initialize Scanner
            from core.scanner import EnhancedScanner
            self.scanner = EnhancedScanner(config)
            
            print(f"{TerminalColors.NEON_GREEN}✅ IntelProbe components initialized successfully!{TerminalColors.RESET}")
            
        except Exception as e:
            print(f"{TerminalColors.RED}⚠️ Error initializing components: {e}{TerminalColors.RESET}")
            print(f"{TerminalColors.YELLOW}🔄 Running in simulation mode...{TerminalColors.RESET}")
    
    def start_simulation(self):
        """Start background simulation"""
        def simulation_loop():
            while self.running:
                # Simulate AI analysis
                if self.ui.ai_active and random.random() < 0.3:
                    self.ui.ai_analyzing = True
                    time.sleep(0.5)
                    thought = self.ui.simulate_ai_analysis()
                    self.ui.add_ai_thought(thought)
                    self.ui.ai_analyzing = False
                
                # Simulate scan results
                if self.ui.scan_active and random.random() < 0.4:
                    ip, os_type = self.ui.simulate_scan_data()
                    self.ui.add_scan_result(ip, os_type)
                
                # Update matrix rain
                self.ui.update_matrix_rain()
                
                time.sleep(2)
        
        simulation_thread = threading.Thread(target=simulation_loop, daemon=True)
        simulation_thread.start()
    
    def handle_input(self):
        """Handle user input (simplified for demo)"""
        # This would be replaced with proper async input handling
        pass
    
    def run(self):
        """Run the main UI loop"""
        self.running = True
        self.start_simulation()
        
        print(f"{TerminalColors.NEON_GREEN}🚀 Starting IntelProbe Cyber Interface...{TerminalColors.RESET}")
        time.sleep(2)
        
        try:
            # Demo sequence
            self.demo_sequence()
        except KeyboardInterrupt:
            self.shutdown()
    
    def demo_sequence(self):
        """Run demo sequence"""
        # Step 1: Show initial interface
        self.ui.clear_screen()
        print(self.ui.draw_complete_interface())
        time.sleep(3)
        
        # Step 2: Activate AI
        self.ui.ai_active = True
        self.ui.add_ai_thought("Neural networks initialized successfully!")
        self.ui.clear_screen()
        print(self.ui.draw_complete_interface())
        time.sleep(2)
        
        # Step 3: Start scanning
        self.ui.scan_active = True
        self.ui.add_ai_thought("Network discovery protocols activated...")
        time.sleep(1)
        
        # Step 4: Show real-time updates
        for i in range(10):
            self.ui.clear_screen()
            
            # Add some scan results
            if i % 2 == 0:
                ip, os_type = self.ui.simulate_scan_data()
                self.ui.add_scan_result(ip, os_type)
            
            # Add AI thoughts
            if i % 3 == 0:
                thought = self.ui.simulate_ai_analysis()
                self.ui.add_ai_thought(thought)
            
            print(self.ui.draw_complete_interface())
            time.sleep(2)
        
        # Final state
        self.ui.add_ai_thought("Network reconnaissance completed successfully!")
        self.ui.add_ai_thought("Threat assessment: Network appears secure")
        self.ui.clear_screen()
        print(self.ui.draw_complete_interface())
        
        print(f"\n{TerminalColors.NEON_GREEN}🎉 IntelProbe Cyber Interface Demo Complete!{TerminalColors.RESET}")
        print(f"{TerminalColors.NEON_YELLOW}Press any key to continue...{TerminalColors.RESET}")
        input()
    
    def shutdown(self):
        """Shutdown the interface"""
        self.running = False
        print(f"\n{TerminalColors.NEON_BLUE}🛡️ IntelProbe Cyber Defense Matrix shutting down...{TerminalColors.RESET}")
        print(f"{TerminalColors.NEON_GREEN}✅ All systems secured. Goodbye!{TerminalColors.RESET}")

if __name__ == "__main__":
    print(f"""
{TerminalColors.NEON_BLUE}╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                          🛡️  INTELLIPROBE INITIALIZATION  🛡️                                        ║
║                                      ⚡ AI-POWERED CYBER DEFENSE MATRIX ⚡                                        ║
╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝{TerminalColors.RESET}
""")
    
    ui = IntelProbeUI()
    ui.run()
