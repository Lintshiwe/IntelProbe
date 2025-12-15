#!/usr/bin/env python3
"""
IntelProbe AI Dashboard - Ultra Modern Terminal Interface
Real-time AI-powered network security visualization
"""

import os
import sys
import time
import json
import threading
import random
from datetime import datetime
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).parent))

class NeonTheme:
    """Ultra-modern neon color theme"""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    BLINK = '\033[5m'
    
    # Cyber neon palette
    ELECTRIC_BLUE = '\033[38;2;0;255;255m'      # #00FFFF
    HOT_PINK = '\033[38;2;255;20;147m'          # #FF1493
    LIME_GREEN = '\033[38;2;50;205;50m'         # #32CD32
    GOLD = '\033[38;2;255;215;0m'               # #FFD700
    PURPLE = '\033[38;2;138;43;226m'            # #8A2BE2
    ORANGE = '\033[38;2;255;165;0m'             # #FFA500
    RED = '\033[38;2;255;0;0m'                  # #FF0000
    
    # Gradients
    MATRIX = '\033[38;2;0;255;0m'               # Matrix green
    CYBER_PINK = '\033[38;2;255;0;255m'         # Cyber magenta
    NEON_YELLOW = '\033[38;2;255;255;0m'        # Electric yellow
    
    # Backgrounds
    BG_DARK = '\033[48;2;0;0;0m'
    BG_BLUE = '\033[48;2;0;0;139m'

class AITerminalDashboard:
    """Ultra-modern AI dashboard for IntelProbe"""
    
    def __init__(self):
        self.width = 140
        self.ai_status = "INITIALIZING"
        self.scan_progress = 0
        self.threats_detected = 0
        self.ai_confidence = 95.7
        self.network_health = "OPTIMAL"
        self.active_scans = []
        self.ai_insights = []
        self.live_feed = []
        self.matrix_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+-=[]{}|;:,.<>?"
        
    def clear_screen(self):
        """Clear terminal"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def create_banner(self):
        """Create stunning ASCII banner"""
        return f"""
{NeonTheme.ELECTRIC_BLUE}
    ██╗███╗   ██╗████████╗███████╗██╗     ██████╗ ██████╗  ██████╗ ██████╗ ███████╗
    ██║████╗  ██║╚══██╔══╝██╔════╝██║     ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
    ██║██╔██╗ ██║   ██║   █████╗  ██║     ██████╔╝██████╔╝██║   ██║██████╔╝█████╗  
    ██║██║╚██╗██║   ██║   ██╔══╝  ██║     ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝  
    ██║██║ ╚████║   ██║   ███████╗███████╗██║     ██║  ██║╚██████╔╝██████╔╝███████╗
    ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
{NeonTheme.RESET}
{NeonTheme.HOT_PINK}                    ⚡ AI-POWERED CYBER DEFENSE MATRIX ⚡{NeonTheme.RESET}
{NeonTheme.GOLD}                         Created by: Lintshiwe Slade (@lintshiwe){NeonTheme.RESET}
"""
    
    def create_status_bar(self):
        """Create animated status bar"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        ai_indicator = f"{NeonTheme.LIME_GREEN}●{NeonTheme.RESET}" if self.ai_status == "ONLINE" else f"{NeonTheme.RED}●{NeonTheme.RESET}"
        
        status_bar = f"""
{NeonTheme.ELECTRIC_BLUE}{'═' * self.width}{NeonTheme.RESET}
{NeonTheme.ELECTRIC_BLUE}║{NeonTheme.RESET} {NeonTheme.CYBER_PINK}🤖 GEMINI AI:{NeonTheme.RESET} {ai_indicator} {NeonTheme.BOLD}{self.ai_status}{NeonTheme.RESET} │ {NeonTheme.PURPLE}🎯 CONFIDENCE:{NeonTheme.RESET} {NeonTheme.GOLD}{self.ai_confidence}%{NeonTheme.RESET} │ {NeonTheme.ORANGE}📡 NETWORK:{NeonTheme.RESET} {NeonTheme.LIME_GREEN}{self.network_health}{NeonTheme.RESET} │ {NeonTheme.ELECTRIC_BLUE}⏰ {timestamp}{NeonTheme.RESET} {NeonTheme.ELECTRIC_BLUE}║{NeonTheme.RESET}
{NeonTheme.ELECTRIC_BLUE}{'═' * self.width}{NeonTheme.RESET}
"""
        return status_bar
    
    def create_live_metrics(self):
        """Create real-time metrics panel"""
        progress_bar = self.create_progress_bar(self.scan_progress, 50)
        
        metrics = f"""
{NeonTheme.ELECTRIC_BLUE}╔══════════════════════════════════════════════════════════════════════════╗{NeonTheme.RESET}
{NeonTheme.ELECTRIC_BLUE}║{NeonTheme.RESET} {NeonTheme.HOT_PINK}📊 LIVE METRICS{NeonTheme.RESET}                                                         {NeonTheme.ELECTRIC_BLUE}║{NeonTheme.RESET}
{NeonTheme.ELECTRIC_BLUE}╠══════════════════════════════════════════════════════════════════════════╣{NeonTheme.RESET}
{NeonTheme.ELECTRIC_BLUE}║{NeonTheme.RESET} {NeonTheme.LIME_GREEN}🔍 Scan Progress:{NeonTheme.RESET} {progress_bar} {NeonTheme.GOLD}{self.scan_progress}%{NeonTheme.RESET}           {NeonTheme.ELECTRIC_BLUE}║{NeonTheme.RESET}
{NeonTheme.ELECTRIC_BLUE}║{NeonTheme.RESET} {NeonTheme.RED}⚠️  Threats Detected:{NeonTheme.RESET} {NeonTheme.BOLD}{self.threats_detected}{NeonTheme.RESET}                                      {NeonTheme.ELECTRIC_BLUE}║{NeonTheme.RESET}
{NeonTheme.ELECTRIC_BLUE}║{NeonTheme.RESET} {NeonTheme.PURPLE}🎯 Active Scans:{NeonTheme.RESET} {NeonTheme.BOLD}{len(self.active_scans)}{NeonTheme.RESET}                                        {NeonTheme.ELECTRIC_BLUE}║{NeonTheme.RESET}
{NeonTheme.ELECTRIC_BLUE}╚══════════════════════════════════════════════════════════════════════════╝{NeonTheme.RESET}
"""
        return metrics
    
    def create_progress_bar(self, percentage, width=30):
        """Create animated progress bar"""
        filled = int(width * percentage / 100)
        bar = f"{NeonTheme.LIME_GREEN}{'█' * filled}{NeonTheme.DIM}{'░' * (width - filled)}{NeonTheme.RESET}"
        return f"[{bar}]"
    
    def create_ai_brain_panel(self):
        """Create AI analysis panel"""
        panel = f"""
{NeonTheme.ELECTRIC_BLUE}╔══════════════════════════════════════════════════════════════════════════╗{NeonTheme.RESET}
{NeonTheme.ELECTRIC_BLUE}║{NeonTheme.RESET} {NeonTheme.CYBER_PINK}🧠 AI NEURAL NETWORK ANALYSIS{NeonTheme.RESET}                                       {NeonTheme.ELECTRIC_BLUE}║{NeonTheme.RESET}
{NeonTheme.ELECTRIC_BLUE}╠══════════════════════════════════════════════════════════════════════════╣{NeonTheme.RESET}
"""
        
        if self.ai_insights:
            for insight in self.ai_insights[-5:]:
                truncated = insight[:70] + "..." if len(insight) > 70 else insight
                panel += f"{NeonTheme.ELECTRIC_BLUE}║{NeonTheme.RESET} {NeonTheme.NEON_YELLOW}▶{NeonTheme.RESET} {NeonTheme.LIME_GREEN}{truncated:<70}{NeonTheme.RESET} {NeonTheme.ELECTRIC_BLUE}║{NeonTheme.RESET}\n"
        else:
            panel += f"{NeonTheme.ELECTRIC_BLUE}║{NeonTheme.RESET} {NeonTheme.DIM}🤖 AI neural networks are analyzing incoming data...{NeonTheme.RESET}                {NeonTheme.ELECTRIC_BLUE}║{NeonTheme.RESET}\n"
        
        panel += f"{NeonTheme.ELECTRIC_BLUE}╚══════════════════════════════════════════════════════════════════════════╝{NeonTheme.RESET}\n"
        return panel
    
    def create_live_feed(self):
        """Create live network activity feed"""
        feed = f"""
{NeonTheme.ELECTRIC_BLUE}╔══════════════════════════════════════════════════════════════════════════╗{NeonTheme.RESET}
{NeonTheme.ELECTRIC_BLUE}║{NeonTheme.RESET} {NeonTheme.HOT_PINK}📡 LIVE NETWORK FEED{NeonTheme.RESET}                                               {NeonTheme.ELECTRIC_BLUE}║{NeonTheme.RESET}
{NeonTheme.ELECTRIC_BLUE}╠══════════════════════════════════════════════════════════════════════════╣{NeonTheme.RESET}
"""
        
        if self.live_feed:
            for entry in self.live_feed[-6:]:
                feed += f"{NeonTheme.ELECTRIC_BLUE}║{NeonTheme.RESET} {entry:<70} {NeonTheme.ELECTRIC_BLUE}║{NeonTheme.RESET}\n"
        else:
            feed += f"{NeonTheme.ELECTRIC_BLUE}║{NeonTheme.RESET} {NeonTheme.DIM}📡 Waiting for network activity...{NeonTheme.RESET}                                 {NeonTheme.ELECTRIC_BLUE}║{NeonTheme.RESET}\n"
        
        feed += f"{NeonTheme.ELECTRIC_BLUE}╚══════════════════════════════════════════════════════════════════════════╝{NeonTheme.RESET}\n"
        return feed
    
    def create_matrix_sidebar(self):
        """Create matrix-style sidebar"""
        sidebar = []
        for i in range(15):
            chars = ''.join(random.choice(self.matrix_chars) for _ in range(10))
            color = random.choice([NeonTheme.MATRIX, NeonTheme.LIME_GREEN, NeonTheme.ELECTRIC_BLUE])
            sidebar.append(f"{color}{chars}{NeonTheme.RESET}")
        return '\n'.join(sidebar)
    
    def create_threat_radar(self):
        """Create threat detection radar"""
        radar = f"""
{NeonTheme.RED}╔══════════════════════════════════════════════════════════════════════════╗{NeonTheme.RESET}
{NeonTheme.RED}║{NeonTheme.RESET} {NeonTheme.RED}🚨 THREAT DETECTION RADAR{NeonTheme.RESET}                                            {NeonTheme.RED}║{NeonTheme.RESET}
{NeonTheme.RED}╠══════════════════════════════════════════════════════════════════════════╣{NeonTheme.RESET}
{NeonTheme.RED}║{NeonTheme.RESET} {NeonTheme.LIME_GREEN}✅ No critical threats detected{NeonTheme.RESET}                                     {NeonTheme.RED}║{NeonTheme.RESET}
{NeonTheme.RED}║{NeonTheme.RESET} {NeonTheme.GOLD}🔍 Scanning for vulnerabilities...{NeonTheme.RESET}                                {NeonTheme.RED}║{NeonTheme.RESET}
{NeonTheme.RED}║{NeonTheme.RESET} {NeonTheme.PURPLE}🛡️ Defense systems: ACTIVE{NeonTheme.RESET}                                        {NeonTheme.RED}║{NeonTheme.RESET}
{NeonTheme.RED}╚══════════════════════════════════════════════════════════════════════════╝{NeonTheme.RESET}
"""
        return radar
    
    def create_controls(self):
        """Create control panel"""
        controls = f"""
{NeonTheme.ELECTRIC_BLUE}╔══════════════════════════════════════════════════════════════════════════╗{NeonTheme.RESET}
{NeonTheme.ELECTRIC_BLUE}║{NeonTheme.RESET} {NeonTheme.GOLD}🎮 CONTROLS:{NeonTheme.RESET} {NeonTheme.LIME_GREEN}[SPACE]{NeonTheme.RESET} Scan │ {NeonTheme.LIME_GREEN}[A]{NeonTheme.RESET} AI Mode │ {NeonTheme.LIME_GREEN}[T]{NeonTheme.RESET} Threats │ {NeonTheme.LIME_GREEN}[Q]{NeonTheme.RESET} Quit          {NeonTheme.ELECTRIC_BLUE}║{NeonTheme.RESET}
{NeonTheme.ELECTRIC_BLUE}╚══════════════════════════════════════════════════════════════════════════╝{NeonTheme.RESET}
"""
        return controls
    
    def add_ai_insight(self, insight):
        """Add AI insight to the feed"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.ai_insights.append(f"[{timestamp}] {insight}")
        if len(self.ai_insights) > 20:
            self.ai_insights = self.ai_insights[-20:]
    
    def add_network_activity(self, activity):
        """Add network activity to live feed"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.live_feed.append(f"{NeonTheme.LIME_GREEN}[{timestamp}]{NeonTheme.RESET} {activity}")
        if len(self.live_feed) > 20:
            self.live_feed = self.live_feed[-20:]
    
    def render_dashboard(self):
        """Render the complete dashboard"""
        dashboard = ""
        dashboard += self.create_banner()
        dashboard += self.create_status_bar()
        dashboard += self.create_live_metrics()
        dashboard += self.create_ai_brain_panel()
        dashboard += self.create_live_feed()
        dashboard += self.create_threat_radar()
        dashboard += self.create_controls()
        
        return dashboard

class IntelProbeAIDashboard:
    """Main dashboard controller"""
    
    def __init__(self):
        self.dashboard = AITerminalDashboard()
        self.running = False
        self.ai_initialized = False
        
    def initialize_ai(self):
        """Initialize AI components"""
        try:
            print(f"{NeonTheme.LIME_GREEN}🚀 Initializing Gemini AI...{NeonTheme.RESET}")
            
            # Try to load actual AI
            with open('config/ai_config.json', 'r') as f:
                config = json.load(f)
            
            from core.ai_engine import AIEngine
            
            class ConfigWrapper:
                def __init__(self, data):
                    self.data = data
                def get_ai_config(self):
                    return self.data.get('ai_config', {})
            
            ai_engine = AIEngine(ConfigWrapper(config))
            self.ai_initialized = True
            self.dashboard.ai_status = "ONLINE"
            
            print(f"{NeonTheme.LIME_GREEN}✅ AI systems online!{NeonTheme.RESET}")
            
        except Exception as e:
            print(f"{NeonTheme.GOLD}⚠️ Running in demo mode: {e}{NeonTheme.RESET}")
            self.dashboard.ai_status = "DEMO_MODE"
    
    def simulate_activity(self):
        """Simulate real-time activity"""
        def activity_loop():
            ai_insights = [
                "Neural pattern recognition enhanced by 15%",
                "Anomaly detection algorithms updated",
                "Threat correlation matrix optimized",
                "Machine learning models retrained",
                "Behavioral analysis patterns refined",
                "Zero-day vulnerability signatures added",
                "Network topology mapping completed",
                "Encryption strength analysis updated",
                "Attack vector prediction improved",
                "Defensive countermeasures calibrated"
            ]
            
            network_activities = [
                "Port scan detected on 192.168.1.10",
                "New device connected: 192.168.1.45",
                "SSL certificate validated for 192.168.1.1",
                "DNS query resolved: google.com",
                "Firewall rule triggered: Block attempt",
                "SSH connection established to 192.168.1.20",
                "HTTP traffic analyzed: Clean",
                "Network latency measured: 12ms",
                "Bandwidth utilization: 45%",
                "VPN tunnel established"
            ]
            
            while self.running:
                # Add AI insights
                if random.random() < 0.4:
                    insight = random.choice(ai_insights)
                    self.dashboard.add_ai_insight(insight)
                
                # Add network activity
                if random.random() < 0.6:
                    activity = random.choice(network_activities)
                    self.dashboard.add_network_activity(activity)
                
                # Update metrics
                self.dashboard.scan_progress = min(100, self.dashboard.scan_progress + random.randint(1, 5))
                if self.dashboard.scan_progress >= 100:
                    self.dashboard.scan_progress = 0
                
                self.dashboard.ai_confidence = 90 + random.random() * 10
                
                time.sleep(2)
        
        thread = threading.Thread(target=activity_loop, daemon=True)
        thread.start()
    
    def run_demo(self):
        """Run the dashboard demo"""
        print(f"{NeonTheme.ELECTRIC_BLUE}🚀 Launching IntelProbe AI Dashboard...{NeonTheme.RESET}")
        time.sleep(2)
        
        self.initialize_ai()
        self.running = True
        self.simulate_activity()
        
        try:
            for i in range(30):  # Run for 30 iterations
                self.dashboard.clear_screen()
                print(self.dashboard.render_dashboard())
                time.sleep(2)
            
        except KeyboardInterrupt:
            pass
        
        self.running = False
        print(f"\n{NeonTheme.CYBER_PINK}🛡️ IntelProbe AI Dashboard shutting down...{NeonTheme.RESET}")
        print(f"{NeonTheme.LIME_GREEN}✅ All systems secured. Session terminated.{NeonTheme.RESET}")

if __name__ == "__main__":
    print(f"""
{NeonTheme.ELECTRIC_BLUE}{'═' * 80}{NeonTheme.RESET}
{NeonTheme.HOT_PINK}    🛡️  INTELLIPROBE AI DASHBOARD INITIALIZING  🛡️{NeonTheme.RESET}
{NeonTheme.GOLD}       ⚡ Next-Generation Cyber Defense Matrix ⚡{NeonTheme.RESET}
{NeonTheme.ELECTRIC_BLUE}{'═' * 80}{NeonTheme.RESET}
""")
    
    dashboard = IntelProbeAIDashboard()
    dashboard.run_demo()
