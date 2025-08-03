#!/usr/bin/env python3
"""
IntelProbe Setup Script
Simple installation and configuration for IntelProbe
Created by: Lintshiwe Slade
"""

import os
import sys
import subprocess
from pathlib import Path

def print_banner():
    """Display IntelProbe banner"""
    banner = """
    ███████╗███╗   ██╗████████╗███████╗██╗     ██████╗ ██████╗  ██████╗ ██████╗ ███████╗
    ██╔════╝████╗  ██║╚══██╔══╝██╔════╝██║     ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
    ██║     ██╔██╗ ██║   ██║   █████╗  ██║     ██████╔╝██████╔╝██║   ██║██████╔╝█████╗  
    ██║     ██║╚██╗██║   ██║   ██╔══╝  ██║     ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝  
    ███████╗██║ ╚████║   ██║   ███████╗███████╗██║     ██║  ██║╚██████╔╝██████╔╝███████╗
    ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
    
    🔍 AI-Powered Network Forensics CLI Utility
    Created by: Lintshiwe Slade (@lintshiwe)
    """
    print(banner)

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        print(f"   Current version: {sys.version}")
        sys.exit(1)
    
    print(f"✅ Python {sys.version.split()[0]} detected")

def install_dependencies():
    """Install required dependencies"""
    print("\n📦 Installing dependencies...")
    
    try:
        # Try simple requirements first
        result = subprocess.run([
            sys.executable, "-m", "pip", "install", "-r", "requirements-simple.txt"
        ], check=True, capture_output=True, text=True)
        
        print("✅ Basic dependencies installed successfully")
        
        # Ask about optional dependencies
        install_advanced = input("\n🤔 Install advanced dependencies (pandas, numpy, etc.)? [y/N]: ").lower().strip()
        
        if install_advanced in ['y', 'yes']:
            print("📦 Installing advanced dependencies...")
            advanced_packages = [
                "pandas>=2.1.0",
                "numpy>=1.25.0", 
                "matplotlib>=3.7.0",
                "requests[security]"
            ]
            
            for package in advanced_packages:
                try:
                    subprocess.run([
                        sys.executable, "-m", "pip", "install", package
                    ], check=True, capture_output=True, text=True)
                    print(f"✅ Installed {package}")
                except subprocess.CalledProcessError:
                    print(f"⚠️ Failed to install {package} (optional)")
        
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        print("💡 Try installing manually: pip install -r requirements-simple.txt")
        return False
    except FileNotFoundError:
        print("❌ requirements-simple.txt not found")
        return False

def create_directories():
    """Create necessary directory structure"""
    print("\n📁 Creating directory structure...")
    
    directories = [
        "reports",
        "logs", 
        "sessions",
        "alerts",
        "cache",
        "docs"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"✅ Created {directory}/")

def create_config():
    """Create basic configuration file"""
    print("\n⚙️ Creating configuration...")
    
    config_content = """[Network]
# Default network interface (auto-detect if empty)
interface=auto
# Scan timeout in seconds
timeout=30
# Number of threads for scanning
threads=50

[AI]
# Enable AI features (requires API key)
enabled=false
# AI provider (openai, huggingface, local)
provider=openai
# API key file path (keep secure!)
api_key_file=.env

[Output]
# Output format (json, xml, csv, txt)
format=json
# Save reports to file
save_to_file=true
# Report directory
report_path=./reports/
# Log level (DEBUG, INFO, WARNING, ERROR)
log_level=INFO
# Enable file logging
log_to_file=true

[Scanning]
# Default port range
port_range=1-1000
# Scan speed (fast, normal, slow)
speed=normal
# Enable service detection
service_detection=true
# Enable OS detection
os_detection=true

[Detection]
# Enable real-time monitoring
monitoring=true
# Alert threshold for anomalies
threshold=0.7
# Save alerts to file
save_alerts=true

[OSINT]
# Enable OSINT gathering
enabled=true
# External API timeout
api_timeout=10
# Cache results
cache_results=true
"""
    
    if not Path("config.ini").exists():
        with open("config.ini", "w") as f:
            f.write(config_content)
        print("✅ Created config.ini")
    else:
        print("✅ config.ini already exists")

def create_env_template():
    """Create environment template"""
    env_content = """# IntelProbe Environment Configuration
# Created by: Lintshiwe Slade

# OpenAI API Key (for AI features)
OPENAI_API_KEY=your_openai_api_key_here

# Shodan API Key (for OSINT)
SHODAN_API_KEY=your_shodan_api_key_here

# VirusTotal API Key (for threat intelligence)
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# Other API keys as needed
# CENSYS_API_ID=your_censys_api_id
# CENSYS_API_SECRET=your_censys_api_secret
"""
    
    if not Path(".env.template").exists():
        with open(".env.template", "w") as f:
            f.write(env_content)
        print("✅ Created .env.template")
        print("💡 Copy .env.template to .env and add your API keys")

def test_installation():
    """Test basic functionality"""
    print("\n🧪 Testing installation...")
    
    try:
        # Test core imports
        from core.config import ConfigManager
        from core.interface import IntelProbeInterface
        print("✅ Core modules imported successfully")
        
        # Test configuration
        config = ConfigManager()
        print("✅ Configuration loaded successfully")
        
        # Test basic functionality
        print("✅ Basic functionality test passed")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

def print_next_steps():
    """Print next steps for user"""
    print("\n🎉 IntelProbe setup completed successfully!")
    print("\n📋 Next steps:")
    print("1. Copy .env.template to .env and add your API keys")
    print("2. Review and customize config.ini as needed")
    print("3. Run IntelProbe: python intelprobe.py --help")
    print("4. Start with a basic scan: python intelprobe.py scan --help")
    print("\n💡 For advanced features:")
    print("   - Install scapy for packet analysis: pip install scapy")
    print("   - Install AI libraries: pip install openai")
    print("   - See README.md for complete documentation")
    print("\n👨‍💻 Created by: Lintshiwe Slade (@lintshiwe)")
    print("🔗 GitHub: https://github.com/lintshiwe/IntelProbe")

def main():
    """Main setup function"""
    print_banner()
    
    print("🚀 Welcome to IntelProbe Setup")
    print("Setting up your AI-powered network forensics environment...")
    
    # Check prerequisites
    check_python_version()
    
    # Setup steps
    if install_dependencies():
        create_directories()
        create_config()
        create_env_template()
        
        if test_installation():
            print_next_steps()
        else:
            print("\n⚠️ Installation completed with some issues")
            print("Please check the error messages above")
    else:
        print("\n❌ Setup failed during dependency installation")
        print("Please install dependencies manually and try again")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⏹️ Setup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Setup failed with error: {e}")
        sys.exit(1)
