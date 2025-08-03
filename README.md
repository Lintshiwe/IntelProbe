# IntelProbe - AI-Powered Network Forensics CLI

<p align="center">
  <img src="assets/banner.png" alt="IntelProbe Banner" width="600"/>
  <br />
  <br />
  <span>
    <b>🔍 Advanced Network Forensics CLI utility with AI-powered analysis, OSINT capabilities, and intelligent attack detection</b>
  </span>
  <br>
  <br>
  <i>Powered by netspionage core technology with enhanced AI intelligence</i>
  <br>
  <br>
  <b>Created by: Lintshiwe Slade</b>
</p>

## 🚀 Features

### ✅ Works Out-of-the-Box (No Installation Required)

IntelProbe provides powerful capabilities using only Python standard library and built-in system tools:

- **✅ Socket-based Port Scanning**: Real TCP port scanning using Python sockets
- **✅ OS Detection**: TTL-based operating system fingerprinting via ping
- **✅ Service Detection**: Banner grabbing and service identification
- **✅ Network Discovery**: Host discovery using ping and ARP
- **✅ Vulnerability Assessment**: CVE database and security analysis
- **✅ Network Monitoring**: Connection tracking via netstat
- **✅ System Intelligence**: Platform and architecture detection
- **✅ Real-time Logging**: Military-grade audit trails and reporting
- **✅ Cross-Platform**: Windows, Linux, macOS support

### 🔬 Enhanced with Professional Tools (Optional)

When professional security tools are installed, IntelProbe unlocks advanced capabilities:

- **🎯 Nmap Integration**: Advanced scanning techniques and stealth modes
- **🔍 Wireshark Analysis**: Deep packet inspection and traffic analysis
- **🕵️ DNS Intelligence**: Comprehensive domain and subdomain enumeration
- **🌐 WHOIS Lookup**: Domain registration and ownership intelligence
- **⚡ Masscan Speed**: Ultra-fast port scanning for large networks
- **🛡️ IDS Evasion**: Advanced stealth and evasion techniques

> **📖 Installation Guide**: See [SECURITY_TOOLS_INSTALL.md](SECURITY_TOOLS_INSTALL.md) for detailed tool installation instructions.

### 🔬 Advanced Network Scanning

- **Intelligent Host Discovery**: AI-enhanced network reconnaissance
- **Smart Port Scanning**: Threaded scanning with service detection
- **WiFi Analysis**: Advanced wireless network enumeration
- **OS Fingerprinting**: Enhanced operating system detection

### 🕵️ OSINT & Intelligence Gathering

- **MAC Address Intelligence**: Vendor lookup and device profiling
- **Network Geolocation**: IP-to-location mapping
- **Threat Intelligence**: Integration with threat feeds
- **Social Engineering Data**: Passive information gathering

### 🛡️ AI-Powered Attack Detection

- **Anomaly Detection**: Machine learning-based network analysis
- **ARP Spoofing Detection**: Real-time man-in-the-middle detection
- **DDoS Detection**: Intelligent flood attack identification
- **Behavioral Analysis**: Pattern recognition for suspicious activities

### 🤖 AI Enhancements

- **Natural Language Queries**: Ask questions about network status
- **Automated Report Generation**: AI-generated forensic reports
- **Threat Prediction**: Predictive analysis for potential attacks
- **Smart Recommendations**: AI-suggested security improvements

## 📦 Installation

### Prerequisites

- Python 3.8+
- Administrative privileges (for network scanning)
- Windows/Linux/macOS support

### Real-World Security Tools (Optional but Recommended)

IntelProbe works with built-in tools, but for full professional capabilities, install these industry-standard tools:

#### Windows Installation:

```powershell
# Install Chocolatey package manager (if not installed)
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install security tools
choco install nmap
choco install wireshark
choco install putty
choco install curl

# Or download directly:
# Nmap: https://nmap.org/download.html
# Wireshark: https://www.wireshark.org/download.html
```

#### Linux Installation:

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nmap dnsutils whois curl netcat-openbsd wireshark

# CentOS/RHEL/Fedora
sudo yum install nmap bind-utils whois curl nc wireshark
# or sudo dnf install nmap bind-utils whois curl nc wireshark

# Arch Linux
sudo pacman -S nmap bind whois curl openbsd-netcat wireshark-qt
```

#### macOS Installation:

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install security tools
brew install nmap
brew install bind
brew install whois
brew install curl
brew install netcat
brew install wireshark

# Or use MacPorts
sudo port install nmap +universal
```

#### Tool Status Check:

```bash
# Check what's available on your system
python quick-start.py --check

# See available real-world commands
python quick-start.py --tools
```

### Quick Install

```bash
# Clone the repository
git clone https://github.com/lintshiwe/IntelProbe.git
cd IntelProbe

# For immediate demo (no dependencies required):
python quick-start.py

# Check what security tools you have installed:
python quick-start.py --check

# See real-world security commands:
python quick-start.py --tools

# For production deployment:
pip install -r requirements-simple.txt
python setup.py

# For military-grade demonstration:
python military_demo.py

# For real-world network reconnaissance:
python network_scanner.py

# For advanced multitasking security platform:
python multitask_scanner.py

# Launch full IntelProbe:
python intelprobe.py
```

### 🎖️ Military-Grade Production Features

IntelProbe is designed for real-world operational deployment:

- **✅ No External Dependencies**: Works with Python standard library
- **✅ Production Scanner**: Multi-threaded, stealth-capable reconnaissance
- **✅ Vulnerability Assessment**: Automated security flaw detection
- **✅ Military Logging**: Comprehensive audit trails and reporting
- **✅ Cross-Platform**: Windows, Linux, macOS support
- **✅ Stealth Mode**: Low-profile scanning techniques
- **✅ Real-Time Analysis**: Live threat detection and monitoring
- **✅ Multitasking Platform**: Simultaneous scanning, vulnerability assessment, and defense
- **✅ Exploitation Intelligence**: Detailed attack vectors and payloads
- **✅ Automated Defense**: Real-time threat blocking and mitigation

### 🚀 Advanced Multitasking Capabilities

IntelProbe's multitasking platform provides comprehensive security assessment:

- **🔍 Real-time Network Reconnaissance**: Continuous discovery and profiling
- **⚔️ Exploitation Intelligence**: Detailed attack vectors, tools, and payloads
- **🛡️ Vulnerability Assessment**: Automated security flaw detection and analysis
- **🚨 Threat Monitoring**: Real-time threat level assessment and alerting
- **🔒 Automated Defense**: Network isolation and threat mitigation
- **📊 Comprehensive Reporting**: Executive summaries and technical details
- **💻 Device Profiling**: OS, hostname, users, shares, and sensitive data discovery
- **🎯 Mitigation Guidance**: Specific remediation steps for each vulnerability

### Quick Demo (No Setup Required)

Try IntelProbe immediately without any installation:

```bash
# Interactive demo
python quick-start.py

# Production military demonstration
python military_demo.py

# Real-world network scanner with exploitation intelligence
python network_scanner.py

# Advanced multitasking security platform
python multitask_scanner.py

# Specific feature demos
python quick-start.py --scan     # Network scanning demo
python quick-start.py --osint    # OSINT gathering demo
python quick-start.py --detect   # Attack detection demo
python quick-start.py --ai       # AI analysis demo
```

### Configuration

Edit `config.ini` to customize your experience:

```ini
[Network]
DefaultInterface=wlan0
ScanTimeout=30
ThreadCount=100

[AI]
EnableAI=true
Model=gpt-4-mini
ApiKey=your_api_key_here

[Output]
LogLevel=INFO
OutputFormat=json
SaveReports=true
ReportPath=./reports/

[Scanning]
PortRange=1-65535
ScanSpeed=fast
ServiceDetection=true
```

## 🎯 Usage

### Interactive Mode

```bash
python intelprobe.py
```

### Command Line Interface

```bash
# Quick network scan
python intelprobe.py scan --target 192.168.1.0/24

# Real-world comprehensive scanning
python intelprobe.py scan --target 192.168.1.0/24 --real-world

# Advanced multitasking security assessment
python multitask_scanner.py

# OSINT gathering
python intelprobe.py osint --mac 00:11:22:33:44:55

# Attack detection
python intelprobe.py detect --mode arp --interface wlan0

# AI analysis
python intelprobe.py ai --query "Analyze network security posture"
```

### Available Commands

#### 🔍 Network Scanning

- `scan network <target>` - Comprehensive network discovery
- `scan ports <target>` - Advanced port scanning
- `scan wifi` - Wireless network enumeration
- `scan vuln <target>` - Vulnerability assessment

#### 🕵️ OSINT & Intelligence

- `osint mac <address>` - MAC address intelligence
- `osint ip <address>` - IP geolocation and threat data
- `osint domain <domain>` - Domain intelligence gathering
- `osint social <target>` - Social engineering reconnaissance

#### 🛡️ Attack Detection

- `detect arp <network>` - ARP spoofing detection
- `detect ddos <interface>` - DDoS attack monitoring
- `detect anomaly <network>` - AI-powered anomaly detection
- `detect mitm <interface>` - Man-in-the-middle detection

#### 🤖 AI Features

- `ai analyze <data>` - AI-powered network analysis
- `ai report <scan_id>` - Generate intelligent reports
- `ai predict <network>` - Threat prediction analysis
- `ai recommend <target>` - Security recommendations

## 🛠️ Advanced Features

### Multi-threaded Scanning

IntelProbe uses intelligent threading for faster scans:

```python
# Automatically optimizes thread count based on target size
intelprobe.py scan network 192.168.1.0/24 --threads auto
```

### Real-time Monitoring

```python
# Continuous network monitoring with AI analysis
intelprobe.py monitor --duration 1h --ai-analysis
```

### Report Generation

```python
# Generate comprehensive forensic reports
intelprobe.py report --scan-id 12345 --format pdf --ai-summary
```

## 🔧 Development

### Project Structure

```
IntelProbe/
├── core/
│   ├── scanner.py          # Enhanced scanning engine
│   ├── osint.py           # OSINT gathering modules
│   ├── detection.py       # Attack detection systems
│   ├── ai_engine.py       # AI analysis engine
│   └── utils.py           # Utility functions
├── modules/
│   ├── network/           # Network scanning modules
│   ├── intelligence/      # OSINT modules
│   ├── detection/         # Attack detection modules
│   └── ai/               # AI enhancement modules
├── config/
│   ├── config.ini        # Main configuration
│   └── ai_models/        # AI model configurations
├── reports/              # Generated reports
├── assets/               # Static assets
└── tests/               # Unit tests
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your enhancement
4. Add tests
5. Submit a pull request

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [API Documentation](docs/api.md)
- [AI Features Guide](docs/ai-features.md)
- [Contributing Guidelines](docs/contributing.md)

## 🔐 Security & Ethics

IntelProbe is designed for:

- ✅ Network security assessment
- ✅ Forensic investigation
- ✅ Educational purposes
- ✅ Authorized penetration testing

**Important**: Only use IntelProbe on networks you own or have explicit permission to test.

## 🙏 Acknowledgments

- Built upon the excellent [netspionage](https://github.com/ANG13T/netspionage) framework by Angelina Tsuboi
- Enhanced with modern AI capabilities and forensic features by Lintshiwe Slade
- Inspired by the network security community

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

- 📧 Email: lintshiwe.slade@intelprobe.dev
- 🐛 Issues: [GitHub Issues](https://github.com/lintshiwe/IntelProbe/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/lintshiwe/IntelProbe/discussions)

---

**🔍 IntelProbe - Where Network Forensics Meets Artificial Intelligence**  
_Created by Lintshiwe Slade_
