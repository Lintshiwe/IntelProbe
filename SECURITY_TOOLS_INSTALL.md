# IntelProbe Security Tools Installation Guide

## Overview

IntelProbe works with built-in Python and system tools, but for full professional-grade capabilities, install these industry-standard security tools. This guide provides step-by-step installation instructions for Windows, Linux, and macOS.

## 🔧 Core Security Tools

### Essential Tools

- **Nmap**: Network discovery and port scanning
- **Wireshark**: Network traffic analysis
- **Dig/NSLookup**: DNS reconnaissance
- **Whois**: Domain intelligence gathering
- **Curl**: HTTP/HTTPS testing
- **Netcat**: Network connectivity testing

### Advanced Tools (Optional)

- **Metasploit**: Penetration testing framework
- **Burp Suite**: Web application security testing
- **OpenVAS/Nessus**: Vulnerability scanning
- **Aircrack-ng**: Wireless security auditing

## 💻 Windows Installation

### Method 1: Chocolatey (Recommended)

First, install Chocolatey package manager:

```powershell
# Run as Administrator
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
```

Then install security tools:

```powershell
# Essential tools
choco install nmap -y
choco install wireshark -y
choco install curl -y
choco install putty -y

# Additional tools
choco install git -y
choco install python3 -y
choco install openssl -y
```

### Method 2: Direct Downloads

Download and install manually:

1. **Nmap**: https://nmap.org/download.html
2. **Wireshark**: https://www.wireshark.org/download.html
3. **Git**: https://git-scm.com/download/win
4. **Python**: https://python.org/downloads/

### Method 3: Windows Subsystem for Linux (WSL)

```powershell
# Enable WSL2
wsl --install
wsl --install -d Ubuntu

# Then follow Linux installation steps in WSL
```

## 🐧 Linux Installation

### Ubuntu/Debian

```bash
# Update package lists
sudo apt update && sudo apt upgrade -y

# Essential security tools
sudo apt install -y \
    nmap \
    dnsutils \
    whois \
    curl \
    netcat-openbsd \
    wireshark \
    tcpdump \
    net-tools \
    traceroute \
    arp-scan \
    masscan

# Python and development tools
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    build-essential

# Optional advanced tools
sudo apt install -y \
    john \
    hashcat \
    aircrack-ng \
    nikto \
    dirb \
    gobuster \
    sqlmap
```

### CentOS/RHEL/Fedora

```bash
# CentOS/RHEL 8+
sudo dnf update -y
sudo dnf install -y \
    nmap \
    bind-utils \
    whois \
    curl \
    nc \
    wireshark \
    tcpdump \
    net-tools \
    traceroute

# Fedora
sudo dnf install -y \
    nmap \
    bind-utils \
    whois \
    curl \
    nc \
    wireshark \
    python3 \
    python3-pip \
    git
```

### Arch Linux

```bash
# Update system
sudo pacman -Syu

# Install security tools
sudo pacman -S \
    nmap \
    bind \
    whois \
    curl \
    openbsd-netcat \
    wireshark-qt \
    tcpdump \
    net-tools \
    traceroute \
    python \
    python-pip \
    git
```

## 🍎 macOS Installation

### Method 1: Homebrew (Recommended)

Install Homebrew first:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Install security tools:

```bash
# Essential tools
brew install nmap
brew install bind
brew install whois
brew install curl
brew install netcat
brew install wireshark
brew install python3
brew install git

# Additional security tools
brew install masscan
brew install arp-scan
brew install tcpdump
brew install john-jumbo
brew install hashcat

# Web security tools
brew install nikto
brew install dirb
brew install gobuster
```

### Method 2: MacPorts

```bash
# Install MacPorts first from https://www.macports.org/install.php

# Install tools
sudo port install nmap +universal
sudo port install bind9 +universal
sudo port install whois
sudo port install curl +universal
sudo port install netcat
```

## 🔍 Verification and Testing

### Check Tool Installation

```bash
# Verify installations
python quick-start.py --check

# Test individual tools
nmap --version
dig google.com
whois google.com
curl --version
wireshark --version
```

### Test IntelProbe with Real Tools

```bash
# Test military-grade capabilities
python military_demo.py

# Test quick-start with all features
python quick-start.py

# Test network scanning
python quick-start.py --scan

# Show available commands
python quick-start.py --tools
```

## 🛡️ Security and Permissions

### Linux/macOS Permissions

Some tools require special permissions:

```bash
# Allow non-root users to capture packets
sudo setcap cap_net_raw+ep /usr/bin/nmap
sudo setcap cap_net_raw,cap_net_admin+ep /usr/bin/wireshark

# Add user to wireshark group
sudo usermod -a -G wireshark $USER

# For network interface access
sudo usermod -a -G netdev $USER
```

### Windows Permissions

- Run Command Prompt or PowerShell as Administrator for network scanning
- Some features require elevated privileges
- Windows Defender may flag security tools - add exceptions if needed

## 🚨 Legal and Ethical Usage

**IMPORTANT**: Only use these tools on:

- Your own networks and systems
- Networks you have explicit written permission to test
- Educational lab environments
- Authorized penetration testing engagements

**Never use these tools on networks you don't own without permission!**

## 📋 Tool-Specific Configuration

### Nmap Optimization

```bash
# Create nmap configuration
mkdir -p ~/.nmap
cat > ~/.nmap/nmap.conf << EOF
# Timing template (0-5, faster = louder)
timing 3

# Default scan type
scan-type sS

# OS detection
os-detection true
EOF
```

### Wireshark Setup

```bash
# Configure Wireshark for non-root usage (Linux)
sudo dpkg-reconfigure wireshark-common
sudo usermod -a -G wireshark $USER
```

## 🔧 Troubleshooting

### Common Issues

1. **Permission Denied**: Run with elevated privileges or configure capabilities
2. **Tool Not Found**: Ensure tools are in system PATH
3. **Firewall Blocking**: Configure firewall rules for security tools
4. **Antivirus False Positives**: Add security tools to antivirus exceptions

### Getting Help

```bash
# Tool-specific help
nmap --help
wireshark --help
dig -h

# IntelProbe help
python intelprobe.py --help
python quick-start.py --help
```

## 📚 Learning Resources

### Documentation

- [Nmap Reference Guide](https://nmap.org/book/)
- [Wireshark User Guide](https://www.wireshark.org/docs/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

### Practice Environments

- **VulnHub**: Vulnerable VMs for practice
- **HackTheBox**: Online penetration testing platform
- **TryHackMe**: Beginner-friendly security challenges
- **OverTheWire**: War games and challenges

---

**Remember**: IntelProbe works with built-in tools, but installing these professional security tools unlocks its full potential for real-world network security assessment.
