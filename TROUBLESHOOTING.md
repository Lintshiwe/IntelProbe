# IntelProbe Troubleshooting Guide

## 🚨 Common Issues and Solutions

### Dependency Issues

#### Problem: "No module named 'netifaces'"

**Solution:**

```bash
# Option 1: Use the quick demo (no dependencies required)
python quick-start.py

# Option 2: Install basic dependencies
pip install -r requirements-simple.txt

# Option 3: Install specific missing dependency
pip install netifaces
```

#### Problem: Python 3.13 compatibility errors with numpy/pandas

**Solution:**

```bash
# Use the compatibility-focused requirements
pip install -r requirements-simple.txt

# Install compatible versions individually
pip install "numpy>=1.25.0"
pip install "pandas>=2.1.0"
```

### Windows-Specific Issues

#### Problem: PowerShell echo commands not working

**Solution:**

```powershell
# Instead of: echo -e "command"
# Use: Get-Content file | python script.py

# Create a command file
echo "help" > commands.txt
echo "scan" >> commands.txt
echo "quit" >> commands.txt

# Then pipe it
Get-Content commands.txt | python quick-start.py
```

#### Problem: Permission errors for network scanning

**Solution:**

- Run PowerShell/Command Prompt as Administrator
- Use the demo mode which doesn't require network privileges
- Install npcap or WinPcap for advanced network features

### Feature-Specific Issues

#### Problem: AI features not working

**Solution:**

1. Copy `.env.template` to `.env`
2. Add your OpenAI API key to `.env`
3. Install openai: `pip install openai`

#### Problem: Advanced scanning features missing

**Solution:**

```bash
# Install optional dependencies
pip install scapy python-nmap

# For Windows, also install npcap
# Download from: https://npcap.com/
```

### Getting Started Without Issues

#### Immediate Demo (No Setup)

```bash
# Works out of the box
python quick-start.py
```

#### Basic Installation

```bash
# Minimal working setup
pip install requests rich click typer
python intelprobe.py --help
```

#### Full Installation

```bash
# Complete setup
pip install -r requirements-simple.txt
python setup.py
```

## 🔧 Verification Steps

### Test Your Installation

```bash
# 1. Test Python version
python --version

# 2. Test basic imports
python -c "import requests, rich, click; print('✅ Core dependencies OK')"

# 3. Test IntelProbe help
python intelprobe.py --help

# 4. Test quick demo
python quick-start.py --scan
```

### Environment Check

```bash
# Check installed packages
pip list | grep -E "(requests|rich|click|typer)"

# Check Python path
python -c "import sys; print(sys.path)"

# Check IntelProbe modules
python -c "from core.config import ConfigManager; print('✅ IntelProbe modules OK')"
```

## 📞 Getting Help

### Self-Help Resources

1. **Quick Demo**: `python quick-start.py` - Always works
2. **Help Command**: `python intelprobe.py --help`
3. **Configuration**: Check `config.ini` for settings
4. **Logs**: Check `logs/` directory for error details

### Community Support

- **GitHub Issues**: https://github.com/lintshiwe/IntelProbe/issues
- **Discussions**: https://github.com/lintshiwe/IntelProbe/discussions
- **Email**: lintshiwe.slade@intelprobe.dev

### Reporting Bugs

When reporting issues, please include:

1. Operating system and Python version
2. Full error message
3. Steps to reproduce
4. Output of `pip list`

---

**Created by: Lintshiwe Slade (@lintshiwe)**
