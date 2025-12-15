#!/usr/bin/env python3
"""
IntelProbe AI Setup Script
Sets up AI dependencies for IntelProbe (OpenAI or Google Gemini)

Author: Lintshiwe Slade (@lintshiwe)
GitHub: https://github.com/lintshiwe/IntelProbe
License: MIT License
Copyright (c) 2025 Lintshiwe Slade
"""

import subprocess
import sys
import json
from pathlib import Path

def install_package(package_name: str) -> bool:
    """Install a Python package using pip"""
    try:
        print(f"📦 Installing {package_name}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
        print(f"✅ {package_name} installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install {package_name}: {e}")
        return False

def check_package(package_name: str) -> bool:
    """Check if a package is already installed"""
    try:
        __import__(package_name)
        return True
    except ImportError:
        return False

def setup_gemini():
    """Setup Google Gemini AI"""
    print("🤖 Setting up Google Gemini AI...")
    
    if check_package("google.generativeai"):
        print("✅ Google Gemini is already installed!")
    else:
        if not install_package("google-generativeai"):
            return False
    
    print("""
🔑 To complete Gemini setup:
1. Go to https://makersuite.google.com/app/apikey
2. Sign in with your Google account
3. Click 'Create API Key'
4. Copy the generated API key
5. Update your config file with:
   - Set "gemini_enabled": true
   - Set "gemini_api_key": "your-api-key-here"
""")
    return True

def setup_openai():
    """Setup OpenAI"""
    print("🤖 Setting up OpenAI...")
    
    if check_package("openai"):
        print("✅ OpenAI is already installed!")
    else:
        if not install_package("openai"):
            return False
    
    print("""
🔑 To complete OpenAI setup:
1. Go to https://platform.openai.com/api-keys
2. Sign in to your OpenAI account
3. Click 'Create new secret key'
4. Copy the generated API key
5. Update your config file with:
   - Set "openai_enabled": true
   - Set "openai_api_key": "your-api-key-here"
""")
    return True

def main():
    print("🚀 IntelProbe AI Setup")
    print("=" * 50)
    
    print("Choose your AI provider:")
    print("1. Google Gemini (Free tier available)")
    print("2. OpenAI GPT (Paid service)")
    print("3. Install both")
    print("4. Skip AI setup")
    
    while True:
        choice = input("\\nEnter your choice (1-4): ").strip()
        
        if choice == "1":
            setup_gemini()
            break
        elif choice == "2":
            setup_openai()
            break
        elif choice == "3":
            setup_gemini()
            setup_openai()
            break
        elif choice == "4":
            print("⏭️ Skipping AI setup. You can run this script later.")
            break
        else:
            print("❌ Invalid choice. Please enter 1, 2, 3, or 4.")
    
    # Create example config if it doesn't exist
    config_path = Path("config/ai_config_example.json")
    if config_path.exists():
        print(f"\\n📄 Example configuration available at: {config_path}")
        print("📝 Copy this file to create your own config and add your API keys!")
    else:
        print("\\n⚠️ Example configuration file not found.")
    
    print("\\n✅ Setup complete! Don't forget to configure your API keys.")

if __name__ == "__main__":
    main()
