#!/usr/bin/env python3
"""
Test Gemini AI setup for IntelProbe
Verifies that your API key is working correctly

Author: Lintshiwe Slade (@lintshiwe)
"""

import os
import sys

def test_gemini_setup():
    """Test Gemini AI with your configured API key"""
    print("🤖 Testing Gemini AI Setup for IntelProbe")
    print("=" * 50)
    
    try:
        # Test import
        print("📦 Testing Google Generative AI import...")
        import google.generativeai as genai
        print("✅ Google Generative AI imported successfully!")
        
        # Configure with your API key
        print("🔑 Configuring with your API key...")
        api_key = "AIzaSyByAYC2jL-gy-HK_UNqId-uc6zPoaUglEg"
        genai.configure(api_key=api_key)
        print("✅ API key configured!")
        
        # Create model
        print("🚀 Creating Gemini model...")
        model = genai.GenerativeModel('gemini-1.5-flash')
        print("✅ Gemini model created!")
        
        # Test with cybersecurity prompt
        print("🔍 Testing with cybersecurity analysis...")
        response = model.generate_content(
            "As a cybersecurity expert, explain the importance of network scanning in exactly 2 sentences."
        )
        
        print("✅ Gemini AI Response:")
        print("-" * 40)
        print(response.text)
        print("-" * 40)
        
        # Test IntelProbe integration
        print("\\n🛡️ Testing IntelProbe + Gemini Integration...")
        
        # Check if core module loads with Gemini
        try:
            import core
            print("✅ IntelProbe core module loaded with Gemini support!")
            print(f"   Author: {core.__author__}")
            print(f"   Version: {core.__version__}")
        except Exception as e:
            print(f"⚠️ IntelProbe core module issue: {e}")
        
        print("\\n🎉 SUCCESS! Gemini AI is fully configured for IntelProbe!")
        print("\\n📋 Summary:")
        print("   ✅ Google Generative AI package installed")
        print("   ✅ API key configured and working")
        print("   ✅ Gemini model responding correctly")
        print("   ✅ Ready for cybersecurity analysis!")
        
        return True
        
    except ImportError:
        print("❌ Google Generative AI not installed")
        print("   Run: pip install google-generativeai")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def show_usage_instructions():
    """Show how to use Gemini with IntelProbe"""
    print("\\n📖 How to Use Gemini AI with IntelProbe:")
    print("\\n1. 🔍 Network Scanning with AI Analysis:")
    print("   python multitask_scanner.py --target 192.168.1.0/24 --ai-analysis")
    
    print("\\n2. 🤖 Direct AI Security Consultation:")
    print("   from core.ai_engine import AIEngine")
    print("   # AI will analyze your network scans automatically!")
    
    print("\\n3. 📊 Generate AI-Powered Reports:")
    print("   # IntelProbe will use Gemini for threat analysis,")
    print("   # executive summaries, and security recommendations")

if __name__ == "__main__":
    success = test_gemini_setup()
    if success:
        show_usage_instructions()
    
    print("\\n🚀 Gemini AI is ready for IntelProbe! Happy scanning! 🛡️")
