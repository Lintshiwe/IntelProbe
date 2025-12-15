#!/usr/bin/env python3
"""
Fixed version of your Gemini AI code
Shows correct syntax and secure API key handling

Author: Lintshiwe Slade (@lintshiwe)
"""

import os

# ✅ CORRECT: Import google.generativeai
import google.generativeai as genai

def test_your_fixed_code():
    """Your code fixed with correct syntax"""
    try:
        # ✅ SECURE: Get API key from environment (not hardcoded!)
        api_key = os.getenv('GEMINI_API_KEY')
        if not api_key:
            print("❌ Please set GEMINI_API_KEY environment variable")
            print("   Windows: set GEMINI_API_KEY=your-api-key-here")
            print("   Linux/Mac: export GEMINI_API_KEY=your-api-key-here")
            return
        
        # ✅ CORRECT: Configure with genai.configure()
        genai.configure(api_key=api_key)
        
        # ✅ CORRECT: Create model with genai.GenerativeModel()
        model = genai.GenerativeModel("gemini-2.0-flash")  # You can use 2.0-flash too!
        
        # ✅ CORRECT: Generate content with model.generate_content()
        response = model.generate_content("Explain how AI works in a few words")
        
        # ✅ CORRECT: Access text with response.text
        print("✅ Gemini Response:")
        print("-" * 40)
        print(response.text)
        print("-" * 40)
        
    except ImportError:
        print("❌ Google Generative AI not installed")
        print("   Install with: pip install google-generativeai")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_with_intelliprobe():
    """Test using IntelProbe's unified AI interface"""
    print("\\n🔍 Testing with IntelProbe AI Engine...")
    
    # For this to work, you'd need to configure IntelProbe with your Gemini key
    print("💡 To use with IntelProbe:")
    print("   1. Run: python setup_ai.py")
    print("   2. Choose option 1 (Google Gemini)")
    print("   3. Get API key from: https://makersuite.google.com/app/apikey")
    print("   4. Configure in config/ai_config.json")

if __name__ == "__main__":
    print("🤖 Fixed Gemini AI Code")
    print("=" * 50)
    
    # Test your fixed code
    test_your_fixed_code()
    
    # Show IntelProbe integration
    test_with_intelliprobe()
    
    print("\\n✅ Code fixed! Key changes:")
    print("   • Import: google.generativeai as genai")
    print("   • Configure: genai.configure(api_key=key)")
    print("   • Model: genai.GenerativeModel(model_name)")
    print("   • Generate: model.generate_content(prompt)")
    print("   • Secure: API key from environment variable")
