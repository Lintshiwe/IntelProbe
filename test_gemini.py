#!/usr/bin/env python3
"""
Gemini AI Test Script for IntelProbe
Tests Google Gemini AI integration

Author: Lintshiwe Slade (@lintshiwe)
GitHub: https://github.com/lintshiwe/IntelProbe
License: MIT License
Copyright (c) 2025 Lintshiwe Slade
"""

import os
import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_gemini_direct():
    """Test Gemini AI directly with correct syntax"""
    try:
        # Correct import
        import google.generativeai as genai
        
        # Get API key from environment variable (secure way)
        api_key = os.getenv('GEMINI_API_KEY')
        if not api_key:
            print("❌ GEMINI_API_KEY environment variable not set")
            print("   Set it with: set GEMINI_API_KEY=your-api-key-here")
            return False
        
        # Configure Gemini (correct way)
        genai.configure(api_key=api_key)
        
        # Create model instance (correct way)
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        # Generate content (correct syntax)
        response = model.generate_content("Explain how AI works in a few words")
        
        print("✅ Gemini AI Response:")
        print("-" * 50)
        print(response.text)
        print("-" * 50)
        
        return True
        
    except ImportError:
        print("❌ Google Generative AI not installed")
        print("   Install with: pip install google-generativeai")
        return False
    except Exception as e:
        print(f"❌ Gemini AI test failed: {e}")
        return False

def test_gemini_with_intelliprobe():
    """Test Gemini AI through IntelProbe's AI engine"""
    try:
        # Import IntelProbe's AI engine
        from core.ai_engine import AIEngine
        
        # Mock configuration for testing
        class MockConfig:
            def get_ai_config(self):
                return {
                    'gemini_enabled': True,
                    'gemini_api_key': os.getenv('GEMINI_API_KEY'),
                    'gemini_model': 'gemini-1.5-flash',
                    'openai_enabled': False
                }
        
        # Create AI engine instance
        config = MockConfig()
        ai_engine = AIEngine(config)
        
        if ai_engine.ai_provider == 'gemini':
            print("✅ IntelProbe AI Engine with Gemini initialized!")
            
            # Test the unified AI query method
            response = ai_engine._query_ai(
                "As a cybersecurity expert, explain the importance of network scanning in 2 sentences.",
                max_tokens=100,
                temperature=0.3
            )
            
            print("✅ IntelProbe + Gemini Response:")
            print("-" * 50)
            print(response)
            print("-" * 50)
            
            return True
        else:
            print(f"❌ AI Engine using: {ai_engine.ai_provider or 'None'}")
            return False
            
    except Exception as e:
        print(f"❌ IntelProbe + Gemini test failed: {e}")
        return False

def main():
    print("🤖 Gemini AI Integration Test for IntelProbe")
    print("=" * 60)
    
    # Test 1: Direct Gemini API
    print("\n🔍 Test 1: Direct Gemini API")
    test1_success = test_gemini_direct()
    
    # Test 2: Gemini through IntelProbe
    print("\n🔍 Test 2: Gemini through IntelProbe AI Engine")
    test2_success = test_gemini_with_intelliprobe()
    
    # Summary
    print("\n📋 Test Summary:")
    print(f"   Direct Gemini API: {'✅ PASS' if test1_success else '❌ FAIL'}")
    print(f"   IntelProbe + Gemini: {'✅ PASS' if test2_success else '❌ FAIL'}")
    
    if test1_success and test2_success:
        print("\n🎉 All tests passed! Gemini AI is ready to use with IntelProbe!")
    else:
        print("\n⚠️ Some tests failed. Check the errors above.")

if __name__ == "__main__":
    main()
