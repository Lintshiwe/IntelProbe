# AI Configuration for IntelProbe

IntelProbe now supports both **Google Gemini AI** and **OpenAI GPT** for enhanced network security analysis! 🤖

## Quick Setup

### Option 1: Google Gemini AI (Recommended)

**Free tier available!** 🆓

1. **Install Gemini:**

   ```bash
   pip install google-generativeai
   ```

2. **Get API Key:**

   - Visit: https://makersuite.google.com/app/apikey
   - Sign in with Google account
   - Click "Create API Key"
   - Copy the generated key

3. **Configure IntelProbe:**
   ```json
   {
     "ai_config": {
       "gemini_enabled": true,
       "gemini_api_key": "your-gemini-api-key-here",
       "gemini_model": "gemini-1.5-flash"
     }
   }
   ```

### Option 2: OpenAI GPT

**Premium service** 💳

1. **Install OpenAI:**

   ```bash
   pip install openai
   ```

2. **Get API Key:**

   - Visit: https://platform.openai.com/api-keys
   - Sign in to OpenAI account
   - Click "Create new secret key"
   - Copy the generated key

3. **Configure IntelProbe:**
   ```json
   {
     "ai_config": {
       "openai_enabled": true,
       "openai_api_key": "your-openai-api-key-here",
       "openai_model": "gpt-3.5-turbo"
     }
   }
   ```

## Easy Setup Script

Run the automated setup script:

```bash
python setup_ai.py
```

This script will:

- ✅ Install required AI packages
- 📋 Guide you through API key setup
- 📝 Create example configuration files

## AI Features

With AI enabled, IntelProbe provides:

- 🔍 **Intelligent Threat Analysis** - AI-powered security assessments
- 📊 **Executive Summaries** - Management-friendly reports
- 🎯 **Predictive Insights** - Future threat predictions
- 🛡️ **Risk Prioritization** - Smart threat ranking

## Model Recommendations

### Gemini Models:

- `gemini-1.5-flash` - ⚡ **Fast & Free** (Recommended)
- `gemini-1.5-pro` - 🎯 **Higher Quality** (Slower)
- `gemini-1.0-pro` - 💪 **Stable**

### OpenAI Models:

- `gpt-3.5-turbo` - ⚡ **Fast & Affordable** (Recommended)
- `gpt-4` - 🎯 **Highest Quality** (Most Expensive)
- `gpt-4-turbo-preview` - ⚖️ **Balanced**

## No AI? No Problem!

IntelProbe works perfectly **without AI** too! All core scanning and analysis features are available with graceful fallbacks when AI is not configured.

---

**Need help?** Check out the full configuration example in `config/ai_config_example.json`

**Pro Tip:** Start with Gemini's free tier to test AI features, then consider upgrading to OpenAI GPT-4 for production use! 🚀
