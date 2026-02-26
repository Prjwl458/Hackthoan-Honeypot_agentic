# 🛡️ Agentic AI Honeypot

A production-ready, asynchronous AI agent designed to engage with scammers, analyze their intent, and extract actionable intelligence in real-time.

## 🚀 Features

- **Async Architecture**: Non-blocking FastAPI with httpx for high-performance concurrent requests
- **Intelligence Extraction**: LLM-powered analysis to identify UPI IDs, bank accounts, phishing links, and phone numbers
- **Tarpitting Strategy**: Keeps scammers engaged with realistic, varied responses
- **Database Persistence**: MongoDB Atlas with in-memory fallback for resilience
- **Production Ready**: Pydantic validation, global error handling, structured logging

## 🛠️ Tech Stack

- **Framework**: FastAPI + Python 3.11+
- **AI**: OpenRouter (Llama 3.1)
- **Database**: MongoDB Atlas (Motor async driver)
- **Deployment**: Render

## 📋 Environment Variables

Create a `.env` file:

```env
# API Security
API_KEY=your_api_key_here

# LLM Configuration
OPENROUTER_API_KEY=sk-or-v1-...

# Database (optional - uses in-memory fallback if not set)
MONGODB_URI=mongodb+srv://...

# Callback URL (optional)
GUVI_CALLBACK_URL=https://your-callback-url.com
```

## 🏃 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run locally
uvicorn main:app --reload

# Deploy to Render
# Set environment variables in Render dashboard
```

## 📡 API Endpoints

### Health Check
```bash
GET /
```

### Process Message
```bash
POST / -H "x-api-key: YOUR_API_KEY"
```

Request body:
```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "Your bank account is blocked! Pay now.",
    "timestamp": 1234567890
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English"
  }
}
```

## 📁 Project Structure

```
├── main.py          # FastAPI application entry point
├── agent.py         # ScamAgent for AI processing
├── database.py      # MongoDB connection manager
├── models.py        # Pydantic schemas
├── requirements.txt # Python dependencies
└── .env.example    # Environment template
```

## 🔒 Security

- All secrets stored in environment variables
- No hardcoded API keys
- CORS configured for production
- Input validation with Pydantic

## 📄 License

MIT License
