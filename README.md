🛡️ Agentic AI Honeypot: Real-Time Scam Intelligence
A high-performance, asynchronous AI agent designed to engage with scammers, analyze their intent, and extract actionable intelligence (UPI IDs, Bank Accounts, Phishing Links) in real-time.

🚀 Key Features
Instant Engagement: Uses an asynchronous architecture to respond to scammers in under 1 second.
Deep Intelligence Extraction: Leverages LLMs to identify scammer pressure tactics and extract financial entities.
Resilience Engine: Implements "Strict JSON Isolation" to handle malformed or conversational AI outputs without system failure.
Automated Callback: Real-time reporting of captured data to security platforms via secure webhooks.
Cloud Ready: Fully containerized logic ready for deployment on platforms like Render.

🛠️ Technical Stack
Core: Python 3.10+ & FastAPI
AI: OpenRouter / LLM (GPT-4o/Claude 3.5)
Concurrency: BackgroundTasks for non-blocking processing.
Deployment: Render + GitHub CI/CD

🏗️ System Architecture
The system is designed to be "fail-safe." Even if the AI provides a talkative response or the external platform is slow, the honeypot remains online and functional.
Request Handler: Receives the scammer's message and immediately returns a generated reply.
Intelligence Layer: In the background, the LLM analyzes the message for entities.
Extraction Logic: A custom regex-based isolation engine filters raw text into structured JSON.
Reporting: The final intelligence payload is sent to the target callback URL.

🧪 Testing Results (Final Output)
The system was validated against high-pressure phishing scenarios. Below is a sample of a successful extraction during a simulated SBI scam attempt:

JSON
{
  "scamDetected": true,
  "extractedIntelligence": {
    "bankAccounts": ["SBI"],
    "suspiciousKeywords": ["URGENT", "blocked in 2 hours", "OTP", "account number"]
  },
  "agentNotes": "The message is a classic phishing scam intent on creating urgency to extract sensitive financial data."
}

