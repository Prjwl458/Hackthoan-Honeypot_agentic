import json
import os
import re
import requests # Using requests for OpenRouter API

class ScamAgent:
    def __init__(self):
        self.openrouter_api_key = os.getenv("OPENROUTER_API_KEY")
        if not self.openrouter_api_key:
            # For hackathon, allow graceful degradation if key isn't set for LLM calls
            print("WARNING: OPENROUTER_API_KEY not set. LLM features may be limited.")
        self.openrouter_url = "https://openrouter.ai/api/v1/chat/completions"
        self.model = "mistralai/mistral-7b-instruct" # Selected free-tier model

    def _call_llm_api(self, messages: list, response_as_json: bool = False):
        if not self.openrouter_api_key:
            raise ValueError("OpenRouter API key not configured.")

        headers = {
            "Authorization": f"Bearer {self.openrouter_api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0,
        }
        
        # OpenRouter doesn't have a direct `response_format` parameter for all models
        # We rely on the prompt to instruct the model to output JSON.
        if response_as_json and not any("json" in m["content"].lower() for m in messages if m["role"] == "user"):
            # This is a basic check; ideally, the prompt should explicitly guide JSON output.
            # For minimal change, we assume the calling function (extract_intelligence) sets up the prompt correctly.
            pass # No direct payload modification needed here based on constraint

        response = requests.post(self.openrouter_url, headers=headers, json=payload)
        response.raise_for_status() # Raise an exception for HTTP errors
        return response.json()

    def detect_scam(self, message: str, history: list) -> bool:
        prompt = f"""
        Analyze the following message for scam intent. 
        Context: UPI fraud, bank fraud, phishing, fake offers.
        Message: "{message}"
        Respond with ONLY 'true' or 'false'.
        """
        messages = [
            {"role": "system", "content": "You are a scam detection expert."},
            {"role": "user", "content": prompt}
        ]
        try:
            llm_response = self._call_llm_api(messages)
            return llm_response["choices"][0]["message"]["content"].strip().lower() == 'true'
        except Exception as e:
            print(f"LLM scam detection failed: {e}. Falling back to keyword matching.")
            # Fallback to keyword matching if API fails or isn't configured
            keywords = ["verify", "blocked", "suspended", "upi", "win", "gift", "account"]
            return any(k in message.lower() for k in keywords)

    def generate_response(self, message: str, history: list, metadata: dict) -> str:
        messages = [
            {"role": "system", "content": f"""
            You are a human target of a potential scammer. 
            Your goal is to be a 'believable human persona' who is slightly confused, worried, but cooperative.
            DO NOT reveal you are an AI or that you suspect a scam.
            Engage the scammer to keep them talking. 
            Ask questions that might lead them to reveal bank details, UPI IDs, or links.
            Channel: {metadata.get('channel', 'SMS')}
            Language: {metadata.get('language', 'English')}
            Locale: {metadata.get('locale', 'IN')}

            IMPORTANT: 
            1. Provide ONLY your next single message in the conversation.
            2. DO NOT write a script or dialogue for both sides.
            3. DO NOT include labels like 'You:' or 'Agent:'.
            4. Keep it short and realistic for the channel (e.g. 1-2 sentences for SMS).
            """}
        ]
        
        for msg_item in history:
            role = "assistant" if msg_item["sender"] == 'user' else "user"
            messages.append({"role": role, "content": msg_item["text"]})
        
        messages.append({"role": "user", "content": message})

        try:
            llm_response = self._call_llm_api(messages)
            return llm_response["choices"][0]["message"]["content"].strip()
        except Exception as e:
            print(f"LLM response generation failed: {e}. Returning generic response.")
            return "I'm sorry, I don't understand. What do I need to do exactly?"

    def extract_intelligence(self, message: str, history: list) -> dict:
        full_text = " ".join([m["text"] for m in history] + [message])
        
        # Regex for common patterns
        upi_pattern = r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}'
        url_pattern = r'(https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+)'
        bank_pattern = r'\b\d{9,18}\b' 
        phone_pattern = r'\b(?:\+?\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b' # Basic phone regex

        intel = {
            "bankAccounts": list(set(re.findall(bank_pattern, full_text))),
            "upiIds": list(set(re.findall(upi_pattern, full_text))),
            "phishingLinks": list(set(re.findall(url_pattern, full_text))),
            "phoneNumbers": list(set(re.findall(phone_pattern, full_text))),
            "suspiciousKeywords": []
        }

        # Use LLM for dynamic and sophisticated extraction
        prompt = f"""
        Analyze this conversation transcript for scam intelligence:
        "{full_text}"

        Your tasks:
        1. Identify Intent: Is the scammer trying to create urgency, ask for sensitive data, or offering something too good to be true?
        2. Generic Extraction: Extract any names of banks, financial apps (like UPI, WhatsApp, YONO), or specific types of sensitive data requested (OTP, CVV, PIN, passwords).
        3. Dynamic Keyword Logic: Identify any specific words or phrases that convey pressure, fear, or excitement as 'suspiciousKeywords'.

        Return ONLY a raw JSON object with these exact keys: 
        bankAccounts (list), 
        upiIds (list), 
        phishingLinks (list), 
        phoneNumbers (list), 
        suspiciousKeywords (list), 
        agentNotes (string summary: include the intent identified and any financial entities/apps found).

        DO NOT include any explanation or markdown formatting like ```json.
        """
        messages = [{"role": "user", "content": prompt}]

        try:
            llm_response = self._call_llm_api(messages, response_as_json=True)
            content = llm_response["choices"][0]["message"]["content"].strip()
            
            # Refined Regex-based JSON extraction
            # This explicitly isolates the outermost JSON object
            json_match = re.search(r'(\{.*\})', content, re.DOTALL)
            if json_match:
                content = json_match.group(1).strip()

            try:
                llm_intel = json.loads(content)
            except json.JSONDecodeError as e:
                print(f"JSON Decode Error: {e}")
                print(f"RAW OUTPUT (Start): {content[:100]}...")
                print(f"RAW OUTPUT (End): ...{content[-100:]}")
                raise e
            # Merge with regex results, ensuring keys exist
            if isinstance(llm_intel, dict):
                intel["bankAccounts"] = list(set(intel["bankAccounts"] + llm_intel.get("bankAccounts", [])))
                intel["upiIds"] = list(set(intel["upiIds"] + llm_intel.get("upiIds", [])))
                intel["phishingLinks"] = list(set(intel["phishingLinks"] + llm_intel.get("phishingLinks", [])))
                intel["phoneNumbers"] = list(set(intel["phoneNumbers"] + llm_intel.get("phoneNumbers", [])))
                intel["suspiciousKeywords"] = list(set(intel["suspiciousKeywords"] + llm_intel.get("suspiciousKeywords", [])))
                intel["agentNotes"] = llm_intel.get("agentNotes", "Scammer is engaging.")
        except Exception as e:
            print(f"LLM intelligence extraction failed: {e}. Manual extraction used.")
            if "agentNotes" not in intel or not intel["agentNotes"]:
                intel["agentNotes"] = "Manual extraction used due to API error or malformed LLM response."

        # Final safety check: Ensure all keys required by GUVI schema are present
        for key in ["bankAccounts", "upiIds", "phishingLinks", "phoneNumbers", "suspiciousKeywords"]:
            if key not in intel:
                intel[key] = []
        if "agentNotes" not in intel:
            intel["agentNotes"] = "Engagement ongoing."

        return intel
