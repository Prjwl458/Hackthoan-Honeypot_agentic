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
        bank_pattern = r'\b\d{9,18}\b' # Simple bank account digit pattern

        intel = {
            "bankAccounts": list(set(re.findall(bank_pattern, full_text))),
            "upiIds": list(set(re.findall(upi_pattern, full_text))),
            "phishingLinks": list(set(re.findall(url_pattern, full_text)))
        }

        # Use LLM for more sophisticated extraction
        prompt = f"""
        Extract scam intelligence from this conversation:
        "{full_text}"
        Return ONLY a raw JSON object with these exact keys: bankAccounts (list), upiIds (list), phishingLinks (list), agentNotes (string summary of tactics).
        DO NOT include any explanation or markdown formatting like ```json.
        """
        messages = [{"role": "user", "content": prompt}]

        try:
            llm_response = self._call_llm_api(messages, response_as_json=True)
            # OpenRouter models often return JSON as a string.
            content = llm_response["choices"][0]["message"]["content"].strip()
            
            # Basic cleanup in case the model ignored "no markdown" instruction
            if content.startswith("```"):
                content = content.split("\n", 1)[-1]
            if content.endswith("```"):
                content = content.rsplit("\n", 1)[0]
            content = content.strip()
            if content.startswith("json"):
                content = content[4:].strip()

            llm_intel = json.loads(content)
            # Merge with regex results, ensuring keys exist
            if isinstance(llm_intel, dict):
                intel["bankAccounts"] = list(set(intel["bankAccounts"] + llm_intel.get("bankAccounts", [])))
                intel["upiIds"] = list(set(intel["upiIds"] + llm_intel.get("upiIds", [])))
                intel["phishingLinks"] = list(set(intel["phishingLinks"] + llm_intel.get("phishingLinks", [])))
                intel["agentNotes"] = llm_intel.get("agentNotes", "Scammer is engaging.")
        except Exception as e:
            print(f"LLM intelligence extraction failed: {e}. Manual extraction used.")
            if "agentNotes" not in intel or not intel["agentNotes"]:
                intel["agentNotes"] = "Manual extraction used due to API error or malformed LLM response."

        # Final safety check: Ensure all keys required by ScamResponse schema are present
        for key in ["bankAccounts", "upiIds", "phishingLinks"]:
            if key not in intel:
                intel[key] = []
        if "agentNotes" not in intel:
            intel["agentNotes"] = "Engagement ongoing."

        return intel
