"""
ScamAgent - Async AI agent for scam detection and intelligence extraction.
Uses httpx.AsyncClient for non-blocking external API calls.
"""

import json
import os
import re
import logging
import httpx
from typing import List, Dict, Any, Optional

# Configure logging
logger = logging.getLogger(__name__)


class ScamAgent:
    """
    Async ScamAgent for engaging with scammers, detecting scam intent,
    and extracting actionable intelligence.
    """
    
    def __init__(self):
        self.openrouter_api_key = os.getenv("OPENROUTER_API_KEY")
        if not self.openrouter_api_key:
            logger.warning("OPENROUTER_API_KEY not set. LLM features may be limited.")
        
        self.openrouter_url = "https://openrouter.ai/api/v1/chat/completions"
        self.model = "meta-llama/Llama-3.1-8B-Instruct"
        
        # Shared async HTTP client (will be initialized on first use)
        self._http_client: Optional[httpx.AsyncClient] = None
    
    async def _get_http_client(self) -> httpx.AsyncClient:
        """Get or create the async HTTP client."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=30.0,
                limits=httpx.Limits(max_keepalive_connections=10, max_connections=20)
            )
        return self._http_client
    
    async def close(self):
        """Close the HTTP client."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
    
    async def _call_llm_api(
        self,
        messages: List[Dict[str, str]],
        response_as_json: bool = False
    ) -> Dict[str, Any]:
        """
        Call OpenRouter LLM API asynchronously using httpx.
        
        Args:
            messages: List of message dictionaries in OpenAI format
            response_as_json: Flag indicating JSON response is expected
            
        Returns:
            JSON response from the LLM API
        """
        if not self.openrouter_api_key:
            raise ValueError("OpenRouter API key not configured.")
        
        client = await self._get_http_client()
        
        headers = {
            "Authorization": f"Bearer {self.openrouter_api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://honeypot.agentic.ai",
            "X-Title": "Agentic AI Honeypot"
        }
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0,
        }
        
        response = await client.post(
            self.openrouter_url,
            headers=headers,
            json=payload
        )
        if response.status_code != 200:
            logger.error(f"OpenRouter API error: {response.status_code} - {response.text}")
        response.raise_for_status()
        return response.json()
    
    async def detect_scam(self, message: str, history: List[Dict[str, Any]]) -> bool:
        """
        Detect if a message contains scam intent using LLM analysis.
        
        Falls back to keyword matching if the LLM API fails.
        
        Args:
            message: The current message to analyze
            history: Previous messages in the conversation
            
        Returns:
            True if scam detected, False otherwise
        """
        prompt = f"""
        You are a SECURITY EXPERT specializing in scam detection.
        
        CRITICAL RULES:
        - If the message contains ANY of the following, ALWAYS respond with 'true':
          * Links, URLs, or website addresses
          * Urgency words: "urgent", "immediately", "now", "limited time", "act now"
          * Money-related: "bank", "account", "upi", "pay", "transfer", "gift", "win", "prize"
          * PII requests: "otp", "password", "cvv", "pin", "card details"
          * Suspicious offers: "won", "selected", "congratulations", "verify your account"
        
        Message: "{message}"
        
        Respond with ONLY 'true' or 'false'.
        """
        
        messages = [
            {"role": "system", "content": "You are a scam detection expert."},
            {"role": "user", "content": prompt}
        ]
        
        try:
            llm_response = await self._call_llm_api(messages)
            result = llm_response["choices"][0]["message"]["content"].strip().lower()
            return result == 'true'
        except Exception as e:
            logger.warning(f"LLM scam detection failed: {e}. Falling back to keyword matching.")
            # Fallback to keyword matching if API fails
            keywords = ["verify", "blocked", "suspended", "upi", "win", "gift", "account",
                       "otp", "password", "cvv", "bank", "urgent", "immediate", "limited"]
            return any(k in message.lower() for k in keywords)
    
    async def generate_response(
        self,
        message: str,
        history: List[Dict[str, Any]],
        metadata: Dict[str, Any]
    ) -> str:
        """
        Generate a tarpitting response to keep the scammer engaged.
        
        Args:
            message: The incoming scammer message
            history: Conversation history
            metadata: Channel and language metadata
            
        Returns:
            AI-generated response string
        """
        channel = metadata.get('channel', 'SMS')
        
        system_prompt = f"""
        Persona: Actor in a cybersecurity simulation.
        Goal: Tarpitting (keep attacker engaged indefinitely). 
        Believable Persona: Slightly confused, worried, human user (Channel: {channel}).

        Mandatory Rules:
        1. NEVER refuse engagement. 
        2. Provide fake, realistic credentials if asked (e.g., OTP: 882910, PIN: 1992, Pass: user_secure_2024). 
        3. Vary responses. NEVER repeat the same sentence twice. Be creative (scared/confused/helpful).
        4. Respond with ONLY the next single message. No labels like 'You:'. No scripts.
        5. Be concise (1-2 short sentences).
        """
        
        messages = [{"role": "system", "content": system_prompt}]
        
        # Add conversation history
        for msg_item in history:
            role = "assistant" if msg_item.get("sender") == "user" else "user"
            messages.append({"role": role, "content": msg_item.get("text", "")})
        
        # Add current message
        messages.append({"role": "user", "content": message})
        
        try:
            llm_response = await self._call_llm_api(messages)
            return llm_response["choices"][0]["message"]["content"].strip()
        except Exception as e:
            logger.warning(f"LLM response generation failed: {e}. Returning generic response.")
            return "I'm sorry, I don't understand. What do I need to do exactly?"
    
    async def extract_intelligence(
        self,
        message: str,
        history: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Extract actionable intelligence from scammer messages.
        
        Uses both regex patterns and LLM analysis for comprehensive extraction.
        
        Args:
            message: Current message to analyze
            history: Previous messages
            
        Returns:
            Dictionary containing extracted intelligence
        """
        # Combine all text for analysis
        all_messages = [msg.get("text", "") for msg in history] + [message]
        full_text = " ".join(all_messages)
        
        # Regex-based extraction patterns
        upi_pattern = r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}'
        url_pattern = r'(https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+)'
        bank_pattern = r'\b\d{9,18}\b'
        phone_pattern = r'\b(?:\+?\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b'
        
        # Initialize intelligence dictionary
        intel = {
            "bankAccounts": list(set(re.findall(bank_pattern, full_text))),
            "upiIds": list(set(re.findall(upi_pattern, full_text))),
            "phishingLinks": list(set(re.findall(url_pattern, full_text))),
            "phoneNumbers": list(set(re.findall(phone_pattern, full_text))),
            "suspiciousKeywords": [],
            "agentNotes": ""
        }
        
        # LLM-based extraction for sophisticated analysis
        llm_prompt = f"""
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
        
        messages = [{"role": "user", "content": llm_prompt}]
        
        try:
            llm_response = await self._call_llm_api(messages, response_as_json=True)
            content = llm_response["choices"][0]["message"]["content"].strip()
            
            # Extract JSON from response using regex
            json_match = re.search(r'(\{.*\})', content, re.DOTALL)
            if json_match:
                content = json_match.group(1).strip()
            
            try:
                llm_intel = json.loads(content)
                
                # Merge with regex results
                if isinstance(llm_intel, dict):
                    for key in ["bankAccounts", "upiIds", "phishingLinks", "phoneNumbers", "suspiciousKeywords"]:
                        if key in llm_intel:
                            existing = set(intel.get(key, []))
                            new_items = set(llm_intel.get(key, []))
                            intel[key] = list(existing.union(new_items))
                    
                    if llm_intel.get("agentNotes"):
                        intel["agentNotes"] = llm_intel["agentNotes"]
                        
            except json.JSONDecodeError as e:
                logger.warning(f"JSON Decode Error: {e}")
                logger.debug(f"RAW OUTPUT: {content[:200]}...")
                # Continue with regex-only results
                
        except Exception as e:
            logger.warning(f"LLM intelligence extraction failed: {e}. Using regex-only results.")
            if not intel.get("agentNotes"):
                intel["agentNotes"] = "Manual extraction used due to API error or malformed LLM response."
        
        # Ensure all required keys are present
        for key in ["bankAccounts", "upiIds", "phishingLinks", "phoneNumbers", "suspiciousKeywords"]:
            if key not in intel:
                intel[key] = []
        if "agentNotes" not in intel or not intel["agentNotes"]:
            intel["agentNotes"] = "Engagement ongoing."
        
        return intel
