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
        Generate a short professional Summary Verdict for the scanner app.
        
        Args:
            message: The incoming message to analyze
            history: Conversation history
            metadata: Channel and language metadata
            
        Returns:
            Short professional verdict string (e.g., 'Phishing attempt targeting HDFC users via UPI')
        """
        # Build context from history
        all_messages = [msg.get("text", "") for msg in history] + [message]
        full_text = " ".join(all_messages)
        
        llm_prompt = f"""
        You are a Professional Security Analyst.
        Analyze this message and provide a Summary Verdict (MAX 15 WORDS).
        
        Message: "{full_text}"
        
        Rules:
        1. STRICTLY MAX 15 WORDS
        2. Format: "[Threat Type] - [Target/Description]"
        3. Examples:
           - "Phishing - HDFC account compromise attempt via OTP"
           - "Lottery scam - fake prize claim requesting bank details"
           - "Tech support - false account suspension warning"
           - "Safe - No malicious content detected"
           - "Neutral - Analysis inconclusive"
        4. NO conversational filler (no 'Hello', no 'I think', no 'In my opinion')
        5. Be direct and professional
        
        Return ONLY the summary verdict. No explanation.
        """
        
        messages = [{"role": "user", "content": llm_prompt}]
        
        try:
            llm_response = await self._call_llm_api(messages)
            return llm_response["choices"][0]["message"]["content"].strip()
        except Exception as e:
            logger.warning(f"LLM verdict generation failed: {e}. Returning default.")
            return "Neutral - Analysis inconclusive due to system error"
    
    async def extract_intelligence(
        self,
        message: str,
        history: List[Dict[str, Any]],
        sender_id: str = None
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
            "agentNotes": "",
            # New enhanced fields
            "scamType": "",
            "urgencyLevel": "",
            "extractedEntities": [],
            "riskScore": 0
        }
        
        # LLM-based extraction for sophisticated analysis
        # Check sender mismatch if sender_id provided
        sender_check = f"""
        Sender Phone/ID: {sender_id}
        """ if sender_id else ""
        
        llm_prompt = f"""
        Analyze this conversation transcript for scam intelligence:
        "{full_text}"
        {sender_check}
        
        Your tasks:
        1. Identify Intent: Is the scammer trying to create urgency, ask for sensitive data, or offering something too good to be true?
        2. Generic Extraction: Extract any names of banks, financial apps (like UPI, WhatsApp, YONO), or specific types of sensitive data requested (OTP, CVV, PIN, passwords).
        3. Dynamic Keyword Logic: Identify any specific words or phrases that convey pressure, fear, or excitement as 'suspiciousKeywords'.
        4. Classify Scam Type: Choose ONE from: Phishing, Lottery, Tech Support, Investment, Romance, Other
        5. Assess Urgency: Rate as Low, Medium, or High based on time pressure words
        6. Calculate Risk Score: Rate 1-100 based on danger level (higher = more dangerous)
        7. SENDER VERIFICATION (IMPORTANT): If sender_id is provided, check if it matches the content:
           - If message mentions "Bank" but sender is personal number (not official bank shortcode), ADD 20 to riskScore
           - If message claims to be from "HDFC/ICICI/SBI" but sender is regular number, ADD 20 to riskScore
           - If sender looks like personal phone (+91xxx) but claims institutional affiliation, ADD 15 to riskScore
           - Note this in agentNotes

        Return ONLY a raw JSON object with these exact keys: 
        bankAccounts (list), 
        upiIds (list), 
        phishingLinks (list), 
        phoneNumbers (list), 
        suspiciousKeywords (list), 
        agentNotes (string summary: include the intent identified and any financial entities/apps found),
        scamType (string: Phishing/Lottery/Tech Support/Investment/Romance/Other),
        urgencyLevel (string: Low/Medium/High),
        riskScore (integer: 1-100),
        extractedEntities (list: combine all UPI IDs, phone numbers, and links found)

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
                    
                    # New enhanced fields from LLM
                    if llm_intel.get("scamType"):
                        intel["scamType"] = llm_intel["scamType"]
                    if llm_intel.get("urgencyLevel"):
                        intel["urgencyLevel"] = llm_intel["urgencyLevel"]
                    if llm_intel.get("riskScore"):
                        intel["riskScore"] = int(llm_intel["riskScore"])
                    if llm_intel.get("extractedEntities"):
                        intel["extractedEntities"] = llm_intel["extractedEntities"]
                        
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
        
        # Set defaults for new enhanced fields
        if not intel.get("scamType"):
            intel["scamType"] = "Unknown"
        if not intel.get("urgencyLevel"):
            intel["urgencyLevel"] = "Low"
        if not intel.get("riskScore"):
            intel["riskScore"] = 10  # Default low risk
        if not intel.get("extractedEntities"):
            # Combine all entities from regex
            entities = []
            entities.extend(intel.get("upiIds", []))
            entities.extend(intel.get("phoneNumbers", []))
            entities.extend(intel.get("phishingLinks", []))
            intel["extractedEntities"] = list(set(entities))
        
        return intel
