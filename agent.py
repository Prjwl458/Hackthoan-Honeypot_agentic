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


def pre_process_message(message: str) -> Optional[Dict[str, Any]]:
    """
    Pre-process message using regex patterns to detect safe/transactional messages.
    
    This whitelist approach avoids calling the LLM for known-safe patterns,
    saving latency and API costs.
    
    Args:
        message: The incoming message to analyze
    
    Returns:
        Dictionary with risk score and scam type if matched, None if no match
    
    Patterns:
        - OTP: 4-6 digit codes with verification keywords
        - Bank Update: Account balance notifications
    """
    message_lower = message.lower()
    
    # OTP Pattern: 4-6 digit code with keywords
    otp_pattern = r'\b\d{4,6}\b'
    otp_keywords = ['otp', 'verification', 'code', 'entered', 'submitted']
    if re.search(otp_pattern, message) and any(kw in message_lower for kw in otp_keywords):
        logger.info("WHITELIST MATCH: OTP pattern detected")
        return {
            "riskScore": 5,
            "scamType": "Safe/Transactional",
            "urgencyLevel": "Low",
            "agentNotes": "OTP/Verification code - Legitimate transactional message",
            "extractedEntities": [],
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": [],
            "phoneNumbers": [],
            "suspiciousKeywords": []
        }
    
    # Banking Pattern: Account balance updates
    bank_keywords = ['available', 'balance', 'credited', 'debited', 'a/c', 'account']
    if any(kw in message_lower for kw in bank_keywords) and ('rs.' in message_lower or '₹' in message):
        logger.info("WHITELIST MATCH: Banking pattern detected")
        return {
            "riskScore": 10,
            "scamType": "Bank Update",
            "urgencyLevel": "Low",
            "agentNotes": "Bank balance notification - Legitimate informational message",
            "extractedEntities": [],
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": [],
            "phoneNumbers": [],
            "suspiciousKeywords": []
        }
    
    return None  # No whitelist match - proceed to LLM analysis


def apply_evidence_guard(intel: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evidence Guard: Post-processing safety override.
    
    If the AI suggests high risk (>70) but there's NO physical evidence
    (links, UPI IDs, bank accounts), cap the risk score and adjust verdict.
    
    This prevents false positives from urgency language alone.
    
    Args:
        intel: Intelligence dictionary from LLM analysis (can be dict or Pydantic)
    
    Returns:
        Modified intelligence with evidence-based scoring
    """
    # Handle both dict and Pydantic object
    if hasattr(intel, 'get'):
        # It's a dict-like object
        phishing_links = intel.get("phishingLinks", [])
        upi_ids = intel.get("upiIds", [])
        bank_accounts = intel.get("bankAccounts", [])
        risk_score = intel.get("riskScore", 0)
        scam_type = intel.get("scamType", "")
        agent_notes = intel.get("agentNotes", "")
    else:
        # It's a Pydantic object or other
        phishing_links = getattr(intel, 'phishingLinks', [])
        upi_ids = getattr(intel, 'upiIds', [])
        bank_accounts = getattr(intel, 'bankAccounts', [])
        risk_score = getattr(intel, 'riskScore', 0)
        scam_type = getattr(intel, 'scamType', "")
        agent_notes = getattr(intel, 'agentNotes', "")
    
    # Check for physical evidence
    has_links = bool(phishing_links)
    has_upi = bool(upi_ids)
    has_bank = bool(bank_accounts)
    has_evidence = has_links or has_upi or has_bank
    
    current_score = risk_score
    logger.info(f"EVIDENCE CHECK: score={current_score}, has_links={has_links}, has_upi={has_upi}, has_bank={has_bank}")
    
    # If high risk but NO evidence, apply cap
    if current_score > 70 and not has_evidence:
        logger.info(f"EVIDENCE GUARD TRIGGERED: High risk ({current_score}) but no physical evidence found - capping score")
        # Update the intel object
        if hasattr(intel, '__setitem__'):
            intel["riskScore"] = 40
            intel["scamType"] = "Unverified/Suspicious"
            intel["agentNotes"] = f"{agent_notes} [Evidence Guard: Risk capped due to lack of physical artifacts]"
        else:
            intel.riskScore = 40
            intel.scamType = "Unverified/Suspicious"
            intel.agentNotes = f"{agent_notes} [Evidence Guard: Risk capped due to lack of physical artifacts]"
    
    return intel


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
        You are an OBJECTIVE SECURITY ANALYST. Your goal is evidence-based analysis,
        NOT assuming malicious intent.
        
        OBJECTIVE RULES:
        - Urgency WITHOUT physical evidence (links, UPI, bank accounts) = NEUTRAL/Informational
        - Only label as 'true' (scam) if there are PHYSICAL ARTIFACTS:
          * Phishing links/URLs
          * UPI payment addresses (xxx@upi)
          * Requests for sensitive data: OTP, CVV, passwords, PINs
        - Transaction alerts (balance updates, OTPs you didn't request) = NEUTRAL
        - Generic urgency without evidence = NEUTRAL
        
        Message: "{message}"
        
        Respond with ONLY 'true' (scam) or 'false' (not scam).
        """
        
        messages = [
            {"role": "system", "content": "You are an objective security analyst. Only flag as scam when physical evidence exists."},
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
        The risk scoring system analyzes multiple factors:
        
        RISK SCORING LOGIC (0-100 scale):
        --------------------------------
        - Base Score: Starts at 0
        - Urgency Language: +20-30 for words like 'urgent', 'immediately', 'limited time'
        - Financial Requests: +25 for OTP, CVV, password, bank details
        - Phishing Indicators: +30 for suspicious links
        - Sender Mismatch: +15-20 if sender claims bank/institution but is personal number
        
        SCAM TYPE CLASSIFICATION:
        - Phishing: Fake login pages, account suspension claims
        - Lottery: Fake prize claims, winning notifications
        - Tech Support: Fake helpdesk, virus warnings
        - Investment: Get-rich-quick schemes
        - Romance: Long-game trust building
        
        Args:
            message: Current message to analyze
            history: Previous messages in conversation
            sender_id: Sender's phone number (optional, for verification)
            
        Returns:
            Dictionary containing:
                - bankAccounts: Extracted bank account numbers
                - upiIds: UPI payment addresses
                - phishingLinks: Suspicious URLs
                - phoneNumbers: Contact numbers mentioned
                - suspiciousKeywords: Red flag words
                - agentNotes: Human-readable summary
                - scamType: Classification (Phishing/Lottery/etc)
                - urgencyLevel: Low/Medium/High
                - riskScore: 0-100 danger rating
                - extractedEntities: Combined list of all entities
        """
        # =====================================================================
        # STEP 1: PRE-PROCESSING (Whitelist) - Skip LLM for known-safe patterns
        # =====================================================================
        whitelist_result = pre_process_message(message)
        if whitelist_result:
            logger.info(f"Whitelist match: {whitelist_result['scamType']} - skipping LLM")
            return whitelist_result
        
        # =====================================================================
        # STEP 2: LLM Analysis (only if no whitelist match)
        # =====================================================================
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
        You are an OBJECTIVE SECURITY ANALYST. Your goal is evidence-based analysis.
        
        OBJECTIVE ANALYSIS RULES:
        - Urgency WITHOUT physical evidence (links, UPI IDs, bank accounts) = Informational/Neutral
        - Transaction alerts (balance updates, OTPs you didn't request) = Informational
        - Generic warnings without actionable links = Informational
        - Only HIGH risk if there are PHYSICAL ARTIFACTS: phishing links, UPI payment requests, PII theft attempts
        
        Analyze this message: "{full_text}"
        {sender_check}
        
        Your tasks:
        1. Extract entities: UPI IDs, phone numbers, links, bank accounts
        2. Identify request type: informational, transactional, or malicious
        3. Classify: Safe/Transactional, Bank Update, Phishing, Lottery, Tech Support, Investment, Romance, Other
        4. Assess Urgency: Low (informational), Medium (needs attention), High (immediate action required)
        5. Risk Score:
           - 1-20: Safe/Transactional (bank alerts, OTPs you expect)
           - 21-40: Low Risk (promotional content)
           - 41-60: Medium Risk (urgency but no payment links)
           - 61-80: High Risk (payment links, PII requests)
           - 81-100: Critical (active fraud in progress)
        
        Return ONLY a raw JSON object with these exact keys: 
        bankAccounts, upiIds, phishingLinks, phoneNumbers, suspiciousKeywords,
        agentNotes, scamType, urgencyLevel, riskScore, extractedEntities
        
        DO NOT include any explanation or markdown formatting.
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
        
        # Add threatSource if sender_id provided
        if sender_id:
            intel["threatSource"] = sender_id
        else:
            intel["threatSource"] = ""
        
        # =====================================================================
        # STEP 3: EVIDENCE GUARD - Post-processing safety override
        # =====================================================================
        intel = apply_evidence_guard(intel)
        
        return intel
