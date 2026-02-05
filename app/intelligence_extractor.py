"""
INTELLIGENCE EXTRACTOR - Light and Heavy extraction system
REFACTORED to fix Problem #1 and #7

KEY CHANGES:
- Split into LIGHT extraction (every turn) and HEAVY extraction (THREAT+ stages)
- Light: keywords, intent hints
- Heavy: UPI IDs, bank accounts, URLs, phone numbers
- Deterministic regex-based extraction
- Track source turn and confidence
"""

import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from .models import ExtractedIntelligence
from .risk_engine import ScamStage


@dataclass
class ExtractionItem:
    """Tracked intelligence extraction with metadata"""
    value: str
    item_type: str  # upi, bank_account, phone, url, keyword, etc.
    confidence: float
    source_turn: int
    context: str
    timestamp: datetime = field(default_factory=datetime.now)


class IntelligenceExtractor:
    """
    Production-grade intelligence extraction for Indian scams.
    
    SPLIT EXTRACTION (Problem #7):
    1. LIGHT extraction - runs every turn (keywords, intent hints)
    2. HEAVY extraction - runs at THREAT+ stages (UPI, bank, phone, URL)
    """
    
    def __init__(self):
        self._init_patterns()
        self._init_keyword_patterns()
        self.extraction_history: Dict[str, List[ExtractionItem]] = {}
        self.turn_counter: Dict[str, int] = {}
    
    def _init_patterns(self):
        """Initialize regex patterns for HEAVY extraction"""
        
        # UPI IDs (all major providers)
        self.patterns = {
            "upi": re.compile(
                r'[a-zA-Z0-9._-]{2,256}@(?:upi|paytm|okaxis|okicici|okhdfcbank|oksbi|ybl|apl|ibl|axl|'
                r'kotak|icici|sbi|hdfc|axis|idfcfirst|indus|federal|rbl|yes|pnb|boi|bob|canara|'
                r'union|idbi|citi|hsbc|sc|dbs|ubi|equitas|bandhan|au|fino|payzapp|airtel|jio|'
                r'waicici|wahdfcbank|wasbi|waaxis|freecharge|mobikwik|amazonpay|phonepe|gpay)',
                re.IGNORECASE
            ),
            
            # Bank account numbers (9-18 digits)
            "bank_account": re.compile(r'\b\d{9,18}\b'),
            
            # IFSC codes
            "ifsc": re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b', re.IGNORECASE),
            
            # Indian phone numbers
            "phone_indian": re.compile(
                r'(?:\+91[\s.-]?)?(?:0)?[6-9]\d{9}|'
                r'\+91\s?\d{5}\s?\d{5}|'
                r'[6-9]\d{2}[\s.-]?\d{3}[\s.-]?\d{4}'
            ),
            
            # URLs
            "url": re.compile(
                r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b'
                r'(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)',
                re.IGNORECASE
            ),
            
            # Shortened URLs (highly suspicious)
            "short_url": re.compile(
                r'(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|'
                r'adf\.ly|j\.mp|tiny\.cc|cutt\.ly|rb\.gy|shorte\.st|shorturl\.at|'
                r'v\.gd|tr\.im|clck\.ru|bc\.vc|ouo\.io)/[\w\-]+',
                re.IGNORECASE
            ),
            
            # Telegram handles
            "telegram": re.compile(r'(?:t\.me/|telegram\.me/|@)([a-zA-Z][a-zA-Z0-9_]{4,31})', re.IGNORECASE),
            
            # WhatsApp links
            "whatsapp": re.compile(r'(?:wa\.me/|whatsapp\.com/send\?phone=)(\+?\d{10,15})', re.IGNORECASE),
            
            # Remote access app mentions
            "remote_apps": re.compile(
                r'\b(?:anydesk|teamviewer|quicksupport|ammyy|ultraviewer|'
                r'airdroid|screenconnect|supremo|rustdesk)\b',
                re.IGNORECASE
            ),
            
            # QR code mentions
            "qr_code": re.compile(
                r'\b(?:qr\s*code|scan\s*(?:this|the)?\s*qr|qr\s*scan)\b',
                re.IGNORECASE
            ),
        }
    
    def _init_keyword_patterns(self):
        """Initialize keyword patterns for LIGHT extraction"""
        
        self.keyword_patterns = {
            "urgency": re.compile(
                r'\b(?:urgent|immediately|right now|asap|quick|hurry|'
                r'within \d+ (?:hours?|minutes?)|deadline|expires? today|'
                r'last (?:chance|warning)|final notice|time sensitive)\b',
                re.IGNORECASE
            ),
            "threat": re.compile(
                r'\b(?:block(?:ed)?|suspend(?:ed)?|freez(?:e|ing)|terminat(?:e|ed)|'
                r'seiz(?:e|ed)|compromised|hack(?:ed)?|unauthori[sz]ed|'
                r'fraud(?:ulent)?|illegal|criminal|arrest|jail|'
                r'penalty|fine|legal action|court|police|warrant)\b',
                re.IGNORECASE
            ),
            "authority": re.compile(
                r'\b(?:rbi|reserve bank|income tax|it department|customs|'
                r'cyber (?:cell|crime|police)|cbi|ed|enforcement|sebi|'
                r'government|official|authorized|verified|certified|'
                r'bank manager|customer (?:care|support)|security team|'
                r'fraud department|investigation|ministry|trai)\b',
                re.IGNORECASE
            ),
            "financial": re.compile(
                r'\b(?:otp|one.?time.?password|verification code|pin|cvv|'
                r'card number|account (?:number|details)|bank details|'
                r'transfer|send money|pay(?:ment)?|refund|cashback|'
                r'prize|lottery|winner|claim|reward|bonus|'
                r'processing fee|advance|deposit|emi|loan)\b',
                re.IGNORECASE
            ),
            "personal_info": re.compile(
                r'\b(?:aadhaar|aadhar|pan (?:card|number)?|passport|'
                r'date of birth|dob|mother\'?s? (?:maiden )?name|'
                r'security question|password|login|credentials|kyc)\b',
                re.IGNORECASE
            ),
            "phishing": re.compile(
                r'\b(?:click (?:here|this|the link)|visit (?:this )?link|'
                r'download (?:this )?app|install|update (?:app|details)|'
                r'verify (?:account|identity)|fill (?:this )?form|'
                r'remote access|screen share)\b',
                re.IGNORECASE
            ),
        }
        
        # Scam type signatures for classification
        self.scam_signatures = {
            "bank_kyc": ["kyc", "account block", "verify", "bank", "update details"],
            "otp_fraud": ["otp", "verification code", "share otp", "enter otp"],
            "upi_fraud": ["upi", "collect request", "qr code", "scan", "payment"],
            "loan_scam": ["loan", "pre-approved", "instant", "low interest", "emi"],
            "refund_scam": ["refund", "cashback", "excess payment", "return"],
            "police_impersonation": ["police", "cyber cell", "arrest", "warrant", "case"],
            "job_scam": ["work from home", "part time", "data entry", "easy money"],
            "delivery_scam": ["delivery", "package", "customs", "parcel", "stuck"],
        }
    
    def extract_light(
        self, 
        text: str, 
        session_id: str,
        turn_number: int
    ) -> Tuple[List[str], List[str]]:
        """
        LIGHT EXTRACTION - Runs every turn.
        Returns: (keywords, intent_hints)
        
        Fast extraction of:
        - Suspicious keywords by category
        - Intent hints (what scammer might be trying to do)
        """
        keywords = []
        intent_hints = []
        text_lower = text.lower()
        
        # Extract keywords by category
        for category, pattern in self.keyword_patterns.items():
            matches = pattern.findall(text)
            for match in matches:
                keyword = match.lower().strip()
                if keyword and keyword not in keywords:
                    keywords.append(keyword)
                    
                    # Generate intent hints
                    if category == "urgency":
                        intent_hints.append("creating_urgency")
                    elif category == "threat":
                        intent_hints.append("threatening_victim")
                    elif category == "authority":
                        intent_hints.append("impersonating_authority")
                    elif category == "financial":
                        intent_hints.append("requesting_financial_info")
                    elif category == "personal_info":
                        intent_hints.append("requesting_personal_info")
                    elif category == "phishing":
                        intent_hints.append("phishing_attempt")
        
        # Detect scam type
        for scam_type, indicators in self.scam_signatures.items():
            if any(ind in text_lower for ind in indicators):
                intent_hints.append(f"scam_type:{scam_type}")
                break
        
        return keywords, list(set(intent_hints))
    
    def extract_heavy(
        self, 
        text: str, 
        current_intelligence: ExtractedIntelligence,
        session_id: str,
        turn_number: int
    ) -> ExtractedIntelligence:
        """
        HEAVY EXTRACTION - Runs at THREAT+ stages only.
        Returns: Updated ExtractedIntelligence
        
        Comprehensive extraction of:
        - UPI IDs
        - Bank accounts
        - Phone numbers
        - URLs/links
        - Telegram/WhatsApp handles
        """
        # Initialize extraction history
        if session_id not in self.extraction_history:
            self.extraction_history[session_id] = []
        
        # Extract UPI IDs
        self._extract_upi_ids(text, current_intelligence, turn_number, session_id)
        
        # Extract bank accounts
        self._extract_bank_accounts(text, current_intelligence, turn_number, session_id)
        
        # Extract phone numbers
        self._extract_phone_numbers(text, current_intelligence, turn_number, session_id)
        
        # Extract URLs
        self._extract_urls(text, current_intelligence, turn_number, session_id)
        
        # Extract additional intel (telegram, remote apps, etc.)
        self._extract_additional_intel(text, current_intelligence, turn_number, session_id)
        
        return current_intelligence
    
    def extract(
        self, 
        text: str, 
        current_intelligence: ExtractedIntelligence, 
        session_id: str,
        scam_stage: ScamStage = ScamStage.NORMAL
    ) -> ExtractedIntelligence:
        """
        Main extraction method - decides light vs heavy based on stage.
        
        EXTRACTION STRATEGY (Problem #7):
        - NORMAL, HOOK: Light extraction only (keywords)
        - TRUST+: Heavy extraction (full intel)
        """
        # Track turn
        if session_id not in self.turn_counter:
            self.turn_counter[session_id] = 0
        self.turn_counter[session_id] += 1
        turn = self.turn_counter[session_id]
        
        # LIGHT extraction - always runs
        keywords, intent_hints = self.extract_light(text, session_id, turn)
        
        # Add keywords to intelligence
        for kw in keywords:
            if kw not in current_intelligence.suspiciousKeywords:
                current_intelligence.suspiciousKeywords.append(kw)
        
        # HEAVY extraction - only at THREAT+ stages
        # This ensures extraction happens AFTER we have enough context
        if scam_stage in [ScamStage.TRUST, ScamStage.THREAT, ScamStage.ACTION, ScamStage.CONFIRMED]:
            current_intelligence = self.extract_heavy(
                text, current_intelligence, session_id, turn
            )
        
        return current_intelligence
    
    def _extract_upi_ids(
        self, 
        text: str, 
        intel: ExtractedIntelligence, 
        turn: int, 
        session_id: str
    ):
        """Extract UPI IDs with validation"""
        matches = self.patterns["upi"].findall(text)
        for upi in matches:
            upi = upi.strip().lower()
            if upi and upi not in intel.upiIds and '@' in upi and len(upi) >= 5:
                intel.upiIds.append(upi)
                self._record_extraction(session_id, upi, "upi", 0.9, turn, text[:50])
    
    def _extract_bank_accounts(
        self, 
        text: str, 
        intel: ExtractedIntelligence, 
        turn: int, 
        session_id: str
    ):
        """Extract bank account numbers with context validation"""
        matches = self.patterns["bank_account"].findall(text)
        
        # Context keywords that indicate a bank account
        account_context = ["account", "a/c", "acc", "transfer", "bank", "ifsc", "beneficiary"]
        text_lower = text.lower()
        has_context = any(ctx in text_lower for ctx in account_context)
        
        for acc in matches:
            # Skip if looks like phone number (starts with 6-9 and is 10 digits)
            if len(acc) == 10 and acc[0] in '6789':
                continue
            # Only accept with context or if very long (likely account number)
            if (has_context or len(acc) >= 11) and acc not in intel.bankAccounts:
                intel.bankAccounts.append(acc)
                self._record_extraction(session_id, acc, "bank_account", 0.85, turn, text[:50])
        
        # Extract IFSC codes
        ifsc_matches = self.patterns["ifsc"].findall(text)
        for ifsc in ifsc_matches:
            ifsc = ifsc.upper()
            ifsc_entry = f"IFSC:{ifsc}"
            if ifsc_entry not in intel.bankAccounts:
                intel.bankAccounts.append(ifsc_entry)
                self._record_extraction(session_id, ifsc, "ifsc", 0.95, turn, text[:50])
    
    def _extract_phone_numbers(
        self, 
        text: str, 
        intel: ExtractedIntelligence, 
        turn: int, 
        session_id: str
    ):
        """Extract phone numbers (Indian format)"""
        matches = self.patterns["phone_indian"].findall(text)
        for phone in matches:
            phone = re.sub(r'[\s.-]', '', phone)
            # Normalize to 10 digits
            if phone.startswith('+91'):
                phone = phone[3:]
            elif phone.startswith('91') and len(phone) == 12:
                phone = phone[2:]
            elif phone.startswith('0'):
                phone = phone[1:]
            
            if len(phone) == 10 and phone not in intel.phoneNumbers:
                intel.phoneNumbers.append(phone)
                self._record_extraction(session_id, phone, "phone", 0.9, turn, text[:50])
    
    def _extract_urls(
        self, 
        text: str, 
        intel: ExtractedIntelligence, 
        turn: int, 
        session_id: str
    ):
        """Extract URLs with suspicion scoring"""
        # Regular URLs
        url_matches = self.patterns["url"].findall(text)
        for url in url_matches:
            if url and url not in intel.phishingLinks:
                # Skip trusted domains
                trusted = ["google.com", "facebook.com", "amazon.in", "flipkart.com", 
                          "paytm.com", "sbi.co.in", "hdfcbank.com"]
                if not any(t in url.lower() for t in trusted):
                    intel.phishingLinks.append(url)
                    self._record_extraction(session_id, url, "url", 0.8, turn, text[:50])
        
        # Shortened URLs (always suspicious)
        short_matches = self.patterns["short_url"].findall(text)
        for short_url in short_matches:
            full_url = f"https://{short_url}" if not short_url.startswith("http") else short_url
            if full_url not in intel.phishingLinks:
                intel.phishingLinks.append(full_url)
                self._record_extraction(session_id, full_url, "short_url", 0.95, turn, text[:50])
    
    def _extract_additional_intel(
        self, 
        text: str, 
        intel: ExtractedIntelligence, 
        turn: int, 
        session_id: str
    ):
        """Extract additional intelligence (telegram, remote apps, etc.)"""
        
        # Telegram handles
        telegram_matches = self.patterns["telegram"].findall(text)
        for handle in telegram_matches:
            handle = f"@{handle}" if not handle.startswith("@") else handle
            entry = f"telegram:{handle}"
            if entry not in intel.suspiciousKeywords:
                intel.suspiciousKeywords.append(entry)
                self._record_extraction(session_id, handle, "telegram", 0.85, turn, text[:50])
        
        # WhatsApp numbers
        whatsapp_matches = self.patterns["whatsapp"].findall(text)
        for num in whatsapp_matches:
            if num not in intel.phoneNumbers:
                intel.phoneNumbers.append(num)
                self._record_extraction(session_id, num, "whatsapp", 0.9, turn, text[:50])
        
        # Remote access app mentions (HIGH PRIORITY)
        remote_matches = self.patterns["remote_apps"].findall(text)
        for app in remote_matches:
            entry = f"remote_app:{app.lower()}"
            if entry not in intel.suspiciousKeywords:
                intel.suspiciousKeywords.append(entry)
                self._record_extraction(session_id, app, "remote_app", 0.95, turn, text[:50])
        
        # QR code mentions (HIGH PRIORITY for UPI scams)
        if self.patterns["qr_code"].search(text):
            if "qr_code_mentioned" not in intel.suspiciousKeywords:
                intel.suspiciousKeywords.append("qr_code_mentioned")
                self._record_extraction(session_id, "qr_code", "indicator", 0.9, turn, text[:50])
    
    def _record_extraction(
        self, 
        session_id: str, 
        value: str, 
        item_type: str, 
        confidence: float, 
        turn: int, 
        context: str
    ):
        """Record extraction with metadata for tracking"""
        if session_id not in self.extraction_history:
            self.extraction_history[session_id] = []
        
        item = ExtractionItem(
            value=value,
            item_type=item_type,
            confidence=confidence,
            source_turn=turn,
            context=context
        )
        self.extraction_history[session_id].append(item)
    
    def get_extraction_summary(self, session_id: str) -> Dict:
        """Get summary of all extractions for a session"""
        history = self.extraction_history.get(session_id, [])
        
        by_type = {}
        for item in history:
            if item.item_type not in by_type:
                by_type[item.item_type] = []
            by_type[item.item_type].append({
                "value": item.value,
                "confidence": item.confidence,
                "turn": item.source_turn
            })
        
        return {
            "total_items": len(history),
            "by_type": by_type,
            "high_value_count": sum(1 for item in history 
                                   if item.item_type in ["upi", "bank_account", "phone"])
        }
    
    def has_high_value_intel(self, intel: ExtractedIntelligence) -> bool:
        """Check if we have extracted high-value intelligence"""
        return bool(intel.upiIds or intel.bankAccounts or 
                   (len(intel.phoneNumbers) > 0 and len(intel.phishingLinks) > 0))


# Singleton instance
intelligence_extractor = IntelligenceExtractor()
