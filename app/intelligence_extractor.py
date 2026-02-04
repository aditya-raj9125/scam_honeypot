import re
from typing import List
from .models import ExtractedIntelligence

class IntelligenceExtractor:
    def __init__(self):
        self.patterns = {
            "upi": r"[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}",
            "bank_account": r"\b\d{9,18}\b",  # 9-18 digit numbers for accounts
            "phone": r"(?:\+91[\s-]?)?[6-9]\d{9}",  # Indian phone numbers
            "international_phone": r"\+\d{1,3}[\s.-]?\d{8,12}",  # International format
            "url": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w.\-]*",
            "suspicious_domains": r"(?:bit\.ly|tinyurl|t\.co|short\.link|[a-z0-9-]+\.(?:tk|ml|cf|ga))/\w+",
            "keywords": r"\b(urgent|verify|block|suspend|kyc|pan|aadhaar|aadhar|otp|click|link|immediate|expire|update|confirm|activate|deactivate|frozen|locked)\b"
        }

    def extract(self, text: str, current_intelligence: ExtractedIntelligence) -> ExtractedIntelligence:
        # Normalize text for better pattern matching
        normalized_text = text.lower()
        
        # UPI extraction
        upis = re.findall(self.patterns["upi"], text, re.IGNORECASE)
        for upi in upis:
            if upi and upi not in current_intelligence.upiIds:
                current_intelligence.upiIds.append(upi)

        # Bank Account extraction with better filtering
        potential_accounts = re.findall(self.patterns["bank_account"], text)
        for acc in potential_accounts:
            # Filter out timestamps and other non-account numbers
            if self._is_likely_bank_account(acc, text) and acc not in current_intelligence.bankAccounts:
                current_intelligence.bankAccounts.append(acc)

        # Phone number extraction (Indian and international)
        indian_phones = re.findall(self.patterns["phone"], text.replace(" ", "").replace("-", ""))
        intl_phones = re.findall(self.patterns["international_phone"], text)
        
        all_phones = indian_phones + intl_phones
        for phone in all_phones:
            if phone and phone not in current_intelligence.phoneNumbers:
                current_intelligence.phoneNumbers.append(phone)
        # URL extraction (both regular URLs and suspicious domains)
        urls = re.findall(self.patterns["url"], text, re.IGNORECASE)
        suspicious_urls = re.findall(self.patterns["suspicious_domains"], text, re.IGNORECASE)
        
        all_urls = urls + ["http://" + url for url in suspicious_urls]  # Add protocol to suspicious domains
        for url in all_urls:
            if url and url not in current_intelligence.phishingLinks:
                current_intelligence.phishingLinks.append(url)
        
        # Keywords extraction
        keywords = re.findall(self.patterns["keywords"], text, re.IGNORECASE)
        for k in keywords:
            if k.lower() not in current_intelligence.suspiciousKeywords:
                current_intelligence.suspiciousKeywords.append(k.lower())

        return current_intelligence
    
    def _is_likely_bank_account(self, number: str, context: str) -> bool:
        """Helper method to determine if a number is likely a bank account"""
        # Filter out timestamps (usually 13 digits starting with 17xx for current era)
        if len(number) == 13 and number.startswith(("17", "16")):
            return False
            
        # Look for contextual clues
        context_lower = context.lower()
        account_indicators = ["account", "bank", "transfer", "deposit", "withdraw", "balance"]
        
        # If context suggests banking, more likely to be account number
        if any(indicator in context_lower for indicator in account_indicators):
            return True
            
        # Standard account number lengths (most banks use 10-16 digits)
        return 10 <= len(number) <= 16
