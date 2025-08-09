"""PII and sensitive information detection module.

This module provides comprehensive detection of Personally Identifiable
Information (PII) and other sensitive data in text inputs. It helps prevent
accidental exposure of sensitive information through LLM prompts.

Supported PII types include:
- Financial: Credit cards, bank accounts, SSNs
- Contact: Email addresses, phone numbers, physical addresses
- Credentials: API keys, passwords, private keys
- Identity: Passport numbers, driver's licenses, dates of birth
- Network: IP addresses, AWS keys

The detector supports multiple redaction modes:
- mask: Replace with asterisks
- remove: Remove entirely with placeholder
- hash: Replace with hash value
- reject: Block processing entirely
"""

import re
from dataclasses import dataclass
from enum import Enum


class PIIType(str, Enum):
    """Enumeration of PII types that can be detected.

    Each type corresponds to specific regex patterns and validation
    logic tailored to detect that category of sensitive information.
    """

    CREDIT_CARD = "credit_card"
    SSN = "ssn"
    EMAIL = "email"
    PHONE = "phone"
    IP_ADDRESS = "ip_address"
    API_KEY = "api_key"
    PASSWORD = "password"
    AWS_KEY = "aws_key"
    PRIVATE_KEY = "private_key"
    BANK_ACCOUNT = "bank_account"
    PASSPORT = "passport"
    DRIVERS_LICENSE = "drivers_license"
    DATE_OF_BIRTH = "date_of_birth"
    ADDRESS = "address"
    GENERIC_SECRET = "generic_secret"


@dataclass
class PIIMatch:
    """Represents a detected PII match in text.

    Contains all information needed to locate, identify, and
    redact the detected sensitive information.

    Attributes:
        pii_type: Category of PII detected
        start_pos: Starting character position in text
        end_pos: Ending character position in text
        masked_value: Partially masked version for display
        confidence: Detection confidence score (0.0-1.0)
        context: Surrounding text for context
    """

    pii_type: PIIType
    start_pos: int
    end_pos: int
    masked_value: str
    confidence: float
    context: str


class PIIDetector:
    """Detects and redacts PII and sensitive information in text.

    Provides pattern-based detection of various PII types with
    configurable sensitivity and redaction options. Includes
    validation logic for formats like credit cards (Luhn algorithm)
    and structured data like SSNs.

    Attributes:
        config: Detection configuration dictionary
        enabled_types: List of PII types to detect
        patterns: Dictionary of compiled regex patterns
    """

    def __init__(self, detection_config: dict | None = None):
        """Initialize PII detector with configuration.

        Args:
            detection_config: Optional configuration dictionary with:
                - types: List of PII types to detect (default: all)
                - confidence_threshold: Minimum confidence to report (default: 0.7)
                - context_window: Characters of context to capture (default: 20)
        """
        self.config = detection_config or {}
        self.enabled_types = self._get_enabled_types()
        self._init_patterns()

    def _get_enabled_types(self) -> list[PIIType]:
        """Get list of PII types to detect based on configuration.

        Returns:
            List of PIIType enums that should be detected
        """
        if "types" in self.config:
            types_list = self.config["types"]
            if types_list and "all" in types_list:
                return list(PIIType)  # All types
            elif types_list:
                return [PIIType(t) for t in types_list]
        return list(PIIType)  # All types by default

    def _init_patterns(self):
        """Initialize regex patterns for each PII type.

        Creates compiled regex patterns for efficient matching.
        Each pattern tuple contains (regex, confidence_score).
        """
        self.patterns = {
            PIIType.CREDIT_CARD: [
                # Visa, MasterCard, Amex, Discover patterns
                (
                    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9][0-9])[0-9]{12})\b",
                    0.8,
                ),
                (r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", 0.6),  # Generic 16-digit
            ],
            PIIType.SSN: [
                (r"\b\d{3}-\d{2}-\d{4}\b", 0.9),  # Standard SSN format
                (r"\b\d{3}\s\d{2}\s\d{4}\b", 0.8),  # Space-separated
                (r"\b\d{9}\b", 0.3),  # 9 consecutive digits (low confidence)
            ],
            PIIType.EMAIL: [
                (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", 0.95),
            ],
            PIIType.PHONE: [
                # US phone numbers
                (r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", 0.8),
                # International format
                (r"\b\+\d{1,3}[-.\s]?\d{1,14}\b", 0.7),
                # Generic 10-digit
                (r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b", 0.7),
            ],
            PIIType.IP_ADDRESS: [
                # IPv4
                (
                    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
                    0.9,
                ),
                # IPv6 (simplified pattern)
                (r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b", 0.9),
            ],
            PIIType.API_KEY: [
                # Common API key patterns
                (r"\b[A-Za-z0-9]{32,}\b", 0.4),  # Generic long alphanumeric
                (r"api[_-]?key[\s=:]+[\'\"]?([A-Za-z0-9\-_]{20,})[\'\"]?", 0.9),
                (r"token[\s=:]+[\'\"]?([A-Za-z0-9\-_]{20,})[\'\"]?", 0.9),
                (r"bearer\s+[A-Za-z0-9\-_\.]+", 0.8),
            ],
            PIIType.PASSWORD: [
                (r"password[\s=:]+[\'\"]?([^\s\'\"]{6,})[\'\"]?", 0.9),
                (r"passwd[\s=:]+[\'\"]?([^\s\'\"]{6,})[\'\"]?", 0.9),
                (r"pwd[\s=:]+[\'\"]?([^\s\'\"]{6,})[\'\"]?", 0.8),
            ],
            PIIType.AWS_KEY: [
                # AWS Access Key ID
                (r"\bAKIA[0-9A-Z]{16}\b", 0.95),
                # AWS Secret Access Key (harder to detect precisely)
                (r"aws_secret_access_key[\s=:]+[\'\"]?([A-Za-z0-9/+=]{40})[\'\"]?", 0.9),
            ],
            PIIType.PRIVATE_KEY: [
                # Private key headers
                (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", 0.99),
                (r"-----BEGIN OPENSSH PRIVATE KEY-----", 0.99),
                (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", 0.99),
            ],
            PIIType.BANK_ACCOUNT: [
                # US routing number (9 digits starting with 0-3)
                (r"\b[0-3]\d{8}\b", 0.4),
                # IBAN
                (r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b", 0.8),
            ],
            PIIType.PASSPORT: [
                # US passport (letter followed by 8 digits)
                (r"\b[A-Z]\d{8}\b", 0.5),
                # Generic passport pattern
                (r"passport[\s:#]+([A-Z0-9]{6,9})", 0.8),
            ],
            PIIType.DATE_OF_BIRTH: [
                # Various date formats that might be DOB
                (
                    r"\b(?:DOB|dob|Date of Birth|date of birth)[\s:]+\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b",
                    0.9,
                ),
                (r"\b(?:born|Born)[\s:]+\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b", 0.8),
            ],
            PIIType.GENERIC_SECRET: [
                # Generic secret patterns
                (r"secret[\s=:]+[\'\"]?([^\s\'\"]{10,})[\'\"]?", 0.8),
                (r"private[\s=:]+[\'\"]?([^\s\'\"]{10,})[\'\"]?", 0.7),
                (r"credential[\s=:]+[\'\"]?([^\s\'\"]{10,})[\'\"]?", 0.8),
            ],
        }

    def detect(self, text: str) -> list[PIIMatch]:
        """
        Detect PII in text.

        Args:
            text: Text to scan for PII

        Returns:
            List of PII matches found
        """
        matches = []

        for pii_type in self.enabled_types:
            if pii_type not in self.patterns:
                continue

            for pattern, confidence in self.patterns[pii_type]:
                for match in re.finditer(pattern, text, re.IGNORECASE):
                    # Get context around the match
                    start = max(0, match.start() - 20)
                    end = min(len(text), match.end() + 20)
                    context = text[start:end]

                    # Mask the value
                    matched_text = match.group()
                    masked = self._mask_value(matched_text, pii_type)

                    # Validate specific types
                    if pii_type == PIIType.CREDIT_CARD:
                        if not self._validate_credit_card(
                            matched_text.replace("-", "").replace(" ", "")
                        ):
                            continue

                    matches.append(
                        PIIMatch(
                            pii_type=pii_type,
                            start_pos=match.start(),
                            end_pos=match.end(),
                            masked_value=masked,
                            confidence=confidence,
                            context=context,
                        )
                    )

        # Remove duplicates and overlapping matches
        return self._deduplicate_matches(matches)

    def _validate_credit_card(self, number: str) -> bool:
        """
        Validate credit card number using Luhn algorithm.

        Args:
            number: Credit card number (digits only)

        Returns:
            True if valid according to Luhn algorithm
        """
        if not number.isdigit() or len(number) < 13 or len(number) > 19:
            return False

        # Luhn algorithm
        total = 0
        reverse = number[::-1]

        for i, digit in enumerate(reverse):
            n = int(digit)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n

        return total % 10 == 0

    def _mask_value(self, value: str, pii_type: PIIType) -> str:
        """
        Mask PII value for safe display.

        Args:
            value: Original value
            pii_type: Type of PII

        Returns:
            Masked version of the value
        """
        if len(value) <= 4:
            return "****"

        if pii_type == PIIType.EMAIL:
            parts = value.split("@")
            if len(parts) == 2:
                username = parts[0]
                if len(username) > 2:
                    return f"{username[:2]}***@{parts[1]}"
                return f"***@{parts[1]}"

        elif pii_type == PIIType.CREDIT_CARD:
            # Show last 4 digits
            clean = value.replace("-", "").replace(" ", "")
            if len(clean) >= 4:
                return f"****-****-****-{clean[-4:]}"

        elif pii_type == PIIType.SSN:
            return "***-**-****"

        elif pii_type == PIIType.PHONE:
            # Show area code
            clean = re.sub(r"[^\d]", "", value)
            if len(clean) >= 10:
                return f"{clean[:3]}-***-****"

        # Default masking - show first 2 and last 2 characters
        if len(value) > 6:
            return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"
        else:
            return "*" * len(value)

    def _deduplicate_matches(self, matches: list[PIIMatch]) -> list[PIIMatch]:
        """
        Remove duplicate and overlapping matches.

        Args:
            matches: List of PII matches

        Returns:
            Deduplicated list of matches
        """
        if not matches:
            return []

        # Sort by position and confidence
        sorted_matches = sorted(matches, key=lambda x: (x.start_pos, -x.confidence))

        result = []
        last_end = -1

        for match in sorted_matches:
            # Skip if this match overlaps with a previous one
            if match.start_pos < last_end:
                continue
            result.append(match)
            last_end = match.end_pos

        return result

    def redact(self, text: str, matches: list[PIIMatch], mode: str = "mask") -> str:
        """
        Redact PII from text.

        Args:
            text: Original text
            matches: List of PII matches to redact
            mode: Redaction mode - "mask", "remove", "hash", "pass-silent", or "pass-alert"

        Returns:
            Redacted text (or original if pass-silent/pass-alert)
        """
        if not matches:
            return text

        # Handle pass-through modes
        if mode in ["pass-silent", "pass-alert"]:
            # Return original text without modifications
            # pass-alert handling is done at the detector level
            return text

        # Sort matches by position (reverse order for replacement)
        sorted_matches = sorted(matches, key=lambda x: x.start_pos, reverse=True)

        result = text
        for match in sorted_matches:
            if mode == "mask":
                replacement = match.masked_value
            elif mode == "remove":
                replacement = f"[{match.pii_type.value.upper()}_REMOVED]"
            elif mode == "hash":
                # Use a consistent hash for the same value
                import hashlib

                original = text[match.start_pos : match.end_pos]
                hash_val = hashlib.sha256(original.encode()).hexdigest()[:8]
                replacement = f"[{match.pii_type.value.upper()}_{hash_val}]"
            else:
                replacement = match.masked_value

            result = result[: match.start_pos] + replacement + result[match.end_pos :]

        return result

    def get_summary(self, matches: list[PIIMatch]) -> dict[str, int]:
        """
        Get summary of detected PII types.

        Args:
            matches: List of PII matches

        Returns:
            Dictionary with counts by PII type
        """
        summary = {}
        for match in matches:
            pii_type = match.pii_type.value
            summary[pii_type] = summary.get(pii_type, 0) + 1
        return summary
