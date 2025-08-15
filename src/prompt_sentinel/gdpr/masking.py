# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Prompt masking utilities for privacy protection."""

import hashlib
import re
from enum import Enum
from typing import Any

import structlog

from prompt_sentinel.detection.pii_detector import PIIDetector, PIIType

logger = structlog.get_logger()


class MaskingStrategy(str, Enum):
    """Strategies for masking sensitive data."""

    REDACT = "redact"  # Replace with [REDACTED]
    HASH = "hash"  # Replace with hash
    PARTIAL = "partial"  # Show partial data (e.g., ***-**-6789)
    TOKENIZE = "tokenize"  # Replace with token ID
    REMOVE = "remove"  # Remove entirely
    ANONYMIZE = "anonymize"  # Replace with fake but valid data


class PromptMasker:
    """Advanced prompt masking for privacy protection."""

    def __init__(self, pii_detector: PIIDetector | None = None):
        """
        Initialize prompt masker.

        Args:
            pii_detector: PII detector instance
        """
        self.pii_detector = pii_detector or PIIDetector()
        self.token_map: dict[str, str] = {}
        self.token_counter = 0

        # Masking patterns for different data types
        self.masking_patterns = {
            PIIType.EMAIL: {
                MaskingStrategy.REDACT: "[EMAIL]",
                MaskingStrategy.PARTIAL: lambda v: f"{v[:2]}***@***.***",
                MaskingStrategy.ANONYMIZE: lambda v: f"user{self._get_hash(v)[:8]}@example.com",
            },
            PIIType.PHONE: {
                MaskingStrategy.REDACT: "[PHONE]",
                MaskingStrategy.PARTIAL: lambda v: f"***-***-{v[-4:]}",
                MaskingStrategy.ANONYMIZE: lambda v: f"555-{self._get_hash(v)[3:6]}-{self._get_hash(v)[6:10]}",
            },
            PIIType.SSN: {
                MaskingStrategy.REDACT: "[SSN]",
                MaskingStrategy.PARTIAL: lambda v: f"***-**-{v[-4:]}",
                MaskingStrategy.ANONYMIZE: lambda v: f"{self._get_hash(v)[:3]}-{self._get_hash(v)[3:5]}-{self._get_hash(v)[5:9]}",
            },
            PIIType.CREDIT_CARD: {
                MaskingStrategy.REDACT: "[CREDIT_CARD]",
                MaskingStrategy.PARTIAL: lambda v: f"****-****-****-{v[-4:]}",
                MaskingStrategy.ANONYMIZE: lambda v: self._generate_fake_card(v),
            },
            PIIType.IP_ADDRESS: {
                MaskingStrategy.REDACT: "[IP_ADDRESS]",
                MaskingStrategy.PARTIAL: lambda v: f"{'.'.join(v.split('.')[:2])}.*.* ",
                MaskingStrategy.ANONYMIZE: lambda v: self._generate_fake_ip(v),
            },
            PIIType.API_KEY: {
                MaskingStrategy.REDACT: "[API_KEY]",
                MaskingStrategy.PARTIAL: lambda v: f"{v[:8]}...{v[-4:]}",
                MaskingStrategy.ANONYMIZE: lambda v: f"sk-{self._get_hash(v)[:32]}",
            },
            PIIType.PASSWORD: {
                MaskingStrategy.REDACT: "[PASSWORD]",
                MaskingStrategy.PARTIAL: lambda v: "*" * min(len(v), 8),
                MaskingStrategy.ANONYMIZE: lambda v: "[REMOVED]",
            },
        }

    def mask_prompt(
        self,
        prompt: str,
        strategy: MaskingStrategy = MaskingStrategy.REDACT,
        pii_types: list[PIIType] | None = None,
        custom_patterns: dict[str, str] | None = None,
    ) -> tuple[str, dict[str, Any]]:
        """
        Mask sensitive data in prompt.

        Args:
            prompt: Input prompt to mask
            strategy: Masking strategy to use
            pii_types: Specific PII types to mask (None = all)
            custom_patterns: Additional custom patterns to mask

        Returns:
            Tuple of (masked prompt, masking metadata)
        """
        # Detect PII
        pii_matches = self.pii_detector.detect(prompt)

        if not pii_matches:
            return prompt, {"masked_count": 0, "pii_found": False}

        # Filter by PII types if specified
        if pii_types:
            pii_matches = [m for m in pii_matches if m.pii_type in pii_types]

        # Sort matches by position (reverse for replacement)
        pii_matches.sort(key=lambda x: x.start_pos, reverse=True)

        masked_prompt = prompt
        masked_items = []

        for match in pii_matches:
            original_value = prompt[match.start_pos : match.end_pos]
            masked_value = self._apply_masking(original_value, match.pii_type, strategy)

            # Replace in prompt
            masked_prompt = (
                masked_prompt[: match.start_pos] + masked_value + masked_prompt[match.end_pos :]
            )

            masked_items.append(
                {
                    "type": match.pii_type.value,
                    "original_length": len(original_value),
                    "masked_value": masked_value,
                    "strategy": strategy.value,
                    "position": [match.start_pos, match.end_pos],
                    "confidence": match.confidence,
                }
            )

        # Apply custom patterns if provided
        if custom_patterns:
            for pattern, replacement in custom_patterns.items():
                masked_prompt = re.sub(pattern, replacement, masked_prompt, flags=re.IGNORECASE)

        metadata = {
            "masked_count": len(masked_items),
            "pii_found": True,
            "masked_items": masked_items,
            "strategy_used": strategy.value,
            "prompt_length": len(prompt),
            "masked_prompt_length": len(masked_prompt),
        }

        return masked_prompt, metadata

    def _apply_masking(self, value: str, pii_type: PIIType, strategy: MaskingStrategy) -> str:
        """Apply masking strategy to value."""
        if strategy == MaskingStrategy.HASH:
            return f"[HASH:{self._get_hash(value)[:16]}]"

        elif strategy == MaskingStrategy.TOKENIZE:
            return self._tokenize_value(value)

        elif strategy == MaskingStrategy.REMOVE:
            return ""

        # Get type-specific masking
        type_masks = self.masking_patterns.get(pii_type, {})

        if strategy in type_masks:
            mask = type_masks[strategy]
            if callable(mask):
                return mask(value)
            return mask

        # Default to generic redaction
        return f"[{pii_type.value.upper()}]"

    def _get_hash(self, value: str) -> str:
        """Get consistent hash of value."""
        return hashlib.sha256(value.encode()).hexdigest()

    def _tokenize_value(self, value: str) -> str:
        """Tokenize value and return token ID."""
        if value not in self.token_map:
            self.token_counter += 1
            token_id = f"TOKEN_{self.token_counter:06d}"
            self.token_map[value] = token_id

        return f"[{self.token_map[value]}]"

    def _generate_fake_card(self, original: str) -> str:
        """Generate fake but valid-looking credit card."""
        hash_val = self._get_hash(original)
        # Use hash to generate consistent fake number
        digits = [int(hash_val[i], 16) % 10 for i in range(16)]
        return f"{digits[0:4]}-{digits[4:8]}-{digits[8:12]}-{digits[12:16]}"

    def _generate_fake_ip(self, original: str) -> str:
        """Generate fake but valid-looking IP address."""
        hash_val = self._get_hash(original)
        octets = [str(int(hash_val[i : i + 2], 16) % 256) for i in range(0, 8, 2)]
        return ".".join(octets)

    def get_token_mapping(self) -> dict[str, str]:
        """Get current token mappings."""
        return self.token_map.copy()

    def reverse_tokenization(self, masked_text: str) -> str:
        """Reverse tokenization (requires token map)."""
        reversed_text = masked_text

        # Create reverse map
        reverse_map = {v: k for k, v in self.token_map.items()}

        # Replace tokens with original values
        for token, original in reverse_map.items():
            reversed_text = reversed_text.replace(f"[{token}]", original)

        return reversed_text

    def batch_mask(
        self, prompts: list[str], strategy: MaskingStrategy = MaskingStrategy.REDACT
    ) -> list[tuple[str, dict[str, Any]]]:
        """
        Mask multiple prompts.

        Args:
            prompts: List of prompts to mask
            strategy: Masking strategy to use

        Returns:
            List of (masked prompt, metadata) tuples
        """
        return [self.mask_prompt(prompt, strategy) for prompt in prompts]

    def create_privacy_report(self, prompt: str) -> dict[str, Any]:
        """
        Create detailed privacy report for prompt.

        Args:
            prompt: Prompt to analyze

        Returns:
            Privacy analysis report
        """
        # Detect all PII
        pii_matches = self.pii_detector.detect(prompt)

        # Categorize by type
        pii_by_type = {}
        for match in pii_matches:
            pii_type = match.pii_type.value
            if pii_type not in pii_by_type:
                pii_by_type[pii_type] = []
            pii_by_type[pii_type].append(
                {
                    "confidence": match.confidence,
                    "position": [match.start_pos, match.end_pos],
                    "length": match.end_pos - match.start_pos,
                }
            )

        # Calculate privacy risk score
        risk_weights = {
            PIIType.SSN: 1.0,
            PIIType.CREDIT_CARD: 0.9,
            PIIType.BANK_ACCOUNT: 0.9,
            PIIType.PASSWORD: 0.8,
            PIIType.API_KEY: 0.8,
            PIIType.PRIVATE_KEY: 1.0,
            PIIType.EMAIL: 0.5,
            PIIType.PHONE: 0.5,
            PIIType.IP_ADDRESS: 0.4,
        }

        risk_score = 0.0
        for match in pii_matches:
            weight = risk_weights.get(match.pii_type, 0.3)
            risk_score += weight * match.confidence

        # Normalize risk score (0-100)
        risk_score = min(100, risk_score * 20)

        # Generate masking recommendations
        recommendations = []
        if risk_score > 80:
            recommendations.append("HIGH RISK: Complete redaction recommended")
            recommended_strategy = MaskingStrategy.REDACT
        elif risk_score > 50:
            recommendations.append("MEDIUM RISK: Partial masking or tokenization recommended")
            recommended_strategy = MaskingStrategy.PARTIAL
        elif risk_score > 20:
            recommendations.append("LOW RISK: Consider anonymization for sensitive fields")
            recommended_strategy = MaskingStrategy.ANONYMIZE
        else:
            recommendations.append("MINIMAL RISK: Masking optional")
            recommended_strategy = MaskingStrategy.PARTIAL

        # Create masked versions with different strategies
        masked_versions = {}
        for strategy in [MaskingStrategy.REDACT, MaskingStrategy.PARTIAL, MaskingStrategy.HASH]:
            masked, _ = self.mask_prompt(prompt, strategy)
            masked_versions[strategy.value] = masked

        return {
            "privacy_risk_score": round(risk_score, 2),
            "risk_level": "HIGH" if risk_score > 80 else "MEDIUM" if risk_score > 50 else "LOW",
            "pii_detected": len(pii_matches) > 0,
            "pii_count": len(pii_matches),
            "pii_types": list(pii_by_type.keys()),
            "pii_details": pii_by_type,
            "recommendations": recommendations,
            "recommended_strategy": recommended_strategy.value,
            "masked_versions": masked_versions,
            "prompt_length": len(prompt),
            "sensitive_data_percentage": (
                round((sum(m.end_pos - m.start_pos for m in pii_matches) / len(prompt)) * 100, 2)
                if prompt
                else 0
            ),
        }


def create_masker(pii_detector: PIIDetector | None = None) -> PromptMasker:
    """Create prompt masker instance."""
    return PromptMasker(pii_detector)


def mask_prompt_simple(prompt: str, strategy: str = "redact") -> str:
    """Simple prompt masking function."""
    masker = PromptMasker()
    masked, _ = masker.mask_prompt(prompt, MaskingStrategy(strategy))
    return masked


# Example usage
if __name__ == "__main__":
    # Test masking
    masker = PromptMasker()

    test_prompt = """
    My email is john.doe@example.com and my SSN is 123-45-6789.
    Please call me at 555-123-4567. My API key is sk-abc123xyz789.
    My credit card is 4111-1111-1111-1111.
    """

    print("Original prompt:")
    print(test_prompt)
    print("\n" + "=" * 60 + "\n")

    # Test different strategies
    for strategy in MaskingStrategy:
        masked, metadata = masker.mask_prompt(test_prompt, strategy)
        print(f"Strategy: {strategy.value}")
        print(f"Masked: {masked}")
        print(f"Metadata: {metadata['masked_count']} items masked")
        print("-" * 40)

    # Create privacy report
    print("\n" + "=" * 60 + "\n")
    print("Privacy Report:")
    report = masker.create_privacy_report(test_prompt)
    for key, value in report.items():
        if key != "masked_versions":
            print(f"{key}: {value}")
