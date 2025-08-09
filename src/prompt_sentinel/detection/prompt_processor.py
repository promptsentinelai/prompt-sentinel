"""Prompt processing, validation, and format normalization.

This module handles the transformation and validation of various prompt
formats into a standardized message structure. It provides utilities for:
- Converting different input formats to standard messages
- Validating role separation and message structure
- Detecting format issues and role confusion
- Sanitizing potentially malicious content
- Calculating prompt complexity metrics

The processor ensures consistent handling of prompts regardless of their
original format, enabling reliable detection across different API versions
and input styles.
"""

import re
from typing import Dict, List, Optional, Tuple, Union
from prompt_sentinel.models.schemas import (
    Message,
    Role,
    FormatRecommendation,
    UnifiedDetectionRequest,
)


class PromptProcessor:
    """Handles prompt format normalization, validation, and analysis.

    Provides utilities for converting various prompt formats into
    standardized message structures, validating role separation,
    and analyzing prompt characteristics for security assessment.

    All methods are static as the processor maintains no state.
    """

    @staticmethod
    def normalize_input(
        input_data: Union[str, List[Dict[str, str]], List[Message]],
        role_hint: Optional[Role] = None,
    ) -> List[Message]:
        """Convert any input format to standardized message format.

        Handles various input formats including:
        - Plain strings (converted to user messages)
        - Lists of dictionaries with role/content keys
        - Lists of Message objects (passed through)

        Args:
            input_data: Raw input in string, dict list, or Message list format
            role_hint: Optional role to use for string inputs (default: USER)

        Returns:
            List of normalized Message objects with validated roles

        Example:
            >>> messages = PromptProcessor.normalize_input("Hello")
            >>> print(messages[0].role)
            Role.USER
        """
        # Handle string input
        if isinstance(input_data, str):
            role = role_hint or Role.USER
            return [Message(role=role, content=input_data)]

        # Handle list of Message objects
        if input_data and isinstance(input_data[0], Message):
            return input_data

        # Handle list of dictionaries
        if isinstance(input_data, list):
            messages = []
            for item in input_data:
                if isinstance(item, dict):
                    role = item.get("role", "user")
                    content = item.get("content", "")

                    # Validate role
                    if role not in ["system", "user", "assistant"]:
                        role = "user"  # Default to user if invalid

                    messages.append(Message(role=Role(role), content=content))
            return messages

        # Fallback for unexpected input
        raise ValueError(f"Unsupported input format: {type(input_data)}")

    @staticmethod
    def validate_role_separation(
        messages: List[Message],
    ) -> Tuple[bool, List[FormatRecommendation]]:
        """Check if system and user prompts are properly separated.

        Validates message structure against security best practices,
        checking for proper role separation and clear boundaries.

        Args:
            messages: List of messages to validate for format compliance

        Returns:
            Tuple containing:
            - is_properly_formatted: True if follows best practices
            - recommendations: List of improvement suggestions
        """
        recommendations = []

        # Check for role separation
        has_system = any(msg.role == Role.SYSTEM for msg in messages)
        has_user = any(msg.role == Role.USER for msg in messages)

        # Check if system prompts come before user prompts
        system_indices = [i for i, msg in enumerate(messages) if msg.role == Role.SYSTEM]
        user_indices = [i for i, msg in enumerate(messages) if msg.role == Role.USER]

        if not has_system and not has_user:
            recommendations.append(
                FormatRecommendation(
                    issue="No role separation detected",
                    recommendation="Consider using explicit 'system' and 'user' roles for better security",
                    severity="warning",
                )
            )
            return False, recommendations

        if not has_system:
            recommendations.append(
                FormatRecommendation(
                    issue="No system prompt found",
                    recommendation="Add a system prompt to define expected behavior and boundaries",
                    severity="info",
                )
            )

        if system_indices and user_indices:
            if max(system_indices) > min(user_indices):
                recommendations.append(
                    FormatRecommendation(
                        issue="System prompts appear after user prompts",
                        recommendation="Place all system prompts before user prompts for better security",
                        severity="warning",
                    )
                )

        # Check for multiple system prompts (potential confusion)
        if len(system_indices) > 1:
            recommendations.append(
                FormatRecommendation(
                    issue="Multiple system prompts detected",
                    recommendation="Consider consolidating system prompts for clarity",
                    severity="info",
                )
            )

        properly_formatted = (
            has_system
            and has_user
            and (not system_indices or not user_indices or max(system_indices) < min(user_indices))
        )

        return properly_formatted, recommendations

    @staticmethod
    def detect_role_confusion(messages: List[Message]) -> List[str]:
        """
        Detect attempts to confuse or manipulate roles.

        Args:
            messages: List of messages to analyze

        Returns:
            List of detected issues
        """
        issues = []

        # Patterns that might indicate role manipulation
        role_manipulation_patterns = [
            r"(you are|you're|act as|pretend to be|roleplay as)",
            r"(system:|user:|assistant:)",
            r"(ignore previous|disregard above|forget what)",
            r"(new instructions|updated instructions|revised instructions)",
        ]

        for msg in messages:
            content_lower = msg.content.lower()

            # Check user messages for system-like instructions
            if msg.role == Role.USER:
                for pattern in role_manipulation_patterns:
                    if re.search(pattern, content_lower):
                        issues.append(
                            f"Potential role manipulation in user message: pattern '{pattern}' detected"
                        )

            # Check for role indicators in content
            if any(role_str in content_lower for role_str in ["system:", "user:", "assistant:"]):
                issues.append("Message content contains role indicators that might cause confusion")

        return issues

    @staticmethod
    def extract_prompt_segments(messages: List[Message]) -> Dict[str, List[str]]:
        """
        Extract and categorize prompt segments by role.

        Args:
            messages: List of messages

        Returns:
            Dictionary with role-based content segments
        """
        segments = {"system": [], "user": [], "assistant": []}

        for msg in messages:
            if msg.role in [Role.SYSTEM, Role.USER, Role.ASSISTANT]:
                segments[msg.role.value].append(msg.content)

        return segments

    @staticmethod
    def calculate_complexity_metrics(content: str) -> Dict[str, float]:
        """
        Calculate complexity metrics for a prompt.

        Args:
            content: Prompt content

        Returns:
            Dictionary of complexity metrics
        """
        # Basic metrics
        length = len(content)
        word_count = len(content.split())

        # Special character ratio
        special_chars = sum(1 for c in content if not c.isalnum() and not c.isspace())
        special_char_ratio = special_chars / max(length, 1)

        # Encoding indicators
        has_base64 = bool(re.search(r"[A-Za-z0-9+/]{20,}={0,2}", content))
        has_hex = bool(re.search(r"\\x[0-9a-fA-F]{2}", content))
        has_unicode = bool(re.search(r"\\u[0-9a-fA-F]{4}", content))

        # URL/URI detection
        url_count = len(re.findall(r"https?://[^\s]+", content))

        # Code-like patterns
        code_indicators = [
            r"\bfunction\b",
            r"\bclass\b",
            r"\bdef\b",
            r"\bimport\b",
            r"\{.*\}",
            r"\[.*\]",
            r"<.*>",
            r"\$\{.*\}",
        ]
        code_score = sum(1 for pattern in code_indicators if re.search(pattern, content))

        return {
            "length": length,
            "word_count": word_count,
            "special_char_ratio": special_char_ratio,
            "has_base64": has_base64,
            "has_hex": has_hex,
            "has_unicode": has_unicode,
            "url_count": url_count,
            "code_score": code_score / len(code_indicators),
        }

    @staticmethod
    def sanitize_prompt(content: str, aggressive: bool = False) -> str:
        """
        Sanitize potentially malicious content from a prompt.

        Args:
            content: Prompt content to sanitize
            aggressive: If True, apply more aggressive sanitization

        Returns:
            Sanitized content
        """
        sanitized = content

        # Remove potential encoding attacks
        sanitized = re.sub(r"\\x[0-9a-fA-F]{2}", "", sanitized)
        sanitized = re.sub(r"\\u[0-9a-fA-F]{4}", "", sanitized)

        # Remove base64-like strings (be careful not to remove legitimate content)
        if aggressive:
            sanitized = re.sub(r"[A-Za-z0-9+/]{40,}={0,2}", "[REMOVED_ENCODING]", sanitized)

        # Remove potential command injection patterns
        dangerous_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:.*?(?=\s|$)",
            r"data:text/html.*?(?=\s|$)",
        ]

        for pattern in dangerous_patterns:
            sanitized = re.sub(pattern, "[REMOVED]", sanitized, flags=re.IGNORECASE | re.DOTALL)

        # Remove excessive whitespace that might be used for obfuscation
        sanitized = re.sub(r"\s{10,}", " ", sanitized)

        # Remove zero-width characters
        zero_width_chars = ["\u200b", "\u200c", "\u200d", "\ufeff"]
        for char in zero_width_chars:
            sanitized = sanitized.replace(char, "")

        return sanitized.strip()
