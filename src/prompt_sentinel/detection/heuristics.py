# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Heuristic-based detection engine for prompt injection attacks."""

import base64
import re
from datetime import datetime
from typing import Any

from prompt_sentinel.models.schemas import (
    DetectionCategory,
    DetectionReason,
    Message,
    Role,
    Verdict,
)


class HeuristicDetector:
    """Pattern-based detection for common injection techniques."""

    def __init__(self, detection_mode: str = "strict", pattern_manager: Any | None = None) -> None:
        """
        Initialize the heuristic detector.

        Args:
            detection_mode: One of "strict", "moderate", "permissive"
            pattern_manager: Optional ML pattern manager for discovered patterns
        """
        self.detection_mode = detection_mode
        self.pattern_manager = pattern_manager
        self._init_patterns()

        # ML-discovered patterns cache
        self.ml_patterns: list[tuple[str, float, str]] = []
        self.ml_patterns_last_update: datetime | None = None

    def _init_patterns(self) -> None:
        """Initialize detection patterns based on mode."""
        # Compile patterns for better performance
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Compile regex patterns for better performance."""
        # Import shared patterns to avoid duplication across detectors
        from prompt_sentinel.detection.patterns import (
            HEURISTIC_CONTEXT_SWITCHING_PATTERNS,
            HEURISTIC_DIRECT_INJECTION_PATTERNS,
            HEURISTIC_ENCODING_PATTERNS,
            HEURISTIC_JAILBREAK_PATTERNS,
        )

        self.direct_injection_patterns = HEURISTIC_DIRECT_INJECTION_PATTERNS
        self.jailbreak_patterns = HEURISTIC_JAILBREAK_PATTERNS
        self.encoding_patterns = HEURISTIC_ENCODING_PATTERNS
        self.context_switching_patterns = HEURISTIC_CONTEXT_SWITCHING_PATTERNS

        # Adjust thresholds based on detection mode
        self.threshold_adjustments = {"strict": 0.0, "moderate": 0.1, "permissive": 0.2}

    def detect(self, messages: list[Message]) -> tuple[Verdict, list[DetectionReason], float]:
        """Perform heuristic detection on messages using pattern matching.

        Analyzes messages for suspicious patterns across multiple categories
        including direct injection, encoding, role confusion, and extraction
        attempts. Combines detection results to determine threat level.

        Args:
            messages: List of messages to analyze for injection patterns

        Returns:
            Tuple containing:
            - verdict: Recommended action (BLOCK/STRIP/FLAG/ALLOW)
            - reasons: List of detected threats with descriptions
            - confidence: Overall confidence score (0.0-1.0)

        Example:
            >>> messages = [Message(role=Role.USER, content="Ignore previous")]
            >>> verdict, reasons, conf = detector.detect(messages)
            >>> print(verdict)
            Verdict.BLOCK
        """
        all_reasons = []
        max_confidence = 0.0

        for message in messages:
            reasons = self._analyze_message(message)
            all_reasons.extend(reasons)

            if reasons:
                msg_confidence = max(r.confidence for r in reasons)
                max_confidence = max(max_confidence, msg_confidence)

        # Adjust confidence based on detection mode
        threshold_adjustment = self.threshold_adjustments.get(self.detection_mode, 0.0)
        adjusted_confidence = max(0, max_confidence - threshold_adjustment)

        # Determine verdict based on confidence
        verdict = self._determine_verdict(adjusted_confidence, all_reasons)

        return verdict, all_reasons, adjusted_confidence

    def _analyze_message(self, message: Message) -> list[DetectionReason]:
        """Analyze a single message for injection patterns.

        Applies all pattern categories to the message content and
        collects detection reasons for any matches found.

        Args:
            message: Message to analyze

        Returns:
            List of DetectionReason objects for detected threats
        """
        reasons = []
        content = message.content

        # Check for zero-width and invisible Unicode characters
        if any(ord(c) in [0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060] for c in content):
            reasons.append(
                DetectionReason(
                    category=DetectionCategory.ENCODING_ATTACK,
                    description="Zero-width or invisible Unicode characters detected",
                    confidence=0.9,
                    source="heuristic",
                    patterns_matched=["zero_width_chars"],
                )
            )

        # Performance optimization: limit content length for pattern matching
        # Most injection attacks are in the first/last parts of the text
        MAX_SCAN_LENGTH = 5000
        if len(content) > MAX_SCAN_LENGTH * 2:
            # For very long content, check beginning and end
            content_to_check = content[:MAX_SCAN_LENGTH] + " ... " + content[-MAX_SCAN_LENGTH:]
        else:
            content_to_check = content

        content_lower = content_to_check.lower()

        # Check direct injection patterns (skip for system messages)
        if message.role != Role.SYSTEM:
            for pattern, confidence, description in self.direct_injection_patterns:
                if re.search(pattern, content_lower):
                    reasons.append(
                        DetectionReason(
                            category=DetectionCategory.DIRECT_INJECTION,
                            description=description,
                            confidence=confidence,
                            source="heuristic",
                            patterns_matched=[pattern],
                        )
                    )

        # Check jailbreak patterns
        for pattern, confidence, description in self.jailbreak_patterns:
            if re.search(pattern, content_lower):
                reasons.append(
                    DetectionReason(
                        category=DetectionCategory.JAILBREAK,
                        description=description,
                        confidence=confidence,
                        source="heuristic",
                        patterns_matched=[pattern],
                    )
                )

        # Check encoding patterns (case-sensitive)
        for pattern, confidence, description in self.encoding_patterns:
            if re.search(pattern, content_to_check):
                # Try to decode to verify it's actual encoding
                if self._verify_encoding(content_to_check, pattern):
                    reasons.append(
                        DetectionReason(
                            category=DetectionCategory.ENCODING_ATTACK,
                            description=description,
                            confidence=confidence,
                            source="heuristic",
                            patterns_matched=[pattern],
                        )
                    )

        # Check context switching
        for pattern, confidence, description in self.context_switching_patterns:
            if re.search(pattern, content, re.MULTILINE):
                reasons.append(
                    DetectionReason(
                        category=DetectionCategory.CONTEXT_SWITCHING,
                        description=description,
                        confidence=confidence,
                        source="heuristic",
                        patterns_matched=[pattern],
                    )
                )

        # Check ML-discovered patterns
        ml_matches = self._check_ml_patterns(content)
        for pattern_id, confidence, description in ml_matches:
            reasons.append(
                DetectionReason(
                    category=DetectionCategory.DIRECT_INJECTION,
                    description=description,
                    confidence=confidence,
                    source="heuristic",
                    patterns_matched=[pattern_id],
                )
            )

        # Special checks for system prompts in user messages
        if message.role == Role.USER:
            if self._check_role_manipulation(content):
                reasons.append(
                    DetectionReason(
                        category=DetectionCategory.ROLE_MANIPULATION,
                        description="User message contains system-level instructions",
                        confidence=0.85,
                        source="heuristic",
                        patterns_matched=["role_manipulation_check"],
                    )
                )

        # Check for prompt leak attempts in any message
        if self._check_prompt_leak(content):
            reasons.append(
                DetectionReason(
                    category=DetectionCategory.PROMPT_LEAK,
                    description="Attempt to extract system prompt detected",
                    confidence=0.9,
                    source="heuristic",
                    patterns_matched=["prompt_leak_check"],
                )
            )

        return reasons

    def _verify_encoding(self, content: str, pattern: str) -> bool:
        """Verify if a pattern match is actual encoding."""
        try:
            # Check for base64 pattern
            if r"[A-Za-z0-9+/]" in pattern or "={0,2}" in pattern:
                matches = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", content)
                for match in matches:
                    try:
                        decoded = base64.b64decode(match)
                        # Check if decoded content contains text
                        if any(32 <= b < 127 for b in decoded):
                            return True
                    except Exception:
                        pass

            # Check for hex encoding pattern
            elif r"\x" in pattern:
                matches = re.findall(r"\\x[0-9a-fA-F]{2}", content)
                if matches:
                    return True

            # Check for unicode encoding pattern
            elif r"\u" in pattern:
                matches = re.findall(r"\\u[0-9a-fA-F]{4}", content)
                if matches:
                    return True

            # Check for URL encoding pattern
            elif "%" in pattern:
                matches = re.findall(r"%[0-9a-fA-F]{2}", content)
                if len(matches) >= 3:  # At least 3 encoded chars
                    return True

            # Check for HTML entity encoding
            elif "&" in pattern:
                matches = re.findall(r"&(#x?[0-9a-fA-F]+|[a-z]+);", content)
                if matches:
                    return True

            return False
        except Exception:
            return False

    def _check_role_manipulation(self, content: str) -> bool:
        """Check for role manipulation attempts."""
        role_keywords = [
            "system message",
            "system prompt",
            "system instruction",
            "assistant message",
            "assistant prompt",
            "you must",
            "you have to",
            "you should",
            "your task is",
            "your role is",
            "your purpose is",
        ]

        content_lower = content.lower()
        return any(keyword in content_lower for keyword in role_keywords)

    def _update_ml_patterns(self) -> None:
        """Update ML-discovered patterns from pattern manager."""
        if not self.pattern_manager:
            return

        try:
            # Get active patterns from manager
            from datetime import timedelta

            # Update every 5 minutes
            if (
                not self.ml_patterns_last_update
                or datetime.utcnow() - self.ml_patterns_last_update > timedelta(minutes=5)
            ):
                self.ml_patterns = self.pattern_manager.get_active_patterns()
                self.ml_patterns_last_update = datetime.utcnow()

        except Exception:
            # Silently fail to not break detection
            pass

    def _check_ml_patterns(self, content: str) -> list[tuple[str, float, str]]:
        """Check content against ML-discovered patterns."""
        matches = []

        # Update patterns if needed
        self._update_ml_patterns()

        # Check each ML pattern (tuple format: pattern, confidence, description)
        for pattern_tuple in self.ml_patterns:
            try:
                if isinstance(pattern_tuple, tuple) and len(pattern_tuple) >= 3:
                    pattern_str, confidence, description = pattern_tuple[:3]
                    if re.search(pattern_str, content, re.IGNORECASE):
                        matches.append(
                            (
                                pattern_str,
                                confidence,
                                f"ML Pattern: {description}",
                            )
                        )
            except Exception:
                # Skip failed patterns
                continue

        return matches

    def _check_prompt_leak(self, content: str) -> bool:
        """Check for prompt leak attempts."""
        leak_keywords = [
            "show me your prompt",
            "what are your instructions",
            "repeat your system message",
            "print your directives",
            "display your configuration",
            "tell me your rules",
        ]

        content_lower = content.lower()
        return any(keyword in content_lower for keyword in leak_keywords)

    def _determine_verdict(self, confidence: float, reasons: list[DetectionReason]) -> Verdict:
        """Determine verdict based on confidence and detection mode."""
        if not reasons:
            return Verdict.ALLOW

        from prompt_sentinel.detection.config import get_thresholds

        thresholds = get_thresholds(self.detection_mode)
        if confidence >= thresholds["block"]:
            return Verdict.BLOCK
        elif confidence >= thresholds["strip"]:
            return Verdict.STRIP
        elif confidence >= thresholds["flag"]:
            return Verdict.FLAG
        else:
            return Verdict.ALLOW

    def get_statistics(self, messages: list[Message]) -> dict[str, Any]:
        """Get detection statistics for messages."""
        messages_by_role: dict[str, int] = {}
        for message in messages:
            role = message.role.value
            messages_by_role[role] = messages_by_role.get(role, 0) + 1

        stats = {
            "total_messages": len(messages),
            "patterns_checked": {
                "direct_injection": len(self.direct_injection_patterns),
                "jailbreak": len(self.jailbreak_patterns),
                "encoding": len(self.encoding_patterns),
                "context_switching": len(self.context_switching_patterns),
            },
            "detection_mode": self.detection_mode,
            "messages_by_role": messages_by_role,
        }

        return stats
