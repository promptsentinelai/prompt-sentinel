# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Pattern extraction from threat indicators."""

import re

import structlog

from .models import AttackTechnique, ThreatIndicator

logger = structlog.get_logger()


class PatternExtractor:
    """Extracts detection patterns from threat indicators."""

    def __init__(self) -> None:
        """Initialize pattern extractor."""
        self.technique_patterns = {
            AttackTechnique.JAILBREAK: [
                r"(DAN|dan)\s+(mode|prompt)",
                r"developer\s+mode",
                r"(ignore|disregard|forget)\s+(all\s+)?(previous|prior)",
                r"(unlock|enable|activate)\s+(hidden|secret|advanced)",
            ],
            AttackTechnique.ROLE_PLAY: [
                r"(you are|you're)\s+(now|going to be|a)",
                r"(act|pretend)\s+(as|like|to be)",
                r"(roleplay|role-play|role play)",
                r"(character|persona|personality)",
            ],
            AttackTechnique.INSTRUCTION_OVERRIDE: [
                r"(new|updated?)\s+(instruction|directive|command)",
                r"(override|replace|modify)\s+(instruction|rule)",
                r"from\s+now\s+on",
                r"going\s+forward",
            ],
            AttackTechnique.CONTEXT_MANIPULATION: [
                r"(system|user|assistant)\s*:",
                r"###\s*(system|instruction|context)",
                r"\[.*\]\s*:",
                r"<\|(system|im_start|im_end)\|>",
            ],
            AttackTechnique.ENCODING_OBFUSCATION: [
                r"[A-Za-z0-9+/]{20,}={0,2}",  # Base64
                r"\\x[0-9a-fA-F]{2}",  # Hex
                r"\\u[0-9a-fA-F]{4}",  # Unicode
                r"(%[0-9a-fA-F]{2}){3,}",  # URL encoding
            ],
            AttackTechnique.PROMPT_LEAKING: [
                r"(repeat|print|output|echo)\s+(the\s+)?(above|previous|prior)",
                r"what\s+(is|are|was|were)\s+(your|the)\s+(instruction|prompt)",
                r"(reveal|show|display)\s+(your|the)\s+(prompt|instruction)",
            ],
            AttackTechnique.INDIRECT_INJECTION: [
                r"(fetch|retrieve|load|get)\s+.*(url|website|link)",
                r"(read|parse|process)\s+.*(file|document|data)",
                r"(execute|run|eval)\s+.*(code|script|command)",
            ],
        }

    def extract_patterns(self, indicator: ThreatIndicator) -> list[tuple[str, float, str]]:
        """Extract detection patterns from indicator.

        Args:
            indicator: Threat indicator

        Returns:
            List of (pattern, confidence, description) tuples
        """
        patterns = []

        # Extract from main pattern field
        if indicator.pattern:
            patterns.append((indicator.pattern, indicator.confidence, indicator.description))

        # Extract from test cases
        if indicator.test_cases:
            for test_case in indicator.test_cases:
                extracted = self._extract_pattern_from_text(test_case, indicator.technique)
                if extracted:
                    patterns.append(
                        (
                            extracted,
                            indicator.confidence * 0.9,
                            f"Extracted: {indicator.description}",
                        )
                    )

        # Deduplicate patterns
        unique_patterns = []
        seen = set()
        for pattern, conf, desc in patterns:
            if pattern not in seen:
                seen.add(pattern)
                unique_patterns.append((pattern, conf, desc))

        return unique_patterns

    def classify_technique(self, text: str) -> AttackTechnique:
        """Classify attack technique from text.

        Args:
            text: Attack text or pattern

        Returns:
            Detected attack technique
        """
        text_lower = text.lower()
        best_match = AttackTechnique.UNKNOWN
        best_score = 0

        for technique, patterns in self.technique_patterns.items():
            score = sum(1 for pattern in patterns if re.search(pattern, text_lower, re.IGNORECASE))
            if score > best_score:
                best_score = score
                best_match = technique

        return best_match

    def generate_regex(
        self, examples: list[str], technique: AttackTechnique | None = None
    ) -> str | None:
        """Generate regex pattern from examples.

        Args:
            examples: Example attack strings
            technique: Known technique (optional)

        Returns:
            Generated regex pattern or None
        """
        if not examples:
            return None

        try:
            # Find common substrings
            common = self._find_common_patterns(examples)
            if not common:
                return None

            # Build regex
            parts = []
            for pattern in common:
                # Escape special regex characters
                escaped = re.escape(pattern)
                # Allow some flexibility
                escaped = escaped.replace(r"\ ", r"\s+")
                parts.append(escaped)

            if parts:
                return "|".join(parts)

        except Exception as e:
            logger.warning("Failed to generate regex", error=str(e))

        return None

    def validate_pattern(self, pattern: str) -> bool:
        """Validate a regex pattern.

        Args:
            pattern: Regex pattern

        Returns:
            True if valid
        """
        try:
            re.compile(pattern)
            return True
        except re.error:
            return False

    # Private methods

    def _extract_pattern_from_text(self, text: str, technique: AttackTechnique) -> str | None:
        """Extract pattern from text based on technique."""
        if technique == AttackTechnique.UNKNOWN:
            technique = self.classify_technique(text)

        if technique in self.technique_patterns:
            # Find matching patterns
            for pattern in self.technique_patterns[technique]:
                if re.search(pattern, text, re.IGNORECASE):
                    # Extract the matching portion
                    match = re.search(pattern, text, re.IGNORECASE)
                    if match:
                        # Create a more specific pattern
                        matched_text = match.group(0)
                        # Escape and generalize
                        escaped = re.escape(matched_text)
                        # Replace numbers with \d+
                        escaped = re.sub(r"\\\d+", r"\\d+", escaped)
                        # Replace spaces with \s+
                        escaped = escaped.replace(r"\ ", r"\s+")
                        return escaped

        return None

    def _find_common_patterns(self, texts: list[str], min_length: int = 5) -> list[str]:
        """Find common patterns in texts."""
        if len(texts) < 2:
            return []

        common_patterns: list[str] = []

        # Use first text as reference
        reference = texts[0].lower()

        # Find common substrings
        for length in range(len(reference), min_length - 1, -1):
            for start in range(len(reference) - length + 1):
                substring = reference[start : start + length]

                # Check if substring appears in all texts
                if all(substring in text.lower() for text in texts[1:]):
                    # Avoid overlapping patterns
                    if not any(substring in p for p in common_patterns):
                        common_patterns.append(substring)

        return common_patterns
