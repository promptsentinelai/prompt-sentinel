# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Optimized heuristic detection with compiled patterns and performance enhancements."""

import re

import pyahocorasick
import structlog

from prompt_sentinel.models.schemas import (
    DetectionCategory,
    DetectionReason,
    Message,
    Verdict,
)

logger = structlog.get_logger()


class OptimizedHeuristicDetector:
    """High-performance pattern-based detection using Aho-Corasick algorithm."""

    def __init__(self, detection_mode: str = "strict"):
        """
        Initialize optimized detector with pre-compiled patterns.

        Args:
            detection_mode: One of "strict", "moderate", "permissive"
        """
        self.detection_mode = detection_mode
        self.compiled_patterns: dict[str, list[re.Pattern]] = {}
        self.pattern_metadata: dict[str, list[tuple[float, str]]] = {}
        self.aho_automaton: pyahocorasick.Automaton | None = None
        self.keyword_patterns: set[str] = set()

        # Performance stats
        self.stats = {"patterns_checked": 0, "patterns_matched": 0, "early_terminations": 0}

        self._compile_all_patterns()
        self._build_aho_corasick()

    def _compile_all_patterns(self) -> None:
        """Pre-compile all regex patterns for better performance."""
        logger.info("Compiling detection patterns")

        # Pattern categories with compiled regex
        pattern_definitions = {
            "injection": [
                (r"ignore (all )?(previous|prior|above)", 0.9, "Instruction override"),
                (
                    r"disregard (all )?(previous|prior|above|your training)",
                    0.9,
                    "Instruction override",
                ),
                (r"forget (everything|all|previous)", 0.85, "Memory manipulation"),
                (r"new (instructions?|commands?|rules?):", 0.8, "New instruction injection"),
                (r"(you are|you're) now", 0.75, "Role manipulation"),
                (r"act as if you (are|were)", 0.75, "Role manipulation"),
                (r"pretend (you are|to be)", 0.7, "Role pretending"),
                (r"from now on", 0.7, "Context switching"),
            ],
            "jailbreak": [
                (r"(DAN|dan) mode", 0.95, "DAN jailbreak"),
                (r"developer mode", 0.9, "Developer mode attempt"),
                (r"(disable|bypass|ignore) (safety|filters?|restrictions?)", 0.9, "Safety bypass"),
                (r"unlimited power", 0.85, "Unrestricted mode"),
                (r"no (restrictions?|limits?|rules?)", 0.8, "Restriction removal"),
            ],
            "data_extraction": [
                (
                    r"(show|reveal|display) (your )?(system )?(prompt|instructions?)",
                    0.9,
                    "System prompt extraction",
                ),
                (r"what are your (instructions?|rules?|guidelines?)", 0.85, "Instruction fishing"),
                (r"repeat (your |the )?(first|initial|original)", 0.8, "Context extraction"),
                (r"(list|show) all (your )?capabilities", 0.75, "Capability enumeration"),
            ],
            "encoding": [
                (r"base64|base32|hex|binary", 0.7, "Encoding detected"),
                (r"rot13|caesar|cipher", 0.75, "Cipher detected"),
                (r"[A-Za-z0-9+/]{50,}={0,2}", 0.6, "Possible base64"),
            ],
        }

        # Compile patterns
        for category, patterns in pattern_definitions.items():
            self.compiled_patterns[category] = []
            self.pattern_metadata[category] = []

            for pattern_str, confidence, description in patterns:
                try:
                    compiled = re.compile(pattern_str, re.IGNORECASE)
                    self.compiled_patterns[category].append(compiled)
                    self.pattern_metadata[category].append((confidence, description))
                except re.error as e:
                    logger.error("Pattern compilation failed", pattern=pattern_str, error=str(e))

        # Extract keywords for Aho-Corasick
        keywords = [
            "ignore",
            "disregard",
            "forget",
            "override",
            "bypass",
            "jailbreak",
            "DAN",
            "developer mode",
            "unlimited",
            "system prompt",
            "initial instructions",
            "reveal",
            "base64",
            "rot13",
            "cipher",
        ]
        self.keyword_patterns = set(keywords)

    def _build_aho_corasick(self) -> None:
        """Build Aho-Corasick automaton for fast keyword matching."""
        try:
            import pyahocorasick

            self.aho_automaton = pyahocorasick.Automaton()

            # Add all keywords
            for keyword in self.keyword_patterns:
                self.aho_automaton.add_word(keyword.lower(), keyword)

            # Build the automaton
            self.aho_automaton.make_automaton()
            logger.info("Aho-Corasick automaton built", keywords=len(self.keyword_patterns))

        except ImportError:
            logger.warning("pyahocorasick not installed, falling back to regex")
            self.aho_automaton = None

    def detect_fast(self, messages: list[Message]) -> tuple[Verdict, list[DetectionReason], float]:
        """
        Fast detection using optimized patterns.

        Args:
            messages: List of messages to analyze

        Returns:
            Tuple of (verdict, reasons, confidence)
        """
        # Combine messages for analysis
        combined_text = " ".join(msg.content for msg in messages)
        combined_lower = combined_text.lower()

        # Quick keyword check using Aho-Corasick
        if self.aho_automaton and not self._quick_keyword_check(combined_lower):
            # No keywords found, likely safe
            self.stats["early_terminations"] += 1
            return Verdict.SAFE, [], 0.0

        reasons = []
        max_confidence = 0.0

        # Check patterns by category (ordered by severity)
        for category in ["injection", "jailbreak", "data_extraction", "encoding"]:
            if category not in self.compiled_patterns:
                continue

            for pattern, (confidence, description) in zip(
                self.compiled_patterns[category], self.pattern_metadata[category], strict=False
            ):
                self.stats["patterns_checked"] += 1

                if pattern.search(combined_text):
                    self.stats["patterns_matched"] += 1

                    # Adjust confidence based on mode
                    adjusted_confidence = self._adjust_confidence(confidence)
                    max_confidence = max(max_confidence, adjusted_confidence)

                    reasons.append(
                        DetectionReason(
                            category=self._get_category(category),
                            description=description,
                            confidence=adjusted_confidence,
                            source="heuristic",
                        )
                    )

                    # Early termination for high confidence threats
                    if adjusted_confidence >= 0.9:
                        self.stats["early_terminations"] += 1
                        verdict = (
                            Verdict.MALICIOUS if adjusted_confidence >= 0.7 else Verdict.SUSPICIOUS
                        )
                        return verdict, reasons, max_confidence

        # Determine verdict
        if max_confidence >= 0.7:
            verdict = Verdict.MALICIOUS
        elif max_confidence >= 0.4:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.SAFE

        return verdict, reasons, max_confidence

    def _quick_keyword_check(self, text: str) -> bool:
        """
        Quick check for keywords using Aho-Corasick.

        Args:
            text: Text to check (should be lowercase)

        Returns:
            True if any keywords found
        """
        if not self.aho_automaton:
            return True  # Skip optimization if not available

        for _, _ in self.aho_automaton.iter(text):
            return True  # Found at least one keyword

        return False

    def _adjust_confidence(self, base_confidence: float) -> float:
        """
        Adjust confidence based on detection mode.

        Args:
            base_confidence: Base confidence value

        Returns:
            Adjusted confidence
        """
        if self.detection_mode == "strict":
            return min(base_confidence * 1.2, 1.0)
        elif self.detection_mode == "permissive":
            return base_confidence * 0.8
        else:  # moderate
            return base_confidence

    def _get_category(self, category_str: str) -> DetectionCategory:
        """Map category string to enum."""
        mapping = {
            "injection": DetectionCategory.PROMPT_INJECTION,
            "jailbreak": DetectionCategory.JAILBREAK,
            "data_extraction": DetectionCategory.DATA_EXFILTRATION,
            "encoding": DetectionCategory.OBFUSCATION,
        }
        return mapping.get(category_str, DetectionCategory.OTHER)

    def get_stats(self) -> dict[str, int]:
        """Get performance statistics."""
        return self.stats.copy()


class BloomFilterDetector:
    """Bloom filter for fast negative detection of known safe prompts."""

    def __init__(self, expected_items: int = 100000, false_positive_rate: float = 0.01):
        """
        Initialize bloom filter.

        Args:
            expected_items: Expected number of items
            false_positive_rate: Desired false positive rate
        """
        try:
            from pybloom_live import BloomFilter

            self.bloom = BloomFilter(capacity=expected_items, error_rate=false_positive_rate)
            self.enabled = True
            logger.info("Bloom filter initialized", capacity=expected_items)
        except ImportError:
            logger.warning("pybloom_live not installed, bloom filter disabled")
            self.bloom = None
            self.enabled = False

    def add_safe_prompt(self, prompt: str) -> None:
        """Add a known safe prompt to the filter."""
        if self.enabled and self.bloom:
            self.bloom.add(prompt.lower())

    def might_be_safe(self, prompt: str) -> bool:
        """
        Check if prompt might be safe (no false negatives).

        Args:
            prompt: Prompt to check

        Returns:
            True if might be safe, False if definitely not in filter
        """
        if not self.enabled or not self.bloom:
            return False  # Conservative: don't skip detection

        return prompt.lower() in self.bloom

    def bulk_add_safe(self, prompts: list[str]) -> None:
        """Add multiple safe prompts."""
        for prompt in prompts:
            self.add_safe_prompt(prompt)
