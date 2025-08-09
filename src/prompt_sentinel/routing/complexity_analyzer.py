"""Advanced complexity analysis for intelligent routing decisions.

This module extends the basic complexity metrics from PromptProcessor
to provide sophisticated analysis for routing decisions. It evaluates
multiple dimensions of prompt complexity to determine the optimal
detection strategy.
"""

import re
import math
from typing import Dict, List, Tuple, Optional
from enum import Enum
from dataclasses import dataclass

from prompt_sentinel.models.schemas import Message, Role


class ComplexityLevel(Enum):
    """Prompt complexity levels for routing decisions."""

    TRIVIAL = "trivial"  # Very simple, safe prompts
    SIMPLE = "simple"  # Basic prompts, low risk
    MODERATE = "moderate"  # Standard complexity
    COMPLEX = "complex"  # High complexity, needs thorough analysis
    CRITICAL = "critical"  # Very complex or suspicious, full analysis


class RiskIndicator(Enum):
    """Risk indicators that affect routing decisions."""

    ENCODING = "encoding"
    ROLE_MANIPULATION = "role_manipulation"
    INSTRUCTION_OVERRIDE = "instruction_override"
    CODE_INJECTION = "code_injection"
    EXCESSIVE_LENGTH = "excessive_length"
    UNUSUAL_PATTERNS = "unusual_patterns"
    MULTI_LANGUAGE = "multi_language"
    OBFUSCATION = "obfuscation"


@dataclass
class ComplexityScore:
    """Detailed complexity analysis result."""

    level: ComplexityLevel
    score: float  # 0.0 to 1.0
    risk_indicators: List[RiskIndicator]
    metrics: Dict[str, float]
    reasoning: str
    recommended_strategy: str


class ComplexityAnalyzer:
    """Analyzes prompt complexity for intelligent routing decisions.

    This analyzer evaluates multiple dimensions of prompt complexity
    to determine the optimal detection strategy, balancing security
    needs with performance requirements.
    """

    # Thresholds for complexity levels
    COMPLEXITY_THRESHOLDS = {
        ComplexityLevel.TRIVIAL: 0.1,
        ComplexityLevel.SIMPLE: 0.3,
        ComplexityLevel.MODERATE: 0.5,
        ComplexityLevel.COMPLEX: 0.7,
        ComplexityLevel.CRITICAL: 0.9,
    }

    # Weights for different complexity factors
    FACTOR_WEIGHTS = {
        "length_score": 0.15,
        "special_char_score": 0.20,
        "encoding_score": 0.25,
        "pattern_score": 0.20,
        "semantic_score": 0.20,
    }

    def analyze(self, messages: List[Message]) -> ComplexityScore:
        """Perform comprehensive complexity analysis on messages.

        Args:
            messages: List of messages to analyze

        Returns:
            ComplexityScore with detailed analysis results
        """
        # Combine all message content for analysis
        combined_content = " ".join(msg.content for msg in messages)

        # Calculate individual complexity factors
        metrics = {}
        risk_indicators = []

        # 1. Length complexity
        length_score = self._calculate_length_complexity(combined_content)
        metrics["length_score"] = length_score

        if length_score > 0.8:
            risk_indicators.append(RiskIndicator.EXCESSIVE_LENGTH)

        # 2. Special character complexity
        special_char_score = self._calculate_special_char_complexity(combined_content)
        metrics["special_char_score"] = special_char_score

        # 3. Encoding complexity
        encoding_score, encoding_risks = self._calculate_encoding_complexity(combined_content)
        metrics["encoding_score"] = encoding_score
        risk_indicators.extend(encoding_risks)

        # 4. Pattern complexity
        pattern_score, pattern_risks = self._calculate_pattern_complexity(combined_content)
        metrics["pattern_score"] = pattern_score
        risk_indicators.extend(pattern_risks)

        # 5. Semantic complexity
        semantic_score, semantic_risks = self._calculate_semantic_complexity(messages)
        metrics["semantic_score"] = semantic_score
        risk_indicators.extend(semantic_risks)

        # Calculate weighted overall score
        overall_score = sum(
            metrics.get(factor, 0) * weight for factor, weight in self.FACTOR_WEIGHTS.items()
        )

        # Boost score if critical risk indicators are present
        if any(
            risk in risk_indicators
            for risk in [
                RiskIndicator.INSTRUCTION_OVERRIDE,
                RiskIndicator.CODE_INJECTION,
                RiskIndicator.ROLE_MANIPULATION,
            ]
        ):
            overall_score = min(1.0, overall_score * 1.3)

        # Determine complexity level
        level = self._determine_complexity_level(overall_score)

        # Generate reasoning
        reasoning = self._generate_reasoning(level, metrics, risk_indicators)

        # Recommend detection strategy
        strategy = self._recommend_strategy(level, risk_indicators)

        return ComplexityScore(
            level=level,
            score=overall_score,
            risk_indicators=list(set(risk_indicators)),
            metrics=metrics,
            reasoning=reasoning,
            recommended_strategy=strategy,
        )

    def _calculate_length_complexity(self, content: str) -> float:
        """Calculate complexity based on content length.

        Args:
            content: Text content to analyze

        Returns:
            Normalized complexity score (0.0 to 1.0)
        """
        length = len(content)
        word_count = len(content.split())

        # Use logarithmic scaling for length
        if length < 100:
            length_score = 0.1
        elif length < 500:
            length_score = 0.3
        elif length < 1000:
            length_score = 0.5
        elif length < 5000:
            length_score = 0.7
        else:
            # Very long prompts are inherently more complex
            length_score = min(1.0, 0.7 + (length - 5000) / 10000)

        # Consider word density (characters per word)
        avg_word_length = length / max(word_count, 1)
        if avg_word_length > 10:  # Unusually long "words" might indicate encoding
            length_score = min(1.0, length_score * 1.2)

        return length_score

    def _calculate_special_char_complexity(self, content: str) -> float:
        """Calculate complexity based on special characters.

        Args:
            content: Text content to analyze

        Returns:
            Normalized complexity score (0.0 to 1.0)
        """
        if not content:
            return 0.0

        # Count different types of special characters
        special_chars = sum(1 for c in content if not c.isalnum() and not c.isspace())
        special_ratio = special_chars / len(content)

        # Check for specific suspicious patterns
        suspicious_patterns = [
            r"[^\x00-\x7F]",  # Non-ASCII characters
            r"[\x00-\x1F\x7F]",  # Control characters
            r"{{.*?}}",  # Template injection patterns
            r"\${.*?}",  # Variable substitution
            r"`.*?`",  # Backticks (command execution)
        ]

        pattern_count = sum(1 for pattern in suspicious_patterns if re.search(pattern, content))

        # Calculate score
        base_score = min(1.0, special_ratio * 3)  # Scale ratio to 0-1
        pattern_boost = pattern_count * 0.1

        return min(1.0, base_score + pattern_boost)

    def _calculate_encoding_complexity(self, content: str) -> Tuple[float, List[RiskIndicator]]:
        """Calculate complexity based on encoding patterns.

        Args:
            content: Text content to analyze

        Returns:
            Tuple of (complexity score, list of risk indicators)
        """
        score = 0.0
        risks = []

        # Check for base64
        base64_pattern = r"[A-Za-z0-9+/]{20,}={0,2}"
        base64_matches = re.findall(base64_pattern, content)
        if base64_matches:
            score += 0.3 * min(len(base64_matches), 3)
            if len(base64_matches) > 2 or any(len(m) > 100 for m in base64_matches):
                risks.append(RiskIndicator.ENCODING)

        # Check for hex encoding
        hex_pattern = r"(?:\\x[0-9a-fA-F]{2}){3,}"
        if re.search(hex_pattern, content):
            score += 0.3
            risks.append(RiskIndicator.ENCODING)

        # Check for unicode encoding
        unicode_pattern = r"(?:\\u[0-9a-fA-F]{4}){3,}"
        if re.search(unicode_pattern, content):
            score += 0.2
            risks.append(RiskIndicator.ENCODING)

        # Check for URL encoding
        url_encoded = r"(?:%[0-9a-fA-F]{2}){3,}"
        if re.search(url_encoded, content):
            score += 0.2
            risks.append(RiskIndicator.ENCODING)

        # Check for potential obfuscation
        if self._detect_obfuscation(content):
            score += 0.3
            risks.append(RiskIndicator.OBFUSCATION)

        return min(1.0, score), risks

    def _calculate_pattern_complexity(self, content: str) -> Tuple[float, List[RiskIndicator]]:
        """Calculate complexity based on suspicious patterns.

        Args:
            content: Text content to analyze

        Returns:
            Tuple of (complexity score, list of risk indicators)
        """
        score = 0.0
        risks = []

        # Instruction override patterns
        override_patterns = [
            r"ignore.*(?:previous|above|prior|preceding)",
            r"disregard.*(?:instructions|rules|constraints)",
            r"forget.*(?:everything|all|previous)",
            r"new.*(?:instructions|rules|task)",
            r"actually.*(?:ignore|disregard|forget)",
        ]

        override_count = sum(
            1 for pattern in override_patterns if re.search(pattern, content, re.IGNORECASE)
        )

        if override_count > 0:
            score += 0.4 * min(override_count, 2)
            risks.append(RiskIndicator.INSTRUCTION_OVERRIDE)

        # Code injection patterns
        code_patterns = [
            r"<script[^>]*>",
            r"javascript:",
            r"eval\s*\(",
            r"exec\s*\(",
            r"system\s*\(",
            r"import\s+os",
            r"require\s*\(",
        ]

        code_count = sum(
            1 for pattern in code_patterns if re.search(pattern, content, re.IGNORECASE)
        )

        if code_count > 0:
            score += 0.3 * min(code_count, 3)
            risks.append(RiskIndicator.CODE_INJECTION)

        # Unusual repetition patterns
        repetition_pattern = r"(.{10,})\1{3,}"
        if re.search(repetition_pattern, content):
            score += 0.2
            risks.append(RiskIndicator.UNUSUAL_PATTERNS)

        return min(1.0, score), risks

    def _calculate_semantic_complexity(
        self, messages: List[Message]
    ) -> Tuple[float, List[RiskIndicator]]:
        """Calculate complexity based on semantic analysis.

        Args:
            messages: List of messages to analyze

        Returns:
            Tuple of (complexity score, list of risk indicators)
        """
        score = 0.0
        risks = []

        # Check for role manipulation
        role_manipulation_indicators = [
            "you are",
            "you're now",
            "act as",
            "pretend to be",
            "roleplay",
            "simulate",
            "impersonate",
            "behave as",
        ]

        for msg in messages:
            if msg.role == Role.USER:
                content_lower = msg.content.lower()
                manipulation_count = sum(
                    1 for indicator in role_manipulation_indicators if indicator in content_lower
                )
                if manipulation_count > 0:
                    score += 0.3 * min(manipulation_count, 2)
                    risks.append(RiskIndicator.ROLE_MANIPULATION)

        # Check for multiple languages (potential bypass attempt)
        if self._detect_multiple_languages(messages):
            score += 0.2
            risks.append(RiskIndicator.MULTI_LANGUAGE)

        # Check message structure complexity
        if len(messages) > 5:
            score += 0.1 * min((len(messages) - 5) / 5, 0.3)

        # Check for system message in user content
        system_in_user = any(
            msg.role == Role.USER
            and any(
                keyword in msg.content.lower() for keyword in ["system:", "[system]", "<system>"]
            )
            for msg in messages
        )
        if system_in_user:
            score += 0.3
            risks.append(RiskIndicator.ROLE_MANIPULATION)

        return min(1.0, score), risks

    def _detect_obfuscation(self, content: str) -> bool:
        """Detect potential obfuscation techniques.

        Args:
            content: Text content to analyze

        Returns:
            True if obfuscation is detected
        """
        # Zero-width characters
        zero_width = ["\u200b", "\u200c", "\u200d", "\ufeff"]
        if any(char in content for char in zero_width):
            return True

        # Excessive whitespace
        if re.search(r"\s{10,}", content):
            return True

        # Mixed case patterns (LiKe ThIs)
        mixed_case_pattern = r"(?:[a-z][A-Z]|[A-Z][a-z]){5,}"
        if re.search(mixed_case_pattern, content):
            return True

        # Homoglyph detection (simplified)
        homoglyphs = {"0": "O", "1": "l", "3": "E"}
        suspicious_substitutions = sum(
            1
            for char, substitute in homoglyphs.items()
            if f"{char}{substitute}" in content or f"{substitute}{char}" in content
        )

        return suspicious_substitutions > 3

    def _detect_multiple_languages(self, messages: List[Message]) -> bool:
        """Detect if multiple languages are used (simplified).

        Args:
            messages: List of messages to analyze

        Returns:
            True if multiple languages detected
        """
        # Simplified detection using character ranges
        scripts_found = set()

        for msg in messages:
            content = msg.content

            # Check for different script types
            if re.search(r"[a-zA-Z]", content):
                scripts_found.add("latin")
            if re.search(r"[\u4e00-\u9fff]", content):
                scripts_found.add("chinese")
            if re.search(r"[\u0400-\u04ff]", content):
                scripts_found.add("cyrillic")
            if re.search(r"[\u0600-\u06ff]", content):
                scripts_found.add("arabic")
            if re.search(r"[\u3040-\u309f\u30a0-\u30ff]", content):
                scripts_found.add("japanese")

        return len(scripts_found) > 1

    def _determine_complexity_level(self, score: float) -> ComplexityLevel:
        """Determine complexity level from score.

        Args:
            score: Overall complexity score (0.0 to 1.0)

        Returns:
            ComplexityLevel enum value
        """
        if score < self.COMPLEXITY_THRESHOLDS[ComplexityLevel.TRIVIAL]:
            return ComplexityLevel.TRIVIAL
        elif score < self.COMPLEXITY_THRESHOLDS[ComplexityLevel.SIMPLE]:
            return ComplexityLevel.SIMPLE
        elif score < self.COMPLEXITY_THRESHOLDS[ComplexityLevel.MODERATE]:
            return ComplexityLevel.MODERATE
        elif score < self.COMPLEXITY_THRESHOLDS[ComplexityLevel.COMPLEX]:
            return ComplexityLevel.COMPLEX
        else:
            return ComplexityLevel.CRITICAL

    def _generate_reasoning(
        self, level: ComplexityLevel, metrics: Dict[str, float], risks: List[RiskIndicator]
    ) -> str:
        """Generate human-readable reasoning for complexity assessment.

        Args:
            level: Determined complexity level
            metrics: Calculated metrics
            risks: Identified risk indicators

        Returns:
            Reasoning string
        """
        reasoning_parts = [f"Complexity level: {level.value}"]

        # Add metric highlights
        high_metrics = [metric for metric, score in metrics.items() if score > 0.6]
        if high_metrics:
            reasoning_parts.append(f"High scores in: {', '.join(high_metrics)}")

        # Add risk highlights
        if risks:
            risk_names = [risk.value for risk in risks[:3]]  # Top 3 risks
            reasoning_parts.append(f"Risk indicators: {', '.join(risk_names)}")

        # Add level-specific reasoning
        level_reasoning = {
            ComplexityLevel.TRIVIAL: "Simple, straightforward prompt with minimal risk",
            ComplexityLevel.SIMPLE: "Basic prompt with low complexity indicators",
            ComplexityLevel.MODERATE: "Standard complexity requiring balanced analysis",
            ComplexityLevel.COMPLEX: "High complexity requiring thorough examination",
            ComplexityLevel.CRITICAL: "Critical complexity with multiple risk indicators",
        }
        reasoning_parts.append(level_reasoning[level])

        return ". ".join(reasoning_parts)

    def _recommend_strategy(self, level: ComplexityLevel, risks: List[RiskIndicator]) -> str:
        """Recommend detection strategy based on analysis.

        Args:
            level: Complexity level
            risks: Identified risk indicators

        Returns:
            Recommended strategy string
        """
        # Critical risks always require full analysis
        critical_risks = [
            RiskIndicator.INSTRUCTION_OVERRIDE,
            RiskIndicator.CODE_INJECTION,
            RiskIndicator.ROLE_MANIPULATION,
        ]

        if any(risk in critical_risks for risk in risks):
            return "full_analysis"

        # Level-based recommendations
        strategies = {
            ComplexityLevel.TRIVIAL: "heuristic_only",
            ComplexityLevel.SIMPLE: "heuristic_cached",
            ComplexityLevel.MODERATE: "heuristic_llm_cached",
            ComplexityLevel.COMPLEX: "heuristic_llm_pii",
            ComplexityLevel.CRITICAL: "full_analysis",
        }

        return strategies[level]
