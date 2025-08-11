# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Custom PII rules loader for loading user-defined detection patterns from YAML.

This module provides functionality to load, validate, and compile custom PII
detection rules from YAML configuration files. Rules are loaded at startup
and merged with built-in detection patterns.

Security considerations:
- YAML safe loading to prevent code injection
- Regex validation to prevent ReDoS attacks
- File permissions verification
- Immutable rules after loading
"""

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog
import yaml

logger = structlog.get_logger()


@dataclass
class CustomPIIPattern:
    """Represents a single custom PII detection pattern.

    Attributes:
        regex: The regular expression pattern
        confidence: Detection confidence score (0.0-1.0)
        description: Human-readable description
        compiled_pattern: Pre-compiled regex for performance
    """

    regex: str
    confidence: float
    description: str
    compiled_pattern: re.Pattern | None = None

    def compile(self) -> None:
        """Compile the regex pattern for efficient matching."""
        try:
            self.compiled_pattern = re.compile(self.regex, re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern '{self.regex}': {e}") from e


@dataclass
class CustomPIIRule:
    """Represents a complete custom PII detection rule.

    Attributes:
        name: Unique identifier for the rule
        description: Human-readable description
        enabled: Whether the rule is active
        severity: Impact level (low/medium/high/critical)
        patterns: List of detection patterns
        mask_format: Format string for masking detected values
        hash_prefix: Prefix for hashed values
    """

    name: str
    description: str
    enabled: bool
    severity: str
    patterns: list[CustomPIIPattern]
    mask_format: str
    hash_prefix: str

    def validate(self) -> None:
        """Validate the rule configuration."""
        if not self.name:
            raise ValueError("Rule name is required")

        if self.severity not in ["low", "medium", "high", "critical"]:
            raise ValueError(
                f"Invalid severity '{self.severity}'. Must be low/medium/high/critical"
            )

        if not self.patterns:
            raise ValueError(f"Rule '{self.name}' must have at least one pattern")

        for pattern in self.patterns:
            if not 0.0 <= pattern.confidence <= 1.0:
                raise ValueError(
                    f"Confidence must be between 0.0 and 1.0, got {pattern.confidence}"
                )
            pattern.compile()  # Validate and compile regex


class CustomPIIRulesLoader:
    """Loads and manages custom PII detection rules from YAML configuration.

    This loader provides secure loading of custom PII rules with validation,
    regex compilation, and ReDoS prevention.
    """

    def __init__(self, config_path: str | Path | None = None):
        """Initialize the custom rules loader.

        Args:
            config_path: Path to the YAML configuration file
        """
        self.config_path = Path(config_path) if config_path else None
        self.rules: list[CustomPIIRule] = []
        self.settings: dict[str, Any] = {}
        self._loaded = False

    def load_rules(self, config_path: str | Path | None = None) -> list[CustomPIIRule]:
        """Load custom PII rules from YAML configuration file.

        Args:
            config_path: Optional path override for configuration file

        Returns:
            List of validated CustomPIIRule objects

        Raises:
            FileNotFoundError: If configuration file doesn't exist
            PermissionError: If file permissions are insecure
            ValueError: If YAML is invalid or rules fail validation
        """
        if config_path:
            self.config_path = Path(config_path)

        if not self.config_path:
            logger.info("No custom PII rules configuration path provided")
            return []

        if not self.config_path.exists():
            logger.warning(f"Custom PII rules file not found: {self.config_path}")
            return []

        # Security: Check file permissions (should not be world-writable)
        self._check_file_permissions()

        try:
            # Security: Use safe_load to prevent code injection
            with open(self.config_path) as f:
                config = yaml.safe_load(f)

            if not config:
                logger.warning("Empty custom PII rules configuration")
                return []

            # Validate version
            version = config.get("version", "1.0")
            if version not in ["1.0", "1.1"]:
                raise ValueError(f"Unsupported configuration version: {version}")

            # Load settings
            self.settings = config.get("settings", {})

            # Load and validate rules
            rules_config = config.get("custom_pii_rules", [])
            self.rules = self._parse_rules(rules_config)

            self._loaded = True
            logger.info(f"Loaded {len(self.rules)} custom PII rules from {self.config_path}")

            return self.rules

        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in {self.config_path}: {e}") from e
        except Exception as e:
            logger.error(f"Failed to load custom PII rules: {e}")
            raise

    def _check_file_permissions(self) -> None:
        """Check that configuration file has secure permissions.

        Raises:
            PermissionError: If file is world-writable
        """
        if not self.config_path:
            return

        # Check if file is world-writable (security risk)
        stat_info = os.stat(self.config_path)
        mode = stat_info.st_mode

        # Check for world-writable permission (002 bit)
        if mode & 0o002:
            raise PermissionError(
                f"Custom PII rules file {self.config_path} is world-writable. "
                "Please restrict permissions for security (e.g., chmod 644)"
            )

    def _parse_rules(self, rules_config: list[dict[str, Any]]) -> list[CustomPIIRule]:
        """Parse and validate rules from configuration.

        Args:
            rules_config: List of rule dictionaries from YAML

        Returns:
            List of validated CustomPIIRule objects
        """
        rules = []

        for rule_dict in rules_config:
            try:
                # Parse patterns
                patterns = []
                for pattern_dict in rule_dict.get("patterns", []):
                    pattern = CustomPIIPattern(
                        regex=pattern_dict["regex"],
                        confidence=float(pattern_dict["confidence"]),
                        description=pattern_dict.get("description", ""),
                    )
                    patterns.append(pattern)

                # Parse redaction settings
                redaction = rule_dict.get("redaction", {})

                # Create rule
                rule = CustomPIIRule(
                    name=rule_dict["name"],
                    description=rule_dict.get("description", ""),
                    enabled=rule_dict.get("enabled", True),
                    severity=rule_dict.get("severity", "medium"),
                    patterns=patterns,
                    mask_format=redaction.get("mask_format", "****"),
                    hash_prefix=redaction.get("hash_prefix", ""),
                )

                # Validate rule (includes regex compilation and ReDoS check)
                rule.validate()

                # Check regex complexity to prevent ReDoS
                max_complexity = self.settings.get("max_regex_complexity", 100)
                skip_rule = False
                for pattern in rule.patterns:
                    if self._estimate_regex_complexity(pattern.regex) > max_complexity:
                        logger.warning(
                            f"Pattern '{pattern.regex}' in rule '{rule.name}' "
                            f"exceeds complexity limit, skipping entire rule for safety"
                        )
                        skip_rule = True
                        break

                if not skip_rule and rule.enabled:
                    rules.append(rule)
                else:
                    logger.debug(f"Skipping disabled rule: {rule.name}")

            except Exception as e:
                logger.error(f"Failed to parse rule: {e}")
                if self.settings.get("strict_validation", False):
                    raise
                continue

        return rules

    def _estimate_regex_complexity(self, pattern: str) -> int:
        """Estimate regex complexity to prevent ReDoS attacks.

        Args:
            pattern: Regular expression pattern

        Returns:
            Estimated complexity score
        """
        complexity = 0

        # Count potentially dangerous constructs
        complexity += pattern.count("*") * 10  # Kleene star
        complexity += pattern.count("+") * 10  # Plus quantifier
        complexity += pattern.count("{") * 5  # Counted repetition
        complexity += pattern.count("(?") * 15  # Lookahead/lookbehind
        complexity += len(re.findall(r"\(.*\)\*", pattern)) * 20  # Nested quantifiers
        complexity += len(re.findall(r"\(.*\)\+", pattern)) * 20  # Nested quantifiers

        # Penalize alternation with quantifiers
        if "|" in pattern and ("*" in pattern or "+" in pattern):
            complexity += 30

        return complexity

    def get_patterns_for_detection(self) -> dict[str, list[tuple[str, float, str]]]:
        """Get patterns formatted for integration with PIIDetector.

        Returns:
            Dictionary mapping rule names to list of (pattern, confidence, description) tuples
        """
        patterns_dict = {}

        for rule in self.rules:
            if not rule.enabled:
                continue

            patterns_list = []
            for pattern in rule.patterns:
                patterns_list.append(
                    (pattern.regex, pattern.confidence, pattern.description or rule.description)
                )

            patterns_dict[rule.name] = patterns_list

        return patterns_dict

    def get_redaction_config(self) -> dict[str, dict[str, str]]:
        """Get redaction configuration for custom rules.

        Returns:
            Dictionary mapping rule names to redaction settings
        """
        redaction_config = {}

        for rule in self.rules:
            if not rule.enabled:
                continue

            redaction_config[rule.name] = {
                "mask_format": rule.mask_format,
                "hash_prefix": rule.hash_prefix,
                "severity": rule.severity,
            }

        return redaction_config

    def validate_rules(self, rules_yaml: str) -> tuple[bool, list[str]]:
        """Validate YAML rules without loading them.

        Args:
            rules_yaml: YAML string containing rules to validate

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        try:
            # Parse YAML
            config = yaml.safe_load(rules_yaml)

            if not config:
                errors.append("Empty configuration")
                return False, errors

            # Check version
            version = config.get("version")
            if not version:
                errors.append("Missing version field")
            elif version not in ["1.0", "1.1"]:
                errors.append(f"Unsupported version: {version}")

            # Validate each rule
            rules_config = config.get("custom_pii_rules", [])
            if not rules_config:
                errors.append("No rules defined")

            for i, rule_dict in enumerate(rules_config):
                rule_errors = self._validate_rule_dict(rule_dict, i)
                errors.extend(rule_errors)

        except yaml.YAMLError as e:
            errors.append(f"Invalid YAML: {e}")
        except Exception as e:
            errors.append(f"Validation error: {e}")

        return len(errors) == 0, errors

    def _validate_rule_dict(self, rule_dict: dict[str, Any], index: int) -> list[str]:
        """Validate a single rule dictionary.

        Args:
            rule_dict: Rule configuration dictionary
            index: Rule index for error messages

        Returns:
            List of validation errors
        """
        errors = []
        rule_name = rule_dict.get("name", f"Rule_{index}")

        # Check required fields
        if not rule_dict.get("name"):
            errors.append(f"Rule {index}: Missing 'name' field")

        if not rule_dict.get("patterns"):
            errors.append(f"{rule_name}: No patterns defined")

        # Validate severity
        severity = rule_dict.get("severity", "medium")
        if severity not in ["low", "medium", "high", "critical"]:
            errors.append(f"{rule_name}: Invalid severity '{severity}'")

        # Validate patterns
        for j, pattern_dict in enumerate(rule_dict.get("patterns", [])):
            if not pattern_dict.get("regex"):
                errors.append(f"{rule_name}, Pattern {j}: Missing regex")
                continue

            # Test regex compilation
            try:
                re.compile(pattern_dict["regex"])
            except re.error as e:
                errors.append(f"{rule_name}, Pattern {j}: Invalid regex - {e}")

            # Check confidence
            confidence = pattern_dict.get("confidence", 0)
            if not 0.0 <= confidence <= 1.0:
                errors.append(f"{rule_name}, Pattern {j}: Confidence must be 0.0-1.0")

        return errors

    def test_rules(self, text: str) -> list[dict[str, Any]]:
        """Test custom rules against sample text.

        Args:
            text: Sample text to test against

        Returns:
            List of detection results
        """
        results = []

        for rule in self.rules:
            if not rule.enabled:
                continue

            for pattern in rule.patterns:
                if pattern.compiled_pattern:
                    matches = pattern.compiled_pattern.findall(text)
                    if matches:
                        results.append(
                            {
                                "rule_name": rule.name,
                                "description": rule.description,
                                "pattern": pattern.regex,
                                "confidence": pattern.confidence,
                                "severity": rule.severity,
                                "matches": matches,
                                "mask_format": rule.mask_format,
                            }
                        )

        return results
