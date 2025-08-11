# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Comprehensive tests for custom PII detection rules functionality."""

import os
import tempfile

import pytest

from prompt_sentinel.detection.custom_pii_loader import (
    CustomPIIPattern,
    CustomPIIRule,
    CustomPIIRulesLoader,
)
from prompt_sentinel.detection.pii_detector import PIIDetector


class TestCustomPIIPattern:
    """Test suite for CustomPIIPattern class."""

    def test_pattern_initialization(self):
        """Test pattern initialization with valid data."""
        pattern = CustomPIIPattern(
            regex=r"TEST[0-9]{4}", confidence=0.85, description="Test pattern"
        )

        assert pattern.regex == r"TEST[0-9]{4}"
        assert pattern.confidence == 0.85
        assert pattern.description == "Test pattern"
        assert pattern.compiled_pattern is None

    def test_pattern_compilation(self):
        """Test regex pattern compilation."""
        pattern = CustomPIIPattern(regex=r"EMP[0-9]{6}", confidence=0.9, description="Employee ID")

        pattern.compile()
        assert pattern.compiled_pattern is not None

        # Test matching
        assert pattern.compiled_pattern.search("EMP123456")
        assert not pattern.compiled_pattern.search("EMP12345")  # Too short

    def test_invalid_regex_compilation(self):
        """Test compilation with invalid regex."""
        pattern = CustomPIIPattern(
            regex=r"[invalid(",
            confidence=0.9,
            description="Invalid pattern",  # Invalid regex
        )

        with pytest.raises(ValueError, match="Invalid regex pattern"):
            pattern.compile()


class TestCustomPIIRule:
    """Test suite for CustomPIIRule class."""

    def test_rule_initialization(self):
        """Test rule initialization with valid data."""
        patterns = [CustomPIIPattern(regex=r"TEST[0-9]{4}", confidence=0.9, description="Test")]

        rule = CustomPIIRule(
            name="test_rule",
            description="Test rule",
            enabled=True,
            severity="high",
            patterns=patterns,
            mask_format="TEST****",
            hash_prefix="TEST_",
        )

        assert rule.name == "test_rule"
        assert rule.enabled is True
        assert rule.severity == "high"
        assert len(rule.patterns) == 1

    def test_rule_validation_valid(self):
        """Test validation of a valid rule."""
        patterns = [CustomPIIPattern(regex=r"VALID[0-9]+", confidence=0.8, description="Valid")]

        rule = CustomPIIRule(
            name="valid_rule",
            description="Valid rule",
            enabled=True,
            severity="medium",
            patterns=patterns,
            mask_format="****",
            hash_prefix="VAL_",
        )

        # Should not raise any exception
        rule.validate()

    def test_rule_validation_invalid_severity(self):
        """Test validation with invalid severity."""
        patterns = [CustomPIIPattern(regex=r"TEST[0-9]+", confidence=0.8, description="Test")]

        rule = CustomPIIRule(
            name="invalid_severity",
            description="Invalid severity rule",
            enabled=True,
            severity="extreme",  # Invalid severity
            patterns=patterns,
            mask_format="****",
            hash_prefix="TEST_",
        )

        with pytest.raises(ValueError, match="Invalid severity"):
            rule.validate()

    def test_rule_validation_invalid_confidence(self):
        """Test validation with invalid confidence value."""
        patterns = [
            CustomPIIPattern(
                regex=r"TEST[0-9]+", confidence=1.5, description="Test"
            )  # Invalid confidence
        ]

        rule = CustomPIIRule(
            name="invalid_confidence",
            description="Invalid confidence rule",
            enabled=True,
            severity="high",
            patterns=patterns,
            mask_format="****",
            hash_prefix="TEST_",
        )

        with pytest.raises(ValueError, match="Confidence must be between"):
            rule.validate()

    def test_rule_validation_no_patterns(self):
        """Test validation with no patterns."""
        rule = CustomPIIRule(
            name="no_patterns",
            description="No patterns rule",
            enabled=True,
            severity="high",
            patterns=[],  # No patterns
            mask_format="****",
            hash_prefix="TEST_",
        )

        with pytest.raises(ValueError, match="must have at least one pattern"):
            rule.validate()


class TestCustomPIIRulesLoader:
    """Test suite for CustomPIIRulesLoader class."""

    @pytest.fixture
    def sample_yaml_config(self):
        """Create a sample YAML configuration."""
        return """
version: "1.0"
custom_pii_rules:
  - name: "employee_id"
    description: "Employee identification number"
    enabled: true
    severity: "high"
    patterns:
      - regex: "EMP[0-9]{6}"
        confidence: 0.95
        description: "Standard employee ID"
    redaction:
      mask_format: "EMP-****"
      hash_prefix: "EMP_"

  - name: "project_code"
    description: "Project codes"
    enabled: true
    severity: "medium"
    patterns:
      - regex: "PROJ-[0-9]{4}-[A-Z]{2}"
        confidence: 0.85
        description: "Project code format"
    redaction:
      mask_format: "PROJ-****-**"
      hash_prefix: "PROJ_"

settings:
  merge_with_builtin: true
  min_confidence_threshold: 0.5
  max_regex_complexity: 100
  cache_compiled_patterns: true
"""

    @pytest.fixture
    def temp_config_file(self, sample_yaml_config):
        """Create a temporary configuration file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(sample_yaml_config)
            temp_path = f.name

        yield temp_path

        # Cleanup
        os.unlink(temp_path)

    def test_loader_initialization(self):
        """Test loader initialization."""
        loader = CustomPIIRulesLoader()
        assert loader.config_path is None
        assert loader.rules == []
        assert loader.settings == {}
        assert loader._loaded is False

    def test_load_rules_from_file(self, temp_config_file):
        """Test loading rules from a YAML file."""
        loader = CustomPIIRulesLoader(temp_config_file)
        rules = loader.load_rules()

        assert len(rules) == 2
        assert rules[0].name == "employee_id"
        assert rules[1].name == "project_code"
        assert loader._loaded is True

    def test_load_rules_nonexistent_file(self):
        """Test loading from a nonexistent file."""
        loader = CustomPIIRulesLoader("nonexistent.yaml")
        rules = loader.load_rules()

        assert rules == []
        assert loader._loaded is False

    def test_load_rules_invalid_yaml(self):
        """Test loading invalid YAML."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("invalid: yaml: content: [")
            temp_path = f.name

        try:
            loader = CustomPIIRulesLoader(temp_path)
            with pytest.raises(ValueError, match="Invalid YAML"):
                loader.load_rules()
        finally:
            os.unlink(temp_path)

    def test_get_patterns_for_detection(self, temp_config_file):
        """Test getting patterns formatted for detection."""
        loader = CustomPIIRulesLoader(temp_config_file)
        loader.load_rules()

        patterns = loader.get_patterns_for_detection()

        assert "employee_id" in patterns
        assert "project_code" in patterns
        assert len(patterns["employee_id"]) == 1
        assert patterns["employee_id"][0][0] == "EMP[0-9]{6}"  # regex
        assert patterns["employee_id"][0][1] == 0.95  # confidence

    def test_get_redaction_config(self, temp_config_file):
        """Test getting redaction configuration."""
        loader = CustomPIIRulesLoader(temp_config_file)
        loader.load_rules()

        redaction = loader.get_redaction_config()

        assert "employee_id" in redaction
        assert redaction["employee_id"]["mask_format"] == "EMP-****"
        assert redaction["employee_id"]["hash_prefix"] == "EMP_"
        assert redaction["employee_id"]["severity"] == "high"

    def test_validate_rules_valid(self, sample_yaml_config):
        """Test validation of valid YAML rules."""
        loader = CustomPIIRulesLoader()
        is_valid, errors = loader.validate_rules(sample_yaml_config)

        assert is_valid is True
        assert errors == []

    def test_validate_rules_invalid(self):
        """Test validation of invalid YAML rules."""
        invalid_yaml = """
version: "1.0"
custom_pii_rules:
  - name: ""  # Empty name
    patterns:
      - regex: "[invalid("  # Invalid regex
        confidence: 2.0  # Invalid confidence
"""
        loader = CustomPIIRulesLoader()
        is_valid, errors = loader.validate_rules(invalid_yaml)

        assert is_valid is False
        assert len(errors) > 0
        assert any("Missing 'name'" in err for err in errors)
        assert any("Invalid regex" in err for err in errors)
        assert any("Confidence must be" in err for err in errors)

    def test_test_rules(self, temp_config_file):
        """Test testing rules against sample text."""
        loader = CustomPIIRulesLoader(temp_config_file)
        loader.load_rules()

        test_text = "Employee EMP123456 is working on PROJ-2024-AB"
        results = loader.test_rules(test_text)

        assert len(results) == 2
        assert any(r["rule_name"] == "employee_id" for r in results)
        assert any(r["rule_name"] == "project_code" for r in results)

    def test_regex_complexity_check(self):
        """Test ReDoS prevention through complexity checking."""
        dangerous_yaml = """
version: "1.0"
custom_pii_rules:
  - name: "dangerous"
    patterns:
      - regex: "(a+)+(b+)+(c+)+"  # Potentially dangerous nested quantifiers
        confidence: 0.9
settings:
  max_regex_complexity: 50  # Low threshold for testing
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(dangerous_yaml)
            temp_path = f.name

        try:
            loader = CustomPIIRulesLoader(temp_path)
            rules = loader.load_rules()
            # Should skip the dangerous pattern
            assert len(rules) == 0 or all(r.name != "dangerous" for r in rules)
        finally:
            os.unlink(temp_path)

    def test_disabled_rules_not_loaded(self):
        """Test that disabled rules are not loaded."""
        yaml_with_disabled = """
version: "1.0"
custom_pii_rules:
  - name: "enabled_rule"
    enabled: true
    severity: "high"
    patterns:
      - regex: "ENABLED[0-9]+"
        confidence: 0.9

  - name: "disabled_rule"
    enabled: false
    severity: "high"
    patterns:
      - regex: "DISABLED[0-9]+"
        confidence: 0.9
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_with_disabled)
            temp_path = f.name

        try:
            loader = CustomPIIRulesLoader(temp_path)
            rules = loader.load_rules()

            assert len(rules) == 1
            assert rules[0].name == "enabled_rule"
        finally:
            os.unlink(temp_path)


class TestPIIDetectorWithCustomRules:
    """Test suite for PIIDetector with custom rules integration."""

    @pytest.fixture
    def custom_rules_loader(self):
        """Create a loader with test rules."""
        yaml_content = """
version: "1.0"
custom_pii_rules:
  - name: "test_id"
    description: "Test identification"
    enabled: true
    severity: "high"
    patterns:
      - regex: "TEST[0-9]{4}"
        confidence: 0.95
        description: "Test ID pattern"
    redaction:
      mask_format: "TEST****"
      hash_prefix: "TEST_"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            temp_path = f.name

        loader = CustomPIIRulesLoader(temp_path)
        loader.load_rules()

        yield loader

        os.unlink(temp_path)

    def test_detector_with_custom_rules(self, custom_rules_loader):
        """Test PIIDetector with custom rules loaded."""
        detector = PIIDetector(
            detection_config={"types": ["all"]}, custom_rules_loader=custom_rules_loader
        )

        # Test detection of custom pattern
        text = "My test ID is TEST1234 and my SSN is 123-45-6789"
        matches = detector.detect(text)

        # Should detect both custom and built-in patterns
        assert len(matches) >= 2
        assert any(str(m.pii_type) == "custom_test_id" for m in matches)
        assert any("ssn" in str(m.pii_type).lower() for m in matches)

    def test_detector_custom_masking(self, custom_rules_loader):
        """Test custom masking formats."""
        detector = PIIDetector(
            detection_config={"types": ["all"]}, custom_rules_loader=custom_rules_loader
        )

        text = "TEST9876"
        matches = detector.detect(text)

        assert len(matches) == 1
        assert matches[0].masked_value == "TEST****"

    def test_detector_without_custom_rules(self):
        """Test PIIDetector works without custom rules."""
        detector = PIIDetector(detection_config={"types": ["all"]}, custom_rules_loader=None)

        text = "My SSN is 123-45-6789"
        matches = detector.detect(text)

        # Should still detect built-in patterns
        assert len(matches) >= 1
        assert any("ssn" in str(m.pii_type).lower() for m in matches)

    def test_detector_custom_patterns_override(self, custom_rules_loader):
        """Test that custom patterns don't override built-in ones."""
        detector = PIIDetector(
            detection_config={"types": ["all"]}, custom_rules_loader=custom_rules_loader
        )

        # Both custom patterns and built-in patterns should work
        assert len(detector.patterns) > 0  # Built-in patterns
        assert len(detector.custom_patterns) > 0  # Custom patterns

        # Test that both types are detected
        text = "Email: test@example.com, ID: TEST5678"
        matches = detector.detect(text)

        assert any("email" in str(m.pii_type).lower() for m in matches)
        assert any("custom_test_id" in str(m.pii_type) for m in matches)
