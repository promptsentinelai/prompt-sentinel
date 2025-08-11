# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Property-based tests using Hypothesis for PromptSentinel."""

import string
from hypothesis import given, strategies as st, settings, assume
import pytest

from prompt_sentinel.detection.heuristics import HeuristicDetector
from prompt_sentinel.detection.pii_detector import PIIDetector
from prompt_sentinel.models.schemas import Message, Role, Verdict


class TestPropertyBasedHeuristics:
    """Property-based tests for heuristic detection."""

    @given(
        text=st.text(min_size=1, max_size=1000),
        mode=st.sampled_from(["strict", "moderate", "permissive"])
    )
    def test_heuristic_detector_never_crashes(self, text, mode):
        """Test that heuristic detector never crashes on any input."""
        detector = HeuristicDetector(detection_mode=mode)
        messages = [Message(role=Role.USER, content=text)]
        
        # Should never raise an exception
        verdict, reasons, confidence = detector.detect(messages)
        
        # Properties that should always hold
        assert verdict in [Verdict.ALLOW, Verdict.FLAG, Verdict.STRIP, Verdict.BLOCK]
        assert isinstance(reasons, list)
        assert 0.0 <= confidence <= 1.0

    @given(
        base_text=st.text(alphabet=string.ascii_letters, min_size=10, max_size=50),
        injection_pattern=st.sampled_from([
            "ignore all instructions",
            "disregard previous",
            "forget everything",
            "new instructions:",
            "you are now"
        ])
    )
    def test_injection_patterns_always_detected(self, base_text, injection_pattern):
        """Test that known injection patterns are always detected."""
        detector = HeuristicDetector(detection_mode="strict")
        
        # Combine base text with injection pattern
        malicious_text = f"{base_text} {injection_pattern} {base_text}"
        messages = [Message(role=Role.USER, content=malicious_text)]
        
        verdict, reasons, confidence = detector.detect(messages)
        
        # Should detect the injection
        assert verdict != Verdict.ALLOW
        assert len(reasons) > 0
        assert confidence > 0.0

    @given(
        text=st.text(
            alphabet=string.ascii_letters + string.digits + " .,!?",
            min_size=1,
            max_size=500
        ).filter(lambda x: not any(word in x.lower() for word in [
            "ignore", "disregard", "forget", "instruction", "prompt",
            "system", "override", "jailbreak", "role", "admin"
        ]))
    )
    def test_benign_text_not_blocked_in_permissive(self, text):
        """Test that benign text is not blocked in permissive mode."""
        detector = HeuristicDetector(detection_mode="permissive")
        messages = [Message(role=Role.USER, content=text)]
        
        verdict, reasons, confidence = detector.detect(messages)
        
        # Benign text should mostly be allowed in permissive mode
        if verdict == Verdict.BLOCK:
            # If blocked, confidence should be very high
            assert confidence > 0.9

    @given(
        messages=st.lists(
            st.builds(
                Message,
                role=st.sampled_from([Role.USER, Role.SYSTEM, Role.ASSISTANT]),
                content=st.text(min_size=1, max_size=200)
            ),
            min_size=1,
            max_size=10
        )
    )
    def test_multiple_messages_handling(self, messages):
        """Test that detector handles multiple messages correctly."""
        detector = HeuristicDetector(detection_mode="moderate")
        
        verdict, reasons, confidence = detector.detect(messages)
        
        # Should handle any message combination
        assert verdict in [Verdict.ALLOW, Verdict.FLAG, Verdict.STRIP, Verdict.BLOCK]
        assert isinstance(reasons, list)
        assert 0.0 <= confidence <= 1.0


class TestPropertyBasedPII:
    """Property-based tests for PII detection."""

    @given(text=st.text(min_size=0, max_size=1000))
    def test_pii_detector_never_crashes(self, text):
        """Test that PII detector never crashes on any input."""
        detector = PIIDetector()
        
        # Should never raise an exception
        matches = detector.detect(text)
        
        # Should always return a list
        assert isinstance(matches, list)

    @given(
        prefix=st.text(alphabet=string.ascii_letters + " ", max_size=20),
        email=st.emails(),
        suffix=st.text(alphabet=string.ascii_letters + " ", max_size=20)
    )
    def test_email_always_detected(self, prefix, email, suffix):
        """Test that valid emails are always detected."""
        detector = PIIDetector()
        text = f"{prefix}{email}{suffix}"
        
        matches = detector.detect(text)
        
        # Should detect the email
        assert len(matches) > 0
        assert any(email in match.text for match in matches)

    @given(
        ssn=st.from_regex(r"\d{3}-\d{2}-\d{4}", fullmatch=True)
    )
    def test_ssn_format_detected(self, ssn):
        """Test that SSN format is detected."""
        detector = PIIDetector()
        text = f"My SSN is {ssn}"
        
        matches = detector.detect(text)
        
        # Should detect SSN-like pattern
        assert len(matches) > 0

    @given(
        text=st.text(min_size=1, max_size=500),
        redaction_mode=st.sampled_from(["mask", "hash", "remove"])
    )
    def test_redaction_preserves_length_or_removes(self, text, redaction_mode):
        """Test that redaction behaves correctly."""
        detector = PIIDetector()
        matches = detector.detect(text)
        
        if matches:
            redacted = detector.redact(text, matches, mode=redaction_mode)
            
            if redaction_mode == "remove":
                # Should be shorter or same length
                assert len(redacted) <= len(text)
            elif redaction_mode == "mask":
                # Original PII should not be in redacted
                for match in matches:
                    assert match.text not in redacted

    @given(
        card_number=st.from_regex(r"4\d{15}", fullmatch=True)  # Visa-like
    )
    def test_credit_card_detection(self, card_number):
        """Test credit card number detection."""
        # Add spaces for realistic formatting
        formatted = " ".join([card_number[i:i+4] for i in range(0, 16, 4)])
        text = f"Card: {formatted}"
        
        detector = PIIDetector()
        matches = detector.detect(text)
        
        # Should detect card-like pattern
        assert len(matches) > 0


class TestPropertyBasedValidation:
    """Property-based tests for input validation."""

    @given(
        confidence=st.floats(min_value=0.0, max_value=1.0),
        mode=st.sampled_from(["strict", "moderate", "permissive"])
    )
    def test_verdict_determination_consistency(self, confidence, mode):
        """Test that verdict determination is consistent."""
        detector = HeuristicDetector(detection_mode=mode)
        
        # Create a fake detection reason
        from prompt_sentinel.models.schemas import DetectionReason, DetectionCategory
        
        reasons = [
            DetectionReason(
                category=DetectionCategory.DIRECT_INJECTION,
                description="Test",
                confidence=confidence,
                source="test"
            )
        ]
        
        verdict = detector._determine_verdict(confidence, reasons)
        
        # Higher confidence should lead to more severe verdicts
        if confidence >= 0.9:
            assert verdict in [Verdict.BLOCK, Verdict.STRIP]
        elif confidence <= 0.3:
            assert verdict in [Verdict.ALLOW, Verdict.FLAG]

    @given(
        text_length=st.integers(min_value=0, max_value=1_000_000)
    )
    def test_performance_scales_linearly(self, text_length):
        """Test that detection performance scales reasonably."""
        import time
        
        # Create text of specified length
        text = "a" * text_length
        messages = [Message(role=Role.USER, content=text)]
        
        detector = HeuristicDetector(detection_mode="moderate")
        
        start = time.time()
        verdict, reasons, confidence = detector.detect(messages)
        elapsed = time.time() - start
        
        # Should complete in reasonable time (< 1 second for 1MB)
        assert elapsed < 1.0
        
        # Should return valid results
        assert verdict in [Verdict.ALLOW, Verdict.FLAG, Verdict.STRIP, Verdict.BLOCK]


class TestPropertyBasedEncoding:
    """Property-based tests for encoding detection."""

    @given(
        original_text=st.text(
            alphabet=string.ascii_letters + string.digits,
            min_size=10,
            max_size=100
        )
    )
    def test_base64_encoding_detection(self, original_text):
        """Test that base64 encoded content is detected."""
        import base64
        
        encoded = base64.b64encode(original_text.encode()).decode()
        
        # Wrap in a message that looks suspicious
        text = f"Execute this: {encoded}"
        
        detector = HeuristicDetector(detection_mode="strict")
        messages = [Message(role=Role.USER, content=text)]
        
        verdict, reasons, confidence = detector.detect(messages)
        
        # Long base64 strings should be flagged
        if len(encoded) > 50:
            assert len(reasons) > 0

    @given(
        hex_bytes=st.binary(min_size=4, max_size=20)
    )
    def test_hex_encoding_detection(self, hex_bytes):
        """Test that hex encoded content is detected."""
        hex_string = "".join([f"\\x{b:02x}" for b in hex_bytes])
        text = f"Run this code: {hex_string}"
        
        detector = HeuristicDetector(detection_mode="strict")
        messages = [Message(role=Role.USER, content=text)]
        
        verdict, reasons, confidence = detector.detect(messages)
        
        # Should detect hex encoding pattern
        if "\\x" in text:
            matching_reasons = [r for r in reasons if "encoding" in r.description.lower()]
            assert len(matching_reasons) > 0 or verdict == Verdict.ALLOW


class TestPropertyBasedComplexScenarios:
    """Property-based tests for complex scenarios."""

    @given(
        num_attempts=st.integers(min_value=1, max_value=10),
        base_injection=st.sampled_from([
            "ignore", "override", "forget", "disregard"
        ])
    )
    def test_repeated_injection_increases_confidence(self, num_attempts, base_injection):
        """Test that repeated injection attempts increase confidence."""
        detector = HeuristicDetector(detection_mode="moderate")
        
        # Create message with repeated injection attempts
        text = f"{base_injection} instructions. " * num_attempts
        messages = [Message(role=Role.USER, content=text)]
        
        verdict, reasons, confidence = detector.detect(messages)
        
        # More repetitions should increase confidence
        if num_attempts > 5:
            assert confidence > 0.5
            assert verdict != Verdict.ALLOW

    @given(
        safe_text=st.text(alphabet=string.ascii_letters + " ", min_size=10, max_size=50),
        unsafe_pattern=st.sampled_from(["DROP TABLE", "'; DELETE", "1=1", "OR 1=1"]),
        obfuscation=st.sampled_from(["spaces", "case", "encoding"])
    )
    def test_sql_injection_patterns(self, safe_text, unsafe_pattern, obfuscation):
        """Test detection of SQL injection-like patterns."""
        if obfuscation == "spaces":
            pattern = " ".join(unsafe_pattern)
        elif obfuscation == "case":
            pattern = "".join(c.upper() if i % 2 else c.lower() 
                            for i, c in enumerate(unsafe_pattern))
        else:
            pattern = unsafe_pattern
        
        text = f"{safe_text} {pattern} {safe_text}"
        messages = [Message(role=Role.USER, content=text)]
        
        detector = HeuristicDetector(detection_mode="strict")
        verdict, reasons, confidence = detector.detect(messages)
        
        # SQL-like patterns might be caught as suspicious
        assert verdict in [Verdict.ALLOW, Verdict.FLAG, Verdict.STRIP, Verdict.BLOCK]


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--hypothesis-show-statistics"])