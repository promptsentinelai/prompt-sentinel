"""Tests for PII detection functionality."""

from prompt_sentinel.detection.pii_detector import PIIDetector, PIIType


class TestPIIDetector:
    """Test cases for PII detector."""

    def test_detect_credit_card(self):
        """Test credit card detection."""
        detector = PIIDetector()

        # Valid credit card numbers
        text = "My card is 4111-1111-1111-1111 for testing"
        matches = detector.detect(text)

        assert len(matches) > 0
        assert matches[0].pii_type == PIIType.CREDIT_CARD
        assert "****-****-****-1111" in matches[0].masked_value

    def test_detect_ssn(self):
        """Test SSN detection."""
        detector = PIIDetector()

        text = "My SSN is 123-45-6789 please keep it safe"
        matches = detector.detect(text)

        assert len(matches) > 0
        assert matches[0].pii_type == PIIType.SSN
        assert matches[0].masked_value == "***-**-****"

    def test_detect_email(self):
        """Test email detection."""
        detector = PIIDetector()

        text = "Contact me at john.doe@example.com for more info"
        matches = detector.detect(text)

        assert len(matches) > 0
        assert matches[0].pii_type == PIIType.EMAIL
        assert "@example.com" in matches[0].masked_value
        assert "jo***" in matches[0].masked_value

    def test_detect_phone(self):
        """Test phone number detection."""
        detector = PIIDetector()

        text = "Call me at (555) 123-4567 or 555-987-6543"
        matches = detector.detect(text)

        assert len(matches) == 2
        assert all(m.pii_type == PIIType.PHONE for m in matches)

    def test_detect_ip_address(self):
        """Test IP address detection."""
        detector = PIIDetector()

        text = "Server is at 192.168.1.1 on the network"
        matches = detector.detect(text)

        assert len(matches) > 0
        assert matches[0].pii_type == PIIType.IP_ADDRESS

    def test_detect_api_key(self):
        """Test API key detection."""
        detector = PIIDetector()

        text = "Use api_key='sk-1234567890abcdefghijklmnop' for auth"
        matches = detector.detect(text)

        assert len(matches) > 0
        assert any(m.pii_type == PIIType.API_KEY for m in matches)

    def test_detect_password(self):
        """Test password detection."""
        detector = PIIDetector()

        text = "Login with password: MySecretPass123!"
        matches = detector.detect(text)

        assert len(matches) > 0
        assert matches[0].pii_type == PIIType.PASSWORD

    def test_detect_aws_key(self):
        """Test AWS key detection."""
        detector = PIIDetector()

        text = "AWS Access Key: AKIAIOSFODNN7EXAMPLE"
        matches = detector.detect(text)

        assert len(matches) > 0
        assert matches[0].pii_type == PIIType.AWS_KEY

    def test_no_pii(self):
        """Test text with no PII."""
        detector = PIIDetector()

        text = "This is a normal text without any sensitive information"
        matches = detector.detect(text)

        assert len(matches) == 0

    def test_multiple_pii_types(self):
        """Test detection of multiple PII types."""
        detector = PIIDetector()

        text = """
        Email: test@example.com
        Phone: 555-123-4567
        SSN: 123-45-6789
        """
        matches = detector.detect(text)

        assert len(matches) >= 3
        pii_types = {m.pii_type for m in matches}
        assert PIIType.EMAIL in pii_types
        assert PIIType.PHONE in pii_types
        assert PIIType.SSN in pii_types

    def test_redact_mask_mode(self):
        """Test PII redaction in mask mode."""
        detector = PIIDetector()

        text = "Email me at john@example.com"
        matches = detector.detect(text)
        redacted = detector.redact(text, matches, mode="mask")

        assert "john@example.com" not in redacted
        assert "@example.com" in redacted

    def test_redact_remove_mode(self):
        """Test PII redaction in remove mode."""
        detector = PIIDetector()

        text = "My SSN is 123-45-6789"
        matches = detector.detect(text)
        redacted = detector.redact(text, matches, mode="remove")

        assert "123-45-6789" not in redacted
        assert "[SSN_REMOVED]" in redacted

    def test_redact_hash_mode(self):
        """Test PII redaction in hash mode."""
        detector = PIIDetector()

        text = "Call 555-123-4567"
        matches = detector.detect(text)
        redacted = detector.redact(text, matches, mode="hash")

        assert "555-123-4567" not in redacted
        assert "[PHONE_" in redacted

    def test_validate_credit_card_luhn(self):
        """Test Luhn algorithm validation for credit cards."""
        detector = PIIDetector()

        # Valid credit card (passes Luhn)
        assert detector._validate_credit_card("4111111111111111")

        # Invalid credit card (fails Luhn)
        assert not detector._validate_credit_card("4111111111111112")

        # Too short
        assert not detector._validate_credit_card("411111")

    def test_configured_types(self):
        """Test detector with specific PII types configured."""
        config = {"types": ["email", "phone"]}
        detector = PIIDetector(config)

        text = """
        Email: test@example.com
        SSN: 123-45-6789
        Phone: 555-123-4567
        """
        matches = detector.detect(text)

        # Should only detect email and phone, not SSN
        pii_types = {m.pii_type for m in matches}
        assert PIIType.EMAIL in pii_types
        assert PIIType.PHONE in pii_types
        assert PIIType.SSN not in pii_types

    def test_deduplicate_overlapping(self):
        """Test deduplication of overlapping matches."""
        detector = PIIDetector()

        # Text that might trigger multiple patterns
        text = "4111111111111111"  # Could match both generic and specific CC patterns
        matches = detector.detect(text)

        # Should not have overlapping matches
        for i, match1 in enumerate(matches):
            for match2 in matches[i + 1 :]:
                # No overlap
                assert match1.end_pos <= match2.start_pos or match2.end_pos <= match1.start_pos

    def test_get_summary(self):
        """Test PII summary generation."""
        detector = PIIDetector()

        text = """
        Email: test@example.com, admin@example.com
        Phone: 555-123-4567
        """
        matches = detector.detect(text)
        summary = detector.get_summary(matches)

        assert summary.get("email", 0) == 2
        assert summary.get("phone", 0) == 1
