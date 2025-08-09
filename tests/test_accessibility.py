"""Accessibility tests for PromptSentinel UI and API."""

import pytest
import asyncio
from typing import Dict, List, Any
from unittest.mock import AsyncMock, MagicMock, patch
from bs4 import BeautifulSoup
import json

from prompt_sentinel.models.schemas import Message, Role, Verdict


class TestScreenReaderSupport:
    """Test screen reader accessibility."""

    @pytest.fixture
    def accessibility_checker(self):
        """Create accessibility checker."""
        from prompt_sentinel.accessibility.checker import AccessibilityChecker
        return AccessibilityChecker()

    @pytest.mark.asyncio
    async def test_aria_labels(self, accessibility_checker):
        """Test ARIA labels are present and descriptive."""
        html = """
        <div>
            <button aria-label="Submit detection request">Detect</button>
            <input type="text" aria-label="Enter prompt text" />
            <div role="alert" aria-live="polite">Detection result</div>
            <nav aria-label="Main navigation">
                <ul>
                    <li><a href="/detect">Detect</a></li>
                    <li><a href="/analyze">Analyze</a></li>
                </ul>
            </nav>
        </div>
        """
        
        result = await accessibility_checker.check_aria_labels(html)
        
        assert result["has_aria_labels"] is True
        assert result["elements_with_labels"] >= 4
        assert all(label for label in result["label_quality"].values())

    @pytest.mark.asyncio
    async def test_semantic_html(self, accessibility_checker):
        """Test proper use of semantic HTML elements."""
        html = """
        <header>
            <h1>PromptSentinel</h1>
            <nav>Navigation</nav>
        </header>
        <main>
            <section>
                <h2>Detection</h2>
                <article>Content</article>
            </section>
        </main>
        <footer>Footer content</footer>
        """
        
        result = await accessibility_checker.check_semantic_structure(html)
        
        assert result["has_header"] is True
        assert result["has_main"] is True
        assert result["has_footer"] is True
        assert result["has_navigation"] is True
        assert result["heading_hierarchy_valid"] is True

    @pytest.mark.asyncio
    async def test_focus_management(self, accessibility_checker):
        """Test keyboard focus management."""
        html = """
        <div>
            <button tabindex="0">First</button>
            <a href="#" tabindex="0">Second</a>
            <input type="text" tabindex="0" />
            <div tabindex="-1">Skip this</div>
            <button tabindex="0">Last</button>
        </div>
        """
        
        result = await accessibility_checker.check_focus_order(html)
        
        assert result["focusable_elements"] == 4
        assert result["focus_order_logical"] is True
        assert result["skip_links_present"] is False  # Should add skip links

    @pytest.mark.asyncio
    async def test_role_attributes(self, accessibility_checker):
        """Test proper use of ARIA roles."""
        html = """
        <div role="banner">Header</div>
        <div role="navigation">Nav</div>
        <div role="main">
            <div role="region" aria-label="Detection Form">
                <form role="form">
                    <div role="group">
                        <label>Prompt</label>
                        <textarea role="textbox"></textarea>
                    </div>
                    <button role="button">Submit</button>
                </form>
            </div>
            <div role="status" aria-live="polite">Ready</div>
        </div>
        """
        
        result = await accessibility_checker.check_aria_roles(html)
        
        assert result["valid_roles"] is True
        assert result["landmark_roles"] >= 3
        assert result["interactive_roles"] >= 2


class TestKeyboardNavigation:
    """Test keyboard navigation support."""

    @pytest.fixture
    def keyboard_tester(self):
        """Create keyboard navigation tester."""
        from prompt_sentinel.accessibility.keyboard import KeyboardNavigationTester
        return KeyboardNavigationTester()

    @pytest.mark.asyncio
    async def test_tab_navigation(self, keyboard_tester):
        """Test tab key navigation."""
        # Simulate tab navigation
        elements = [
            {"id": "input1", "type": "input", "tabindex": 0},
            {"id": "button1", "type": "button", "tabindex": 0},
            {"id": "link1", "type": "a", "tabindex": 0},
            {"id": "select1", "type": "select", "tabindex": 0}
        ]
        
        result = await keyboard_tester.test_tab_order(elements)
        
        assert result["all_reachable"] is True
        assert result["tab_order"] == ["input1", "button1", "link1", "select1"]
        assert result["reverse_tab_works"] is True

    @pytest.mark.asyncio
    async def test_keyboard_shortcuts(self, keyboard_tester):
        """Test keyboard shortcuts."""
        shortcuts = {
            "Alt+D": "focus_detection_input",
            "Alt+S": "submit_detection",
            "Alt+C": "clear_form",
            "Escape": "close_modal"
        }
        
        # Test shortcut conflicts
        conflicts = await keyboard_tester.check_shortcut_conflicts(shortcuts)
        assert len(conflicts) == 0
        
        # Test shortcut accessibility
        accessibility = await keyboard_tester.check_shortcut_accessibility(shortcuts)
        assert accessibility["all_documented"] is True
        assert accessibility["no_single_key_shortcuts"] is True
        assert accessibility["modifier_keys_used"] is True

    @pytest.mark.asyncio
    async def test_focus_trap(self, keyboard_tester):
        """Test focus trap in modals."""
        modal_elements = [
            {"id": "modal_title", "type": "h2", "tabindex": -1},
            {"id": "modal_input", "type": "input", "tabindex": 0},
            {"id": "modal_cancel", "type": "button", "tabindex": 0},
            {"id": "modal_confirm", "type": "button", "tabindex": 0}
        ]
        
        result = await keyboard_tester.test_focus_trap(
            modal_elements,
            container_id="modal"
        )
        
        assert result["focus_trapped"] is True
        assert result["escape_closes"] is True
        assert result["focus_restored_on_close"] is True


class TestColorContrast:
    """Test color contrast for visual accessibility."""

    @pytest.fixture
    def contrast_checker(self):
        """Create color contrast checker."""
        from prompt_sentinel.accessibility.contrast import ContrastChecker
        return ContrastChecker()

    def test_text_contrast_ratio(self, contrast_checker):
        """Test text color contrast ratios."""
        # Test various color combinations
        test_cases = [
            {"fg": "#000000", "bg": "#FFFFFF", "expected_ratio": 21},  # Black on white
            {"fg": "#767676", "bg": "#FFFFFF", "expected_ratio": 4.54},  # Gray on white
            {"fg": "#FF0000", "bg": "#FFFFFF", "expected_ratio": 3.99},  # Red on white
        ]
        
        for case in test_cases:
            ratio = contrast_checker.calculate_contrast_ratio(
                case["fg"],
                case["bg"]
            )
            
            # Check WCAG AA compliance (4.5:1 for normal text)
            is_compliant = contrast_checker.check_wcag_compliance(
                ratio,
                level="AA",
                text_size="normal"
            )
            
            if case["expected_ratio"] >= 4.5:
                assert is_compliant is True

    def test_large_text_contrast(self, contrast_checker):
        """Test contrast requirements for large text."""
        # Large text has lower contrast requirement (3:1)
        ratio = contrast_checker.calculate_contrast_ratio("#757575", "#FFFFFF")
        
        # Should pass for large text but fail for normal
        assert contrast_checker.check_wcag_compliance(
            ratio,
            level="AA",
            text_size="large"
        ) is True
        
        assert contrast_checker.check_wcag_compliance(
            ratio,
            level="AA",
            text_size="normal"
        ) is False

    def test_color_blind_safe_palettes(self, contrast_checker):
        """Test color palettes for color blind users."""
        palette = {
            "success": "#10B981",  # Green
            "warning": "#F59E0B",  # Amber
            "error": "#EF4444",     # Red
            "info": "#3B82F6"       # Blue
        }
        
        # Test deuteranopia (red-green color blindness)
        result = contrast_checker.check_color_blind_safety(
            palette,
            type="deuteranopia"
        )
        
        assert result["distinguishable"] is True
        assert len(result["problem_pairs"]) == 0
        
        # Test with problematic palette
        bad_palette = {
            "status1": "#FF0000",  # Red
            "status2": "#00FF00",  # Green (problem for red-green blind)
        }
        
        result = contrast_checker.check_color_blind_safety(
            bad_palette,
            type="protanopia"
        )
        
        assert len(result["problem_pairs"]) > 0


class TestTextAccessibility:
    """Test text content accessibility."""

    @pytest.fixture
    def text_checker(self):
        """Create text accessibility checker."""
        from prompt_sentinel.accessibility.text import TextAccessibilityChecker
        return TextAccessibilityChecker()

    @pytest.mark.asyncio
    async def test_readability_score(self, text_checker):
        """Test text readability scoring."""
        texts = {
            "simple": "Click the button to detect threats. The result will show here.",
            "complex": "Utilize the heuristic-based detection mechanism to ascertain potential security vulnerabilities inherent in the submitted textual input.",
            "technical": "The LLM classifier employs transformer-based architectures with attention mechanisms for contextual analysis."
        }
        
        for name, text in texts.items():
            score = await text_checker.calculate_readability(text)
            
            if name == "simple":
                assert score["flesch_reading_ease"] > 60  # Easy to read
                assert score["grade_level"] < 10
            elif name == "complex":
                assert score["flesch_reading_ease"] < 30  # Difficult
                assert score["grade_level"] > 14

    @pytest.mark.asyncio
    async def test_plain_language(self, text_checker):
        """Test use of plain language."""
        content = {
            "good": "Enter your text and click 'Check' to scan for threats.",
            "bad": "Input textual data and actuate verification protocol."
        }
        
        good_result = await text_checker.check_plain_language(content["good"])
        bad_result = await text_checker.check_plain_language(content["bad"])
        
        assert good_result["score"] > bad_result["score"]
        assert len(good_result["complex_words"]) < len(bad_result["complex_words"])

    @pytest.mark.asyncio
    async def test_alternative_text(self, text_checker):
        """Test alternative text for images."""
        images = [
            {
                "src": "detection-icon.png",
                "alt": "Shield icon indicating security detection"
            },
            {
                "src": "graph.png",
                "alt": ""  # Missing alt text
            },
            {
                "src": "decorative.png",
                "alt": "",
                "role": "presentation"  # Decorative image
            }
        ]
        
        results = await text_checker.check_alt_text(images)
        
        assert results[0]["has_alt"] is True
        assert results[0]["alt_quality"] == "good"
        
        assert results[1]["has_alt"] is False
        assert results[1]["issue"] == "missing_alt"
        
        assert results[2]["has_alt"] is True
        assert results[2]["decorative"] is True


class TestFormAccessibility:
    """Test form accessibility features."""

    @pytest.fixture
    def form_checker(self):
        """Create form accessibility checker."""
        from prompt_sentinel.accessibility.forms import FormAccessibilityChecker
        return FormAccessibilityChecker()

    @pytest.mark.asyncio
    async def test_form_labels(self, form_checker):
        """Test form label associations."""
        form_html = """
        <form>
            <label for="prompt-input">Enter your prompt:</label>
            <textarea id="prompt-input" name="prompt"></textarea>
            
            <label>Mode:
                <select name="mode">
                    <option>Strict</option>
                    <option>Moderate</option>
                </select>
            </label>
            
            <input type="checkbox" id="pii-check" />
            <label for="pii-check">Check for PII</label>
            
            <button type="submit">Detect</button>
        </form>
        """
        
        result = await form_checker.check_label_associations(form_html)
        
        assert result["all_inputs_labeled"] is True
        assert result["label_methods"]["explicit"] >= 2
        assert result["label_methods"]["implicit"] >= 1

    @pytest.mark.asyncio
    async def test_error_messaging(self, form_checker):
        """Test accessible error messaging."""
        error_scenarios = [
            {
                "field": "prompt",
                "error": "Prompt is required",
                "aria_invalid": True,
                "aria_describedby": "prompt-error"
            },
            {
                "field": "mode",
                "error": "Please select a detection mode",
                "aria_invalid": True,
                "aria_describedby": "mode-error"
            }
        ]
        
        for scenario in error_scenarios:
            result = await form_checker.check_error_accessibility(scenario)
            
            assert result["has_error_message"] is True
            assert result["aria_invalid_set"] is True
            assert result["aria_describedby_linked"] is True
            assert result["error_announced"] is True

    @pytest.mark.asyncio
    async def test_field_grouping(self, form_checker):
        """Test logical field grouping."""
        fieldset_html = """
        <fieldset>
            <legend>Detection Options</legend>
            <input type="radio" id="mode-strict" name="mode" value="strict" />
            <label for="mode-strict">Strict</label>
            
            <input type="radio" id="mode-moderate" name="mode" value="moderate" />
            <label for="mode-moderate">Moderate</label>
            
            <input type="radio" id="mode-permissive" name="mode" value="permissive" />
            <label for="mode-permissive">Permissive</label>
        </fieldset>
        """
        
        result = await form_checker.check_field_grouping(fieldset_html)
        
        assert result["uses_fieldset"] is True
        assert result["has_legend"] is True
        assert result["group_labeled"] is True


class TestResponsiveAccessibility:
    """Test accessibility across different viewports."""

    @pytest.fixture
    def responsive_checker(self):
        """Create responsive accessibility checker."""
        from prompt_sentinel.accessibility.responsive import ResponsiveAccessibilityChecker
        return ResponsiveAccessibilityChecker()

    @pytest.mark.asyncio
    async def test_mobile_touch_targets(self, responsive_checker):
        """Test touch target sizes on mobile."""
        elements = [
            {"type": "button", "width": 44, "height": 44},  # Good size
            {"type": "link", "width": 20, "height": 20},    # Too small
            {"type": "input", "width": 200, "height": 40}   # Good size
        ]
        
        results = await responsive_checker.check_touch_targets(
            elements,
            viewport="mobile"
        )
        
        assert results[0]["adequate_size"] is True
        assert results[1]["adequate_size"] is False
        assert results[1]["recommendation"] == "Increase to at least 44x44 pixels"

    @pytest.mark.asyncio
    async def test_zoom_support(self, responsive_checker):
        """Test support for browser zoom."""
        # Test at different zoom levels
        zoom_levels = [100, 200, 300, 400]
        
        for zoom in zoom_levels:
            result = await responsive_checker.test_zoom_compatibility(zoom)
            
            assert result["text_readable"] is True
            assert result["layout_intact"] is True
            assert result["horizontal_scroll"] is False or zoom <= 200
            
            if zoom >= 200:
                assert result["supports_reflow"] is True

    @pytest.mark.asyncio
    async def test_orientation_support(self, responsive_checker):
        """Test accessibility in different orientations."""
        orientations = ["portrait", "landscape"]
        
        for orientation in orientations:
            result = await responsive_checker.test_orientation(orientation)
            
            assert result["content_accessible"] is True
            assert result["navigation_usable"] is True
            assert result["forms_functional"] is True


class TestAnimationAccessibility:
    """Test animation and motion accessibility."""

    @pytest.fixture
    def animation_checker(self):
        """Create animation accessibility checker."""
        from prompt_sentinel.accessibility.animation import AnimationAccessibilityChecker
        return AnimationAccessibilityChecker()

    @pytest.mark.asyncio
    async def test_reduced_motion_support(self, animation_checker):
        """Test support for prefers-reduced-motion."""
        css = """
        @media (prefers-reduced-motion: reduce) {
            * {
                animation-duration: 0.01ms !important;
                transition-duration: 0.01ms !important;
            }
        }
        
        .spinner {
            animation: spin 2s linear infinite;
        }
        
        .fade-in {
            animation: fadeIn 0.3s ease-in;
        }
        """
        
        result = await animation_checker.check_reduced_motion_support(css)
        
        assert result["supports_reduced_motion"] is True
        assert result["animations_can_be_disabled"] is True

    @pytest.mark.asyncio
    async def test_pause_controls(self, animation_checker):
        """Test animation pause controls."""
        animations = [
            {"id": "carousel", "auto_play": True, "has_pause": True},
            {"id": "video", "auto_play": True, "has_pause": False},
            {"id": "progress", "auto_play": False, "has_pause": False}
        ]
        
        for animation in animations:
            result = await animation_checker.check_pause_control(animation)
            
            if animation["auto_play"]:
                assert result["needs_pause_control"] is True
                if animation["has_pause"]:
                    assert result["compliant"] is True
                else:
                    assert result["compliant"] is False

    @pytest.mark.asyncio
    async def test_seizure_prevention(self, animation_checker):
        """Test prevention of seizure-inducing content."""
        # Check for dangerous flash rates
        animations = [
            {"flash_rate": 2, "duration": 1},   # Safe
            {"flash_rate": 5, "duration": 1},   # Dangerous
            {"flash_rate": 10, "duration": 0.1}  # Short duration, less dangerous
        ]
        
        for animation in animations:
            result = await animation_checker.check_flash_rate(animation)
            
            if animation["flash_rate"] >= 3 and animation["duration"] >= 1:
                assert result["safe"] is False
                assert "seizure" in result["warning"].lower()
            else:
                assert result["safe"] is True


class TestDocumentStructure:
    """Test document structure accessibility."""

    @pytest.fixture
    def structure_checker(self):
        """Create document structure checker."""
        from prompt_sentinel.accessibility.structure import DocumentStructureChecker
        return DocumentStructureChecker()

    @pytest.mark.asyncio
    async def test_heading_hierarchy(self, structure_checker):
        """Test proper heading hierarchy."""
        html = """
        <h1>PromptSentinel</h1>
        <h2>Features</h2>
        <h3>Detection</h3>
        <h3>Analysis</h3>
        <h2>Getting Started</h2>
        <h3>Installation</h3>
        <h4>Requirements</h4>
        """
        
        result = await structure_checker.check_heading_hierarchy(html)
        
        assert result["has_h1"] is True
        assert result["single_h1"] is True
        assert result["no_skipped_levels"] is True
        assert result["logical_order"] is True

    @pytest.mark.asyncio
    async def test_landmark_regions(self, structure_checker):
        """Test landmark region structure."""
        html = """
        <header role="banner">
            <nav role="navigation">Menu</nav>
        </header>
        <main role="main">
            <section aria-label="Detection">Content</section>
        </main>
        <aside role="complementary">Sidebar</aside>
        <footer role="contentinfo">Footer</footer>
        """
        
        result = await structure_checker.check_landmarks(html)
        
        assert result["has_main"] is True
        assert result["has_navigation"] is True
        assert result["unique_landmarks"] is True
        assert result["labeled_regions"] is True

    @pytest.mark.asyncio
    async def test_table_structure(self, structure_checker):
        """Test accessible table structure."""
        table_html = """
        <table>
            <caption>Detection Results</caption>
            <thead>
                <tr>
                    <th scope="col">Timestamp</th>
                    <th scope="col">Verdict</th>
                    <th scope="col">Confidence</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>2024-01-01 12:00</td>
                    <td>BLOCK</td>
                    <td>0.95</td>
                </tr>
            </tbody>
        </table>
        """
        
        result = await structure_checker.check_table_accessibility(table_html)
        
        assert result["has_caption"] is True
        assert result["has_headers"] is True
        assert result["headers_have_scope"] is True
        assert result["structure_valid"] is True


class TestAPIAccessibility:
    """Test API accessibility features."""

    @pytest.fixture
    def api_checker(self):
        """Create API accessibility checker."""
        from prompt_sentinel.accessibility.api import APIAccessibilityChecker
        return APIAccessibilityChecker()

    @pytest.mark.asyncio
    async def test_error_response_clarity(self, api_checker):
        """Test clarity of API error responses."""
        error_responses = [
            {
                "status": 400,
                "error": {
                    "code": "INVALID_INPUT",
                    "message": "The prompt field is required",
                    "field": "prompt",
                    "suggestion": "Please provide a prompt text to analyze"
                }
            },
            {
                "status": 500,
                "error": {
                    "message": "Internal error"  # Too vague
                }
            }
        ]
        
        for response in error_responses:
            result = await api_checker.check_error_clarity(response)
            
            if response["status"] == 400:
                assert result["has_clear_message"] is True
                assert result["has_field_reference"] is True
                assert result["has_suggestion"] is True
            else:
                assert result["has_clear_message"] is False

    @pytest.mark.asyncio
    async def test_response_format_options(self, api_checker):
        """Test multiple response format support."""
        formats = ["json", "xml", "csv", "plain"]
        
        for format in formats:
            result = await api_checker.check_format_support(format)
            
            if format in ["json", "xml"]:
                assert result["supported"] is True
                assert result["structured"] is True
            
            # Plain text for screen readers
            if format == "plain":
                assert result["screen_reader_friendly"] is True

    @pytest.mark.asyncio
    async def test_rate_limit_communication(self, api_checker):
        """Test clear communication of rate limits."""
        headers = {
            "X-RateLimit-Limit": "100",
            "X-RateLimit-Remaining": "10",
            "X-RateLimit-Reset": "1609459200",
            "Retry-After": "60"
        }
        
        result = await api_checker.check_rate_limit_headers(headers)
        
        assert result["has_limit_info"] is True
        assert result["has_remaining_info"] is True
        assert result["has_reset_info"] is True
        assert result["has_retry_info"] is True
        assert result["human_readable"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])