# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Character encoding handling for internationalization."""

import unicodedata
from typing import Any, Literal


class EncodingHandler:
    """Handle various character encodings and scripts."""

    def __init__(self):
        """Initialize encoding handler."""
        self.supported_encodings = ["utf-8", "utf-16", "latin-1", "ascii"]

    def handle_emoji(self, text: str) -> dict[str, Any]:
        """Handle emoji in text."""
        has_emoji = any(
            unicodedata.category(char) == "So"
            or 0x1F600 <= ord(char) <= 0x1F64F  # Emoticons
            or 0x1F300 <= ord(char) <= 0x1F5FF  # Misc Symbols and Pictographs
            or 0x1F680 <= ord(char) <= 0x1F6FF  # Transport and Map
            or 0x2600 <= ord(char) <= 0x26FF  # Misc symbols
            or 0x2700 <= ord(char) <= 0x27BF  # Dingbats
            for char in text
        )

        return {
            "has_emoji": has_emoji,
            "text_without_emoji": "".join(
                char
                for char in text
                if not (unicodedata.category(char) == "So" or 0x1F600 <= ord(char) <= 0x1F6FF)
            ),
        }

    def handle_rtl(self, text: str) -> dict[str, Any]:
        """Handle right-to-left scripts."""
        # Check for RTL characters (Arabic, Hebrew, etc.)
        rtl_chars = 0
        for char in text:
            if unicodedata.bidirectional(char) in ["R", "AL"]:
                rtl_chars += 1

        is_rtl = rtl_chars > len(text) / 2

        return {
            "is_rtl": is_rtl,
            "rtl_char_count": rtl_chars,
            "direction": "rtl" if is_rtl else "ltr",
        }

    def handle_special_chars(self, text: str) -> dict[str, Any]:
        """Handle special characters."""
        special_chars = []

        for char in text:
            category = unicodedata.category(char)
            if category.startswith("P") or category.startswith("S"):
                special_chars.append(char)

        return {
            "has_special_chars": len(special_chars) > 0,
            "special_char_count": len(special_chars),
            "special_chars": list(set(special_chars)),
        }

    def normalize(self, text: str, form: Literal["NFC", "NFD", "NFKC", "NFKD"] = "NFC") -> str:
        """Normalize Unicode text."""
        return unicodedata.normalize(form, text)

    def detect_encoding(self, text: bytes) -> str:
        """Detect text encoding."""
        # Try common encodings
        for encoding in self.supported_encodings:
            try:
                text.decode(encoding)
                return encoding
            except UnicodeDecodeError:
                continue
        return "unknown"
