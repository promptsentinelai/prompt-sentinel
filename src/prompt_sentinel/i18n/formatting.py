# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Locale-specific formatting for internationalization."""


class LocaleFormatter:
    """Format data according to locale."""

    def __init__(self, locale: str = "en_US"):
        """Initialize locale formatter."""
        self.locale = locale

        # Currency symbols by locale
        self.currency_symbols = {
            "en_US": "$",
            "en_GB": "£",
            "eu_EU": "€",
            "ja_JP": "¥",
            "zh_CN": "¥",
            "ru_RU": "₽",
        }

        # Number formatting
        self.number_formats = {
            "en_US": {"decimal": ".", "thousands": ","},
            "de_DE": {"decimal": ",", "thousands": "."},
            "fr_FR": {"decimal": ",", "thousands": " "},
        }

    def format_currency(self, amount: float) -> str:
        """Format currency for locale."""
        symbol = self.currency_symbols.get(self.locale, "$")

        # Format number
        formatted = self.format_number(amount)

        # Position based on locale
        if self.locale in ["en_US", "en_GB"]:
            return f"{symbol}{formatted}"
        else:
            return f"{formatted} {symbol}"

    def format_percentage(self, value: float) -> str:
        """Format percentage for locale."""
        percentage = value * 100
        formatted = self.format_number(percentage)

        # Some locales put space before %
        if self.locale in ["fr_FR"]:
            return f"{formatted} %"
        else:
            return f"{formatted}%"

    def format_number(self, number: float, decimals: int = 2) -> str:
        """Format number according to locale."""
        fmt = self.number_formats.get(self.locale, self.number_formats["en_US"])

        # Format with decimals
        formatted = f"{number:.{decimals}f}"

        # Replace decimal separator
        if fmt["decimal"] != ".":
            formatted = formatted.replace(".", fmt["decimal"])

        # Add thousands separator
        parts = formatted.split(fmt["decimal"])
        integer_part = parts[0]

        # Add thousands separators
        if len(integer_part) > 3:
            result = ""
            for i, digit in enumerate(reversed(integer_part)):
                if i > 0 and i % 3 == 0:
                    result = fmt["thousands"] + result
                result = digit + result
            integer_part = result

        if len(parts) > 1:
            return integer_part + fmt["decimal"] + parts[1]
        return integer_part

    def format_date(self, year: int, month: int, day: int) -> str:
        """Format date according to locale."""
        if self.locale == "en_US":
            return f"{month:02d}/{day:02d}/{year}"
        elif self.locale in ["en_GB", "fr_FR", "de_DE"]:
            return f"{day:02d}/{month:02d}/{year}"
        elif self.locale in ["ja_JP", "zh_CN"]:
            return f"{year}/{month:02d}/{day:02d}"
        else:
            return f"{year}-{month:02d}-{day:02d}"  # ISO format
