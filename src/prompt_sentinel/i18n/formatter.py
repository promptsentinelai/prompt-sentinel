# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Locale-specific formatting utilities."""

from datetime import datetime


class LocaleFormatter:
    """Format data according to locale settings."""

    def __init__(self, locale: str = "en_US"):
        """Initialize formatter with locale."""
        self.locale = locale
        if "_" in locale:
            parts = locale.split("_")
            self.language: str = parts[0]
            self.region: str | None = parts[1] if len(parts) > 1 else None
        else:
            self.language = locale
            self.region = None

    def format_number(self, number: float, decimal_places: int = 2) -> str:
        """Format number according to locale."""
        if self.locale.startswith("en"):
            # English: 1,234.56
            formatted = f"{number:,.{decimal_places}f}"
        elif self.locale.startswith("de") or self.locale.startswith("fr"):
            # German/French: 1.234,56
            formatted = (
                f"{number:,.{decimal_places}f}".replace(",", "X")
                .replace(".", ",")
                .replace("X", ".")
            )
        else:
            # Default to English format
            formatted = f"{number:,.{decimal_places}f}"
        return formatted

    def format_percentage(self, value: float) -> str:
        """Format percentage according to locale."""
        percentage = value * 100
        if self.locale.startswith("en"):
            return f"{percentage:.1f}%"
        elif self.locale.startswith("fr"):
            return f"{percentage:.1f} %"  # Space before %
        else:
            return f"{percentage:.1f}%"

    def format_currency(self, amount: float, currency: str = "USD") -> str:
        """Format currency according to locale."""
        symbols = {
            "USD": "$",
            "EUR": "€",
            "GBP": "£",
            "JPY": "¥",
            "CNY": "¥",
        }

        symbol = symbols.get(currency, currency)

        if self.locale.startswith("en_US"):
            return f"{symbol}{amount:,.2f}"
        elif self.locale.startswith("en_GB"):
            return f"{symbol}{amount:,.2f}"
        elif self.locale.startswith("de"):
            formatted = f"{amount:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
            return f"{formatted} {symbol}"
        elif self.locale.startswith("fr"):
            formatted = f"{amount:,.2f}".replace(",", " ").replace(".", ",")
            return f"{formatted} {symbol}"
        else:
            return f"{symbol}{amount:,.2f}"

    def format_date(self, date: datetime) -> str:
        """Format date according to locale."""
        if self.locale.startswith("en_US"):
            return date.strftime("%m/%d/%Y")
        elif self.locale.startswith("en_GB"):
            return date.strftime("%d/%m/%Y")
        elif self.locale.startswith("de"):
            return date.strftime("%d.%m.%Y")
        elif self.locale.startswith("fr"):
            return date.strftime("%d/%m/%Y")
        elif self.locale.startswith("ja"):
            return date.strftime("%Y年%m月%d日")
        else:
            return date.strftime("%Y-%m-%d")

    def format_time(self, time: datetime) -> str:
        """Format time according to locale."""
        if self.locale.startswith("en_US"):
            return time.strftime("%I:%M %p")
        else:
            return time.strftime("%H:%M")

    def format_datetime(self, dt: datetime) -> str:
        """Format datetime according to locale."""
        date_part = self.format_date(dt)
        time_part = self.format_time(dt)

        if self.locale.startswith("en"):
            return f"{date_part} {time_part}"
        elif self.locale.startswith("de"):
            return f"{date_part}, {time_part}"
        elif self.locale.startswith("fr"):
            return f"{date_part} à {time_part}"
        elif self.locale.startswith("ja"):
            return f"{date_part} {time_part}"
        else:
            return f"{date_part} {time_part}"

    def get_decimal_separator(self) -> str:
        """Get decimal separator for locale."""
        if self.locale.startswith("en"):
            return "."
        elif self.locale.startswith("de") or self.locale.startswith("fr"):
            return ","
        else:
            return "."

    def get_thousands_separator(self) -> str:
        """Get thousands separator for locale."""
        if self.locale.startswith("en"):
            return ","
        elif self.locale.startswith("de"):
            return "."
        elif self.locale.startswith("fr"):
            return " "
        else:
            return ","
