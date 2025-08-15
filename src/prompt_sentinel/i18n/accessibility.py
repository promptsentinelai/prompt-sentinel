# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Accessibility support for internationalization."""


class AccessibilityI18n:
    """Provide accessibility support across languages."""

    def __init__(self, locale: str = "en_US"):
        """Initialize accessibility support."""
        self.locale = locale
        self.aria_labels = {
            "en_US": {
                "alert": "Alert",
                "warning": "Warning",
                "error": "Error",
                "success": "Success",
            },
            "es_ES": {
                "alert": "Alerta",
                "warning": "Advertencia",
                "error": "Error",
                "success": "Éxito",
            },
            "fr_FR": {
                "alert": "Alerte",
                "warning": "Avertissement",
                "error": "Erreur",
                "success": "Succès",
            },
        }

    def get_aria_label(self, key: str) -> str:
        """Get ARIA label for screen readers."""
        labels = self.aria_labels.get(self.locale, self.aria_labels["en_US"])
        return labels.get(key, key)

    def format_for_screen_reader(self, message: str, severity: str = "info") -> dict[str, str]:
        """Format message for screen reader."""
        return {
            "message": message,
            "aria_label": self.get_aria_label(severity),
            "role": "alert" if severity in ["error", "warning"] else "status",
            "aria_live": "assertive" if severity == "error" else "polite",
        }

    def get_error_announcement(self, error: str) -> str:
        """Get screen reader announcement for error."""
        aria_label = self.get_aria_label("error")
        return f"{aria_label}: {error}"
