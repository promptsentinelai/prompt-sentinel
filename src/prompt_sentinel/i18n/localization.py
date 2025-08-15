# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Localization manager for internationalization."""


class LocalizationManager:
    """Manage localization and translations."""

    def __init__(self, locale: str = "en_US"):
        """Initialize localization manager."""
        self.locale = locale
        self.translations = {
            "en_US": {
                "injection_detected": "Injection attempt detected",
                "high_risk": "High risk",
                "medium_risk": "Medium risk",
                "low_risk": "Low risk",
            },
            "es_ES": {
                "injection_detected": "Intento de inyección detectado",
                "high_risk": "Alto riesgo",
                "medium_risk": "Riesgo medio",
                "low_risk": "Bajo riesgo",
            },
            "fr_FR": {
                "injection_detected": "Tentative d'injection détectée",
                "high_risk": "Risque élevé",
                "medium_risk": "Risque moyen",
                "low_risk": "Faible risque",
            },
        }

    def get_message(self, key: str, **kwargs) -> str:
        """Get localized message."""
        messages = self.translations.get(self.locale, self.translations["en_US"])
        message = messages.get(key, key)

        # Format message with kwargs
        try:
            return message.format(**kwargs)
        except Exception:
            return message

    def set_locale(self, locale: str) -> None:
        """Set the current locale."""
        self.locale = locale

    def get_supported_locales(self) -> list[str]:
        """Get list of supported locales."""
        return list(self.translations.keys())

    async def initialize(self) -> None:
        """Initialize localization resources."""
        # Stub initialization
        pass
