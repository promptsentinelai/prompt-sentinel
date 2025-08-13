# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Message translation utilities."""

from typing import Any


class MessageTranslator:
    """Translate messages between languages."""

    def __init__(self, source_language: str = "en", target_language: str = "en"):
        """Initialize translator."""
        self.source_language = source_language
        self.target_language = target_language

        # Stub translations
        self.translations = {
            "en": {
                "injection_detected": "Injection attempt detected",
                "high_risk": "High risk prompt detected",
                "blocked": "Request blocked for security reasons",
                "flagged": "Request flagged for review",
                "allowed": "Request allowed",
                "error": "An error occurred",
            },
            "es": {
                "injection_detected": "Intento de inyección detectado",
                "high_risk": "Prompt de alto riesgo detectado",
                "blocked": "Solicitud bloqueada por razones de seguridad",
                "flagged": "Solicitud marcada para revisión",
                "allowed": "Solicitud permitida",
                "error": "Se produjo un error",
            },
            "fr": {
                "injection_detected": "Tentative d'injection détectée",
                "high_risk": "Prompt à haut risque détecté",
                "blocked": "Demande bloquée pour des raisons de sécurité",
                "flagged": "Demande signalée pour examen",
                "allowed": "Demande autorisée",
                "error": "Une erreur s'est produite",
            },
        }

    def translate(self, key: str, language: str | None = None) -> str:
        """Translate a message key."""
        lang = language or self.target_language
        lang_dict = self.translations.get(lang, self.translations["en"])
        return lang_dict.get(key, key)

    def translate_error(self, error_code: str, language: str | None = None) -> str:
        """Translate error messages."""
        error_messages = {
            "INVALID_INPUT": {
                "en": "Invalid input provided",
                "es": "Entrada no válida proporcionada",
                "fr": "Entrée invalide fournie",
            },
            "RATE_LIMITED": {
                "en": "Rate limit exceeded",
                "es": "Límite de velocidad excedido",
                "fr": "Limite de débit dépassée",
            },
            "UNAUTHORIZED": {
                "en": "Unauthorized access",
                "es": "Acceso no autorizado",
                "fr": "Accès non autorisé",
            },
        }

        lang = language or self.target_language
        error_dict = error_messages.get(error_code, {"en": f"Error: {error_code}"})
        return error_dict.get(lang, error_dict.get("en", f"Error: {error_code}"))

    def localize_response(self, response: dict[str, Any], language: str) -> dict[str, Any]:
        """Localize a response object."""
        localized = response.copy()

        # Translate verdict message
        if "verdict" in localized:
            verdict_key = (
                localized["verdict"].lower()
                if hasattr(localized["verdict"], "lower")
                else str(localized["verdict"]).lower()
            )
            if verdict_key == "block":
                localized["message"] = self.translate("blocked", language)
            elif verdict_key == "flag":
                localized["message"] = self.translate("flagged", language)
            elif verdict_key == "allow":
                localized["message"] = self.translate("allowed", language)

        # Translate reasons
        if "reasons" in localized and isinstance(localized["reasons"], list):
            # For now, keep reasons in English as they're technical
            pass

        return localized

    def get_supported_languages(self) -> list[str]:
        """Get list of supported languages."""
        return list(self.translations.keys())

    def is_language_supported(self, language: str) -> bool:
        """Check if language is supported."""
        return language in self.translations
