# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Internationalized response formatting for detection results."""

from typing import Any

from prompt_sentinel.i18n.formatter import LocaleFormatter
from prompt_sentinel.models.schemas import DetectionResponse, Verdict


class ResponseFormatter:
    """Format detection responses based on user locale."""

    def __init__(self, locale: str = "en_US"):
        """Initialize response formatter with locale."""
        self.locale = locale
        self.language = locale.split("_")[0] if "_" in locale else locale
        self.formatter = LocaleFormatter(locale)
        self.translations = self._load_translations()

    def _load_translations(self) -> dict[str, dict[str, str]]:
        """Load translation dictionaries for all supported languages."""
        return {
            "en": {
                # Verdicts
                "verdict.allow": "Allowed",
                "verdict.block": "Blocked",
                "verdict.flag": "Flagged for Review",
                "verdict.strip": "Content Stripped",
                "verdict.redact": "PII Redacted",
                # Detection reasons
                "reason.injection_detected": "Prompt injection detected",
                "reason.jailbreak_attempt": "Jailbreak attempt detected",
                "reason.data_extraction": "Data extraction attempt detected",
                "reason.encoding_attack": "Encoding-based attack detected",
                "reason.pii_detected": "Personal information detected",
                # Recommendations
                "rec.use_role_separation": "Use role separation for better security",
                "rec.avoid_direct_instructions": "Avoid direct instruction overrides",
                "rec.sanitize_user_input": "Sanitize user input before processing",
                "rec.implement_validation": "Implement input validation",
                # Status messages
                "status.processing": "Processing request...",
                "status.complete": "Analysis complete",
                "status.error": "An error occurred during analysis",
                # Confidence levels
                "confidence.very_high": "Very High Confidence",
                "confidence.high": "High Confidence",
                "confidence.medium": "Medium Confidence",
                "confidence.low": "Low Confidence",
            },
            "es": {
                # Spanish translations
                "verdict.allow": "Permitido",
                "verdict.block": "Bloqueado",
                "verdict.flag": "Marcado para Revisión",
                "verdict.strip": "Contenido Eliminado",
                "verdict.redact": "IIP Censurado",
                "reason.injection_detected": "Inyección de prompt detectada",
                "reason.jailbreak_attempt": "Intento de jailbreak detectado",
                "reason.data_extraction": "Intento de extracción de datos detectado",
                "reason.encoding_attack": "Ataque basado en codificación detectado",
                "reason.pii_detected": "Información personal detectada",
                "rec.use_role_separation": "Use separación de roles para mejor seguridad",
                "rec.avoid_direct_instructions": "Evite anulaciones directas de instrucciones",
                "rec.sanitize_user_input": "Desinfecte la entrada del usuario antes de procesar",
                "rec.implement_validation": "Implemente validación de entrada",
                "status.processing": "Procesando solicitud...",
                "status.complete": "Análisis completo",
                "status.error": "Se produjo un error durante el análisis",
                "confidence.very_high": "Confianza Muy Alta",
                "confidence.high": "Confianza Alta",
                "confidence.medium": "Confianza Media",
                "confidence.low": "Confianza Baja",
            },
            "fr": {
                # French translations
                "verdict.allow": "Autorisé",
                "verdict.block": "Bloqué",
                "verdict.flag": "Signalé pour Examen",
                "verdict.strip": "Contenu Supprimé",
                "verdict.redact": "IIP Expurgées",
                "reason.injection_detected": "Injection de prompt détectée",
                "reason.jailbreak_attempt": "Tentative de jailbreak détectée",
                "reason.data_extraction": "Tentative d'extraction de données détectée",
                "reason.encoding_attack": "Attaque basée sur l'encodage détectée",
                "reason.pii_detected": "Informations personnelles détectées",
                "rec.use_role_separation": "Utilisez la séparation des rôles pour une meilleure sécurité",
                "rec.avoid_direct_instructions": "Évitez les remplacements directs d'instructions",
                "rec.sanitize_user_input": "Assainissez l'entrée utilisateur avant le traitement",
                "rec.implement_validation": "Implémentez la validation des entrées",
                "status.processing": "Traitement de la demande...",
                "status.complete": "Analyse terminée",
                "status.error": "Une erreur s'est produite pendant l'analyse",
                "confidence.very_high": "Confiance Très Élevée",
                "confidence.high": "Confiance Élevée",
                "confidence.medium": "Confiance Moyenne",
                "confidence.low": "Confiance Faible",
            },
            "de": {
                # German translations
                "verdict.allow": "Erlaubt",
                "verdict.block": "Blockiert",
                "verdict.flag": "Zur Überprüfung Markiert",
                "verdict.strip": "Inhalt Entfernt",
                "verdict.redact": "PII Geschwärzt",
                "reason.injection_detected": "Prompt-Injektion erkannt",
                "reason.jailbreak_attempt": "Jailbreak-Versuch erkannt",
                "reason.data_extraction": "Datenextraktionsversuch erkannt",
                "reason.encoding_attack": "Kodierungsbasierter Angriff erkannt",
                "reason.pii_detected": "Persönliche Informationen erkannt",
                "rec.use_role_separation": "Verwenden Sie Rollentrennung für bessere Sicherheit",
                "rec.avoid_direct_instructions": "Vermeiden Sie direkte Anweisungsüberschreibungen",
                "rec.sanitize_user_input": "Bereinigen Sie Benutzereingaben vor der Verarbeitung",
                "rec.implement_validation": "Implementieren Sie Eingabevalidierung",
                "status.processing": "Anfrage wird verarbeitet...",
                "status.complete": "Analyse abgeschlossen",
                "status.error": "Bei der Analyse ist ein Fehler aufgetreten",
                "confidence.very_high": "Sehr Hohes Vertrauen",
                "confidence.high": "Hohes Vertrauen",
                "confidence.medium": "Mittleres Vertrauen",
                "confidence.low": "Niedriges Vertrauen",
            },
            "ja": {
                # Japanese translations
                "verdict.allow": "許可",
                "verdict.block": "ブロック",
                "verdict.flag": "レビュー対象",
                "verdict.strip": "コンテンツ削除",
                "verdict.redact": "個人情報編集",
                "reason.injection_detected": "プロンプトインジェクションを検出",
                "reason.jailbreak_attempt": "脱獄試行を検出",
                "reason.data_extraction": "データ抽出試行を検出",
                "reason.encoding_attack": "エンコーディング攻撃を検出",
                "reason.pii_detected": "個人情報を検出",
                "rec.use_role_separation": "セキュリティ向上のためロール分離を使用",
                "rec.avoid_direct_instructions": "直接的な指示の上書きを避ける",
                "rec.sanitize_user_input": "処理前にユーザー入力をサニタイズ",
                "rec.implement_validation": "入力検証を実装",
                "status.processing": "リクエスト処理中...",
                "status.complete": "分析完了",
                "status.error": "分析中にエラーが発生しました",
                "confidence.very_high": "非常に高い確信度",
                "confidence.high": "高い確信度",
                "confidence.medium": "中程度の確信度",
                "confidence.low": "低い確信度",
            },
        }

    def translate(self, key: str, fallback: str | None = None) -> str:
        """Get translated string for the current locale."""
        language_dict = self.translations.get(self.language, self.translations["en"])
        return language_dict.get(key, fallback or key)

    def format_verdict(self, verdict: Verdict) -> str:
        """Format verdict for display."""
        return self.translate(f"verdict.{verdict.value}", verdict.value.title())

    def format_confidence(self, confidence: float) -> str:
        """Format confidence level with localized description."""
        formatted_percentage = self.formatter.format_percentage(confidence)

        if confidence >= 0.9:
            level = self.translate("confidence.very_high")
        elif confidence >= 0.7:
            level = self.translate("confidence.high")
        elif confidence >= 0.4:
            level = self.translate("confidence.medium")
        else:
            level = self.translate("confidence.low")

        return f"{formatted_percentage} ({level})"

    def format_response(self, response: DetectionResponse) -> dict[str, Any]:
        """Format detection response for the current locale."""
        formatted = {
            "verdict": self.format_verdict(response.verdict),
            "confidence": self.format_confidence(response.confidence),
            "processing_time": self.formatter.format_number(response.processing_time_ms, 2) + " ms",
            "timestamp": self.formatter.format_datetime(response.timestamp),
        }

        # Format reasons if present
        if response.reasons:
            formatted["reasons"] = []
            for reason in response.reasons:
                reason_key = f"reason.{reason.category.value}"
                formatted["reasons"].append(
                    {
                        "category": self.translate(reason_key, reason.category.value),
                        "description": reason.description,
                        "confidence": self.formatter.format_percentage(reason.confidence),
                    }
                )

        # Format recommendations if present
        if response.format_recommendations:
            formatted["recommendations"] = []
            for rec in response.format_recommendations:
                # Try to translate common recommendations
                rec_text = rec.recommendation
                if "role separation" in rec_text.lower():
                    rec_text = self.translate("rec.use_role_separation")
                elif "direct instruction" in rec_text.lower():
                    rec_text = self.translate("rec.avoid_direct_instructions")
                elif "sanitize" in rec_text.lower():
                    rec_text = self.translate("rec.sanitize_user_input")
                elif "validation" in rec_text.lower():
                    rec_text = self.translate("rec.implement_validation")

                formatted["recommendations"].append(
                    {
                        "issue": rec.issue,
                        "recommendation": rec_text,
                        "severity": rec.severity,
                    }
                )

        # Add modified prompt if present
        if response.modified_prompt:
            formatted["modified_prompt"] = response.modified_prompt

        # Add metadata if present
        if response.metadata:
            formatted["metadata"] = response.metadata

        return formatted

    def get_supported_locales(self) -> list[str]:
        """Get list of supported locales."""
        return list(self.translations.keys())

    def is_rtl_language(self) -> bool:
        """Check if current language is right-to-left."""
        return self.language in ["ar", "he", "fa", "ur"]
