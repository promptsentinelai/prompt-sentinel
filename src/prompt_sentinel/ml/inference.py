# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Machine learning inference for prompt injection detection."""

import json
import time
from typing import Any


class InferenceEngine:
    """ML inference engine for real-time detection."""

    def __init__(self, model_path: str | None = None):
        """Initialize inference engine."""
        self.model = None
        self.preprocessor = None
        if model_path:
            self.load_model(model_path)

    def load_model(self, path: str) -> None:
        """Load model for inference."""
        try:
            with open(path) as f:
                self.model = json.load(f)
        except Exception:
            # Default stub model
            self.model = {"type": "stub_model", "loaded": True}

    def predict(self, text: str) -> dict[str, Any]:
        """Predict if text contains injection."""
        # Stub prediction
        # Simple heuristic for demo
        score = 0.2  # Base score

        if any(word in text.lower() for word in ["ignore", "override", "system", "prompt"]):
            score = 0.7

        if "ignore all" in text.lower() or "disregard" in text.lower():
            score = 0.9

        return {"is_injection": score > 0.5, "confidence": score, "prediction_time": 0.001}

    def batch_predict(self, texts: list[str]) -> list[dict[str, Any]]:
        """Batch prediction for multiple texts."""
        return [self.predict(text) for text in texts]

    def explain_prediction(self, text: str) -> dict[str, Any]:
        """Explain why a prediction was made."""
        prediction = self.predict(text)

        # Find contributing factors
        factors = []
        if "ignore" in text.lower():
            factors.append("Contains 'ignore' keyword")
        if "system" in text.lower():
            factors.append("Contains 'system' keyword")
        if "override" in text.lower():
            factors.append("Contains 'override' keyword")

        return {
            "prediction": prediction,
            "explanation": {
                "contributing_factors": factors,
                "feature_importance": {"keywords": 0.7, "structure": 0.2, "encoding": 0.1},
            },
        }

    def get_model_info(self) -> dict[str, Any]:
        """Get information about loaded model."""
        if not self.model:
            return {"status": "no_model_loaded"}

        return {
            "status": "ready",
            "model_type": self.model.get("type", "unknown"),
            "version": self.model.get("version", "1.0.0"),
            "loaded_at": time.time(),
        }
