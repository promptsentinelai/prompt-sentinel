# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Machine learning training pipeline."""

import json
from typing import Any

import numpy as np


class TrainingPipeline:
    """ML training pipeline for prompt injection detection."""

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize training pipeline."""
        self.config = config or {}
        self.model: dict[str, Any] | None = None
        self.preprocessor: Any | None = None
        self.feature_extractor: Any | None = None
        self.best_params: dict[str, Any] | None = None

    def preprocess_data(self, data: list[dict[str, Any]]) -> tuple[list[str], list[int]]:
        """Preprocess training data."""
        texts = []
        labels = []

        for item in data:
            texts.append(item.get("text", ""))
            # Convert label to binary: 1 for malicious, 0 for benign
            label = item.get("label", "benign")
            labels.append(1 if label in ["malicious", "injection"] else 0)

        return texts, labels

    def extract_features(self, texts: list[str]) -> np.ndarray:
        """Extract features from text."""
        # Simple feature extraction: length, special chars, keywords
        features = []

        for text in texts:
            text_features = [
                len(text),  # Length
                text.count("ignore"),  # Keyword count
                text.count("system"),
                text.count("!"),  # Special chars
                text.count("?"),
                text.count("<"),
                text.count(">"),
                1 if "override" in text.lower() else 0,  # Binary features
                1 if "instruction" in text.lower() else 0,
                1 if "prompt" in text.lower() else 0,
            ]
            features.append(text_features)

        return np.array(features)

    def train(self, X: np.ndarray, y: list[int]) -> Any:
        """Train the model."""
        # Stub training - just store the data
        self.model = {
            "type": "stub_model",
            "n_samples": len(X),
            "n_features": X.shape[1] if len(X.shape) > 1 else 1,
            "classes": list(set(y)),
        }
        return self.model

    def tune_hyperparameters(
        self, X: np.ndarray, y: list[int], _param_grid: dict[str, list[Any]]
    ) -> dict[str, Any]:
        """Tune hyperparameters."""
        # Stub hyperparameter tuning
        self.best_params = {"learning_rate": 0.01, "max_depth": 5, "n_estimators": 100}
        return self.best_params

    def evaluate(self, X: np.ndarray, y: list[int]) -> dict[str, float]:
        """Evaluate model performance."""
        # Stub evaluation
        return {"accuracy": 0.85, "precision": 0.87, "recall": 0.83, "f1_score": 0.85}

    def save_model(self, path: str) -> None:
        """Save trained model."""
        with open(path, "w") as f:
            json.dump(self.model, f)

    def load_model(self, path: str) -> None:
        """Load trained model."""
        with open(path) as f:
            self.model = json.load(f)
