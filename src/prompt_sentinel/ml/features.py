"""Feature extraction for pattern discovery.

Extracts various features from prompts for ML clustering and pattern analysis.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass

import numpy as np
import structlog

logger = structlog.get_logger()


@dataclass
class FeatureVector:
    """Container for extracted features."""

    # Basic features
    length: int
    word_count: int
    char_count: int
    line_count: int

    # Statistical features
    entropy: float
    char_diversity: float
    word_diversity: float
    avg_word_length: float

    # Syntactic features
    punctuation_ratio: float
    special_char_ratio: float
    uppercase_ratio: float
    digit_ratio: float
    whitespace_ratio: float

    # Pattern features
    has_encoding: bool
    has_delimiters: bool
    has_role_markers: bool
    has_instructions: bool
    max_repetition: int

    # N-gram features
    char_ngrams: dict[str, int]
    word_ngrams: dict[str, int]

    # Semantic features (optional, requires embeddings)
    embedding: list[float] | None = None

    def to_array(self) -> np.ndarray:
        """Convert to numpy array for ML algorithms."""
        features = [
            self.length,
            self.word_count,
            self.char_count,
            self.line_count,
            self.entropy,
            self.char_diversity,
            self.word_diversity,
            self.avg_word_length,
            self.punctuation_ratio,
            self.special_char_ratio,
            self.uppercase_ratio,
            self.digit_ratio,
            self.whitespace_ratio,
            float(self.has_encoding),
            float(self.has_delimiters),
            float(self.has_role_markers),
            float(self.has_instructions),
            self.max_repetition,
        ]

        # Add top N-gram frequencies
        top_char_ngrams = sorted(self.char_ngrams.values(), reverse=True)[:10]
        features.extend(top_char_ngrams + [0] * (10 - len(top_char_ngrams)))

        top_word_ngrams = sorted(self.word_ngrams.values(), reverse=True)[:10]
        features.extend(top_word_ngrams + [0] * (10 - len(top_word_ngrams)))

        return np.array(features, dtype=np.float32)


class FeatureExtractor:
    """Extracts features from prompts for ML analysis."""

    def __init__(
        self,
        use_embeddings: bool = False,
        embedding_model: str | None = None,
        ngram_range: tuple[int, int] = (2, 3),
        max_ngrams: int = 100,
    ):
        """Initialize the feature extractor.

        Args:
            use_embeddings: Whether to generate embeddings
            embedding_model: Model to use for embeddings
            ngram_range: Range of n-gram sizes
            max_ngrams: Maximum number of n-grams to track
        """
        self.use_embeddings = use_embeddings
        self.embedding_model = embedding_model
        self.ngram_range = ngram_range
        self.max_ngrams = max_ngrams

        # Patterns for detection
        self.encoding_pattern = re.compile(
            r"([A-Za-z0-9+/]{20,}={0,2})|"  # Base64
            r"(\\x[0-9a-fA-F]{2})|"  # Hex
            r"(\\u[0-9a-fA-F]{4})|"  # Unicode
            r"(%[0-9a-fA-F]{2})"  # URL encoding
        )

        self.delimiter_pattern = re.compile(
            r"(<\|.*?\|>)|"  # Special delimiters
            r"(\[\[.*?\]\])|"  # Bracket commands
            r"({{.*?}})|"  # Template syntax
            r"(###)|"  # Section markers
            r"(={5,})|"  # Separators
            r"(-{5,})"  # Dividers
        )

        self.role_pattern = re.compile(
            r"(system:|user:|assistant:|human:|ai:|bot:)|"
            r"(\[INST\]|\[/INST\])|"
            r"(### (System|User|Assistant|Human|AI))"
        )

        self.instruction_pattern = re.compile(
            r"(ignore|disregard|forget|override|bypass|unlock|enable|disable|activate|deactivate)|"
            r"(instructions?|commands?|directives?|rules?|restrictions?|settings?)|"
            r"(you (are|must|should|will) (now|be|act|behave))|"
            r"(act as|pretend|roleplay|impersonate)"
        )

        # Embedding model initialization
        self.embedder = None
        if self.use_embeddings:
            try:
                from sentence_transformers import SentenceTransformer

                self.embedder = SentenceTransformer(embedding_model or "all-MiniLM-L6-v2")
                logger.info("Embedding model loaded", model=embedding_model)
            except ImportError:
                logger.warning("sentence-transformers not installed, embeddings disabled")
                self.use_embeddings = False

    def extract_features(self, text: str) -> FeatureVector:
        """Extract features from text.

        Args:
            text: Input text to analyze

        Returns:
            Extracted feature vector
        """
        # Basic features
        length = len(text)
        lines = text.split("\n")
        line_count = len(lines)
        words = text.split()
        word_count = len(words)
        char_count = len(text.replace(" ", "").replace("\n", ""))

        # Statistical features
        entropy = self._calculate_entropy(text)
        char_diversity = len(set(text)) / max(len(text), 1)
        word_diversity = len(set(words)) / max(len(words), 1)
        avg_word_length = sum(len(w) for w in words) / max(len(words), 1)

        # Syntactic features
        punctuation_count = sum(1 for c in text if c in ".,;:!?()[]{}\"'-_")
        special_char_count = sum(1 for c in text if not c.isalnum() and not c.isspace())
        uppercase_count = sum(1 for c in text if c.isupper())
        digit_count = sum(1 for c in text if c.isdigit())
        whitespace_count = sum(1 for c in text if c.isspace())

        punctuation_ratio = punctuation_count / max(length, 1)
        special_char_ratio = special_char_count / max(length, 1)
        uppercase_ratio = uppercase_count / max(length, 1)
        digit_ratio = digit_count / max(length, 1)
        whitespace_ratio = whitespace_count / max(length, 1)

        # Pattern features
        has_encoding = bool(self.encoding_pattern.search(text))
        has_delimiters = bool(self.delimiter_pattern.search(text))
        has_role_markers = bool(self.role_pattern.search(text.lower()))
        has_instructions = bool(self.instruction_pattern.search(text.lower()))
        max_repetition = self._find_max_repetition(text)

        # N-gram features
        char_ngrams = self._extract_char_ngrams(text)
        word_ngrams = self._extract_word_ngrams(words)

        # Embedding features
        embedding = None
        if self.use_embeddings and self.embedder:
            try:
                embedding = self.embedder.encode(text[:512]).tolist()  # Limit text length
            except Exception as e:
                logger.warning("Failed to generate embedding", error=str(e))

        return FeatureVector(
            length=length,
            word_count=word_count,
            char_count=char_count,
            line_count=line_count,
            entropy=entropy,
            char_diversity=char_diversity,
            word_diversity=word_diversity,
            avg_word_length=avg_word_length,
            punctuation_ratio=punctuation_ratio,
            special_char_ratio=special_char_ratio,
            uppercase_ratio=uppercase_ratio,
            digit_ratio=digit_ratio,
            whitespace_ratio=whitespace_ratio,
            has_encoding=has_encoding,
            has_delimiters=has_delimiters,
            has_role_markers=has_role_markers,
            has_instructions=has_instructions,
            max_repetition=max_repetition,
            char_ngrams=char_ngrams,
            word_ngrams=word_ngrams,
            embedding=embedding,
        )

    def extract_batch(self, texts: list[str]) -> list[FeatureVector]:
        """Extract features from multiple texts.

        Args:
            texts: List of texts to analyze

        Returns:
            List of feature vectors
        """
        return [self.extract_features(text) for text in texts]

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0

        # Count character frequencies
        freq_dict = Counter(text)
        total = len(text)

        # Calculate entropy
        entropy = 0.0
        for count in freq_dict.values():
            prob = count / total
            if prob > 0:
                entropy -= prob * math.log2(prob)

        return entropy

    def _find_max_repetition(self, text: str) -> int:
        """Find maximum character repetition."""
        if not text:
            return 0

        max_rep = 1
        current_rep = 1

        for i in range(1, len(text)):
            if text[i] == text[i - 1]:
                current_rep += 1
                max_rep = max(max_rep, current_rep)
            else:
                current_rep = 1

        return max_rep

    def _extract_char_ngrams(self, text: str) -> dict[str, int]:
        """Extract character n-grams."""
        ngrams: Counter[str] = Counter()
        text_lower = text.lower()

        for n in range(self.ngram_range[0], self.ngram_range[1] + 1):
            for i in range(len(text_lower) - n + 1):
                ngram = text_lower[i : i + n]
                if ngram.strip():  # Skip whitespace-only ngrams
                    ngrams[ngram] += 1

        # Keep only top N ngrams
        return dict(ngrams.most_common(self.max_ngrams))

    def _extract_word_ngrams(self, words: list[str]) -> dict[str, int]:
        """Extract word n-grams."""
        ngrams: Counter[str] = Counter()
        words_lower = [w.lower() for w in words]

        for n in range(self.ngram_range[0], min(self.ngram_range[1] + 1, len(words) + 1)):
            for i in range(len(words_lower) - n + 1):
                ngram = " ".join(words_lower[i : i + n])
                ngrams[ngram] += 1

        # Keep only top N ngrams
        return dict(ngrams.most_common(self.max_ngrams))

    def compute_similarity(self, features1: FeatureVector, features2: FeatureVector) -> float:
        """Compute similarity between two feature vectors.

        Args:
            features1: First feature vector
            features2: Second feature vector

        Returns:
            Similarity score between 0 and 1
        """
        # If embeddings available, use cosine similarity
        if features1.embedding and features2.embedding:
            emb1 = np.array(features1.embedding)
            emb2 = np.array(features2.embedding)

            # Cosine similarity
            dot_product = np.dot(emb1, emb2)
            norm1 = np.linalg.norm(emb1)
            norm2 = np.linalg.norm(emb2)

            if norm1 > 0 and norm2 > 0:
                return dot_product / (norm1 * norm2)

        # Otherwise use feature-based similarity
        vec1 = features1.to_array()
        vec2 = features2.to_array()

        # Normalize vectors
        vec1_norm = vec1 / (np.linalg.norm(vec1) + 1e-8)
        vec2_norm = vec2 / (np.linalg.norm(vec2) + 1e-8)

        # Cosine similarity
        return np.dot(vec1_norm, vec2_norm)

    def get_feature_importance(self, features: list[FeatureVector]) -> dict[str, float]:
        """Calculate feature importance scores.

        Args:
            features: List of feature vectors

        Returns:
            Dictionary of feature names to importance scores
        """
        if not features:
            return {}

        # Convert to array
        feature_matrix = np.array([f.to_array() for f in features])

        # Calculate variance for each feature
        variances = np.var(feature_matrix, axis=0)

        # Feature names
        feature_names = [
            "length",
            "word_count",
            "char_count",
            "line_count",
            "entropy",
            "char_diversity",
            "word_diversity",
            "avg_word_length",
            "punctuation_ratio",
            "special_char_ratio",
            "uppercase_ratio",
            "digit_ratio",
            "whitespace_ratio",
            "has_encoding",
            "has_delimiters",
            "has_role_markers",
            "has_instructions",
            "max_repetition",
        ]

        # Add n-gram feature names
        for i in range(10):
            feature_names.append(f"char_ngram_{i}")
        for i in range(10):
            feature_names.append(f"word_ngram_{i}")

        # Create importance dictionary
        importance = {}
        for i, name in enumerate(feature_names):
            if i < len(variances):
                importance[name] = float(variances[i])

        # Normalize to 0-1 range
        max_importance = max(importance.values()) if importance else 1.0
        if max_importance > 0:
            importance = {k: v / max_importance for k, v in importance.items()}

        return importance
