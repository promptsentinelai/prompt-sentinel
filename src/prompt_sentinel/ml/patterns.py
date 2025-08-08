"""Pattern extraction from clusters.

Extracts common patterns and generates regex rules from clustered attack samples.
"""

import re
import hashlib
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import Counter, defaultdict
from datetime import datetime
import difflib

import structlog

logger = structlog.get_logger()


@dataclass
class ExtractedPattern:
    """Represents an extracted pattern from clustering."""
    pattern_id: str
    regex: str
    confidence: float
    support: int  # Number of samples matching
    cluster_id: int
    category: str
    description: str
    examples: List[str]
    created_at: datetime
    metadata: Dict[str, any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "pattern_id": self.pattern_id,
            "regex": self.regex,
            "confidence": self.confidence,
            "support": self.support,
            "cluster_id": self.cluster_id,
            "category": self.category,
            "description": self.description,
            "examples": self.examples[:5],  # Limit examples
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata
        }
    
    def test(self, text: str) -> bool:
        """Test if text matches this pattern."""
        try:
            return bool(re.search(self.regex, text, re.IGNORECASE))
        except re.error:
            logger.warning("Invalid regex pattern", pattern_id=self.pattern_id)
            return False


class PatternExtractor:
    """Extracts patterns from clustered events."""
    
    def __init__(
        self,
        min_support: int = 3,
        min_confidence: float = 0.7,
        max_pattern_length: int = 200,
        use_genetic_algorithm: bool = False
    ):
        """Initialize pattern extractor.
        
        Args:
            min_support: Minimum samples for valid pattern
            min_confidence: Minimum confidence for pattern
            max_pattern_length: Maximum regex pattern length
            use_genetic_algorithm: Use GA for pattern optimization
        """
        self.min_support = min_support
        self.min_confidence = min_confidence
        self.max_pattern_length = max_pattern_length
        self.use_genetic_algorithm = use_genetic_algorithm
        
        # Pattern templates for common attacks
        self.pattern_templates = {
            "instruction_override": [
                r"(ignore|disregard|forget).{0,20}(previous|prior|above)",
                r"(new|update).{0,20}(instruction|directive|command)",
                r"(override|bypass|disable).{0,20}(safety|restriction|filter)"
            ],
            "role_manipulation": [
                r"(you are|you're|act as).{0,20}(now|going to be)",
                r"(pretend|roleplay|impersonate).{0,20}(as|to be)",
                r"(system|admin|developer).{0,20}(mode|access|privilege)"
            ],
            "extraction": [
                r"(show|tell|reveal|print).{0,20}(system|initial|original).{0,20}(prompt|instruction)",
                r"(repeat|output|display).{0,20}(above|previous|prior)",
                r"(what is|what are).{0,20}(your|the).{0,20}(instruction|rule|directive)"
            ],
            "encoding": [
                r"[A-Za-z0-9+/]{40,}={0,2}",  # Base64
                r"\\x[0-9a-fA-F]{2,}",        # Hex
                r"\\u[0-9a-fA-F]{4,}",        # Unicode
                r"%[0-9a-fA-F]{2,}"           # URL encoding
            ]
        }
    
    async def extract_patterns(
        self,
        cluster: any,
        events: List[any]
    ) -> List[ExtractedPattern]:
        """Extract patterns from a cluster.
        
        Args:
            cluster: Cluster object
            events: Events in the cluster
            
        Returns:
            List of extracted patterns
        """
        patterns = []
        
        # Get prompts from events
        prompts = []
        for idx in cluster.members:
            if idx < len(events) and hasattr(events[idx], 'prompt'):
                prompts.append(events[idx].prompt)
        
        if len(prompts) < self.min_support:
            return patterns
        
        # Try different extraction methods
        
        # 1. Common substring extraction
        substring_patterns = self._extract_common_substrings(prompts)
        patterns.extend(substring_patterns)
        
        # 2. Template matching
        template_patterns = self._match_templates(prompts, cluster.dominant_category)
        patterns.extend(template_patterns)
        
        # 3. N-gram patterns
        ngram_patterns = self._extract_ngram_patterns(prompts)
        patterns.extend(ngram_patterns)
        
        # 4. Differential analysis
        diff_patterns = self._extract_diff_patterns(prompts)
        patterns.extend(diff_patterns)
        
        # 5. Genetic algorithm optimization (if enabled)
        if self.use_genetic_algorithm and patterns:
            patterns = await self._optimize_patterns_ga(patterns, prompts)
        
        # Filter and rank patterns
        patterns = self._filter_patterns(patterns, prompts)
        patterns.sort(key=lambda p: (p.confidence, p.support), reverse=True)
        
        # Limit number of patterns per cluster
        return patterns[:10]
    
    def _extract_common_substrings(self, prompts: List[str]) -> List[ExtractedPattern]:
        """Extract common substrings from prompts."""
        patterns = []
        
        if len(prompts) < 2:
            return patterns
        
        # Find longest common substrings
        common_strings = set()
        
        for i in range(len(prompts)):
            for j in range(i + 1, len(prompts)):
                # Use SequenceMatcher to find common substrings
                matcher = difflib.SequenceMatcher(None, prompts[i].lower(), prompts[j].lower())
                
                for match in matcher.get_matching_blocks():
                    if match.size >= 10:  # Minimum substring length
                        substring = prompts[i][match.a:match.a + match.size]
                        common_strings.add(substring.strip())
        
        # Convert substrings to patterns
        for substring in common_strings:
            if len(substring) > self.max_pattern_length:
                continue
            
            # Escape special regex characters
            escaped = re.escape(substring)
            
            # Count support
            support = sum(1 for p in prompts if substring.lower() in p.lower())
            
            if support >= self.min_support:
                pattern = ExtractedPattern(
                    pattern_id=self._generate_pattern_id(escaped),
                    regex=escaped,
                    confidence=support / len(prompts),
                    support=support,
                    cluster_id=getattr(cluster, 'cluster_id', 0),
                    category="common_substring",
                    description=f"Common substring: {substring[:50]}...",
                    examples=[p for p in prompts if substring.lower() in p.lower()][:3],
                    created_at=datetime.utcnow()
                )
                patterns.append(pattern)
        
        return patterns
    
    def _match_templates(self, prompts: List[str], category: str) -> List[ExtractedPattern]:
        """Match prompts against template patterns."""
        patterns = []
        
        # Get templates for category
        templates = self.pattern_templates.get(category, [])
        
        for template in templates:
            try:
                # Count matches
                matches = []
                for prompt in prompts:
                    if re.search(template, prompt, re.IGNORECASE):
                        matches.append(prompt)
                
                support = len(matches)
                if support >= self.min_support:
                    pattern = ExtractedPattern(
                        pattern_id=self._generate_pattern_id(template),
                        regex=template,
                        confidence=support / len(prompts),
                        support=support,
                        cluster_id=getattr(cluster, 'cluster_id', 0),
                        category=category,
                        description=f"Template match for {category}",
                        examples=matches[:3],
                        created_at=datetime.utcnow(),
                        metadata={"template": True}
                    )
                    patterns.append(pattern)
            except re.error:
                logger.warning("Invalid template regex", template=template)
        
        return patterns
    
    def _extract_ngram_patterns(self, prompts: List[str]) -> List[ExtractedPattern]:
        """Extract n-gram based patterns."""
        patterns = []
        
        # Extract word n-grams
        ngram_counts = Counter()
        
        for prompt in prompts:
            words = prompt.lower().split()
            
            # Extract 2-grams to 4-grams
            for n in range(2, min(5, len(words) + 1)):
                for i in range(len(words) - n + 1):
                    ngram = ' '.join(words[i:i+n])
                    ngram_counts[ngram] += 1
        
        # Convert frequent n-grams to patterns
        for ngram, count in ngram_counts.most_common(20):
            if count >= self.min_support:
                # Create flexible regex pattern
                words = ngram.split()
                regex_parts = []
                for word in words:
                    regex_parts.append(re.escape(word))
                
                # Allow some flexibility between words
                regex = r'\s*'.join(regex_parts)
                
                pattern = ExtractedPattern(
                    pattern_id=self._generate_pattern_id(regex),
                    regex=regex,
                    confidence=count / len(prompts),
                    support=count,
                    cluster_id=getattr(cluster, 'cluster_id', 0),
                    category="ngram",
                    description=f"N-gram pattern: {ngram}",
                    examples=[p for p in prompts if ngram in p.lower()][:3],
                    created_at=datetime.utcnow(),
                    metadata={"ngram": ngram, "n": len(words)}
                )
                patterns.append(pattern)
        
        return patterns
    
    def _extract_diff_patterns(self, prompts: List[str]) -> List[ExtractedPattern]:
        """Extract patterns using differential analysis."""
        patterns = []
        
        if len(prompts) < 3:
            return patterns
        
        # Find variable and fixed parts
        fixed_parts = []
        variable_parts = []
        
        # Compare first few prompts to find pattern
        base_prompt = prompts[0]
        
        for other_prompt in prompts[1:4]:
            matcher = difflib.SequenceMatcher(None, base_prompt, other_prompt)
            
            for tag, i1, i2, j1, j2 in matcher.get_opcodes():
                if tag == 'equal':
                    fixed_parts.append(base_prompt[i1:i2])
                elif tag in ['replace', 'insert']:
                    variable_parts.append((i1, i2))
        
        # Build regex pattern from fixed parts
        if fixed_parts:
            # Combine fixed parts with wildcards for variable sections
            regex_parts = []
            for part in fixed_parts:
                if len(part) > 5:  # Significant fixed part
                    regex_parts.append(re.escape(part))
            
            if regex_parts:
                regex = '.*?'.join(regex_parts)
                
                # Test pattern
                matches = sum(1 for p in prompts if re.search(regex, p, re.IGNORECASE))
                
                if matches >= self.min_support:
                    pattern = ExtractedPattern(
                        pattern_id=self._generate_pattern_id(regex),
                        regex=regex,
                        confidence=matches / len(prompts),
                        support=matches,
                        cluster_id=getattr(cluster, 'cluster_id', 0),
                        category="differential",
                        description="Pattern from differential analysis",
                        examples=prompts[:3],
                        created_at=datetime.utcnow(),
                        metadata={"method": "differential"}
                    )
                    patterns.append(pattern)
        
        return patterns
    
    async def _optimize_patterns_ga(
        self,
        patterns: List[ExtractedPattern],
        prompts: List[str]
    ) -> List[ExtractedPattern]:
        """Optimize patterns using genetic algorithm (simplified)."""
        # This is a placeholder for GA optimization
        # In production, would use a proper GA library
        return patterns
    
    def _filter_patterns(
        self,
        patterns: List[ExtractedPattern],
        prompts: List[str]
    ) -> List[ExtractedPattern]:
        """Filter and validate patterns."""
        filtered = []
        seen_patterns = set()
        
        for pattern in patterns:
            # Check confidence
            if pattern.confidence < self.min_confidence:
                continue
            
            # Check uniqueness
            pattern_key = pattern.regex[:50]
            if pattern_key in seen_patterns:
                continue
            seen_patterns.add(pattern_key)
            
            # Validate regex
            try:
                re.compile(pattern.regex)
            except re.error:
                logger.warning("Invalid regex pattern", pattern_id=pattern.pattern_id)
                continue
            
            # Check pattern length
            if len(pattern.regex) > self.max_pattern_length:
                continue
            
            # Verify support
            actual_matches = sum(1 for p in prompts if pattern.test(p))
            if actual_matches < self.min_support:
                continue
            
            # Update support if needed
            pattern.support = actual_matches
            pattern.confidence = actual_matches / len(prompts)
            
            filtered.append(pattern)
        
        return filtered
    
    def _generate_pattern_id(self, regex: str) -> str:
        """Generate unique pattern ID."""
        hash_input = f"{regex}_{datetime.utcnow().isoformat()}"
        return f"pat_{hashlib.sha256(hash_input.encode()).hexdigest()[:12]}"
    
    def merge_similar_patterns(
        self,
        patterns: List[ExtractedPattern],
        similarity_threshold: float = 0.8
    ) -> List[ExtractedPattern]:
        """Merge similar patterns to reduce redundancy."""
        if len(patterns) <= 1:
            return patterns
        
        merged = []
        used = set()
        
        for i, pattern1 in enumerate(patterns):
            if i in used:
                continue
            
            # Find similar patterns
            similar_group = [pattern1]
            
            for j, pattern2 in enumerate(patterns[i+1:], i+1):
                if j in used:
                    continue
                
                # Check similarity (simplified - check overlap in examples)
                overlap = len(set(pattern1.examples) & set(pattern2.examples))
                similarity = overlap / max(len(pattern1.examples), len(pattern2.examples))
                
                if similarity >= similarity_threshold:
                    similar_group.append(pattern2)
                    used.add(j)
            
            # Merge group
            if len(similar_group) > 1:
                # Combine patterns (take most general)
                merged_pattern = ExtractedPattern(
                    pattern_id=self._generate_pattern_id("merged"),
                    regex=similar_group[0].regex,  # Could combine regexes
                    confidence=max(p.confidence for p in similar_group),
                    support=max(p.support for p in similar_group),
                    cluster_id=similar_group[0].cluster_id,
                    category=similar_group[0].category,
                    description=f"Merged pattern from {len(similar_group)} similar patterns",
                    examples=list(set(sum([p.examples for p in similar_group], []))[:5]),
                    created_at=datetime.utcnow(),
                    metadata={"merged_count": len(similar_group)}
                )
                merged.append(merged_pattern)
            else:
                merged.append(pattern1)
        
        return merged
    
    def evaluate_pattern(
        self,
        pattern: ExtractedPattern,
        test_prompts: List[Tuple[str, bool]]
    ) -> Dict[str, float]:
        """Evaluate pattern performance on test data.
        
        Args:
            pattern: Pattern to evaluate
            test_prompts: List of (prompt, is_malicious) tuples
            
        Returns:
            Evaluation metrics
        """
        true_positives = 0
        false_positives = 0
        true_negatives = 0
        false_negatives = 0
        
        for prompt, is_malicious in test_prompts:
            matches = pattern.test(prompt)
            
            if matches and is_malicious:
                true_positives += 1
            elif matches and not is_malicious:
                false_positives += 1
            elif not matches and not is_malicious:
                true_negatives += 1
            elif not matches and is_malicious:
                false_negatives += 1
        
        # Calculate metrics
        total = len(test_prompts)
        accuracy = (true_positives + true_negatives) / total if total > 0 else 0
        
        precision = true_positives / (true_positives + false_positives) \
            if (true_positives + false_positives) > 0 else 0
        
        recall = true_positives / (true_positives + false_negatives) \
            if (true_positives + false_negatives) > 0 else 0
        
        f1_score = 2 * (precision * recall) / (precision + recall) \
            if (precision + recall) > 0 else 0
        
        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "true_negatives": true_negatives,
            "false_negatives": false_negatives
        }