# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Heuristic-based detection engine for prompt injection attacks."""

import re
import base64
import json
from typing import Dict, List, Optional, Tuple
from prompt_sentinel.models.schemas import (
    DetectionCategory,
    DetectionReason,
    Message,
    Role,
    Verdict
)


class HeuristicDetector:
    """Pattern-based detection for common injection techniques."""
    
    def __init__(self, detection_mode: str = "strict", pattern_manager=None):
        """
        Initialize the heuristic detector.
        
        Args:
            detection_mode: One of "strict", "moderate", "permissive"
            pattern_manager: Optional ML pattern manager for discovered patterns
        """
        self.detection_mode = detection_mode
        self.pattern_manager = pattern_manager
        self._init_patterns()
        
        # ML-discovered patterns cache
        self.ml_patterns = []
        self.ml_patterns_last_update = None
    
    def _init_patterns(self):
        """Initialize detection patterns based on mode."""
        # Direct injection patterns
        self.direct_injection_patterns = [
            # Instruction override attempts
            (r"ignore (all )?(previous|prior|above)", 0.9, "Instruction override attempt"),
            (r"disregard (all )?(previous|prior|above)", 0.9, "Instruction override attempt"),
            (r"forget (everything|all|what)", 0.85, "Memory reset attempt"),
            (r"new instructions?:?", 0.8, "New instruction injection"),
            (r"update.{0,20}(instruction|directive|command)", 0.8, "Instruction update attempt"),
            
            # Role play and impersonation
            (r"(you are|you're) (now |going to be |a )", 0.85, "Role manipulation"),
            (r"act (as|like) (a|an)", 0.8, "Role playing request"),
            (r"pretend (to be|you)", 0.85, "Impersonation attempt"),
            (r"roleplay as", 0.85, "Role playing request"),
            
            # System prompt extraction
            (r"(what|tell me|show me).{0,20}(system|initial|original) (prompt|instruction)", 
             0.9, "System prompt extraction attempt"),
            (r"repeat.{0,20}(instruction|prompt|directive)", 0.85, "Prompt leak attempt"),
            (r"(print|output|display|show).{0,20}(above|previous|prior)", 0.8, "Content extraction"),
            
            # Command injection style
            (r"<\|.*\|>", 0.9, "Special delimiter injection"),
            (r"\[\[.*\]\]", 0.7, "Bracket command injection"),
            (r"{{.*}}", 0.7, "Template injection"),
            (r"execute:?", 0.8, "Command execution attempt"),
        ]
        
        # Jailbreak patterns
        self.jailbreak_patterns = [
            (r"DAN (mode|prompt)", 0.95, "DAN jailbreak attempt"),
            (r"developer mode", 0.9, "Developer mode jailbreak"),
            (r"(unlock|enable|activate).{0,20}(hidden|secret|advanced)", 0.85, "Feature unlock attempt"),
            (r"sudo ", 0.8, "Privilege escalation attempt"),
            (r"admin (mode|access|privileges?)", 0.85, "Admin access attempt"),
            (r"bypass.{0,20}(restriction|filter|safety)", 0.9, "Bypass attempt"),
        ]
        
        # Encoding attack patterns
        self.encoding_patterns = [
            (r"[A-Za-z0-9+/]{50,}={0,2}", 0.7, "Potential base64 encoding"),
            (r"\\x[0-9a-fA-F]{2}", 0.8, "Hex encoding detected"),
            (r"\\u[0-9a-fA-F]{4}", 0.8, "Unicode encoding detected"),
            (r"%[0-9a-fA-F]{2}", 0.6, "URL encoding detected"),
            (r"&(#x?[0-9a-fA-F]+|[a-z]+);", 0.6, "HTML entity encoding"),
        ]
        
        # Context switching patterns
        self.context_switching_patterns = [
            (r"###.{0,20}(system|user|assistant)", 0.8, "Role delimiter injection"),
            (r"(end of|close) (conversation|chat|session)", 0.7, "Context termination attempt"),
            (r"(start|begin) (new|another) (conversation|session)", 0.7, "Context reset attempt"),
            (r"\n{3,}", 0.5, "Excessive newlines for context break"),
            (r"={10,}", 0.6, "Separator injection"),
        ]
        
        # Adjust thresholds based on detection mode
        self.threshold_adjustments = {
            "strict": 0.0,
            "moderate": 0.1,
            "permissive": 0.2
        }
    
    def detect(self, messages: List[Message]) -> Tuple[Verdict, List[DetectionReason], float]:
        """Perform heuristic detection on messages using pattern matching.
        
        Analyzes messages for suspicious patterns across multiple categories
        including direct injection, encoding, role confusion, and extraction
        attempts. Combines detection results to determine threat level.
        
        Args:
            messages: List of messages to analyze for injection patterns
            
        Returns:
            Tuple containing:
            - verdict: Recommended action (BLOCK/STRIP/FLAG/ALLOW)
            - reasons: List of detected threats with descriptions
            - confidence: Overall confidence score (0.0-1.0)
            
        Example:
            >>> messages = [Message(role=Role.USER, content=\"Ignore previous\")]
            >>> verdict, reasons, conf = detector.detect(messages)
            >>> print(verdict)
            Verdict.BLOCK
        """
        all_reasons = []
        max_confidence = 0.0
        
        for message in messages:
            reasons = self._analyze_message(message)
            all_reasons.extend(reasons)
            
            if reasons:
                msg_confidence = max(r.confidence for r in reasons)
                max_confidence = max(max_confidence, msg_confidence)
        
        # Adjust confidence based on detection mode
        threshold_adjustment = self.threshold_adjustments.get(self.detection_mode, 0.0)
        adjusted_confidence = max(0, max_confidence - threshold_adjustment)
        
        # Determine verdict based on confidence
        verdict = self._determine_verdict(adjusted_confidence, all_reasons)
        
        return verdict, all_reasons, adjusted_confidence
    
    def _analyze_message(self, message: Message) -> List[DetectionReason]:
        """Analyze a single message for injection patterns.
        
        Applies all pattern categories to the message content and
        collects detection reasons for any matches found.
        
        Args:
            message: Message to analyze
            
        Returns:
            List of DetectionReason objects for detected threats
        """
        reasons = []
        content = message.content
        content_lower = content.lower()
        
        # Check direct injection patterns
        for pattern, confidence, description in self.direct_injection_patterns:
            if re.search(pattern, content_lower):
                reasons.append(DetectionReason(
                    category=DetectionCategory.DIRECT_INJECTION,
                    description=description,
                    confidence=confidence,
                    source="heuristic",
                    patterns_matched=[pattern]
                ))
        
        # Check jailbreak patterns
        for pattern, confidence, description in self.jailbreak_patterns:
            if re.search(pattern, content_lower):
                reasons.append(DetectionReason(
                    category=DetectionCategory.JAILBREAK,
                    description=description,
                    confidence=confidence,
                    source="heuristic",
                    patterns_matched=[pattern]
                ))
        
        # Check encoding patterns (case-sensitive)
        for pattern, confidence, description in self.encoding_patterns:
            if re.search(pattern, content):
                # Try to decode to verify it's actual encoding
                if self._verify_encoding(content, pattern):
                    reasons.append(DetectionReason(
                        category=DetectionCategory.ENCODING_ATTACK,
                        description=description,
                        confidence=confidence,
                        source="heuristic",
                        patterns_matched=[pattern]
                    ))
        
        # Check context switching
        for pattern, confidence, description in self.context_switching_patterns:
            if re.search(pattern, content, re.MULTILINE):
                reasons.append(DetectionReason(
                    category=DetectionCategory.CONTEXT_SWITCHING,
                    description=description,
                    confidence=confidence,
                    source="heuristic",
                    patterns_matched=[pattern]
                ))
        
        # Check ML-discovered patterns
        ml_matches = self._check_ml_patterns(content)
        for pattern_id, confidence, description in ml_matches:
            reasons.append(DetectionReason(
                category=DetectionCategory.DIRECT_INJECTION,
                description=description,
                confidence=confidence,
                source="ml_pattern",
                patterns_matched=[pattern_id]
            ))
        
        # Special checks for system prompts in user messages
        if message.role == Role.USER:
            if self._check_role_manipulation(content):
                reasons.append(DetectionReason(
                    category=DetectionCategory.ROLE_MANIPULATION,
                    description="User message contains system-level instructions",
                    confidence=0.85,
                    source="heuristic",
                    patterns_matched=["role_manipulation_check"]
                ))
        
        # Check for prompt leak attempts in any message
        if self._check_prompt_leak(content):
            reasons.append(DetectionReason(
                category=DetectionCategory.PROMPT_LEAK,
                description="Attempt to extract system prompt detected",
                confidence=0.9,
                source="heuristic",
                patterns_matched=["prompt_leak_check"]
            ))
        
        return reasons
    
    def _verify_encoding(self, content: str, pattern: str) -> bool:
        """Verify if a pattern match is actual encoding."""
        try:
            # Check for base64
            if "base64" in pattern.lower():
                matches = re.findall(r'[A-Za-z0-9+/]{50,}={0,2}', content)
                for match in matches:
                    try:
                        decoded = base64.b64decode(match)
                        # Check if decoded content contains text
                        if any(32 <= b < 127 for b in decoded):
                            return True
                    except Exception:
                        pass
            return False
        except Exception:
            return False
    
    def _check_role_manipulation(self, content: str) -> bool:
        """Check for role manipulation attempts."""
        role_keywords = [
            "system message", "system prompt", "system instruction",
            "assistant message", "assistant prompt",
            "you must", "you have to", "you should",
            "your task is", "your role is", "your purpose is"
        ]
        
        content_lower = content.lower()
        return any(keyword in content_lower for keyword in role_keywords)
    
    def _update_ml_patterns(self):
        """Update ML-discovered patterns from pattern manager."""
        if not self.pattern_manager:
            return
        
        try:
            # Get active patterns from manager
            from datetime import datetime, timedelta
            
            # Update every 5 minutes
            if (not self.ml_patterns_last_update or 
                datetime.utcnow() - self.ml_patterns_last_update > timedelta(minutes=5)):
                
                self.ml_patterns = self.pattern_manager.get_active_patterns()
                self.ml_patterns_last_update = datetime.utcnow()
                
        except Exception:
            # Silently fail to not break detection
            pass
    
    def _check_ml_patterns(self, content: str) -> List[Tuple[str, float, str]]:
        """Check content against ML-discovered patterns."""
        matches = []
        
        # Update patterns if needed
        self._update_ml_patterns()
        
        # Check each ML pattern
        for pattern in self.ml_patterns:
            try:
                if pattern.test(content):
                    matches.append((
                        pattern.pattern_id,
                        pattern.confidence,
                        f"ML Pattern: {pattern.description}"
                    ))
            except Exception:
                # Skip failed patterns
                continue
        
        return matches
    
    def _check_prompt_leak(self, content: str) -> bool:
        """Check for prompt leak attempts."""
        leak_keywords = [
            "show me your prompt",
            "what are your instructions",
            "repeat your system message",
            "print your directives",
            "display your configuration",
            "tell me your rules"
        ]
        
        content_lower = content.lower()
        return any(keyword in content_lower for keyword in leak_keywords)
    
    def _determine_verdict(self, confidence: float, reasons: List[DetectionReason]) -> Verdict:
        """Determine verdict based on confidence and detection mode."""
        if not reasons:
            return Verdict.ALLOW
        
        # Mode-specific thresholds
        thresholds = {
            "strict": {"block": 0.7, "strip": 0.5, "flag": 0.3},
            "moderate": {"block": 0.8, "strip": 0.6, "flag": 0.4},
            "permissive": {"block": 0.9, "strip": 0.7, "flag": 0.5}
        }
        
        mode_thresholds = thresholds.get(self.detection_mode, thresholds["moderate"])
        
        if confidence >= mode_thresholds["block"]:
            return Verdict.BLOCK
        elif confidence >= mode_thresholds["strip"]:
            return Verdict.STRIP
        elif confidence >= mode_thresholds["flag"]:
            return Verdict.FLAG
        else:
            return Verdict.ALLOW
    
    def get_statistics(self, messages: List[Message]) -> Dict:
        """Get detection statistics for messages."""
        stats = {
            "total_messages": len(messages),
            "patterns_checked": {
                "direct_injection": len(self.direct_injection_patterns),
                "jailbreak": len(self.jailbreak_patterns),
                "encoding": len(self.encoding_patterns),
                "context_switching": len(self.context_switching_patterns)
            },
            "detection_mode": self.detection_mode,
            "messages_by_role": {}
        }
        
        for message in messages:
            role = message.role.value
            stats["messages_by_role"][role] = stats["messages_by_role"].get(role, 0) + 1
        
        return stats