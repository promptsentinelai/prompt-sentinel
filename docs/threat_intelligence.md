# Threat Intelligence Configuration

PromptSentinel includes a comprehensive threat intelligence system with real-world attack patterns for LLM security.

## Pattern Categories

### 1. Prompt Injection Patterns (15 patterns)
- **File**: `feeds/patterns/prompt_injection.json`
- **Description**: Direct instruction override attempts and system-level manipulations
- **Examples**:
  - Ignore all previous instructions
  - System prompt injection
  - Hidden instructions in comments
  - Code injection attempts

### 2. Jailbreak Patterns (15 patterns)
- **File**: `feeds/patterns/jailbreak.json`
- **Description**: Known jailbreak techniques from security research
- **Examples**:
  - DAN (Do Anything Now)
  - STAN (Strive To Avoid Norms)
  - AIM (Always Intelligent and Machiavellian)
  - Developer mode exploits
  - Token smuggling

### 3. Data Exfiltration Patterns (15 patterns)
- **File**: `feeds/patterns/data_exfiltration.json`
- **Description**: Attempts to extract sensitive data or system information
- **Examples**:
  - User data extraction
  - API key/credential theft
  - Environment variable probing
  - Training data reconnaissance

### 4. Role Manipulation Patterns (15 patterns)
- **File**: `feeds/patterns/role_manipulation.json`
- **Description**: Attempts to manipulate or bypass role-based security
- **Examples**:
  - Admin privilege claims
  - Identity confusion attacks
  - Safety override attempts
  - False authority assertions

## Pattern Structure

Each pattern file contains:
```json
{
  "metadata": {
    "name": "Pattern Category Name",
    "version": "1.0.0",
    "updated": "2025-01-14",
    "source": "Source description",
    "description": "Category description"
  },
  "patterns": [
    {
      "id": "unique-id",
      "pattern": "Main pattern text",
      "variants": ["variant1", "variant2"],
      "technique": "attack_technique",
      "severity": "low|medium|high|critical",
      "confidence": 0.0-1.0,
      "description": "Pattern description",
      "tags": ["tag1", "tag2"]
    }
  ]
}
```

## Feed Configuration

The default feed configuration is in `feeds/config/default_feeds.yaml` and includes:

1. **OWASP LLM Top 10** - Community patterns from OWASP
2. **GitHub Jailbreak Database** - Research repositories
3. **HuggingFace Datasets** - Curated malicious prompts
4. **MITRE ATLAS** - Adversarial ML techniques
5. **Local Patterns** - PromptSentinel core patterns

## Using the Patterns

### Loading Patterns
```python
import json
from pathlib import Path

# Load pattern file
with open("feeds/patterns/prompt_injection.json") as f:
    patterns = json.load(f)["patterns"]

# Check for matches
def check_prompt(user_input):
    for pattern in patterns:
        if pattern["pattern"].lower() in user_input.lower():
            return pattern
        
        # Check variants
        for variant in pattern.get("variants", []):
            if variant.lower() in user_input.lower():
                return pattern
    
    return None
```

### Feed Manager Integration
```python
from prompt_sentinel.threat_intelligence.feed_manager import ThreatFeedManager

# Initialize manager
manager = ThreatFeedManager()
await manager.initialize()

# Search for patterns
results = await manager.search_indicators("ignore instructions")

# Get high-confidence indicators
indicators = await manager.get_active_indicators(min_confidence=0.8)
```

## Pattern Statistics

- **Total Patterns**: 60
- **Pattern Categories**: 4
- **Confidence Range**: 0.6 - 0.95
- **Severity Levels**: Low, Medium, High, Critical

## Security Best Practices

1. **Regular Updates**: Keep patterns updated with latest attack techniques
2. **Confidence Thresholds**: Set appropriate thresholds based on use case
3. **False Positive Handling**: Report false positives to improve accuracy
4. **Pattern Testing**: Test patterns against benign prompts
5. **Monitoring**: Track detection rates and adjust as needed

## Sources and References

- OWASP Top 10 for LLM Applications
- MITRE ATLAS Framework
- GitHub Security Research Repositories
- HuggingFace Security Datasets
- Academic Papers on LLM Security