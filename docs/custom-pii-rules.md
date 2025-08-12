# Custom PII Detection Rules

## Overview

PromptSentinel supports custom PII (Personally Identifiable Information) detection rules that allow you to define organization-specific patterns for sensitive data detection. These rules are loaded from a YAML configuration file at startup and work alongside the built-in PII detection patterns.

## Features

- **YAML-based Configuration**: Define rules in an easy-to-read YAML format
- **Pattern Validation**: Automatic validation of regex patterns with ReDoS prevention
- **Custom Redaction**: Configure custom masking formats for each PII type
- **Severity Levels**: Assign severity levels (low/medium/high/critical) to custom patterns
- **API Testing**: Test rules via API before deployment
- **Security-First Design**: Rules are immutable after startup for security

## Configuration

### Enabling Custom Rules

Custom PII rules are enabled by default. You can configure them via environment variables:

```env
# Enable/disable custom PII rules (default: true)
CUSTOM_PII_RULES_ENABLED=true

# Path to custom rules YAML file (default: config/custom_pii_rules.yaml)
CUSTOM_PII_RULES_PATH=config/custom_pii_rules.yaml
```

### YAML File Structure

Create a `config/custom_pii_rules.yaml` file with the following structure:

```yaml
version: "1.0"

# Global settings for custom rules
settings:
  merge_with_builtin: true           # Combine with built-in patterns
  min_confidence_threshold: 0.5      # Minimum confidence for detection
  max_regex_complexity: 100          # ReDoS prevention threshold
  cache_compiled_patterns: true      # Cache compiled regex patterns

# Custom PII rule definitions
custom_pii_rules:
  - name: "employee_id"
    description: "Company employee identification number"
    enabled: true
    severity: "high"                 # low, medium, high, critical
    patterns:
      - regex: "EMP[0-9]{6}"
        confidence: 0.95             # 0.0 to 1.0
        description: "Standard employee ID format"
      - regex: "E[0-9]{8}"
        confidence: 0.85
        description: "Legacy employee ID format"
    redaction:
      mask_format: "EMP-****"        # Custom masking pattern
      hash_prefix: "EMP_"            # Prefix for hash redaction

  - name: "internal_api_key"
    description: "Internal API keys"
    enabled: true
    severity: "critical"
    patterns:
      - regex: "int_api_[a-zA-Z0-9]{32}"
        confidence: 0.99
        description: "Internal API key pattern"
    redaction:
      mask_format: "int_api_****"
      hash_prefix: "IAPI_"

  - name: "project_code"
    description: "Confidential project codes"
    enabled: true
    severity: "medium"
    patterns:
      - regex: "PROJ-[0-9]{4}-[A-Z]{2}"
        confidence: 0.85
        description: "Project code format PROJ-YYYY-XX"
    redaction:
      mask_format: "PROJ-****-**"
      hash_prefix: "PROJ_"
```

## Rule Components

### Rule Properties

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `name` | string | Yes | Unique identifier for the rule |
| `description` | string | No | Human-readable description |
| `enabled` | boolean | No | Whether the rule is active (default: true) |
| `severity` | string | No | Severity level: low/medium/high/critical (default: medium) |
| `patterns` | array | Yes | List of regex patterns to match |
| `redaction` | object | No | Custom redaction configuration |

### Pattern Properties

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `regex` | string | Yes | Regular expression pattern |
| `confidence` | float | Yes | Detection confidence (0.0-1.0) |
| `description` | string | No | Pattern description |

### Redaction Properties

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `mask_format` | string | No | Custom mask format (default: ****) |
| `hash_prefix` | string | No | Prefix for hash redaction |

## API Endpoints

### Validate Rules

Test YAML configuration without applying it:

```bash
curl -X POST http://localhost:8080/api/v1/pii/validate-rules \
  -H "Content-Type: application/yaml" \
  --data-binary @custom_rules.yaml
```

Response:
```json
{
  "valid": true,
  "rules_count": 3,
  "errors": [],
  "warnings": []
}
```

### Test Rules

Test rules against sample text:

```bash
curl -X POST http://localhost:8080/api/v1/pii/test-rules \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Employee EMP123456 accessed project PROJ-2024-AB",
    "rules_yaml": "..."
  }'
```

Response:
```json
{
  "matches": [
    {
      "rule_name": "employee_id",
      "matched_text": "EMP123456",
      "masked_value": "EMP-****",
      "confidence": 0.95,
      "severity": "high",
      "position": {"start": 9, "end": 18}
    },
    {
      "rule_name": "project_code",
      "matched_text": "PROJ-2024-AB",
      "masked_value": "PROJ-****-**",
      "confidence": 0.85,
      "severity": "medium",
      "position": {"start": 36, "end": 48}
    }
  ],
  "total_matches": 2
}
```

### Get Rules Status

Check loaded rules status:

```bash
curl http://localhost:8080/api/v1/pii/rules/status
```

Response:
```json
{
  "custom_rules_enabled": true,
  "rules_loaded": 3,
  "rules": [
    {
      "name": "employee_id",
      "enabled": true,
      "patterns_count": 2,
      "severity": "high"
    }
  ],
  "config_path": "config/custom_pii_rules.yaml",
  "last_loaded": "2025-01-11T10:30:00Z"
}
```

### Reload Rules

Reload rules from file (requires restart in production):

```bash
curl -X POST http://localhost:8080/api/v1/pii/rules/reload \
  -H "Authorization: Bearer your-api-key"
```

## Security Considerations

### ReDoS Prevention

The system automatically checks regex patterns for potential ReDoS (Regular Expression Denial of Service) vulnerabilities:

- Patterns with high complexity scores are rejected
- Nested quantifiers are detected and flagged
- Maximum complexity threshold is configurable

Example of rejected pattern:
```yaml
# This pattern would be rejected due to nested quantifiers
- regex: "(a+)+(b+)+(c+)+"  # DANGEROUS - can cause ReDoS
```

### YAML Safety

- Only `safe_load` is used to parse YAML files
- Code execution via YAML is prevented
- File permissions are checked before loading

### Immutability

- Rules are loaded once at startup
- Cannot be modified via API during runtime
- Changes require service restart (by design)

## Best Practices

### 1. Pattern Design

```yaml
# GOOD: Specific, anchored pattern
- regex: "\\bEMP[0-9]{6}\\b"
  confidence: 0.95

# BAD: Too generic, may cause false positives
- regex: "[0-9]{6}"
  confidence: 0.95
```

### 2. Confidence Scores

- **0.90-1.00**: Very specific patterns with low false positive rate
- **0.70-0.89**: Moderately specific patterns
- **0.50-0.69**: Generic patterns that need context
- **Below 0.50**: Not recommended

### 3. Testing

Always test rules before deployment:

1. Validate YAML syntax
2. Test against sample data
3. Check for false positives
4. Verify performance impact

### 4. Organization

Group related patterns:

```yaml
custom_pii_rules:
  # Financial patterns
  - name: "internal_account_number"
    patterns: [...]
  
  - name: "transaction_id"
    patterns: [...]
  
  # Employee patterns
  - name: "employee_id"
    patterns: [...]
  
  - name: "badge_number"
    patterns: [...]
```

## Examples

### Healthcare Organization

```yaml
custom_pii_rules:
  - name: "patient_id"
    description: "Patient identification number"
    severity: "critical"
    patterns:
      - regex: "PAT-[0-9]{3}-[0-9]{6}"
        confidence: 0.95
        description: "Standard patient ID"
    redaction:
      mask_format: "PAT-***-******"
      
  - name: "medical_record_number"
    description: "Medical record number"
    severity: "critical"
    patterns:
      - regex: "MRN[0-9]{10}"
        confidence: 0.95
    redaction:
      mask_format: "MRN**********"
```

### Financial Institution

```yaml
custom_pii_rules:
  - name: "account_number"
    description: "Internal account numbers"
    severity: "high"
    patterns:
      - regex: "ACC-[0-9]{4}-[0-9]{6}-[0-9]{2}"
        confidence: 0.95
    redaction:
      mask_format: "ACC-****-******-**"
      
  - name: "transaction_reference"
    description: "Transaction reference codes"
    severity: "medium"
    patterns:
      - regex: "TXN[0-9]{12}"
        confidence: 0.90
    redaction:
      mask_format: "TXN************"
```

### Software Company

```yaml
custom_pii_rules:
  - name: "license_key"
    description: "Software license keys"
    severity: "high"
    patterns:
      - regex: "LIC-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}"
        confidence: 0.95
    redaction:
      mask_format: "LIC-****-****-****-****"
      
  - name: "api_client_id"
    description: "API client identifiers"
    severity: "medium"
    patterns:
      - regex: "client_[a-z0-9]{24}"
        confidence: 0.90
    redaction:
      mask_format: "client_************************"
```

## Troubleshooting

### Rules Not Loading

1. Check file path in environment variable
2. Verify YAML syntax
3. Check file permissions
4. Review application logs for errors

### Pattern Not Matching

1. Test regex pattern independently
2. Verify confidence threshold settings
3. Check if pattern complexity exceeds limit
4. Ensure rule is enabled

### Performance Issues

1. Reduce pattern complexity
2. Use anchors (^, $, \b) in patterns
3. Avoid excessive alternation
4. Limit number of active rules

## Monitoring

Monitor custom PII detection effectiveness:

- Track detection rates per rule
- Monitor false positive rates
- Review processing time impact
- Audit redacted content samples

## Integration with Built-in Detection

Custom rules work alongside built-in PII detection:

- Custom patterns are checked in addition to built-in patterns
- Custom PII types are prefixed with `custom_` in detection results
- Both can trigger redaction based on configuration
- Confidence thresholds apply to both types

Example detection response:
```json
{
  "pii_detected": [
    {
      "pii_type": "ssn",              // Built-in type
      "masked_value": "***-**-****",
      "confidence": 0.9
    },
    {
      "pii_type": "custom_employee_id",  // Custom type
      "masked_value": "EMP-****",
      "confidence": 0.95
    }
  ]
}
```

## Support

For questions or issues with custom PII rules:

1. Check the [documentation](https://github.com/promptsentinelai/prompt-sentinel/docs)
2. Review [example configurations](https://github.com/promptsentinelai/prompt-sentinel/examples)
3. Submit issues to the [GitHub repository](https://github.com/promptsentinelai/prompt-sentinel/issues)