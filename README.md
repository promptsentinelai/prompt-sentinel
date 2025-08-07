# 🛡️ PromptSentinel

[![CI/CD Pipeline](https://github.com/rhoska/prompt-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/rhoska/prompt-sentinel/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-green.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A defensive security microservice for detecting and mitigating prompt injection attacks in LLM-based systems. PromptSentinel provides real-time protection using multi-layered detection strategies.

## 🚀 Features

- **Multi-Layer Detection**: Combines heuristic patterns with LLM-based classification
- **Flexible Input Formats**: Supports both simple strings and role-separated messages
- **Multi-Provider LLM Support**: Anthropic (primary), OpenAI, and Google Gemini with automatic failover
- **Configurable Detection Modes**: Strict, moderate, or permissive based on your needs
- **Format Recommendations**: Helps developers write more secure prompts
- **Enterprise Ready**: SOC 2, FINRA, and GDPR compliant with OpenTelemetry support
- **High Performance**: Built with FastAPI and UV for optimal speed

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [API Documentation](#api-documentation)
- [Configuration](#configuration)
- [Detection Strategies](#detection-strategies)
- [Development](#development)
- [Deployment](#deployment)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## 🔧 Installation

### Using UV (Recommended)

```bash
# Install UV
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone the repository
git clone https://github.com/rhoska/prompt-sentinel.git
cd prompt-sentinel

# Create virtual environment and install dependencies
uv venv --python 3.11
source .venv/bin/activate
uv pip install -e .
```

### Using Docker

```bash
docker pull promptsentinel/prompt-sentinel:latest
```

## 🚀 Quick Start

1. **Set up environment variables**:
```bash
cp .env.example .env
# Edit .env with your API keys
```

2. **Run the service**:
```bash
# Using UV
./scripts/run_local.sh

# Using Docker
docker-compose up

# Direct execution
uvicorn prompt_sentinel.main:app --reload
```

3. **Test the API**:
```bash
# Simple detection
curl -X POST http://localhost:8080/v1/detect \
  -H "Content-Type: application/json" \
  -d '{"prompt": "What is the weather today?"}'

# Advanced detection with role separation
curl -X POST http://localhost:8080/v2/detect \
  -H "Content-Type: application/json" \
  -d '{
    "input": [
      {"role": "system", "content": "You are a helpful assistant."},
      {"role": "user", "content": "Help me with my task."}
    ]
  }'
```

## 📚 API Documentation

### Endpoints

#### `POST /v1/detect`
Simple string-based detection for backward compatibility.

**Request**:
```json
{
  "prompt": "Your prompt text here",
  "role": "user"  // Optional: "user", "system", or "combined"
}
```

**Response**:
```json
{
  "verdict": "allow",  // "allow", "block", "flag", or "strip"
  "confidence": 0.95,
  "reasons": [...],
  "processing_time_ms": 42.3
}
```

#### `POST /v2/detect`
Enhanced detection with support for role-separated messages.

**Request**:
```json
{
  "input": [
    {"role": "system", "content": "System instructions"},
    {"role": "user", "content": "User prompt"}
  ],
  "config": {
    "use_heuristics": true,
    "use_llm": true
  }
}
```

#### `POST /v2/analyze`
Comprehensive analysis with per-message details.

#### `POST /v2/format-assist`
Helps developers format prompts securely.

#### `GET /health`
Health check endpoint for monitoring.

Full API documentation available at `http://localhost:8080/docs` when running.

## ⚙️ Configuration

### Environment Variables

```bash
# LLM Providers
LLM_PROVIDER_ORDER=anthropic,openai,gemini
ANTHROPIC_API_KEY=your_key_here
OPENAI_API_KEY=your_key_here
GEMINI_API_KEY=your_key_here

# Detection Settings
DETECTION_MODE=strict  # strict, moderate, or permissive
CONFIDENCE_THRESHOLD=0.7
MAX_PROMPT_LENGTH=50000

# Detection Components (can be independently controlled)
HEURISTIC_ENABLED=true          # Pattern-based detection
LLM_CLASSIFICATION_ENABLED=true # AI-based classification
PII_DETECTION_ENABLED=true      # PII detection and redaction

# Redis (Optional)
REDIS_ENABLED=true
REDIS_HOST=localhost
REDIS_PORT=6379
```

### Detection Modes

- **Strict**: High sensitivity, catches more threats but may have false positives
- **Moderate**: Balanced approach for most use cases
- **Permissive**: Low sensitivity, fewer false positives but may miss subtle attacks

### Detection Components

You can independently control which detection methods are active:

```bash
# Enable/disable detection components
HEURISTIC_ENABLED=true          # Pattern-based detection
LLM_CLASSIFICATION_ENABLED=true # AI-based classification
PII_DETECTION_ENABLED=true      # PII detection and redaction
```

#### Disabling LLM Classification

Setting `LLM_CLASSIFICATION_ENABLED=false` runs the service with pattern-based detection only.

**Advantages of Heuristic-Only Mode:**
- ⚡ **Faster Response Times**: Reduces latency from 500-2000ms to <50ms
- 💰 **Cost Reduction**: No API costs for LLM providers
- 🔌 **Offline Operation**: Works without internet or API keys
- 📊 **Predictable Performance**: Consistent latency without API variability
- 🚀 **No Rate Limits**: Unlimited throughput without provider restrictions

**Disadvantages of Heuristic-Only Mode:**
- 🎯 **Reduced Accuracy**: Sophisticated attacks may evade pattern matching
- 🔍 **Higher False Negatives**: Subtle jailbreaks and encoded attacks harder to detect
- 📉 **Limited Adaptability**: Can't detect novel attack patterns without rule updates
- 🤝 **No Consensus Scoring**: Loses confidence boost from multi-method agreement

**When to Use Heuristic-Only Mode:**
- ✅ High-volume, low-risk applications
- ✅ Cost-sensitive deployments  
- ✅ Offline/air-gapped environments
- ✅ Real-time systems requiring <100ms latency
- ✅ Initial filtering layer before expensive checks

**When to Keep LLM Enabled:**
- ⚠️ High-security applications
- ⚠️ User-facing chatbots with sensitive data
- ⚠️ Financial or healthcare systems
- ⚠️ Environments with sophisticated attack risks

### PII Redaction Modes

Configure how detected PII is handled using `PII_REDACTION_MODE`:

| Mode | Description | Security Level | Use Case |
|------|-------------|----------------|----------|
| `mask` | Replace PII with masked values (e.g., `***-**-1234`) | ✅ High | Default - balances security and usability |
| `remove` | Replace with `[TYPE_REMOVED]` placeholders | ✅ High | When PII context isn't needed |
| `hash` | Replace with hashed values | ✅ High | When consistency across requests is needed |
| `reject` | Block entire request if PII detected | ✅ Highest | Zero-tolerance environments |
| `pass-alert` | ⚠️ Pass PII through but log warnings | ⚠️ Low | Development/debugging only |
| `pass-silent` | ❌ Pass PII through unchanged | ❌ None | **NOT RECOMMENDED** - Dangerous |

**⚠️ Security Warning**: 
- `pass-silent` mode is **extremely dangerous** and should never be used in production. It completely bypasses PII protection.
- `pass-alert` mode should only be used for debugging with `PII_LOG_DETECTED=true`. It still exposes PII but at least provides visibility.
- For production environments, always use `mask`, `remove`, `hash`, or `reject` modes.

## 🛡️ Detection Strategies

PromptSentinel uses multiple detection layers:

### 1. Heuristic Detection
- Pattern matching for known injection techniques
- Role manipulation detection
- Encoding attack identification
- Context switching detection

### 2. LLM-Based Classification
- Semantic analysis using AI models
- Context-aware threat assessment
- Multi-provider consensus for accuracy

### 3. Format Validation
- Role separation checking
- Security best practice recommendations
- Input sanitization

### 4. PII Detection and Redaction
- Detects 15+ PII types (SSN, credit cards, emails, phones, etc.)
- Multiple redaction modes with configurable behavior
- Luhn algorithm validation for credit cards
- Configurable confidence thresholds

## 🔧 Development

### Prerequisites
- Python 3.11+
- UV package manager
- API keys for LLM providers (at least one)

### Setup Development Environment

```bash
# Install development dependencies
uv pip install -e ".[dev]"

# Run tests
uv run pytest

# Run with coverage
uv run pytest --cov=src/prompt_sentinel

# Format code
uv run black src/

# Lint code
uv run ruff src/

# Type checking
uv run mypy src/
```

### Adding New Detection Patterns

Edit `src/prompt_sentinel/detection/heuristics.py`:

```python
self.new_patterns = [
    (r"pattern_regex", confidence_score, "description"),
    # Add more patterns
]
```

### Adding New LLM Provider

1. Create provider in `src/prompt_sentinel/providers/`
2. Inherit from `LLMProvider` base class
3. Implement required methods
4. Register in `llm_classifier.py`

## 🚢 Deployment

### Docker Deployment

```bash
# Build image
docker build -t prompt-sentinel .

# Run container
docker run -p 8080:8080 --env-file .env prompt-sentinel
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prompt-sentinel
spec:
  replicas: 3
  selector:
    matchLabels:
      app: prompt-sentinel
  template:
    metadata:
      labels:
        app: prompt-sentinel
    spec:
      containers:
      - name: prompt-sentinel
        image: promptsentinel/prompt-sentinel:latest
        ports:
        - containerPort: 8080
        envFrom:
        - secretRef:
            name: prompt-sentinel-secrets
```

### AWS ECS/EKS

See the `deployment/` directory for:
- Terraform modules for ECS Fargate
- CloudFormation templates for ECS
- Kubernetes manifests for EKS
- Deployment scripts and documentation

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 🔒 Security

This is a defensive security tool. Please:
- Never use it to create or test attacks
- Report security vulnerabilities responsibly
- Keep API keys secure
- Follow security best practices

For security concerns, contact: security@promptsentinel.ai

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- OpenAI, Anthropic, and Google for LLM APIs
- FastAPI team for the excellent framework
- UV team for the blazing-fast package manager
- The security research community for prompt injection research

## 📊 Status

- ✅ Core detection engine
- ✅ Multi-provider LLM support
- ✅ REST API
- ✅ Docker support
- ✅ Basic testing
- 🚧 Redis caching
- 🚧 Advanced corpus management
- 🚧 Web UI dashboard
- 📋 SDK libraries (Python, JS, Go)

---

Built with ❤️ for securing AI applications