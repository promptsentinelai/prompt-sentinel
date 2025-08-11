# Changelog

All notable changes to PromptSentinel will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-14

### 🎉 Initial Public Release

PromptSentinel is now ready for production use! This release represents months of development, testing, and refinement to create a comprehensive prompt injection detection system.

### ✨ Features

#### Core Detection
- **Multi-Layer Detection Engine**: Combines heuristic patterns, LLM classification, and PII detection
- **Intelligent Routing**: Automatically routes prompts to optimal detection strategy based on complexity analysis
- **Confidence Scoring**: Detailed confidence scores with explanations for transparency
- **Format Validation**: Encourages secure prompt design with role separation
- **Custom Detection Rules**: Support for organization-specific patterns via YAML configuration

#### Performance & Scalability
- **Sub-100ms Response Times**: Optimized for real-time detection
- **Redis Caching**: Optional caching layer providing 98% performance improvement (12ms vs 700ms)
- **Horizontal Scaling**: Kubernetes-ready with Helm charts and HPA support
- **Rate Limiting**: Token bucket algorithm with per-client and global limits
- **WebSocket Support**: Real-time streaming detection for continuous monitoring

#### Security & Privacy
- **PII Detection & Redaction**: 15+ built-in PII types with multiple redaction modes
- **Custom PII Rules**: Organization-specific PII patterns via YAML configuration
- **Multiple Auth Modes**: No auth (sidecar), optional (mixed), or required (SaaS)
- **API Key Management**: Secure API key generation and validation
- **Security Headers**: Comprehensive security headers for production deployments

#### Machine Learning
- **Pattern Discovery**: Self-learning system that discovers new attack patterns
- **Clustering Analysis**: DBSCAN/HDBSCAN for attack pattern identification
- **Feature Extraction**: Advanced feature engineering for ML models
- **A/B Testing Framework**: Built-in experimentation for optimization

#### Monitoring & Observability
- **OpenTelemetry Integration**: Full tracing and metrics support
- **Structured Logging**: JSON-formatted logs with correlation IDs
- **Health Checks**: Comprehensive health endpoints with dependency checks
- **Usage Tracking**: API usage monitoring with budget controls
- **Prometheus Metrics**: Detailed metrics for monitoring and alerting

#### Integration & Deployment
- **Multiple LLM Providers**: Anthropic (Claude), OpenAI (GPT), Google (Gemini) with failover
- **Docker Support**: Production-ready Alpine-based images
- **Kubernetes Ready**: Helm charts, manifests, and deployment guides
- **SDK Libraries**: Python, JavaScript, and Go client libraries
- **Integration Guides**: FastAPI, Express.js, and LangChain examples

### 📦 Components

- **Core Service**: FastAPI-based microservice with async support
- **Docker Image**: `promptsentinelai/prompt-sentinel:1.0.0`
- **Python SDK**: Ready for PyPI publication
- **JavaScript SDK**: Ready for npm publication  
- **Go SDK**: Ready for pkg.go.dev publication

### 🏗️ Infrastructure

- **Container**: Alpine Linux base, non-root user, security hardened
- **Dependencies**: 78 production dependencies, all security scanned
- **Test Coverage**: 1,653 tests with 100% pass rate, 61% code coverage
- **Documentation**: Comprehensive guides for deployment, monitoring, and troubleshooting

### 🔒 Security

- **Zero Vulnerabilities**: Clean security scan across all components
- **SBOM Generation**: Software Bill of Materials for compliance
- **Secret Management**: Multiple secure options documented
- **License**: Elastic License 2.0 for commercial protection

### 📊 Performance Benchmarks

- **Heuristic Detection**: 2-5ms average response time
- **LLM Classification**: 500-1500ms (provider dependent)
- **PII Detection**: 10-20ms for standard documents
- **Cached Responses**: 1-2ms with Redis enabled
- **Throughput**: 1000+ requests/second per instance

### 🛠️ Development

- **Python**: 3.11+ with full type hints
- **Package Manager**: UV for fast dependency resolution
- **Testing**: pytest with async support
- **Code Quality**: Black, Ruff, mypy, bandit
- **CI/CD**: GitHub Actions with matrix testing

### 📚 Documentation

- **API Documentation**: Full OpenAPI/Swagger spec
- **Deployment Guides**: Docker, Kubernetes, ECS, Terraform
- **Integration Examples**: Multiple framework integrations
- **Troubleshooting Guide**: Common issues and solutions
- **Architecture Deep Dive**: System design and internals

### 🙏 Acknowledgments

Special thanks to all early testers and contributors who helped shape PromptSentinel into a production-ready security tool.

### 🚀 Getting Started

```bash
# Docker
docker run -p 8080:8080 promptsentinelai/prompt-sentinel:1.0.0

# Docker Compose
docker-compose up

# Kubernetes
helm install promptsentinel ./deployment/helm
```

For detailed installation and configuration instructions, see the [README](README.md).

---

[1.0.0]: https://github.com/promptsentinelai/prompt-sentinel/releases/tag/v1.0.0