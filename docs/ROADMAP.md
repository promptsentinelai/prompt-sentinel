# PromptSentinel Roadmap

This document outlines planned and in-progress areas. Status reflects the current main branch. Items marked Experimental/Stub have scaffolding present but are not production-ready.

## Near-Term (0-2 releases)

- Intelligent Router modularization (DONE)
  - Strategy selection extracted to `routing/strategy.py`
  - Execution helpers extracted to `routing/execution.py`
- Provider parsing consolidation (DONE)
  - Shared JSON parsing and category mapping in `providers/base.py`
- Heuristic consistency (DONE)
  - Centralized patterns and thresholds in detection config
- Docker/CI reliability (DONE)
  - Fixed test invocation and added Makefile cleanup targets
- Documentation updates (THIS PR)
  - README status and roadmap; stub clarifications

## In Development (scaffolding exists)

- A/B Testing Framework (Experimental)
  - Endpoints present in `api/experiments/routes.py`; some return 501
  - Schemas defined; wiring to manager is partial; tests are skipped in some paths

- Observability Modules (Experimental)
  - Structured logging (`observability/logging.py`) – test/in-memory stub
  - Tracing, alerting, pipeline – test scaffolding in `observability/*` with skipped tests
  - Prefer `monitoring/metrics.py` for production metrics (Prometheus)

- Performance Middleware (Experimental)
  - `api/performance_middleware.py` present but not wired into `main.py`
  - Use with caution after benchmarking

- i18n / Multilingual Detection (Experimental)
  - `i18n/detector.py` includes helpers; placeholders for translation-assisted detection
  - Multiple i18n modules (localization, encoding, cultural) have stubs and skipped tests

- ML Extensions (Experimental)
  - `ml/training.py`, `ml/inference.py`, `ml/evaluation.py` include stubbed functionality
  - Advanced features (active learning, federated learning, explainability) are scaffolded with skipped tests

- Batch/Async Processing (Planned)
  - `api/batch_endpoint.py` includes TODOs for async job tracking and status queries

- Performance Benchmarks (Experimental)
  - Rate limiting impact benchmark is stubbed and marked experimental in `tests/performance/benchmark_suite.py`
  - Action: implement once `RateLimitMiddleware` (or equivalent) is available

## Mid-Term (2-5 releases)

- Enhanced ML Features
  - Embedding-based detection and semantic clustering
  - Pattern mining improvements and evaluation automation

- Multi-Language Support
  - Language-specific patterns and translation-assisted detection
  - Coverage for top non-English languages

- Observability Maturation
  - OpenTelemetry tracing integration and dashboards
  - Alerting and SLOs with actionable runbooks

- Cloud-Native Integrations
  - Serverless adapters (AWS Lambda, Cloud Functions, Azure Functions)
  - Helm chart refinements and autoscaling policies

## Long-Term

- Enterprise Features
  - SAML/SSO, audit logging enhancements, compliance reporting
  - Advanced access control policies and multi-tenant quotas

- SDK & Integration Ecosystem
  - Official releases to PyPI, npm, pkg.go.dev
  - Example integrations (LangChain, FastAPI/Express middleware)

## Notes on Stubs and Experimental Modules

- Stubs exist to document intended APIs and to support test scaffolding. They are intentionally not wired into production flows.
- Prefer `prompt_sentinel.monitoring` over `observability.*` for metrics and production monitoring.
- Performance middleware is optional and should be enabled only after benchmarking in your environment.

## Contributing to the Roadmap

Contributions are welcome. Please open a GitHub issue to propose roadmap items or to volunteer for existing ones. Prioritize changes that reduce complexity, improve maintainability, or close gaps identified by the test suite and static analysis.
