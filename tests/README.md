# Test Organization

This directory contains all tests for PromptSentinel, organized by test type and component.

## Directory Structure

```
tests/
├── unit/           # Fast, isolated unit tests
├── integration/    # Component integration tests  
├── e2e/           # End-to-end workflow tests
├── performance/   # Performance benchmarks
├── security/      # Security-specific tests
├── infrastructure/# Infrastructure & deployment tests
├── fixtures/      # Shared test data
└── pending/       # Tests awaiting fixes
```

## Test Categories

### Unit Tests (`unit/`)
Fast, isolated tests for individual components:
- **detection/** - Core detection logic (detector, heuristics, PII, LLM classifier)
- **providers/** - LLM provider implementations (Anthropic, OpenAI, Gemini)
- **auth/** - Authentication & authorization components
- **cache/** - Caching layer tests
- **ml/** - Machine learning components
- **monitoring/** - Metrics, rate limiting, usage tracking
- **experiments/** - A/B testing framework

### Integration Tests (`integration/`)
Tests for component interactions:
- API endpoint integration
- Database operations
- WebSocket functionality
- Batch processing
- Data pipelines

### End-to-End Tests (`e2e/`)
Complete workflow tests:
- Full detection flows
- Error recovery scenarios
- Edge cases
- Health checks

### Performance Tests (`performance/`)
- Benchmarks
- Load testing
- Performance regression tests

### Security Tests (`security/`)
- Security scenarios
- Attack vector testing
- Security feature validation

### Infrastructure Tests (`infrastructure/`)
- Docker integration
- Deployment validation
- Distributed systems
- Edge computing

## Running Tests

### Run all tests
```bash
make test
```

### Run specific test categories
```bash
# Unit tests only (fast)
pytest tests/unit/

# Integration tests
pytest tests/integration/

# E2E tests
pytest tests/e2e/

# Performance benchmarks
pytest tests/performance/
```

### Run specific component tests
```bash
# Detection unit tests
pytest tests/unit/detection/

# Auth integration tests
pytest tests/integration/test_auth_flow.py
```

### Run with coverage
```bash
pytest tests/unit/ --cov=src/prompt_sentinel --cov-report=term-missing
```

## Test Naming Conventions

- `test_*.py` - All test files start with `test_`
- Test classes start with `Test`
- Test methods start with `test_`
- Use descriptive names: `test_detect_injection_with_role_switching`

## Adding New Tests

1. Determine test type:
   - **Unit**: Testing a single function/class in isolation → `tests/unit/{component}/`
   - **Integration**: Testing multiple components together → `tests/integration/`
   - **E2E**: Testing complete user workflows → `tests/e2e/`

2. Place in appropriate directory
3. Follow existing patterns in that directory
4. Update this README if adding new categories

## Test Status

- **Total Tests**: 1,769
- **Coverage**: ~37% (comprehensive tests)
- **Pending Fixes**: 5 test files in `pending/` directory

## Common Fixtures

Shared fixtures are in `conftest.py` and `fixtures/`:
- Mock LLM providers
- Sample detection requests
- Attack vectors
- Test API clients