# Testing Documentation

## Overview

PromptSentinel maintains a comprehensive test suite with 100% test pass rate and 61% code coverage.

## Test Statistics

- **Total Tests**: 1,653
- **Pass Rate**: 100% ✅
- **Code Coverage**: 61%
- **Test Framework**: pytest with async support
- **Last Updated**: January 2025

## Test Categories

### Unit Tests (~650 tests)
Comprehensive coverage of individual components:
- Heuristic detection patterns
- LLM provider integrations
- PII detection algorithms
- Authentication and authorization
- Cache management
- Rate limiting

### Integration Tests (~150 tests)
End-to-end workflow validation:
- API endpoint integration
- Multi-provider failover
- WebSocket communication
- Database interactions
- Redis cache integration

### E2E Tests (~50 tests)
Full system tests:
- Complete detection flows
- Format assistance workflows
- Authentication scenarios
- WebSocket real-time detection
- Error recovery mechanisms

### Performance Tests (~30 tests)
Benchmarks and optimization:
- Response time validation
- Cache hit/miss ratios
- Concurrent request handling
- Memory usage patterns
- Rate limiting effectiveness

### Security Tests (~100 tests)
Attack pattern validation:
- Injection detection accuracy
- PII redaction completeness
- Authentication bypass attempts
- Rate limiting enforcement
- Input validation

## Running Tests

### Quick Start
```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run specific category
uv run pytest tests/test_integration.py -v
```

### Common Test Commands
```bash
# Run comprehensive tests only (fastest)
uv run pytest tests/*comprehensive*.py

# Run tests matching pattern
uv run pytest -k "test_detection"

# Run with verbose output
uv run pytest -v

# Run with coverage report
uv run pytest --cov=src/prompt_sentinel --cov-report=html

# Run specific test
uv run pytest tests/test_detector_comprehensive.py::TestDetector::test_simple_detection
```

### Test Organization
```
tests/
├── conftest.py                    # Shared fixtures
├── test_*_comprehensive.py        # Complete module coverage
├── test_integration.py            # API integration tests
├── test_e2e_integration.py        # End-to-end tests
├── test_performance.py            # Performance benchmarks
├── test_security_complete.py      # Security tests
├── test_negative_cases.py         # Error conditions
└── test_edge_cases_complete.py    # Boundary conditions
```

## Test Coverage

### Well-Covered Areas (>80%)
- Core detection logic
- Heuristic patterns
- API routes and middleware
- Authentication system
- PII detection

### Areas for Improvement (<50%)
- Advanced ML features (intentionally limited)
- Experimental features
- Some error recovery paths
- WebSocket edge cases

## Writing Tests

### Test Structure
```python
import pytest
from prompt_sentinel.detection.detector import PromptDetector

class TestDetector:
    @pytest.fixture
    def detector(self):
        """Create detector instance."""
        return PromptDetector()
    
    @pytest.mark.asyncio
    async def test_detection(self, detector):
        """Test basic detection."""
        result = await detector.detect(messages=[...])
        assert result.verdict == "block"
```

### Best Practices
1. Use fixtures for common setup
2. Mock external dependencies (LLM APIs)
3. Test both success and failure paths
4. Include edge cases and boundary conditions
5. Use descriptive test names
6. Group related tests in classes

## CI/CD Integration

Tests run automatically on:
- Pull requests
- Commits to main branch
- Nightly scheduled runs

GitHub Actions workflow ensures:
- All tests pass before merge
- Coverage doesn't decrease
- Performance benchmarks are met

## Troubleshooting

### Common Issues

**Import Errors**
```bash
# Ensure dev dependencies are installed
uv pip install -e ".[dev]"
```

**Async Test Failures**
```python
# Mark async tests properly
@pytest.mark.asyncio
async def test_async_function():
    ...
```

**API Key Errors**
```bash
# Tests use mocked providers, no real API keys needed
# But can set test keys if needed:
export ANTHROPIC_API_KEY=test-key
```

## Future Improvements

- [ ] Increase coverage to 70%+
- [ ] Add mutation testing
- [ ] Implement property-based testing
- [ ] Add load testing suite
- [ ] Create test data generators
- [ ] Add visual regression tests for UI components