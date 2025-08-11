# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""API versioning and compatibility tests for PromptSentinel."""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock

import pytest

# Skip all tests in this file - feature not implemented
pytestmark = pytest.mark.skip(reason="Feature not yet implemented")


class TestAPIVersioning:
    """Test API versioning strategies."""

    @pytest.fixture
    def version_manager(self):
        """Create API version manager."""
        from prompt_sentinel.api.versioning import VersionManager

        return VersionManager()

    @pytest.mark.asyncio
    async def test_version_detection(self, version_manager):
        """Test API version detection from request."""
        # Header-based versioning
        request_with_header = {"headers": {"X-API-Version": "2.0"}, "path": "/detect"}
        version_header = await version_manager.detect_version(request_with_header)
        assert version_header == "2.0"

        # URL path versioning
        request_with_path = {"headers": {}, "path": "/api/v1/detect"}
        version_path = await version_manager.detect_version(request_with_path)
        assert version_path == "2.0"

        # Query parameter versioning
        request_with_query = {"headers": {}, "path": "/detect", "query": {"version": "1.5"}}
        version_query = await version_manager.detect_version(request_with_query)
        assert version_query == "1.5"

        # Accept header versioning
        request_with_accept = {
            "headers": {"Accept": "application/vnd.promptsentinel.v3+json"},
            "path": "/detect",
        }
        version_accept = await version_manager.detect_version(request_with_accept)
        assert version_accept == "3.0"

    @pytest.mark.asyncio
    async def test_version_routing(self, version_manager):
        """Test routing to correct version handler."""
        # Register version handlers
        handlers = {
            "1.0": AsyncMock(return_value={"version": "1.0", "format": "legacy"}),
            "2.0": AsyncMock(return_value={"version": "2.0", "format": "current"}),
            "3.0": AsyncMock(return_value={"version": "3.0", "format": "next"}),
        }

        for ver, handler in handlers.items():
            version_manager.register_handler(ver, handler)

        # Route requests
        response_v1 = await version_manager.route_request("1.0", {})
        assert response_v1["version"] == "1.0"

        response_v2 = await version_manager.route_request("2.0", {})
        assert response_v2["version"] == "2.0"

        # Test version fallback
        response_v15 = await version_manager.route_request("1.5", {})
        assert response_v15["version"] == "1.0"  # Falls back to 1.0

    @pytest.mark.asyncio
    async def test_deprecation_warnings(self, version_manager):
        """Test deprecation warning headers."""
        # Mark version as deprecated
        await version_manager.deprecate_version(
            version="1.0",
            sunset_date=datetime.utcnow() + timedelta(days=90),
            migration_guide="https://docs.example.com/migration/v2",
        )

        # Make request to deprecated version
        response = await version_manager.handle_request(version="1.0", request={})

        assert "Deprecation" in response["headers"]
        assert "Sunset" in response["headers"]
        assert "Link" in response["headers"]
        assert response["headers"]["Deprecation"] == 'version="1.0"'

    @pytest.mark.asyncio
    async def test_version_negotiation(self, version_manager):
        """Test content negotiation for API versions."""
        # Client accepts multiple versions
        request = {
            "headers": {
                "Accept": "application/vnd.promptsentinel.v3+json;q=0.9, "
                "application/vnd.promptsentinel.v2+json;q=1.0, "
                "application/vnd.promptsentinel.v1+json;q=0.5"
            }
        }

        # Server supports v1 and v2
        version_manager.set_supported_versions(["1.0", "2.0"])

        # Should negotiate to v2 (highest quality that's supported)
        negotiated = await version_manager.negotiate_version(request)
        assert negotiated == "2.0"

    @pytest.mark.asyncio
    async def test_breaking_change_detection(self, version_manager):
        """Test detection of breaking changes between versions."""
        # Define API schemas for different versions
        schema_v1 = {
            "endpoints": {
                "/detect": {
                    "request": {"prompt": "string"},
                    "response": {"is_malicious": "boolean"},
                }
            }
        }

        schema_v2 = {
            "endpoints": {
                "/detect": {
                    "request": {"input": {"messages": "array"}},
                    "response": {"verdict": "string"},
                }
            }
        }

        # Check for breaking changes
        changes = await version_manager.analyze_changes(schema_v1, schema_v2)

        assert changes["has_breaking_changes"] is True
        assert "request_format_changed" in changes["breaking_changes"]
        assert "response_format_changed" in changes["breaking_changes"]


class TestBackwardCompatibility:
    """Test backward compatibility features."""

    @pytest.fixture
    def compatibility_layer(self):
        """Create compatibility layer."""
        from prompt_sentinel.api.compatibility import CompatibilityLayer

        return CompatibilityLayer()

    @pytest.mark.asyncio
    async def test_request_transformation(self, compatibility_layer):
        """Test transforming old format requests to new format."""
        # V1 request format
        v1_request = {"prompt": "Test prompt", "check_pii": True}

        # Transform to V2 format
        v2_request = await compatibility_layer.transform_request(
            request=v1_request, from_version="1.0", to_version="2.0"
        )

        assert "input" in v2_request
        assert "messages" in v2_request["input"]
        assert v2_request["input"]["messages"][0]["content"] == "Test prompt"
        assert v2_request["config"]["check_pii"] is True

    @pytest.mark.asyncio
    async def test_response_transformation(self, compatibility_layer):
        """Test transforming new format responses to old format."""
        # V2 response format
        v2_response = {
            "verdict": "BLOCK",
            "confidence": 0.95,
            "reasons": [{"category": "INJECTION", "description": "SQL injection"}],
        }

        # Transform to V1 format
        v1_response = await compatibility_layer.transform_response(
            response=v2_response, from_version="2.0", to_version="1.0"
        )

        assert "is_malicious" in v1_response
        assert v1_response["is_malicious"] is True
        assert v1_response["confidence"] == 0.95
        assert "SQL injection" in v1_response["reason"]

    @pytest.mark.asyncio
    async def test_field_mapping(self, compatibility_layer):
        """Test field mapping between versions."""
        # Define field mappings
        mappings = {
            "1.0->2.0": {
                "prompt": "input.messages[0].content",
                "user_id": "metadata.user_id",
                "check_pii": "config.check_pii",
            },
            "2.0->1.0": {"verdict": lambda v: v == "BLOCK", "reasons[0].description": "reason"},
        }

        await compatibility_layer.register_mappings(mappings)

        # Test forward mapping
        v1_data = {"prompt": "test", "user_id": "123"}
        v2_data = await compatibility_layer.map_fields(v1_data, "1.0", "2.0")

        assert v2_data["input"]["messages"][0]["content"] == "test"
        assert v2_data["metadata"]["user_id"] == "123"

    @pytest.mark.asyncio
    async def test_feature_availability(self, compatibility_layer):
        """Test feature availability across versions."""
        # Define feature matrix
        features = {
            "1.0": ["basic_detection", "pii_check"],
            "2.0": ["basic_detection", "pii_check", "role_based_detection", "streaming"],
            "3.0": [
                "basic_detection",
                "pii_check",
                "role_based_detection",
                "streaming",
                "ml_scoring",
            ],
        }

        await compatibility_layer.set_feature_matrix(features)

        # Check feature availability
        assert await compatibility_layer.is_feature_available("streaming", "1.0") is False
        assert await compatibility_layer.is_feature_available("streaming", "2.0") is True

        # Get feature diff
        diff = await compatibility_layer.get_feature_diff("1.0", "2.0")
        assert "role_based_detection" in diff["added"]
        assert "streaming" in diff["added"]
        assert len(diff["removed"]) == 0


class TestVersionMigration:
    """Test version migration helpers."""

    @pytest.fixture
    def migration_helper(self):
        """Create migration helper."""
        from prompt_sentinel.api.migration import MigrationHelper

        return MigrationHelper()

    @pytest.mark.asyncio
    async def test_migration_guide_generation(self, migration_helper):
        """Test automatic migration guide generation."""
        # Generate migration guide
        guide = await migration_helper.generate_migration_guide(
            from_version="1.0", to_version="2.0"
        )

        assert "breaking_changes" in guide
        assert "code_examples" in guide
        assert "timeline" in guide

        # Check code examples
        assert "before" in guide["code_examples"]
        assert "after" in guide["code_examples"]

    @pytest.mark.asyncio
    async def test_client_sdk_compatibility(self, migration_helper):
        """Test client SDK compatibility checking."""
        # Check SDK compatibility
        sdk_versions = {"python-sdk": "1.2.3", "js-sdk": "2.0.0", "go-sdk": "1.5.0"}

        compatibility = await migration_helper.check_sdk_compatibility(
            api_version="2.0", sdk_versions=sdk_versions
        )

        assert compatibility["python-sdk"]["compatible"] is False
        assert compatibility["python-sdk"]["minimum_version"] == "2.0.0"
        assert compatibility["js-sdk"]["compatible"] is True

    @pytest.mark.asyncio
    async def test_gradual_migration(self, migration_helper):
        """Test gradual migration support."""
        # Configure gradual migration
        migration_config = {
            "start_date": datetime.utcnow(),
            "end_date": datetime.utcnow() + timedelta(days=90),
            "stages": [
                {"percentage": 10, "duration_days": 7},
                {"percentage": 50, "duration_days": 14},
                {"percentage": 100, "duration_days": 69},
            ],
        }

        await migration_helper.configure_gradual_migration(
            from_version="1.0", to_version="2.0", config=migration_config
        )

        # Check migration progress
        progress = await migration_helper.get_migration_progress()
        assert 0 <= progress["percentage"] <= 100
        assert "current_stage" in progress
        assert "estimated_completion" in progress


class TestVersionedEndpoints:
    """Test versioned endpoint management."""

    @pytest.fixture
    def endpoint_manager(self):
        """Create endpoint manager."""
        from prompt_sentinel.api.endpoints import EndpointManager

        return EndpointManager()

    @pytest.mark.asyncio
    async def test_endpoint_registration(self, endpoint_manager):
        """Test registering versioned endpoints."""
        # Register endpoints for different versions
        endpoints = {
            "1.0": {
                "/detect": {"method": "POST", "handler": "detect_v1"},
                "/status": {"method": "GET", "handler": "status_v1"},
            },
            "2.0": {
                "/detect": {"method": "POST", "handler": "detect_v2"},
                "/analyze": {"method": "POST", "handler": "analyze_v2"},
                "/status": {"method": "GET", "handler": "status_v2"},
            },
        }

        for version, version_endpoints in endpoints.items():
            for path, config in version_endpoints.items():
                await endpoint_manager.register_endpoint(version=version, path=path, **config)

        # Get available endpoints
        v1_endpoints = await endpoint_manager.get_endpoints("1.0")
        assert len(v1_endpoints) == 2

        v2_endpoints = await endpoint_manager.get_endpoints("2.0")
        assert len(v2_endpoints) == 3
        assert "/analyze" in [e["path"] for e in v2_endpoints]

    @pytest.mark.asyncio
    async def test_endpoint_deprecation(self, endpoint_manager):
        """Test endpoint deprecation."""
        # Deprecate endpoint
        await endpoint_manager.deprecate_endpoint(
            version="1.0",
            path="/old_endpoint",
            replacement="/new_endpoint",
            sunset_date=datetime.utcnow() + timedelta(days=60),
        )

        # Check deprecation status
        status = await endpoint_manager.get_endpoint_status("1.0", "/old_endpoint")
        assert status["deprecated"] is True
        assert status["replacement"] == "/new_endpoint"
        assert status["sunset_date"] is not None

    @pytest.mark.asyncio
    async def test_endpoint_aliasing(self, endpoint_manager):
        """Test endpoint aliasing for compatibility."""
        # Create alias for backward compatibility
        await endpoint_manager.create_alias(
            from_path="/old/detect", to_path="/api/v1/detect", versions=["1.0", "1.5"]
        )

        # Request to alias should route to new endpoint
        result = await endpoint_manager.resolve_endpoint("/old/detect", "1.0")
        assert result["actual_path"] == "/api/v1/detect"
        assert result["is_alias"] is True


class TestVersionedSchemas:
    """Test versioned schema validation."""

    @pytest.fixture
    def schema_manager(self):
        """Create schema manager."""
        from prompt_sentinel.api.schemas import SchemaManager

        return SchemaManager()

    @pytest.mark.asyncio
    async def test_schema_evolution(self, schema_manager):
        """Test schema evolution tracking."""
        # Define schema versions
        schemas = {
            "1.0": {
                "type": "object",
                "properties": {"prompt": {"type": "string"}, "user_id": {"type": "string"}},
                "required": ["prompt"],
            },
            "1.1": {
                "type": "object",
                "properties": {
                    "prompt": {"type": "string"},
                    "user_id": {"type": "string"},
                    "mode": {"type": "string", "enum": ["strict", "moderate"]},
                },
                "required": ["prompt"],
            },
            "2.0": {
                "type": "object",
                "properties": {
                    "input": {"type": "object", "properties": {"messages": {"type": "array"}}}
                },
                "required": ["input"],
            },
        }

        for ver, schema in schemas.items():
            await schema_manager.register_schema(ver, schema)

        # Track evolution
        evolution = await schema_manager.get_schema_evolution("1.0", "2.0")
        assert evolution["major_version_change"] is True
        assert "added_fields" in evolution
        assert "removed_fields" in evolution
        assert "type_changes" in evolution

    @pytest.mark.asyncio
    async def test_schema_validation(self, schema_manager):
        """Test request/response validation against versioned schemas."""
        # Register schema
        schema = {
            "type": "object",
            "properties": {"prompt": {"type": "string", "minLength": 1, "maxLength": 1000}},
            "required": ["prompt"],
        }

        await schema_manager.register_schema("1.0", schema)

        # Valid request
        valid_request = {"prompt": "Test prompt"}
        validation = await schema_manager.validate(valid_request, "1.0")
        assert validation["valid"] is True

        # Invalid request
        invalid_request = {"prompt": ""}
        validation = await schema_manager.validate(invalid_request, "1.0")
        assert validation["valid"] is False
        assert "minLength" in validation["errors"][0]

    @pytest.mark.asyncio
    async def test_schema_compatibility(self, schema_manager):
        """Test schema compatibility checking."""
        # Define schemas
        schema_v1 = {
            "type": "object",
            "properties": {"field1": {"type": "string"}, "field2": {"type": "number"}},
        }

        # Backward compatible change (adding optional field)
        schema_v1_1 = {
            "type": "object",
            "properties": {
                "field1": {"type": "string"},
                "field2": {"type": "number"},
                "field3": {"type": "boolean"},  # New optional field
            },
        }

        # Breaking change (changing type)
        schema_v2 = {
            "type": "object",
            "properties": {
                "field1": {"type": "string"},
                "field2": {"type": "string"},  # Changed from number to string
            },
        }

        # Check compatibility
        compat_1_1 = await schema_manager.check_compatibility(schema_v1, schema_v1_1)
        assert compat_1_1["backward_compatible"] is True

        compat_2 = await schema_manager.check_compatibility(schema_v1, schema_v2)
        assert compat_2["backward_compatible"] is False
        assert "type_change" in compat_2["breaking_changes"]


class TestVersionLifecycle:
    """Test API version lifecycle management."""

    @pytest.fixture
    def lifecycle_manager(self):
        """Create lifecycle manager."""
        from prompt_sentinel.api.lifecycle import LifecycleManager

        return LifecycleManager()

    @pytest.mark.asyncio
    async def test_version_states(self, lifecycle_manager):
        """Test version state transitions."""
        # Define version lifecycle
        version = "3.0"

        # Alpha state
        await lifecycle_manager.set_version_state(version, "alpha")
        state = await lifecycle_manager.get_version_state(version)
        assert state["state"] == "alpha"
        assert state["stability"] == "unstable"

        # Beta state
        await lifecycle_manager.transition_version(version, "beta")
        state = await lifecycle_manager.get_version_state(version)
        assert state["state"] == "beta"
        assert state["stability"] == "testing"

        # GA (General Availability)
        await lifecycle_manager.transition_version(version, "ga")
        state = await lifecycle_manager.get_version_state(version)
        assert state["state"] == "ga"
        assert state["stability"] == "stable"

        # Deprecated
        await lifecycle_manager.transition_version(version, "deprecated")
        state = await lifecycle_manager.get_version_state(version)
        assert state["state"] == "deprecated"
        assert "sunset_date" in state

    @pytest.mark.asyncio
    async def test_version_support_policy(self, lifecycle_manager):
        """Test version support policy enforcement."""
        # Define support policy
        policy = {
            "lts_versions": ["2.0", "3.0"],  # Long-term support
            "lts_duration_months": 24,
            "standard_support_months": 12,
            "security_only_months": 6,
            "max_supported_versions": 3,
        }

        await lifecycle_manager.set_support_policy(policy)

        # Check version support status
        support_status = await lifecycle_manager.get_support_status("2.0")
        assert support_status["is_lts"] is True
        assert support_status["support_end_date"] is not None
        assert support_status["security_end_date"] is not None

    @pytest.mark.asyncio
    async def test_version_sunset(self, lifecycle_manager):
        """Test version sunset process."""
        # Schedule version sunset
        sunset_date = datetime.utcnow() + timedelta(days=90)

        await lifecycle_manager.schedule_sunset(
            version="1.0", sunset_date=sunset_date, migration_path="2.0"
        )

        # Get sunset timeline
        timeline = await lifecycle_manager.get_sunset_timeline("1.0")

        assert timeline["deprecation_date"] < timeline["sunset_date"]
        assert timeline["migration_window_days"] == 90
        assert timeline["notifications_scheduled"] is True

    @pytest.mark.asyncio
    async def test_version_metrics(self, lifecycle_manager):
        """Test version usage metrics."""
        # Record version usage
        for _ in range(100):
            await lifecycle_manager.record_usage("2.0")

        for _ in range(50):
            await lifecycle_manager.record_usage("1.0")

        for _ in range(10):
            await lifecycle_manager.record_usage("3.0")

        # Get usage metrics
        metrics = await lifecycle_manager.get_usage_metrics()

        assert metrics["2.0"]["percentage"] > 60
        assert metrics["1.0"]["percentage"] > 30
        assert metrics["3.0"]["percentage"] < 10

        # Get adoption trends
        trends = await lifecycle_manager.get_adoption_trends()
        assert trends["trending_up"] == ["2.0", "3.0"]
        assert trends["trending_down"] == ["1.0"]


class TestVersionDocumentation:
    """Test versioned API documentation."""

    @pytest.fixture
    def doc_manager(self):
        """Create documentation manager."""
        from prompt_sentinel.api.documentation import DocumentationManager

        return DocumentationManager()

    @pytest.mark.asyncio
    async def test_openapi_generation(self, doc_manager):
        """Test OpenAPI spec generation for versions."""
        # Generate OpenAPI spec
        spec = await doc_manager.generate_openapi_spec(version="2.0", include_deprecated=False)

        assert spec["openapi"] == "3.0.0"
        assert spec["info"]["version"] == "2.0"
        assert "paths" in spec
        assert "components" in spec
        assert "schemas" in spec["components"]

    @pytest.mark.asyncio
    async def test_changelog_generation(self, doc_manager):
        """Test changelog generation between versions."""
        # Generate changelog
        changelog = await doc_manager.generate_changelog(from_version="1.0", to_version="2.0")

        assert "added" in changelog
        assert "changed" in changelog
        assert "deprecated" in changelog
        assert "removed" in changelog
        assert "fixed" in changelog
        assert "security" in changelog

    @pytest.mark.asyncio
    async def test_migration_examples(self, doc_manager):
        """Test migration code examples."""
        # Generate migration examples
        examples = await doc_manager.generate_migration_examples(
            from_version="1.0", to_version="2.0", languages=["python", "javascript", "go"]
        )

        for lang in ["python", "javascript", "go"]:
            assert lang in examples
            assert "before" in examples[lang]
            assert "after" in examples[lang]
            assert "explanation" in examples[lang]

    @pytest.mark.asyncio
    async def test_interactive_docs(self, doc_manager):
        """Test interactive API documentation."""
        # Generate interactive docs
        interactive_docs = await doc_manager.generate_interactive_docs(
            version="2.0", base_url="https://api.promptsentinel.com"
        )

        assert interactive_docs["swagger_ui_enabled"] is True
        assert interactive_docs["redoc_enabled"] is True
        assert interactive_docs["try_it_out_enabled"] is True
        assert "authentication_configured" in interactive_docs


class TestVersionedTesting:
    """Test version-specific testing strategies."""

    @pytest.fixture
    def test_manager(self):
        """Create test manager."""
        from prompt_sentinel.api.testing import VersionTestManager

        return VersionTestManager()

    @pytest.mark.asyncio
    async def test_compatibility_test_suite(self, test_manager):
        """Test compatibility test suite generation."""
        # Generate compatibility tests
        test_suite = await test_manager.generate_compatibility_tests(versions=["1.0", "2.0", "3.0"])

        assert "cross_version_tests" in test_suite
        assert "backward_compatibility_tests" in test_suite
        assert "forward_compatibility_tests" in test_suite

        # Each test should validate data flow between versions
        for test in test_suite["cross_version_tests"]:
            assert "from_version" in test
            assert "to_version" in test
            assert "test_cases" in test

    @pytest.mark.asyncio
    async def test_contract_testing(self, test_manager):
        """Test contract testing between versions."""
        # Define contracts
        contracts = {
            "1.0": {
                "request_contract": {"prompt": "required|string"},
                "response_contract": {"is_malicious": "required|boolean"},
            },
            "2.0": {
                "request_contract": {"input": "required|object"},
                "response_contract": {"verdict": "required|enum:ALLOW,BLOCK,FLAG,STRIP"},
            },
        }

        # Run contract tests
        results = await test_manager.run_contract_tests(contracts)

        assert results["all_contracts_valid"] is True
        assert len(results["versions_tested"]) == 2

    @pytest.mark.asyncio
    async def test_regression_testing(self, test_manager):
        """Test regression testing across versions."""
        # Define regression test cases
        test_cases = [
            {
                "name": "basic_detection",
                "input": {"prompt": "DROP TABLE users"},
                "expected_v1": {"is_malicious": True},
                "expected_v2": {"verdict": "BLOCK"},
            }
        ]

        # Run regression tests
        results = await test_manager.run_regression_tests(test_cases, versions=["1.0", "2.0"])

        assert results["passed"] == len(test_cases) * 2
        assert results["failed"] == 0
        assert results["behavior_consistent"] is True

    @pytest.mark.asyncio
    async def test_performance_comparison(self, test_manager):
        """Test performance comparison between versions."""
        # Run performance tests
        perf_results = await test_manager.compare_performance(
            versions=["1.0", "2.0"], test_duration=60, concurrent_requests=10
        )

        assert "1.0" in perf_results
        assert "2.0" in perf_results

        for version in perf_results:
            assert "latency_p50" in perf_results[version]
            assert "latency_p99" in perf_results[version]
            assert "throughput" in perf_results[version]
            assert "error_rate" in perf_results[version]


class TestVersionNegotiation:
    """Test version negotiation strategies."""

    @pytest.fixture
    def negotiator(self):
        """Create version negotiator."""
        from prompt_sentinel.api.negotiation import VersionNegotiator

        return VersionNegotiator()

    @pytest.mark.asyncio
    async def test_client_server_negotiation(self, negotiator):
        """Test client-server version negotiation."""
        # Client capabilities
        client = {
            "supported_versions": ["1.0", "1.5", "2.0"],
            "preferred_version": "2.0",
            "minimum_version": "1.0",
        }

        # Server capabilities
        server = {
            "supported_versions": ["1.0", "2.0", "3.0"],
            "recommended_version": "2.0",
            "deprecated_versions": ["1.0"],
        }

        # Negotiate
        negotiated = await negotiator.negotiate(client, server)

        assert negotiated["version"] == "2.0"
        assert negotiated["client_compatible"] is True
        assert negotiated["server_compatible"] is True
        assert "upgrade_available" in negotiated

    @pytest.mark.asyncio
    async def test_feature_negotiation(self, negotiator):
        """Test feature-level negotiation."""
        # Client requested features
        client_features = ["basic_detection", "streaming", "ml_scoring"]

        # Server available features by version
        server_features = {
            "1.0": ["basic_detection"],
            "2.0": ["basic_detection", "streaming"],
            "3.0": ["basic_detection", "streaming", "ml_scoring"],
        }

        # Negotiate based on features
        result = await negotiator.negotiate_by_features(
            required_features=client_features, available_features=server_features
        )

        assert result["selected_version"] == "3.0"
        assert set(result["available_features"]) == set(client_features)

    @pytest.mark.asyncio
    async def test_graceful_degradation(self, negotiator):
        """Test graceful degradation when version unavailable."""
        # Client requests unavailable version
        client_request = {"version": "4.0", "fallback_versions": ["3.0", "2.0", "1.0"]}

        # Server only has older versions
        server_versions = ["1.0", "2.0"]

        # Should degrade gracefully
        result = await negotiator.handle_version_mismatch(client_request, server_versions)

        assert result["selected_version"] == "2.0"
        assert result["degraded"] is True
        assert "missing_features" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
