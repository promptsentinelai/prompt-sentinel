"""Workflow automation tests for PromptSentinel."""

import asyncio
import time
from datetime import datetime, timedelta
from enum import Enum
from unittest.mock import patch

import pytest

# Skip all tests in this file - feature not implemented
pytestmark = pytest.mark.skip(reason="Feature not yet implemented")


class WorkflowStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TestWorkflowEngine:
    """Test workflow automation engine."""

    @pytest.fixture
    def workflow_engine(self):
        """Create workflow engine."""
        from prompt_sentinel.automation.workflow import WorkflowEngine

        return WorkflowEngine()

    @pytest.mark.asyncio
    async def test_workflow_definition(self, workflow_engine):
        """Test defining and registering workflows."""
        # Define detection workflow
        workflow_def = {
            "name": "detection_workflow",
            "version": "1.0",
            "description": "Automated detection and response workflow",
            "trigger": {"type": "event", "event": "detection.completed"},
            "steps": [
                {
                    "name": "validate_detection",
                    "type": "validation",
                    "config": {"min_confidence": 0.8},
                },
                {
                    "name": "enrich_data",
                    "type": "enrichment",
                    "depends_on": ["validate_detection"],
                    "config": {"data_sources": ["threat_intel", "user_context"]},
                },
                {
                    "name": "risk_assessment",
                    "type": "assessment",
                    "depends_on": ["enrich_data"],
                    "config": {"scoring_model": "risk_v2"},
                },
                {
                    "name": "automated_response",
                    "type": "action",
                    "depends_on": ["risk_assessment"],
                    "condition": "risk_score > 0.9",
                    "config": {"actions": ["block_user", "alert_security_team"]},
                },
            ],
        }

        result = await workflow_engine.register_workflow(workflow_def)

        assert result["registered"] is True
        assert result["workflow_id"] is not None
        assert result["version"] == "1.0"

    @pytest.mark.asyncio
    async def test_workflow_execution(self, workflow_engine):
        """Test workflow execution."""
        # Register simple workflow
        workflow_id = await workflow_engine.register_workflow(
            {
                "name": "simple_test",
                "steps": [
                    {"name": "step1", "type": "log", "config": {"message": "Step 1"}},
                    {"name": "step2", "type": "log", "config": {"message": "Step 2"}},
                ],
            }
        )

        # Execute workflow
        execution = await workflow_engine.execute_workflow(
            workflow_id=workflow_id["workflow_id"], input_data={"detection_id": "test_123"}
        )

        assert execution["execution_id"] is not None
        assert execution["status"] == WorkflowStatus.RUNNING.value

        # Wait for completion
        await asyncio.sleep(1)

        status = await workflow_engine.get_execution_status(execution["execution_id"])

        assert status["status"] == WorkflowStatus.COMPLETED.value
        assert len(status["completed_steps"]) == 2

    @pytest.mark.asyncio
    async def test_conditional_execution(self, workflow_engine):
        """Test conditional workflow steps."""
        # Workflow with conditions
        conditional_workflow = {
            "name": "conditional_response",
            "steps": [
                {
                    "name": "check_severity",
                    "type": "condition",
                    "config": {"field": "risk_score", "operator": ">", "value": 0.8},
                },
                {
                    "name": "high_risk_action",
                    "type": "action",
                    "condition": "check_severity == true",
                    "config": {"action": "immediate_block"},
                },
                {
                    "name": "low_risk_action",
                    "type": "action",
                    "condition": "check_severity == false",
                    "config": {"action": "log_only"},
                },
            ],
        }

        workflow_id = await workflow_engine.register_workflow(conditional_workflow)

        # Execute with high risk score
        execution1 = await workflow_engine.execute_workflow(
            workflow_id=workflow_id["workflow_id"], input_data={"risk_score": 0.9}
        )

        await asyncio.sleep(1)
        status1 = await workflow_engine.get_execution_status(execution1["execution_id"])

        # Should execute high risk action
        executed_steps = [step["name"] for step in status1["step_details"]]
        assert "high_risk_action" in executed_steps
        assert "low_risk_action" not in executed_steps

        # Execute with low risk score
        execution2 = await workflow_engine.execute_workflow(
            workflow_id=workflow_id["workflow_id"], input_data={"risk_score": 0.3}
        )

        await asyncio.sleep(1)
        status2 = await workflow_engine.get_execution_status(execution2["execution_id"])

        # Should execute low risk action
        executed_steps = [step["name"] for step in status2["step_details"]]
        assert "low_risk_action" in executed_steps
        assert "high_risk_action" not in executed_steps

    @pytest.mark.asyncio
    async def test_parallel_execution(self, workflow_engine):
        """Test parallel step execution."""
        # Workflow with parallel steps
        parallel_workflow = {
            "name": "parallel_processing",
            "steps": [
                {
                    "name": "parallel_group",
                    "type": "parallel",
                    "steps": [
                        {
                            "name": "threat_lookup",
                            "type": "external_api",
                            "config": {"service": "threat_intel"},
                        },
                        {
                            "name": "user_lookup",
                            "type": "external_api",
                            "config": {"service": "user_service"},
                        },
                        {
                            "name": "reputation_check",
                            "type": "external_api",
                            "config": {"service": "reputation_api"},
                        },
                    ],
                },
                {
                    "name": "aggregate_results",
                    "type": "aggregation",
                    "depends_on": ["parallel_group"],
                    "config": {"merge_strategy": "combine"},
                },
            ],
        }

        workflow_id = await workflow_engine.register_workflow(parallel_workflow)

        start_time = time.time()
        execution = await workflow_engine.execute_workflow(
            workflow_id=workflow_id["workflow_id"], input_data={"user_id": "user_123"}
        )

        await asyncio.sleep(2)
        end_time = time.time()

        status = await workflow_engine.get_execution_status(execution["execution_id"])

        # Parallel execution should be faster than sequential
        assert status["status"] == WorkflowStatus.COMPLETED.value
        assert end_time - start_time < 5  # Should complete quickly due to parallelism

    @pytest.mark.asyncio
    async def test_error_handling(self, workflow_engine):
        """Test workflow error handling and recovery."""
        # Workflow with error handling
        error_workflow = {
            "name": "error_handling_test",
            "error_handling": {
                "retry_policy": {"max_attempts": 3, "backoff": "exponential", "initial_delay": 1},
                "fallback_steps": ["error_notification"],
            },
            "steps": [
                {
                    "name": "failing_step",
                    "type": "external_api",
                    "config": {"service": "unreliable_service"},
                },
                {
                    "name": "success_step",
                    "type": "log",
                    "depends_on": ["failing_step"],
                    "config": {"message": "Success!"},
                },
                {
                    "name": "error_notification",
                    "type": "notification",
                    "config": {"message": "Workflow failed, using fallback"},
                },
            ],
        }

        workflow_id = await workflow_engine.register_workflow(error_workflow)

        # Mock failing service
        with patch(
            "prompt_sentinel.automation.workflow.external_api_call",
            side_effect=Exception("Service unavailable"),
        ):
            execution = await workflow_engine.execute_workflow(
                workflow_id=workflow_id["workflow_id"], input_data={}
            )

            await asyncio.sleep(3)  # Wait for retries

            status = await workflow_engine.get_execution_status(execution["execution_id"])

            # Should execute fallback
            assert status["status"] == WorkflowStatus.COMPLETED.value
            executed_steps = [step["name"] for step in status["step_details"]]
            assert "error_notification" in executed_steps

            # Check retry attempts
            failing_step = next(
                step for step in status["step_details"] if step["name"] == "failing_step"
            )
            assert failing_step["attempts"] <= 3

    @pytest.mark.asyncio
    async def test_workflow_scheduling(self, workflow_engine):
        """Test scheduled workflow execution."""
        # Schedule workflow
        scheduled_workflow = {
            "name": "daily_cleanup",
            "schedule": {
                "type": "cron",
                "expression": "0 2 * * *",  # Daily at 2 AM
                "timezone": "UTC",
            },
            "steps": [
                {"name": "cleanup_logs", "type": "cleanup", "config": {"retention_days": 30}}
            ],
        }

        workflow_id = await workflow_engine.register_workflow(scheduled_workflow)

        # Enable scheduling
        schedule_result = await workflow_engine.schedule_workflow(
            workflow_id=workflow_id["workflow_id"]
        )

        assert schedule_result["scheduled"] is True
        assert schedule_result["next_run"] is not None

        # Get scheduled workflows
        scheduled = await workflow_engine.get_scheduled_workflows()

        assert len(scheduled) >= 1
        assert any(w["name"] == "daily_cleanup" for w in scheduled)

    @pytest.mark.asyncio
    async def test_workflow_versioning(self, workflow_engine):
        """Test workflow version management."""
        # Register initial version
        workflow_v1 = {
            "name": "versioned_workflow",
            "version": "1.0",
            "steps": [{"name": "step1", "type": "log"}],
        }

        v1_result = await workflow_engine.register_workflow(workflow_v1)

        # Register updated version
        workflow_v2 = {
            "name": "versioned_workflow",
            "version": "2.0",
            "steps": [{"name": "step1", "type": "log"}, {"name": "step2", "type": "log"}],
        }

        await workflow_engine.register_workflow(workflow_v2)

        # Get workflow versions
        versions = await workflow_engine.get_workflow_versions("versioned_workflow")

        assert len(versions) == 2
        assert "1.0" in versions
        assert "2.0" in versions

        # Execute specific version
        execution = await workflow_engine.execute_workflow(
            workflow_id=v1_result["workflow_id"], version="1.0"
        )

        await asyncio.sleep(1)
        status = await workflow_engine.get_execution_status(execution["execution_id"])

        # Should have only 1 step (v1)
        assert len(status["completed_steps"]) == 1


class TestWorkflowSteps:
    """Test individual workflow step types."""

    @pytest.fixture
    def step_executor(self):
        """Create step executor."""
        from prompt_sentinel.automation.steps import StepExecutor

        return StepExecutor()

    @pytest.mark.asyncio
    async def test_validation_step(self, step_executor):
        """Test validation step execution."""
        # Validation step config
        validation_config = {
            "rules": [
                {"field": "confidence", "operator": ">=", "value": 0.8},
                {"field": "verdict", "operator": "in", "value": ["BLOCK", "FLAG"]},
                {"field": "reasons", "operator": "contains", "value": "injection"},
            ],
            "mode": "all",  # All rules must pass
        }

        # Valid input
        valid_input = {
            "confidence": 0.9,
            "verdict": "BLOCK",
            "reasons": ["injection_detected", "high_risk"],
        }

        result = await step_executor.execute_validation(validation_config, valid_input)

        assert result["valid"] is True
        assert result["passed_rules"] == 3
        assert result["failed_rules"] == 0

        # Invalid input
        invalid_input = {
            "confidence": 0.5,  # Below threshold
            "verdict": "ALLOW",
            "reasons": ["safe_content"],
        }

        result = await step_executor.execute_validation(validation_config, invalid_input)

        assert result["valid"] is False
        assert result["failed_rules"] > 0

    @pytest.mark.asyncio
    async def test_enrichment_step(self, step_executor):
        """Test data enrichment step."""
        # Enrichment configuration
        enrichment_config = {
            "sources": [
                {
                    "name": "user_profile",
                    "type": "api",
                    "endpoint": "/users/{user_id}",
                    "fields": ["risk_level", "account_type"],
                },
                {
                    "name": "threat_intel",
                    "type": "lookup",
                    "table": "indicators",
                    "key_field": "indicator_value",
                },
            ]
        }

        input_data = {"user_id": "user_123", "indicator_value": "malicious_pattern"}

        # Mock external data sources
        with (
            patch("prompt_sentinel.automation.steps.api_call") as mock_api,
            patch("prompt_sentinel.automation.steps.lookup_data") as mock_lookup,
        ):
            mock_api.return_value = {"risk_level": "high", "account_type": "premium"}
            mock_lookup.return_value = {"threat_type": "injection", "severity": "critical"}

            result = await step_executor.execute_enrichment(enrichment_config, input_data)

            assert result["enriched"] is True
            assert result["data"]["risk_level"] == "high"
            assert result["data"]["threat_type"] == "injection"
            assert len(result["sources_queried"]) == 2

    @pytest.mark.asyncio
    async def test_transformation_step(self, step_executor):
        """Test data transformation step."""
        # Transformation rules
        transform_config = {
            "transformations": [
                {
                    "type": "map",
                    "field": "verdict",
                    "mapping": {"BLOCK": "blocked", "ALLOW": "allowed", "FLAG": "flagged"},
                },
                {
                    "type": "calculate",
                    "field": "risk_score",
                    "expression": "confidence * severity_multiplier",
                    "variables": {"severity_multiplier": 1.5},
                },
                {"type": "format", "field": "timestamp", "format": "iso8601"},
            ]
        }

        input_data = {"verdict": "BLOCK", "confidence": 0.8, "timestamp": 1643723400}

        result = await step_executor.execute_transformation(transform_config, input_data)

        assert result["data"]["verdict"] == "blocked"
        assert result["data"]["risk_score"] == 1.2  # 0.8 * 1.5
        assert "T" in result["data"]["timestamp"]  # ISO format

    @pytest.mark.asyncio
    async def test_notification_step(self, step_executor):
        """Test notification step."""
        # Notification configuration
        notification_config = {
            "channels": [
                {
                    "type": "slack",
                    "webhook": "https://hooks.slack.com/services/...",
                    "channel": "#security-alerts",
                },
                {
                    "type": "email",
                    "recipients": ["security@example.com"],
                    "template": "security_alert",
                },
            ],
            "message_template": {
                "title": "Security Alert: {{verdict}}",
                "body": "Detection ID: {{detection_id}}\nConfidence: {{confidence}}",
            },
        }

        input_data = {"detection_id": "det_123", "verdict": "BLOCK", "confidence": 0.95}

        with (
            patch("prompt_sentinel.automation.steps.send_slack_message") as mock_slack,
            patch("prompt_sentinel.automation.steps.send_email") as mock_email,
        ):
            mock_slack.return_value = {"sent": True, "message_id": "slack_123"}
            mock_email.return_value = {"sent": True, "message_id": "email_456"}

            result = await step_executor.execute_notification(notification_config, input_data)

            assert result["notifications_sent"] == 2
            assert result["results"]["slack"]["sent"] is True
            assert result["results"]["email"]["sent"] is True

    @pytest.mark.asyncio
    async def test_action_step(self, step_executor):
        """Test action execution step."""
        # Action configuration
        action_config = {
            "actions": [
                {"type": "block_user", "config": {"user_id": "{{user_id}}", "duration": "24h"}},
                {
                    "type": "update_risk_score",
                    "config": {"user_id": "{{user_id}}", "increment": 10},
                },
                {
                    "type": "create_incident",
                    "config": {
                        "title": "High-risk detection",
                        "severity": "high",
                        "assignee": "security-team",
                    },
                },
            ]
        }

        input_data = {"user_id": "user_789", "detection_id": "det_456"}

        with patch("prompt_sentinel.automation.steps.execute_action") as mock_action:
            mock_action.return_value = {"executed": True, "action_id": "action_123"}

            result = await step_executor.execute_action(action_config, input_data)

            assert result["actions_executed"] == 3
            assert all(action["executed"] for action in result["results"])


class TestWorkflowOrchestration:
    """Test workflow orchestration and coordination."""

    @pytest.fixture
    def orchestrator(self):
        """Create workflow orchestrator."""
        from prompt_sentinel.automation.orchestrator import WorkflowOrchestrator

        return WorkflowOrchestrator()

    @pytest.mark.asyncio
    async def test_workflow_chaining(self, orchestrator):
        """Test chaining multiple workflows."""
        # Define workflow chain
        workflow_chain = {
            "name": "detection_response_chain",
            "workflows": [
                {
                    "name": "initial_detection",
                    "workflow_id": "detection_wf_1",
                    "inputs": {"detection_data": "{{trigger_data}}"},
                },
                {
                    "name": "risk_assessment",
                    "workflow_id": "risk_wf_1",
                    "inputs": {"detection_result": "{{initial_detection.output}}"},
                    "condition": "{{initial_detection.verdict}} != 'ALLOW'",
                },
                {
                    "name": "incident_response",
                    "workflow_id": "incident_wf_1",
                    "inputs": {"risk_data": "{{risk_assessment.output}}"},
                    "condition": "{{risk_assessment.risk_score}} > 0.8",
                },
            ],
        }

        result = await orchestrator.register_workflow_chain(workflow_chain)

        assert result["registered"] is True
        assert result["chain_id"] is not None

        # Execute chain
        execution = await orchestrator.execute_workflow_chain(
            chain_id=result["chain_id"],
            trigger_data={"user_id": "test_user", "prompt": "test prompt"},
        )

        assert execution["execution_id"] is not None
        assert execution["status"] == "running"

    @pytest.mark.asyncio
    async def test_workflow_coordination(self, orchestrator):
        """Test coordinating multiple concurrent workflows."""
        # Coordinate multiple workflows
        coordination_config = {
            "name": "multi_analysis",
            "coordination_type": "fan_out_fan_in",
            "fan_out": [
                {"workflow": "malware_analysis", "input_field": "content"},
                {"workflow": "sentiment_analysis", "input_field": "content"},
                {"workflow": "language_detection", "input_field": "content"},
            ],
            "fan_in": {
                "aggregation_strategy": "merge",
                "wait_for": "all",  # or "any", "majority"
                "timeout_seconds": 300,
            },
        }

        coordination_id = await orchestrator.setup_coordination(coordination_config)

        # Execute coordinated workflows
        execution = await orchestrator.execute_coordinated_workflows(
            coordination_id=coordination_id, input_data={"content": "suspicious text content"}
        )

        await asyncio.sleep(2)

        status = await orchestrator.get_coordination_status(execution["execution_id"])

        assert "fan_out_results" in status
        assert "fan_in_result" in status or status["status"] == "running"

    @pytest.mark.asyncio
    async def test_workflow_templates(self, orchestrator):
        """Test workflow templates and instantiation."""
        # Define workflow template
        template = {
            "name": "security_response_template",
            "parameters": [
                {"name": "severity_threshold", "type": "float", "default": 0.8},
                {"name": "notification_channels", "type": "list", "required": True},
                {"name": "auto_block", "type": "boolean", "default": False},
            ],
            "workflow_definition": {
                "steps": [
                    {
                        "name": "assess_severity",
                        "type": "condition",
                        "config": {
                            "field": "confidence",
                            "operator": ">",
                            "value": "{{severity_threshold}}",
                        },
                    },
                    {
                        "name": "send_notifications",
                        "type": "notification",
                        "condition": "assess_severity == true",
                        "config": {"channels": "{{notification_channels}}"},
                    },
                    {
                        "name": "auto_block_user",
                        "type": "action",
                        "condition": "assess_severity == true and {{auto_block}} == true",
                        "config": {"action": "block_user"},
                    },
                ]
            },
        }

        template_id = await orchestrator.register_template(template)

        # Instantiate template
        instance = await orchestrator.instantiate_template(
            template_id=template_id,
            parameters={
                "severity_threshold": 0.9,
                "notification_channels": ["slack", "email"],
                "auto_block": True,
            },
        )

        assert instance["workflow_id"] is not None
        assert instance["instantiated"] is True

    @pytest.mark.asyncio
    async def test_workflow_monitoring(self, orchestrator):
        """Test workflow execution monitoring and metrics."""
        # Start monitoring
        await orchestrator.start_monitoring()

        # Execute some workflows for monitoring
        for i in range(5):
            await orchestrator.execute_workflow(
                workflow_id="test_workflow", input_data={"iteration": i}
            )

        await asyncio.sleep(2)

        # Get monitoring metrics
        metrics = await orchestrator.get_workflow_metrics()

        assert "total_executions" in metrics
        assert "success_rate" in metrics
        assert "avg_execution_time" in metrics
        assert "active_executions" in metrics

        # Get workflow health
        health = await orchestrator.get_workflow_health("test_workflow")

        assert "status" in health
        assert "last_execution" in health
        assert "success_rate_24h" in health

    @pytest.mark.asyncio
    async def test_workflow_scaling(self, orchestrator):
        """Test automatic workflow scaling."""
        # Configure auto-scaling
        scaling_config = {
            "enabled": True,
            "min_workers": 2,
            "max_workers": 10,
            "scale_up_threshold": 80,  # CPU %
            "scale_down_threshold": 20,
            "scale_up_cooldown": 60,
            "scale_down_cooldown": 300,
        }

        await orchestrator.configure_auto_scaling(scaling_config)

        # Simulate high load
        tasks = []
        for i in range(100):
            task = orchestrator.execute_workflow(
                workflow_id="load_test_workflow", input_data={"load_test": i}
            )
            tasks.append(task)

        # Start executions
        await asyncio.gather(*tasks[:10])  # Start first batch

        await asyncio.sleep(1)

        # Check if scaling occurred
        worker_status = await orchestrator.get_worker_status()

        assert "worker_count" in worker_status
        assert "cpu_usage" in worker_status

        # Scaling may or may not occur depending on actual load
        if worker_status["cpu_usage"] > 80:
            assert worker_status["worker_count"] > scaling_config["min_workers"]


class TestEventDrivenWorkflows:
    """Test event-driven workflow automation."""

    @pytest.fixture
    def event_engine(self):
        """Create event-driven workflow engine."""
        from prompt_sentinel.automation.events import EventDrivenEngine

        return EventDrivenEngine()

    @pytest.mark.asyncio
    async def test_event_triggers(self, event_engine):
        """Test event-based workflow triggering."""
        # Register event handlers
        handlers = [
            {
                "event_pattern": "detection.high_risk",
                "workflow_id": "high_risk_response",
                "condition": "event.confidence > 0.9",
            },
            {
                "event_pattern": "user.suspicious_behavior",
                "workflow_id": "user_investigation",
                "condition": "event.risk_indicators >= 3",
            },
            {
                "event_pattern": "system.anomaly_detected",
                "workflow_id": "anomaly_response",
                "priority": "high",
            },
        ]

        for handler in handlers:
            result = await event_engine.register_event_handler(handler)
            assert result["registered"] is True

        # Publish events
        events = [
            {
                "type": "detection.high_risk",
                "data": {"confidence": 0.95, "user_id": "user1"},
                "timestamp": datetime.utcnow().isoformat(),
            },
            {
                "type": "user.suspicious_behavior",
                "data": {"user_id": "user2", "risk_indicators": 5},
                "timestamp": datetime.utcnow().isoformat(),
            },
        ]

        triggered_workflows = []
        for event in events:
            result = await event_engine.publish_event(event)
            triggered_workflows.extend(result.get("triggered_workflows", []))

        assert len(triggered_workflows) >= 2

    @pytest.mark.asyncio
    async def test_event_correlation(self, event_engine):
        """Test event correlation and aggregation."""
        # Configure correlation rules
        correlation_rules = [
            {
                "name": "coordinated_attack",
                "pattern": [
                    {"event_type": "detection.injection", "time_window": "5m"},
                    {"event_type": "detection.injection", "time_window": "5m", "count": 3},
                    {"event_type": "user.login_failure", "time_window": "10m"},
                ],
                "correlation_key": "source_ip",
                "action": {
                    "type": "trigger_workflow",
                    "workflow_id": "coordinated_attack_response",
                },
            }
        ]

        await event_engine.configure_correlation_rules(correlation_rules)

        # Generate correlated events
        base_time = datetime.utcnow()
        correlated_events = [
            {
                "type": "detection.injection",
                "data": {"source_ip": "192.168.1.100"},
                "timestamp": base_time.isoformat(),
            },
            {
                "type": "detection.injection",
                "data": {"source_ip": "192.168.1.100"},
                "timestamp": (base_time + timedelta(minutes=1)).isoformat(),
            },
            {
                "type": "detection.injection",
                "data": {"source_ip": "192.168.1.100"},
                "timestamp": (base_time + timedelta(minutes=2)).isoformat(),
            },
            {
                "type": "user.login_failure",
                "data": {"source_ip": "192.168.1.100"},
                "timestamp": (base_time + timedelta(minutes=3)).isoformat(),
            },
        ]

        correlation_results = []
        for event in correlated_events:
            result = await event_engine.process_event_correlation(event)
            if result.get("correlation_detected"):
                correlation_results.append(result)

        # Should detect coordinated attack pattern
        assert len(correlation_results) > 0
        assert any("coordinated_attack" in r.get("matched_rules", []) for r in correlation_results)

    @pytest.mark.asyncio
    async def test_complex_event_processing(self, event_engine):
        """Test complex event processing (CEP)."""
        # Define complex event patterns
        cep_patterns = [
            {
                "name": "escalation_pattern",
                "description": "Detect escalating attack attempts",
                "pattern": """
                PATTERN SEQ(
                    A as detection.low_risk,
                    B as detection.medium_risk,
                    C as detection.high_risk
                )
                WHERE A.user_id = B.user_id AND B.user_id = C.user_id
                WITHIN 1 hour
                """,
                "action": {"workflow_id": "escalation_response", "priority": "critical"},
            }
        ]

        await event_engine.configure_cep_patterns(cep_patterns)

        # Generate pattern events
        user_id = "escalating_user"
        pattern_events = [
            {
                "type": "detection.low_risk",
                "data": {"user_id": user_id, "confidence": 0.3},
                "timestamp": datetime.utcnow().isoformat(),
            },
            {
                "type": "detection.medium_risk",
                "data": {"user_id": user_id, "confidence": 0.6},
                "timestamp": (datetime.utcnow() + timedelta(minutes=15)).isoformat(),
            },
            {
                "type": "detection.high_risk",
                "data": {"user_id": user_id, "confidence": 0.9},
                "timestamp": (datetime.utcnow() + timedelta(minutes=30)).isoformat(),
            },
        ]

        pattern_matches = []
        for event in pattern_events:
            result = await event_engine.process_cep_event(event)
            if result.get("pattern_matched"):
                pattern_matches.append(result)

        # Should detect escalation pattern
        assert len(pattern_matches) > 0

    @pytest.mark.asyncio
    async def test_event_sourcing(self, event_engine):
        """Test event sourcing for workflow state."""
        # Configure event sourcing
        await event_engine.enable_event_sourcing(
            {"store_type": "persistent", "retention_days": 90, "compression": True}
        )

        # Execute workflow with event sourcing
        workflow_id = "event_sourced_workflow"
        execution = await event_engine.execute_workflow_with_sourcing(
            workflow_id=workflow_id, input_data={"test": "data"}
        )

        # Wait for workflow completion
        await asyncio.sleep(1)

        # Retrieve event history
        event_history = await event_engine.get_execution_events(
            execution_id=execution["execution_id"]
        )

        assert len(event_history) > 0

        # Should have workflow lifecycle events
        event_types = [event["type"] for event in event_history]
        assert "workflow.started" in event_types
        assert "workflow.completed" in event_types or "workflow.failed" in event_types

        # Replay workflow from events
        replay_result = await event_engine.replay_workflow_from_events(
            execution_id=execution["execution_id"], target_event_id=event_history[-1]["event_id"]
        )

        assert replay_result["replayed"] is True
        assert replay_result["final_state"] is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
