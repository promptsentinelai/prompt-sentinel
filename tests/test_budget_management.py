"""Tests for budget management and cost tracking."""

import pytest
import asyncio
from datetime import datetime, timedelta
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch

from prompt_sentinel.monitoring.budget_manager import (
    BudgetManager, BudgetExceeded, CostCalculator
)
from prompt_sentinel.models.schemas import Message, Role


class TestBudgetManager:
    """Test budget management functionality."""

    @pytest.fixture
    def budget_manager(self):
        """Create budget manager instance."""
        return BudgetManager(
            monthly_budget=100.0,
            daily_budget=10.0,
            alert_threshold=0.8
        )

    @pytest.mark.asyncio
    async def test_track_api_cost(self, budget_manager):
        """Test tracking API call costs."""
        # Track some costs
        await budget_manager.track_cost(
            provider="anthropic",
            model="claude-3-opus",
            input_tokens=1000,
            output_tokens=500,
            cost=0.015
        )
        
        await budget_manager.track_cost(
            provider="openai",
            model="gpt-4",
            input_tokens=500,
            output_tokens=300,
            cost=0.024
        )
        
        # Check total cost
        total = await budget_manager.get_total_cost()
        assert total == 0.039

    @pytest.mark.asyncio
    async def test_budget_enforcement(self, budget_manager):
        """Test budget limit enforcement."""
        # Set small budget for testing
        manager = BudgetManager(
            monthly_budget=1.0,
            daily_budget=0.5
        )
        
        # Use up budget
        await manager.track_cost(
            provider="anthropic",
            model="claude-3",
            cost=0.4
        )
        
        # Should still allow (under daily limit)
        can_proceed = await manager.check_budget_available()
        assert can_proceed is True
        
        # Exceed daily budget
        await manager.track_cost(
            provider="anthropic",
            model="claude-3",
            cost=0.2
        )
        
        # Should not allow
        can_proceed = await manager.check_budget_available()
        assert can_proceed is False

    @pytest.mark.asyncio
    async def test_budget_alerts(self, budget_manager):
        """Test budget alert thresholds."""
        alerts = []
        
        # Set alert handler
        budget_manager.on_alert(lambda alert: alerts.append(alert))
        
        # Use 85% of daily budget (above 80% threshold)
        await budget_manager.track_cost(
            provider="anthropic",
            model="claude-3",
            cost=8.5
        )
        
        # Should trigger alert
        assert len(alerts) == 1
        assert "daily budget" in alerts[0]["message"].lower()
        assert alerts[0]["percentage"] == 85

    @pytest.mark.asyncio
    async def test_cost_by_provider(self, budget_manager):
        """Test tracking costs by provider."""
        # Track costs for different providers
        await budget_manager.track_cost(
            provider="anthropic",
            model="claude-3",
            cost=5.0
        )
        
        await budget_manager.track_cost(
            provider="openai",
            model="gpt-4",
            cost=3.0
        )
        
        await budget_manager.track_cost(
            provider="anthropic",
            model="claude-3",
            cost=2.0
        )
        
        # Get breakdown
        breakdown = await budget_manager.get_cost_breakdown()
        
        assert breakdown["anthropic"] == 7.0
        assert breakdown["openai"] == 3.0
        assert breakdown["total"] == 10.0

    @pytest.mark.asyncio
    async def test_budget_reset(self, budget_manager):
        """Test budget reset cycles."""
        # Track some costs
        await budget_manager.track_cost(
            provider="anthropic",
            cost=5.0
        )
        
        # Check cost
        assert await budget_manager.get_total_cost(period="daily") == 5.0
        
        # Simulate day change
        await budget_manager.reset_daily_budget()
        
        # Daily cost should be reset
        assert await budget_manager.get_total_cost(period="daily") == 0.0
        
        # Monthly should remain
        assert await budget_manager.get_total_cost(period="monthly") == 5.0


class TestCostCalculator:
    """Test cost calculation for different providers."""

    @pytest.fixture
    def calculator(self):
        """Create cost calculator."""
        return CostCalculator()

    def test_anthropic_cost_calculation(self, calculator):
        """Test Anthropic API cost calculation."""
        cost = calculator.calculate_cost(
            provider="anthropic",
            model="claude-3-opus-20240229",
            input_tokens=1000,
            output_tokens=500
        )
        
        # Claude 3 Opus: $15/1M input, $75/1M output
        expected = (1000 * 15 / 1_000_000) + (500 * 75 / 1_000_000)
        assert cost == pytest.approx(expected, rel=0.01)

    def test_openai_cost_calculation(self, calculator):
        """Test OpenAI API cost calculation."""
        cost = calculator.calculate_cost(
            provider="openai",
            model="gpt-4-turbo",
            input_tokens=1000,
            output_tokens=500
        )
        
        # GPT-4 Turbo: $10/1M input, $30/1M output
        expected = (1000 * 10 / 1_000_000) + (500 * 30 / 1_000_000)
        assert cost == pytest.approx(expected, rel=0.01)

    def test_gemini_cost_calculation(self, calculator):
        """Test Gemini API cost calculation."""
        cost = calculator.calculate_cost(
            provider="gemini",
            model="gemini-pro",
            input_tokens=1000,
            output_tokens=500
        )
        
        # Gemini Pro: $0.50/1M input, $1.50/1M output
        expected = (1000 * 0.5 / 1_000_000) + (500 * 1.5 / 1_000_000)
        assert cost == pytest.approx(expected, rel=0.01)

    def test_unknown_model_fallback(self, calculator):
        """Test fallback for unknown models."""
        cost = calculator.calculate_cost(
            provider="unknown",
            model="unknown-model",
            input_tokens=1000,
            output_tokens=500
        )
        
        # Should use default rates
        assert cost > 0


class TestBudgetPersistence:
    """Test budget data persistence."""

    @pytest.mark.asyncio
    async def test_save_budget_state(self):
        """Test saving budget state to storage."""
        manager = BudgetManager(
            monthly_budget=100.0,
            storage_backend="file",
            storage_path="/tmp/budget.json"
        )
        
        # Track some costs
        await manager.track_cost(provider="anthropic", cost=10.0)
        
        # Save state
        await manager.save_state()
        
        # Create new manager and load state
        new_manager = BudgetManager(
            monthly_budget=100.0,
            storage_backend="file",
            storage_path="/tmp/budget.json"
        )
        await new_manager.load_state()
        
        # Should have same costs
        assert await new_manager.get_total_cost() == 10.0

    @pytest.mark.asyncio
    async def test_budget_history(self):
        """Test maintaining budget history."""
        manager = BudgetManager(
            monthly_budget=100.0,
            enable_history=True
        )
        
        # Track costs over time
        for day in range(7):
            await manager.track_cost(
                provider="anthropic",
                cost=5.0 + day,
                timestamp=datetime.utcnow() - timedelta(days=day)
            )
        
        # Get history
        history = await manager.get_cost_history(days=7)
        
        assert len(history) == 7
        assert sum(h["cost"] for h in history) == 35.0 + sum(range(7))


class TestBudgetOptimization:
    """Test budget optimization strategies."""

    @pytest.mark.asyncio
    async def test_provider_cost_optimization(self):
        """Test choosing providers based on cost."""
        from prompt_sentinel.monitoring.budget_optimizer import BudgetOptimizer
        
        optimizer = BudgetOptimizer(
            budget_manager=BudgetManager(daily_budget=10.0),
            provider_costs={
                "anthropic": {"per_1k_tokens": 0.015},
                "openai": {"per_1k_tokens": 0.020},
                "gemini": {"per_1k_tokens": 0.001}
            }
        )
        
        # Get cheapest provider for simple task
        provider = await optimizer.get_optimal_provider(
            estimated_tokens=1000,
            quality_requirement="low"
        )
        
        assert provider == "gemini"  # Cheapest
        
        # Get best provider for complex task
        provider = await optimizer.get_optimal_provider(
            estimated_tokens=1000,
            quality_requirement="high"
        )
        
        assert provider in ["anthropic", "openai"]  # Better quality

    @pytest.mark.asyncio
    async def test_dynamic_budget_allocation(self):
        """Test dynamic budget allocation across time periods."""
        from prompt_sentinel.monitoring.budget_optimizer import BudgetOptimizer
        
        optimizer = BudgetOptimizer(
            budget_manager=BudgetManager(
                daily_budget=100.0,
                hourly_limits=True
            )
        )
        
        # Get hourly allocation based on usage patterns
        allocation = await optimizer.get_hourly_allocation(
            current_hour=14,  # 2 PM
            historical_pattern="business_hours"
        )
        
        # Business hours should get more budget
        assert allocation > 100.0 / 24  # More than equal distribution

    @pytest.mark.asyncio
    async def test_budget_forecasting(self):
        """Test budget forecasting based on usage."""
        manager = BudgetManager(
            monthly_budget=100.0,
            enable_forecasting=True
        )
        
        # Simulate usage pattern
        for day in range(10):
            await manager.track_cost(
                provider="anthropic",
                cost=3.0 + (day * 0.5),  # Increasing usage
                timestamp=datetime.utcnow() - timedelta(days=10-day)
            )
        
        # Forecast remaining month
        forecast = await manager.forecast_monthly_cost()
        
        # Should predict overage based on trend
        assert forecast["predicted_total"] > 100.0
        assert forecast["will_exceed_budget"] is True
        assert "recommended_daily_limit" in forecast


class TestCostAllocation:
    """Test cost allocation to users/projects."""

    @pytest.mark.asyncio
    async def test_user_cost_tracking(self):
        """Test tracking costs per user."""
        manager = BudgetManager(
            monthly_budget=1000.0,
            enable_user_tracking=True
        )
        
        # Track costs for different users
        await manager.track_cost(
            provider="anthropic",
            cost=5.0,
            user_id="user1"
        )
        
        await manager.track_cost(
            provider="openai",
            cost=3.0,
            user_id="user2"
        )
        
        await manager.track_cost(
            provider="anthropic",
            cost=2.0,
            user_id="user1"
        )
        
        # Get per-user costs
        user_costs = await manager.get_user_costs()
        
        assert user_costs["user1"] == 7.0
        assert user_costs["user2"] == 3.0

    @pytest.mark.asyncio
    async def test_project_budget_limits(self):
        """Test project-specific budget limits."""
        manager = BudgetManager(
            monthly_budget=1000.0,
            project_budgets={
                "project_a": 300.0,
                "project_b": 500.0,
                "project_c": 200.0
            }
        )
        
        # Track project costs
        await manager.track_cost(
            provider="anthropic",
            cost=250.0,
            project="project_a"
        )
        
        # Check if project can continue
        can_proceed = await manager.check_project_budget("project_a")
        assert can_proceed is True  # 250 < 300
        
        # Exceed project budget
        await manager.track_cost(
            provider="anthropic",
            cost=60.0,
            project="project_a"
        )
        
        can_proceed = await manager.check_project_budget("project_a")
        assert can_proceed is False  # 310 > 300


class TestBudgetReporting:
    """Test budget reporting and analytics."""

    @pytest.mark.asyncio
    async def test_generate_cost_report(self):
        """Test generating cost reports."""
        manager = BudgetManager(
            monthly_budget=1000.0,
            enable_reporting=True
        )
        
        # Generate usage
        providers = ["anthropic", "openai", "gemini"]
        models = ["claude-3", "gpt-4", "gemini-pro"]
        
        for i in range(30):
            await manager.track_cost(
                provider=providers[i % 3],
                model=models[i % 3],
                cost=10.0 + (i % 5),
                timestamp=datetime.utcnow() - timedelta(days=30-i)
            )
        
        # Generate report
        report = await manager.generate_report(
            start_date=datetime.utcnow() - timedelta(days=30),
            end_date=datetime.utcnow()
        )
        
        assert "total_cost" in report
        assert "daily_average" in report
        assert "provider_breakdown" in report
        assert "model_breakdown" in report
        assert len(report["daily_costs"]) == 30

    @pytest.mark.asyncio
    async def test_cost_anomaly_detection(self):
        """Test detecting unusual cost patterns."""
        manager = BudgetManager(
            monthly_budget=1000.0,
            enable_anomaly_detection=True
        )
        
        # Normal usage pattern
        for day in range(20):
            await manager.track_cost(
                provider="anthropic",
                cost=20.0 + (day % 3),  # 20-22 per day
                timestamp=datetime.utcnow() - timedelta(days=20-day)
            )
        
        # Anomaly - sudden spike
        await manager.track_cost(
            provider="anthropic",
            cost=100.0,  # 5x normal
            timestamp=datetime.utcnow()
        )
        
        # Check for anomalies
        anomalies = await manager.detect_anomalies()
        
        assert len(anomalies) > 0
        assert anomalies[0]["severity"] == "high"
        assert anomalies[0]["cost"] == 100.0


class TestBudgetWebhooks:
    """Test budget alert webhooks."""

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient")
    async def test_webhook_notifications(self, mock_client):
        """Test sending webhook notifications for budget alerts."""
        manager = BudgetManager(
            daily_budget=10.0,
            webhook_url="https://example.com/webhook",
            alert_threshold=0.8
        )
        
        # Mock webhook response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client.return_value.post.return_value = mock_response
        
        # Trigger alert
        await manager.track_cost(
            provider="anthropic",
            cost=8.5  # 85% of budget
        )
        
        # Webhook should be called
        mock_client.return_value.post.assert_called_once()
        call_args = mock_client.return_value.post.call_args
        
        assert call_args[0][0] == "https://example.com/webhook"
        assert "budget_alert" in call_args[1]["json"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])