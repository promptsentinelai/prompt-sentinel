# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Statistical analysis engine for A/B testing experiments.

This module provides comprehensive statistical analysis for experiment results,
including significance testing, confidence intervals, and effect size calculations.
"""

import math
import statistics
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class MetricType(Enum):
    """Types of metrics that can be analyzed."""

    BINARY = "binary"  # Success/failure (e.g., detection accuracy)
    CONTINUOUS = "continuous"  # Numeric values (e.g., response time)
    COUNT = "count"  # Count metrics (e.g., API calls)
    RATE = "rate"  # Rate metrics (e.g., requests per second)


class SignificanceTest(Enum):
    """Statistical tests for significance testing."""

    T_TEST = "t_test"  # Student's t-test for continuous metrics
    Z_TEST = "z_test"  # Z-test for proportions
    CHI_SQUARE = "chi_square"  # Chi-square test for categorical data
    MANN_WHITNEY = "mann_whitney"  # Non-parametric test
    BAYESIAN = "bayesian"  # Bayesian analysis


@dataclass
class MetricData:
    """Statistical data for a metric."""

    values: list[float]
    sample_size: int
    mean: float
    std_dev: float
    variance: float
    median: float
    percentiles: dict[int, float]  # e.g., {50: median, 95: p95, 99: p99}

    @classmethod
    def from_values(cls, values: list[float]) -> "MetricData":
        """Create MetricData from list of values."""
        if not values:
            return cls(
                values=[],
                sample_size=0,
                mean=0.0,
                std_dev=0.0,
                variance=0.0,
                median=0.0,
                percentiles={},
            )

        sorted_values = sorted(values)
        n = len(values)
        mean = statistics.mean(values)

        return cls(
            values=values,
            sample_size=n,
            mean=mean,
            std_dev=statistics.stdev(values) if n > 1 else 0.0,
            variance=statistics.variance(values) if n > 1 else 0.0,
            median=statistics.median(values),
            percentiles={
                25: cls._percentile(sorted_values, 25),
                50: cls._percentile(sorted_values, 50),
                75: cls._percentile(sorted_values, 75),
                90: cls._percentile(sorted_values, 90),
                95: cls._percentile(sorted_values, 95),
                99: cls._percentile(sorted_values, 99),
            },
        )

    @staticmethod
    def _percentile(sorted_values: list[float], percentile: int) -> float:
        """Calculate percentile from sorted values."""
        if not sorted_values:
            return 0.0

        n = len(sorted_values)
        k = (n - 1) * percentile / 100.0
        f = math.floor(k)
        c = math.ceil(k)

        if f == c:
            return sorted_values[int(k)]

        d0 = sorted_values[int(f)] * (c - k)
        d1 = sorted_values[int(c)] * (k - f)
        return d0 + d1


@dataclass
class ExperimentResult:
    """Results of statistical analysis for an experiment."""

    experiment_id: str
    metric_name: str
    control_variant_id: str
    treatment_variant_id: str

    # Statistical results
    control_metrics: MetricData
    treatment_metrics: MetricData
    effect_size: float
    effect_size_ci: tuple[float, float]  # Confidence interval for effect size

    # Significance testing
    p_value: float
    is_significant: bool
    confidence_level: float
    test_statistic: float
    test_type: SignificanceTest

    # Practical significance
    min_detectable_effect: float
    practical_significance: bool

    # Power analysis
    statistical_power: float
    required_sample_size: int | None

    # Metadata
    analysis_timestamp: datetime
    total_observations: int
    experiment_duration_days: float

    def get_summary(self) -> dict[str, Any]:
        """Get human-readable summary of results."""
        improvement = (
            (self.treatment_metrics.mean - self.control_metrics.mean)
            / self.control_metrics.mean
            * 100
            if self.control_metrics.mean != 0
            else 0
        )

        return {
            "experiment_id": self.experiment_id,
            "metric": self.metric_name,
            "improvement_percent": round(improvement, 2),
            "is_significant": self.is_significant,
            "p_value": round(self.p_value, 4),
            "confidence_level": self.confidence_level,
            "effect_size": round(self.effect_size, 4),
            "statistical_power": round(self.statistical_power, 3),
            "control_mean": round(self.control_metrics.mean, 4),
            "treatment_mean": round(self.treatment_metrics.mean, 4),
            "sample_size_control": self.control_metrics.sample_size,
            "sample_size_treatment": self.treatment_metrics.sample_size,
            "practical_significance": self.practical_significance,
        }


class StatisticalAnalyzer:
    """Statistical analysis engine for experiment results.

    Provides comprehensive statistical analysis including significance testing,
    effect size calculation, power analysis, and confidence intervals.
    """

    def __init__(self, default_confidence_level: float = 0.95):
        """Initialize statistical analyzer.

        Args:
            default_confidence_level: Default confidence level for tests
        """
        self.default_confidence_level = default_confidence_level

    async def analyze_experiment(
        self,
        experiment_id: str,
        metric_data: dict[str, dict[str, list[float]]],
        metric_configs: dict[str, dict[str, Any]],
        min_sample_size: int = 100,
        confidence_level: float | None = None,
    ) -> list[ExperimentResult]:
        """Analyze experiment results for all metrics.

        Args:
            experiment_id: Experiment identifier
            metric_data: Nested dict {metric_name: {variant_id: [values]}}
            metric_configs: Configuration for each metric
            min_sample_size: Minimum sample size per variant
            confidence_level: Confidence level for analysis

        Returns:
            List of analysis results for each metric
        """
        confidence = confidence_level or self.default_confidence_level
        results = []

        for metric_name, variant_data in metric_data.items():
            if len(variant_data) < 2:
                logger.warning(
                    "Insufficient variants for analysis",
                    experiment_id=experiment_id,
                    metric=metric_name,
                )
                continue

            # Find control and treatment variants
            control_id, treatment_ids = self._identify_variants(variant_data)
            if not control_id or not treatment_ids:
                logger.warning(
                    "Could not identify control/treatment variants",
                    experiment_id=experiment_id,
                    metric=metric_name,
                )
                continue

            # Analyze each treatment against control
            for treatment_id in treatment_ids:
                control_values = variant_data[control_id]
                treatment_values = variant_data[treatment_id]

                # Check minimum sample size
                if len(control_values) < min_sample_size or len(treatment_values) < min_sample_size:
                    logger.debug(
                        "Insufficient sample size",
                        experiment_id=experiment_id,
                        metric=metric_name,
                        control_size=len(control_values),
                        treatment_size=len(treatment_values),
                    )
                    continue

                # Perform analysis
                result = await self._analyze_metric(
                    experiment_id=experiment_id,
                    metric_name=metric_name,
                    control_variant_id=control_id,
                    treatment_variant_id=treatment_id,
                    control_values=control_values,
                    treatment_values=treatment_values,
                    metric_config=metric_configs.get(metric_name, {}),
                    confidence_level=confidence,
                )

                if result:
                    results.append(result)

        return results

    async def _analyze_metric(
        self,
        experiment_id: str,
        metric_name: str,
        control_variant_id: str,
        treatment_variant_id: str,
        control_values: list[float],
        treatment_values: list[float],
        metric_config: dict[str, Any],
        confidence_level: float,
    ) -> ExperimentResult | None:
        """Analyze a single metric comparison.

        Args:
            experiment_id: Experiment identifier
            metric_name: Metric name
            control_variant_id: Control variant ID
            treatment_variant_id: Treatment variant ID
            control_values: Control group values
            treatment_values: Treatment group values
            metric_config: Metric configuration
            confidence_level: Confidence level for analysis

        Returns:
            Analysis result or None if analysis failed
        """
        try:
            # Prepare metric data
            control_data = MetricData.from_values(control_values)
            treatment_data = MetricData.from_values(treatment_values)

            # Determine test type
            metric_type = MetricType(metric_config.get("type", "continuous"))
            test_type = self._select_test_type(metric_type, control_data, treatment_data)

            # Perform significance test
            p_value, test_statistic = self._perform_significance_test(
                control_values, treatment_values, test_type
            )

            # Calculate effect size
            effect_size = self._calculate_effect_size(control_data, treatment_data, metric_type)

            # Calculate confidence interval for effect size
            effect_size_ci = self._calculate_effect_size_ci(
                control_data, treatment_data, confidence_level
            )

            # Determine significance
            alpha = 1.0 - confidence_level
            is_significant = p_value < alpha

            # Calculate statistical power
            statistical_power = self._calculate_power(
                control_data, treatment_data, alpha, effect_size
            )

            # Check practical significance
            min_detectable_effect = metric_config.get("min_effect_size", 0.05)
            practical_significance = abs(effect_size) >= min_detectable_effect

            # Calculate required sample size
            required_sample_size = self._calculate_required_sample_size(
                effect_size,
                alpha,
                0.8,  # 80% power
            )

            return ExperimentResult(
                experiment_id=experiment_id,
                metric_name=metric_name,
                control_variant_id=control_variant_id,
                treatment_variant_id=treatment_variant_id,
                control_metrics=control_data,
                treatment_metrics=treatment_data,
                effect_size=effect_size,
                effect_size_ci=effect_size_ci,
                p_value=p_value,
                is_significant=is_significant,
                confidence_level=confidence_level,
                test_statistic=test_statistic,
                test_type=test_type,
                min_detectable_effect=min_detectable_effect,
                practical_significance=practical_significance,
                statistical_power=statistical_power,
                required_sample_size=required_sample_size,
                analysis_timestamp=datetime.utcnow(),
                total_observations=len(control_values) + len(treatment_values),
                experiment_duration_days=0.0,  # Would be calculated from timestamps
            )

        except Exception as e:
            logger.error(
                "Failed to analyze metric",
                experiment_id=experiment_id,
                metric=metric_name,
                error=str(e),
            )
            return None

    def _identify_variants(
        self, variant_data: dict[str, list[float]]
    ) -> tuple[str | None, list[str]]:
        """Identify control and treatment variants.

        Args:
            variant_data: Dictionary mapping variant IDs to values

        Returns:
            Tuple of (control_id, treatment_ids)
        """
        variant_ids = list(variant_data.keys())

        # Look for explicit control indicator
        control_id = None
        for vid in variant_ids:
            if "control" in vid.lower() or vid.endswith("_0"):
                control_id = vid
                break

        # If no explicit control, use first variant
        if not control_id:
            control_id = variant_ids[0]

        treatment_ids = [vid for vid in variant_ids if vid != control_id]

        return control_id, treatment_ids

    def _select_test_type(
        self, metric_type: MetricType, control_data: MetricData, treatment_data: MetricData
    ) -> SignificanceTest:
        """Select appropriate statistical test.

        Args:
            metric_type: Type of metric
            control_data: Control group data
            treatment_data: Treatment group data

        Returns:
            Appropriate test type
        """
        if metric_type == MetricType.BINARY:
            return SignificanceTest.Z_TEST

        # For continuous metrics, check normality assumptions
        if control_data.sample_size >= 30 and treatment_data.sample_size >= 30:
            return SignificanceTest.T_TEST

        # For small samples or non-normal distributions
        return SignificanceTest.MANN_WHITNEY

    def _perform_significance_test(
        self,
        control_values: list[float],
        treatment_values: list[float],
        test_type: SignificanceTest,
    ) -> tuple[float, float]:
        """Perform statistical significance test.

        Args:
            control_values: Control group values
            treatment_values: Treatment group values
            test_type: Type of statistical test

        Returns:
            Tuple of (p_value, test_statistic)
        """
        if test_type == SignificanceTest.T_TEST:
            return self._t_test(control_values, treatment_values)

        elif test_type == SignificanceTest.Z_TEST:
            return self._z_test(control_values, treatment_values)

        elif test_type == SignificanceTest.MANN_WHITNEY:
            return self._mann_whitney_test(control_values, treatment_values)

        else:
            # Fallback to t-test
            return self._t_test(control_values, treatment_values)

    def _t_test(
        self, control_values: list[float], treatment_values: list[float]
    ) -> tuple[float, float]:
        """Perform Welch's t-test for unequal variances.

        Args:
            control_values: Control group values
            treatment_values: Treatment group values

        Returns:
            Tuple of (p_value, t_statistic)
        """
        n1, n2 = len(control_values), len(treatment_values)
        mean1, mean2 = statistics.mean(control_values), statistics.mean(treatment_values)

        if n1 <= 1 or n2 <= 1:
            return 1.0, 0.0

        var1 = statistics.variance(control_values)
        var2 = statistics.variance(treatment_values)

        # Welch's t-test
        pooled_se = math.sqrt(var1 / n1 + var2 / n2)
        if pooled_se == 0:
            return 1.0, 0.0

        t_stat = (mean2 - mean1) / pooled_se

        # Degrees of freedom for Welch's test
        df = ((var1 / n1 + var2 / n2) ** 2) / (
            (var1 / n1) ** 2 / (n1 - 1) + (var2 / n2) ** 2 / (n2 - 1)
        )

        # Approximate p-value calculation (simplified)
        p_value = 2 * (1 - self._t_cdf(abs(t_stat), df))

        return max(0.0, min(1.0, p_value)), t_stat

    def _z_test(
        self, control_values: list[float], treatment_values: list[float]
    ) -> tuple[float, float]:
        """Perform z-test for proportions.

        Args:
            control_values: Control group values (0s and 1s)
            treatment_values: Treatment group values (0s and 1s)

        Returns:
            Tuple of (p_value, z_statistic)
        """
        n1, n2 = len(control_values), len(treatment_values)
        x1, x2 = sum(control_values), sum(treatment_values)

        p1, p2 = x1 / n1, x2 / n2
        p_pooled = (x1 + x2) / (n1 + n2)

        if p_pooled == 0 or p_pooled == 1:
            return 1.0, 0.0

        se = math.sqrt(p_pooled * (1 - p_pooled) * (1 / n1 + 1 / n2))
        if se == 0:
            return 1.0, 0.0

        z_stat = (p2 - p1) / se

        # Two-tailed p-value
        p_value = 2 * (1 - self._normal_cdf(abs(z_stat)))

        return max(0.0, min(1.0, p_value)), z_stat

    def _mann_whitney_test(
        self, control_values: list[float], treatment_values: list[float]
    ) -> tuple[float, float]:
        """Perform Mann-Whitney U test (simplified implementation).

        Args:
            control_values: Control group values
            treatment_values: Treatment group values

        Returns:
            Tuple of (p_value, u_statistic)
        """
        # Simplified implementation - in practice would use scipy.stats
        n1, n2 = len(control_values), len(treatment_values)

        # Combine and rank values
        combined = [(val, 0) for val in control_values] + [(val, 1) for val in treatment_values]
        combined.sort()

        # Calculate ranks
        ranks = {}
        for i, (val, _group) in enumerate(combined):
            if val not in ranks:
                ranks[val] = []
            ranks[val].append(i + 1)

        # Assign average ranks for ties
        for val in ranks:
            avg_rank = sum(ranks[val]) / len(ranks[val])
            ranks[val] = avg_rank

        # Calculate U statistics
        r1 = sum(ranks[val] for val in control_values)
        u1 = r1 - n1 * (n1 + 1) / 2
        u2 = n1 * n2 - u1

        u_stat = min(u1, u2)

        # Normal approximation for large samples
        if n1 > 20 or n2 > 20:
            mu = n1 * n2 / 2
            sigma = math.sqrt(n1 * n2 * (n1 + n2 + 1) / 12)
            z = (u_stat - mu) / sigma if sigma > 0 else 0
            p_value = 2 * (1 - self._normal_cdf(abs(z)))
        else:
            # For small samples, use approximation
            p_value = 0.5  # Conservative estimate

        return max(0.0, min(1.0, p_value)), u_stat

    def _calculate_effect_size(
        self, control_data: MetricData, treatment_data: MetricData, metric_type: MetricType
    ) -> float:
        """Calculate effect size (Cohen's d or other appropriate measure).

        Args:
            control_data: Control group statistics
            treatment_data: Treatment group statistics
            metric_type: Type of metric

        Returns:
            Effect size
        """
        if metric_type == MetricType.BINARY:
            # Cohen's h for proportions
            p1, p2 = control_data.mean, treatment_data.mean
            return 2 * (math.asin(math.sqrt(p2)) - math.asin(math.sqrt(p1)))

        else:
            # Cohen's d for continuous variables
            pooled_std = math.sqrt(
                (
                    (control_data.sample_size - 1) * control_data.variance
                    + (treatment_data.sample_size - 1) * treatment_data.variance
                )
                / (control_data.sample_size + treatment_data.sample_size - 2)
            )

            if pooled_std == 0:
                return 0.0

            return (treatment_data.mean - control_data.mean) / pooled_std

    def _calculate_effect_size_ci(
        self, control_data: MetricData, treatment_data: MetricData, confidence_level: float
    ) -> tuple[float, float]:
        """Calculate confidence interval for effect size.

        Args:
            control_data: Control group statistics
            treatment_data: Treatment group statistics
            confidence_level: Confidence level

        Returns:
            Tuple of (lower_bound, upper_bound)
        """
        # Simplified implementation - would use more sophisticated methods in practice
        n1, n2 = control_data.sample_size, treatment_data.sample_size

        if n1 <= 1 or n2 <= 1:
            return (0.0, 0.0)

        # Standard error of effect size (approximation)
        se = math.sqrt((n1 + n2) / (n1 * n2) + 0.5 / (n1 + n2 - 2))

        # Critical value for confidence interval
        alpha = 1 - confidence_level
        z_critical = self._normal_ppf(1 - alpha / 2)

        effect_size = self._calculate_effect_size(
            control_data, treatment_data, MetricType.CONTINUOUS
        )

        margin_of_error = z_critical * se

        return (effect_size - margin_of_error, effect_size + margin_of_error)

    def _calculate_power(
        self, control_data: MetricData, treatment_data: MetricData, alpha: float, effect_size: float
    ) -> float:
        """Calculate statistical power of the test.

        Args:
            control_data: Control group statistics
            treatment_data: Treatment group statistics
            alpha: Significance level
            effect_size: Effect size

        Returns:
            Statistical power (0.0 to 1.0)
        """
        n1, n2 = control_data.sample_size, treatment_data.sample_size

        if n1 <= 1 or n2 <= 1:
            return 0.0

        # Simplified power calculation
        ncp = abs(effect_size) * math.sqrt(n1 * n2 / (n1 + n2))  # Non-centrality parameter
        critical_value = self._normal_ppf(1 - alpha / 2)

        # Power = P(|Z| > critical_value | effect_size)
        power = 1 - self._normal_cdf(critical_value - ncp) + self._normal_cdf(-critical_value - ncp)

        return max(0.0, min(1.0, power))

    def _calculate_required_sample_size(
        self, effect_size: float, alpha: float, power: float
    ) -> int:
        """Calculate required sample size for desired power.

        Args:
            effect_size: Expected effect size
            alpha: Significance level
            power: Desired statistical power

        Returns:
            Required sample size per group
        """
        if abs(effect_size) < 1e-6:
            return 10000  # Very large sample needed for tiny effects

        z_alpha = self._normal_ppf(1 - alpha / 2)
        z_beta = self._normal_ppf(power)

        # Formula for two-sample t-test
        n = 2 * ((z_alpha + z_beta) / effect_size) ** 2

        return max(10, int(math.ceil(n)))

    def _normal_cdf(self, x: float) -> float:
        """Cumulative distribution function for standard normal distribution.

        Args:
            x: Input value

        Returns:
            CDF value
        """
        # Approximation using error function
        return 0.5 * (1 + math.erf(x / math.sqrt(2)))

    def _normal_ppf(self, p: float) -> float:
        """Percent point function (inverse CDF) for standard normal distribution.

        Args:
            p: Probability

        Returns:
            Z-score
        """
        # Approximation - in practice would use scipy.stats.norm.ppf
        if p <= 0:
            return -float("inf")
        if p >= 1:
            return float("inf")
        if p == 0.5:
            return 0.0

        # Simple approximation
        if p < 0.5:
            return -self._normal_ppf(1 - p)

        # Rational approximation
        t = math.sqrt(-2 * math.log(1 - p))
        return t - (2.30753 + 0.27061 * t) / (1 + 0.99229 * t + 0.04481 * t * t)

    def _t_cdf(self, x: float, df: float) -> float:
        """Cumulative distribution function for t-distribution.

        Args:
            x: Input value
            df: Degrees of freedom

        Returns:
            CDF value
        """
        # Approximation - in practice would use scipy.stats.t.cdf
        if df > 30:
            return self._normal_cdf(x)  # Normal approximation for large df

        # Simple approximation for small df
        return 0.5 + x / (4 * df) * (1 + x * x / df)  # Very rough approximation
