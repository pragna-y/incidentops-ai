"""
Metric Correlator — maps incident scenarios to simulated infrastructure metrics.

In production, this layer would issue queries to Prometheus, Google Cloud
Monitoring, or Datadog. For this portfolio project, metrics are pre-configured
per scenario so the pipeline works fully offline.

Design: The correlator returns a MetricsSnapshot populated with values that
are consistent with the anomalies visible in each sample log file.
"""

from __future__ import annotations

from src.core.state import MetricsSnapshot

# ---------------------------------------------------------------------------
# Pre-configured metrics per scenario
# Values chosen to be consistent with the sample log files.
# ---------------------------------------------------------------------------

_SCENARIO_METRICS: dict[str, MetricsSnapshot] = {
    "db_pool_exhaustion": MetricsSnapshot(
        cpu_percent=44.0,
        memory_percent=61.0,
        db_pool_utilization_percent=100.0,   # Pool completely exhausted
        error_rate_per_minute=23.0,
        active_connections=50,               # At the hard limit
        raw_data={
            "pool_name": "ProductionPool",
            "pool_max": 50,
            "pool_active": 50,
            "pool_pending": 8,
            "avg_query_ms": 4200,
            "p99_latency_ms": 12800,
        },
    ),
    "cpu_spike": MetricsSnapshot(
        cpu_percent=97.0,                    # Near saturation
        memory_percent=71.0,
        db_pool_utilization_percent=None,
        error_rate_per_minute=89.0,
        active_connections=None,
        raw_data={
            "thread_pool_active": 200,
            "thread_pool_max": 200,
            "load_average_1m": 15.8,
            "load_average_5m": 12.4,
            "context_switches_per_sec": 48000,
        },
    ),
    "memory_leak": MetricsSnapshot(
        cpu_percent=34.0,
        memory_percent=92.0,                 # Critically high
        db_pool_utilization_percent=None,
        error_rate_per_minute=11.0,
        heap_used_gb=3.7,                    # 3.7 of 4.0 GB limit
        raw_data={
            "heap_max_gb": 4.0,
            "heap_used_gb": 3.7,
            "heap_percent": 92.5,
            "gc_pause_ms_p99": 2400,
            "gc_collections_per_min": 18,
            "container_memory_limit_gb": 5.0,
        },
    ),
}

# Normalise scenario key variations to canonical names
_ALIASES: dict[str, str] = {
    # Human-readable scenario labels produced by CLI _detect_scenario()
    "db connection pool exhaustion": "db_pool_exhaustion",
    "db_connection_pool_exhaustion": "db_pool_exhaustion",
    "db pool exhaustion": "db_pool_exhaustion",
    # CPU spike variants
    "cpu spike": "cpu_spike",
    "cpu spike — thread exhaustion": "cpu_spike",
    "cpu spike thread exhaustion": "cpu_spike",
    "cpu_spike_thread_exhaustion": "cpu_spike",
    # Memory leak variants
    "memory leak": "memory_leak",
    "memory leak — jvm heap oom": "memory_leak",
    "memory leak jvm heap oom": "memory_leak",
    "memory_leak_jvm_heap_oom": "memory_leak",
}


class MetricCorrelator:
    """
    Correlates an incident scenario with its infrastructure metrics.

    Extends the pre-configured snapshot with any additional signals
    extracted from the parsed log anomalies.
    """

    def correlate(self, scenario: str, anomalies: list[str]) -> MetricsSnapshot:
        """
        Return a MetricsSnapshot for the given scenario.

        Args:
            scenario: Human-readable or slug-style scenario name.
            anomalies: List of anomaly descriptions from LogParser.

        Returns:
            A populated MetricsSnapshot. Falls back to an empty snapshot
            if the scenario is not recognised.
        """
        key = self._normalise(scenario)
        snapshot = _SCENARIO_METRICS.get(key)

        if snapshot is None:
            # Unknown scenario — return empty snapshot (won't block pipeline)
            return MetricsSnapshot(
                raw_data={"scenario": scenario, "status": "unknown — no metric mapping"}
            )

        # Enrich raw_data with anomaly count for downstream agents
        enriched = dict(snapshot.raw_data)
        enriched["anomaly_count"] = len(anomalies)
        enriched["scenario_key"] = key

        return snapshot.model_copy(update={"raw_data": enriched})

    @staticmethod
    def _normalise(scenario: str) -> str:
        """Convert scenario string to canonical snake_case key."""
        lower = scenario.lower().strip()
        # Try direct alias lookup first
        if lower in _ALIASES:
            return _ALIASES[lower]
        # Try slug form
        slug = lower.replace(" ", "_").replace("-", "_").replace("—", "_")
        if slug in _ALIASES:
            return _ALIASES[slug]
        # Return slug as-is (may or may not match a key)
        return slug
