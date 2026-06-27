"""Distributed processing — multi-account orchestration via ECS."""

from .aggregator import ResultsAggregator
from .orchestrator import AccountTarget, MultiAccountOrchestrator

__all__ = ["AccountTarget", "MultiAccountOrchestrator", "ResultsAggregator"]
