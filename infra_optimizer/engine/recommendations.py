"""Recommendation and report data models."""

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Category(str, Enum):
    COST = "cost"
    SECURITY = "security"
    PERFORMANCE = "performance"


class Recommendation(BaseModel):
    """A single optimization recommendation."""

    id: str
    category: Category
    severity: Severity
    title: str
    description: str
    current_state: str
    recommended_action: str
    estimated_impact: str
    affected_resources: list[str] = Field(default_factory=list)
    cfn_fix: str | None = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    effort: str = "medium"  # low | medium | high


class ReportSummary(BaseModel):
    """Aggregated summary of an analysis report."""

    total_recommendations: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    cost_count: int = 0
    security_count: int = 0
    performance_count: int = 0
    total_savings: float = 0.0
    savings_pct: float = 0.0


class AnalysisReport(BaseModel):
    """Full analysis report for an account/region."""

    account_id: str
    region: str
    analyzed_at: str
    total_stacks: int = 0
    total_resources: int = 0
    monthly_cost: float = 0.0
    recommendations: list[Recommendation] = Field(default_factory=list)
    summary: ReportSummary = Field(default_factory=ReportSummary)
