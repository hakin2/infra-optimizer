"""Results aggregation from distributed ECS tasks."""

import json
import logging
import re
from datetime import datetime, timezone

import boto3

from ..engine.recommendations import (
    AnalysisReport,
    Category,
    Recommendation,
    ReportSummary,
    Severity,
)
from ..engine.scorer import RecommendationScorer

logger = logging.getLogger(__name__)


class ResultsAggregator:
    """Merges results from all ECS tasks into a unified report."""

    def __init__(self, table_name: str):
        self.dynamodb = boto3.resource("dynamodb")
        self.table = self.dynamodb.Table(table_name)
        self.scorer = RecommendationScorer()

    def aggregate(self, job_id: str) -> AnalysisReport:
        """Fetch all task results and build a unified report."""
        items = self._fetch_all_results(job_id)

        all_recs: list[Recommendation] = []
        for item in items:
            raw_recs = json.loads(item.get("recommendations", "[]"))
            for raw in raw_recs:
                try:
                    all_recs.append(Recommendation(**raw))
                except Exception:
                    logger.debug("Skipping unparseable recommendation: %s", raw)

        # Deduplicate and rank
        deduped = self._deduplicate(all_recs)
        ranked = self.scorer.rank(deduped)

        summary = self._build_summary(ranked)

        return AnalysisReport(
            account_id="aggregated",
            region="all",
            analyzed_at=datetime.now(timezone.utc).isoformat(),
            recommendations=ranked,
            summary=summary,
        )

    def _fetch_all_results(self, job_id: str) -> list[dict]:
        """Query all results for a job, excluding the META record."""
        response = self.table.query(
            KeyConditionExpression="job_id = :jid",
            ExpressionAttributeValues={":jid": job_id},
        )
        return [
            item
            for item in response.get("Items", [])
            if item.get("account_region") != "META"
        ]

    @staticmethod
    def _deduplicate(recs: list[Recommendation]) -> list[Recommendation]:
        """Remove duplicate recommendations based on title + affected resources."""
        seen: set[str] = set()
        unique: list[Recommendation] = []
        for rec in recs:
            key = f"{rec.title}|{'|'.join(sorted(rec.affected_resources))}"
            if key not in seen:
                seen.add(key)
                unique.append(rec)
        return unique

    @staticmethod
    def _build_summary(recs: list[Recommendation]) -> ReportSummary:
        """Build aggregate summary from recommendations."""
        total_savings = 0.0
        for rec in recs:
            match = re.search(r"\$?([\d,]+(?:\.\d+)?)", rec.estimated_impact)
            if match:
                total_savings += float(match.group(1).replace(",", ""))

        return ReportSummary(
            total_recommendations=len(recs),
            critical_count=sum(1 for r in recs if r.severity == Severity.CRITICAL),
            high_count=sum(1 for r in recs if r.severity == Severity.HIGH),
            medium_count=sum(1 for r in recs if r.severity == Severity.MEDIUM),
            low_count=sum(1 for r in recs if r.severity == Severity.LOW),
            cost_count=sum(1 for r in recs if r.category == Category.COST),
            security_count=sum(1 for r in recs if r.category == Category.SECURITY),
            performance_count=sum(1 for r in recs if r.category == Category.PERFORMANCE),
            total_savings=total_savings,
        )
