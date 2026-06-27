"""Recommendation scoring and prioritization."""

import re

from .recommendations import Recommendation


class RecommendationScorer:
    """Scores and ranks recommendations by impact, effort, confidence, severity."""

    SEVERITY_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    EFFORT_WEIGHTS = {"low": 3, "medium": 2, "high": 1}

    def score(self, rec: Recommendation) -> float:
        """Compute a 0–100 priority score for a recommendation."""
        severity_score = self.SEVERITY_WEIGHTS.get(rec.severity.value, 1)
        effort_score = self.EFFORT_WEIGHTS.get(rec.effort, 2)
        impact_score = self._parse_impact(rec.estimated_impact)

        return (
            severity_score * 0.3
            + effort_score * 0.2
            + impact_score * 0.3
            + rec.confidence * 0.2
        ) * 100

    def rank(self, recs: list[Recommendation]) -> list[Recommendation]:
        """Sort recommendations by score descending."""
        return sorted(recs, key=lambda r: self.score(r), reverse=True)

    @staticmethod
    def _parse_impact(impact_str: str) -> float:
        """Extract a normalized 0–1 impact score from the estimated_impact string."""
        # Try to find a dollar amount
        match = re.search(r"\$?([\d,]+(?:\.\d+)?)", impact_str)
        if match:
            amount = float(match.group(1).replace(",", ""))
            # Normalize: $0 = 0, $1000+/month = 1.0
            return min(amount / 1000.0, 1.0)

        # Try percentage
        match = re.search(r"(\d+(?:\.\d+)?)\s*%", impact_str)
        if match:
            return min(float(match.group(1)) / 100.0, 1.0)

        return 0.3  # default moderate impact
