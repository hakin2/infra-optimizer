"""Cost Explorer data collector."""

import logging
from datetime import datetime, timedelta, timezone

from .base import BaseCollector, CollectedData

logger = logging.getLogger(__name__)


class CostExplorerCollector(BaseCollector):
    """Pulls cost/usage data, rightsizing recommendations, and RI utilization."""

    source = "cost_explorer"

    async def collect(self, lookback_days: int = 30) -> list[CollectedData]:
        ce = self.session.client("ce", region_name="us-east-1")
        account_id = self._get_account_id()

        end_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        start_date = (
            datetime.now(timezone.utc) - timedelta(days=lookback_days)
        ).strftime("%Y-%m-%d")

        results: list[CollectedData] = []

        # Cost by service
        try:
            cost_resp = ce.get_cost_and_usage(
                TimePeriod={"Start": start_date, "End": end_date},
                Granularity="DAILY",
                Metrics=["UnblendedCost", "UsageQuantity"],
                GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
            )
            results.append(
                CollectedData(
                    source=self.source,
                    account_id=account_id,
                    region="global",
                    resource_type="cost_by_service",
                    data={
                        "period": {"start": start_date, "end": end_date},
                        "results_by_time": cost_resp["ResultsByTime"],
                    },
                )
            )
        except Exception:
            logger.exception("Failed to fetch cost data")

        # Rightsizing recommendations
        try:
            rs_resp = ce.get_rightsizing_recommendation(
                Service="AmazonEC2",
                Configuration={
                    "RecommendationTarget": "SAME_INSTANCE_FAMILY",
                    "BenefitsConsidered": True,
                },
            )
            results.append(
                CollectedData(
                    source=self.source,
                    account_id=account_id,
                    region="global",
                    resource_type="rightsizing",
                    data={
                        "recommendations": rs_resp.get(
                            "RightsizingRecommendations", []
                        ),
                        "summary": rs_resp.get("Summary", {}),
                    },
                )
            )
        except Exception:
            logger.exception("Failed to fetch rightsizing recommendations")

        # Reservation utilization
        try:
            ri_resp = ce.get_reservation_utilization(
                TimePeriod={"Start": start_date, "End": end_date},
                Granularity="MONTHLY",
            )
            results.append(
                CollectedData(
                    source=self.source,
                    account_id=account_id,
                    region="global",
                    resource_type="ri_utilization",
                    data={
                        "utilizations_by_time": ri_resp.get("UtilizationsByTime", []),
                        "total": ri_resp.get("Total", {}),
                    },
                )
            )
        except Exception:
            logger.exception("Failed to fetch RI utilization")

        logger.info("Collected %d cost data items for %s", len(results), account_id)
        return results
