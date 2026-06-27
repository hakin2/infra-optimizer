"""Entry point for ECS Fargate task — runs inside the container."""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone

import boto3

from ..agent.core import InfraOptimizationAgent
from ..collectors import (
    CloudFormationCollector,
    ConfigServiceCollector,
    CostExplorerCollector,
    ResourceInventoryCollector,
)
from ..engine.analyzer import PatternAnalyzer

logger = logging.getLogger(__name__)


def assume_role(role_arn: str, region: str) -> boto3.Session:
    """Assume a cross-account role and return a session."""
    sts = boto3.client("sts")
    creds = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="infra-optimizer-analysis",
        DurationSeconds=3600,
    )["Credentials"]

    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


def store_results(
    job_id: str, account_id: str, region: str, recommendations: list[dict]
) -> None:
    """Store analysis results in DynamoDB."""
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(os.environ["RESULTS_TABLE"])
    table.put_item(
        Item={
            "job_id": job_id,
            "account_region": f"{account_id}#{region}",
            "status": "COMPLETE",
            "recommendations": json.dumps(recommendations, default=str),
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
    )


async def run_analysis() -> None:
    """Main analysis workflow for a single account/region."""
    job_id = os.environ["JOB_ID"]
    account_id = os.environ["TARGET_ACCOUNT"]
    role_arn = os.environ["TARGET_ROLE_ARN"]
    region = os.environ["TARGET_REGION"]

    logger.info("Starting analysis for %s/%s (job %s)", account_id, region, job_id)

    # 1. Assume cross-account role
    session = assume_role(role_arn, region)

    # 2. Collect data from all sources
    collectors = [
        CloudFormationCollector(session),
        CostExplorerCollector(session),
        ConfigServiceCollector(session),
        ResourceInventoryCollector(session),
    ]

    all_collected = []
    collected_by_source: dict[str, str] = {}

    for collector in collectors:
        try:
            data = await collector.collect()
            all_collected.extend(data)
            collected_by_source[collector.source] = json.dumps(
                [d.data for d in data], default=str
            )
        except Exception:
            logger.exception("Collector %s failed", collector.source)

    # 3. Run deterministic pattern analysis
    pattern_analyzer = PatternAnalyzer()
    pattern_recs = pattern_analyzer.analyze(all_collected)

    # 4. Run AI agent analysis
    agent = InfraOptimizationAgent()
    ai_recs = await agent.analyze({
        "templates": collected_by_source.get("cloudformation", "N/A"),
        "resources": collected_by_source.get("resource_inventory", "N/A"),
        "costs": collected_by_source.get("cost_explorer", "N/A"),
        "compliance": collected_by_source.get("config_service", "N/A"),
    })

    # 5. Merge and store results
    all_recs = [r.model_dump() for r in pattern_recs] + ai_recs
    store_results(job_id, account_id, region, all_recs)

    logger.info(
        "Analysis complete for %s/%s: %d recommendations", account_id, region, len(all_recs)
    )


def main() -> None:
    """Container entry point."""
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_analysis())


if __name__ == "__main__":
    main()
