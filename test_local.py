"""Local test script — runs collectors against the current AWS account.

Usage:
    source .venv/bin/activate
    python test_local.py              # collectors only
    python test_local.py --with-agent # collectors + AI agent analysis
"""

import asyncio
import json
import logging
import sys
from pathlib import Path

import boto3

from infra_optimizer.collectors import (
    CloudFormationCollector,
    ConfigServiceCollector,
    CostExplorerCollector,
    ResourceInventoryCollector,
)
from infra_optimizer.engine.analyzer import PatternAnalyzer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("test_local")


async def run_collectors(session: boto3.Session) -> dict:
    """Run all collectors and return results grouped by source."""
    collectors = [
        ("CloudFormation", CloudFormationCollector(session)),
        ("Cost Explorer", CostExplorerCollector(session)),
        ("Config Service", ConfigServiceCollector(session)),
        ("Resource Inventory", ResourceInventoryCollector(session)),
    ]

    all_collected = []
    collected_by_source: dict[str, list] = {}

    for name, collector in collectors:
        logger.info("Running collector: %s", name)
        try:
            data = await collector.collect()
            all_collected.extend(data)
            collected_by_source[collector.source] = [d.data for d in data]
            logger.info("  ✓ %s returned %d items", name, len(data))
        except Exception as e:
            logger.error("  ✗ %s failed: %s", name, e)
            collected_by_source[collector.source] = []

    return {
        "all_collected": all_collected,
        "by_source": collected_by_source,
    }


def run_pattern_analyzer(collected_data: list) -> list:
    """Run the deterministic pattern analyzer."""
    logger.info("Running pattern analyzer...")
    analyzer = PatternAnalyzer()
    recommendations = analyzer.analyze(collected_data)
    logger.info("Pattern analyzer produced %d recommendations", len(recommendations))
    return recommendations


async def run_agent(collected_by_source: dict) -> list:
    """Run the AI agent analysis (requires Bedrock access)."""
    from infra_optimizer.agent.core import InfraOptimizationAgent

    logger.info("Running AI agent analysis (Bedrock)...")
    agent = InfraOptimizationAgent()
    recommendations = await agent.analyze({
        "templates": json.dumps(collected_by_source.get("cloudformation", []), default=str),
        "resources": json.dumps(collected_by_source.get("resource_inventory", []), default=str),
        "costs": json.dumps(collected_by_source.get("cost_explorer", []), default=str),
        "compliance": json.dumps(collected_by_source.get("config_service", []), default=str),
    })
    logger.info("AI agent produced %d recommendations", len(recommendations))
    return recommendations


async def main():
    use_agent = "--with-agent" in sys.argv

    session = boto3.Session()
    account_id = session.client("sts").get_caller_identity()["Account"]
    region = session.region_name or "us-east-1"

    logger.info("=" * 60)
    logger.info("Infra Optimizer — Local Test Run")
    logger.info("Account: %s | Region: %s", account_id, region)
    logger.info("Agent enabled: %s", use_agent)
    logger.info("=" * 60)

    # 1. Run collectors
    results = await run_collectors(session)

    # 2. Run pattern analyzer
    pattern_recs = run_pattern_analyzer(results["all_collected"])

    # 3. Optionally run AI agent
    ai_recs = []
    if use_agent:
        ai_recs = await run_agent(results["by_source"])

    # 4. Print summary
    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)
    print(f"\nCollected data:")
    for source, items in results["by_source"].items():
        print(f"  {source}: {len(items)} items")

    print(f"\nPattern-based recommendations: {len(pattern_recs)}")
    for rec in pattern_recs[:10]:
        r = rec.model_dump() if hasattr(rec, "model_dump") else rec
        print(f"  [{r.get('severity', '?')}] {r.get('title', r.get('description', '?'))}")

    if ai_recs:
        print(f"\nAI agent recommendations: {len(ai_recs)}")
        for rec in ai_recs[:10]:
            title = rec.get("title", rec.get("description", rec.get("raw_output", "?")[:80]))
            print(f"  • {title}")

    print(f"\nTotal recommendations: {len(pattern_recs) + len(ai_recs)}")
    print("=" * 60)

    # 5. Save report for dashboard
    from infra_optimizer.engine.recommendations import AnalysisReport, ReportSummary
    from infra_optimizer.engine.scorer import RecommendationScorer
    import re

    all_recs_objs = pattern_recs  # already Recommendation objects
    all_recs_dicts = [r.model_dump() for r in pattern_recs] + ai_recs

    # Build summary
    scorer = RecommendationScorer()
    ranked = scorer.rank(pattern_recs)

    total_savings = 0.0
    for rec in ranked:
        match = re.search(r"\$?([\d,]+(?:\.\d+)?)", rec.estimated_impact)
        if match:
            total_savings += float(match.group(1).replace(",", ""))

    # Estimate monthly cost from cost explorer data
    monthly_cost = 0.0
    cost_data = results["by_source"].get("cost_explorer", [])
    for item in cost_data:
        for time_result in item.get("results_by_time", []):
            for group in time_result.get("Groups", []):
                for metric_key, metric_val in group.get("Metrics", {}).items():
                    try:
                        monthly_cost += float(metric_val.get("Amount", 0))
                    except (ValueError, TypeError):
                        pass

    from infra_optimizer.engine.recommendations import Category, Severity

    report = AnalysisReport(
        account_id=account_id,
        region=region,
        analyzed_at=__import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat(),
        total_stacks=len(results["by_source"].get("cloudformation", [])),
        total_resources=len(results["by_source"].get("resource_inventory", [])),
        monthly_cost=monthly_cost,
        recommendations=ranked,
        summary=ReportSummary(
            total_recommendations=len(ranked),
            critical_count=sum(1 for r in ranked if r.severity == Severity.CRITICAL),
            high_count=sum(1 for r in ranked if r.severity == Severity.HIGH),
            medium_count=sum(1 for r in ranked if r.severity == Severity.MEDIUM),
            low_count=sum(1 for r in ranked if r.severity == Severity.LOW),
            cost_count=sum(1 for r in ranked if r.category == Category.COST),
            security_count=sum(1 for r in ranked if r.category == Category.SECURITY),
            performance_count=sum(1 for r in ranked if r.category == Category.PERFORMANCE),
            total_savings=total_savings,
            savings_pct=(total_savings / monthly_cost * 100) if monthly_cost > 0 else 0,
        ),
    )

    report_path = Path(__file__).parent / "local_report.json"
    report_path.write_text(report.model_dump_json(indent=2))
    logger.info("Report saved to %s", report_path)
    print(f"\n📄 Report saved to: {report_path}")
    print("   Run the dashboard with: streamlit run infra_optimizer/dashboard/app.py")


if __name__ == "__main__":
    asyncio.run(main())
