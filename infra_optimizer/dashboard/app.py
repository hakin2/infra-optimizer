"""Streamlit dashboard entry point."""

import sys
from pathlib import Path

# Ensure the project root is on sys.path so absolute imports work
# when Streamlit runs this file as a standalone script.
_project_root = str(Path(__file__).resolve().parents[2])
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import asyncio
import json
import logging
import re
from datetime import datetime, timezone

import boto3
import streamlit as st

st.set_page_config(
    page_title="Infra Optimizer",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "Get Help": None,
        "Report a bug": None,
        "About": "Infra Optimizer — AI-Powered Infrastructure Analysis",
    },
)

# Hide Streamlit's deploy button and footer
st.markdown(
    """
    <style>
    [data-testid="stAppDeployButton"] { display: none; }
    footer { display: none; }
    #MainMenu { visibility: hidden; }
    </style>
    """,
    unsafe_allow_html=True,
)

from infra_optimizer.collectors import (  # noqa: E402
    CloudFormationCollector,
    ConfigServiceCollector,
    CostExplorerCollector,
    ResourceInventoryCollector,
)
from infra_optimizer.dashboard.views import cost_analysis, overview, recommendations, security_findings  # noqa: E402
from infra_optimizer.engine.analyzer import PatternAnalyzer  # noqa: E402
from infra_optimizer.engine.recommendations import (  # noqa: E402
    AnalysisReport,
    Category,
    ReportSummary,
    Severity,
)
from infra_optimizer.engine.scorer import RecommendationScorer  # noqa: E402

logger = logging.getLogger(__name__)


# --- Analysis runner ---
def run_analysis(regions: list[str], use_agent: bool = False) -> AnalysisReport:
    """Run collectors and pattern analysis against the current AWS credentials."""
    session = boto3.Session(region_name=regions[0])
    account_id = session.client("sts").get_caller_identity()["Account"]

    all_collected = []
    collected_by_source: dict[str, list] = {}
    total_steps = len(regions) * 4 + 2  # 4 collectors per region + analysis + agent
    current_step = 0
    progress = st.progress(0, text="Starting analysis...")

    for region in regions:
        region_session = boto3.Session(region_name=region)
        collectors = [
            ("CloudFormation", CloudFormationCollector(region_session)),
            ("Cost Explorer", CostExplorerCollector(region_session)),
            ("AWS Config", ConfigServiceCollector(region_session)),
            ("Resource Inventory", ResourceInventoryCollector(region_session)),
        ]

        for name, collector in collectors:
            current_step += 1
            progress.progress(
                current_step / total_steps,
                text=f"Scanning {name} in {region}...",
            )
            try:
                data = asyncio.run(collector.collect())
                all_collected.extend(data)
                source = collector.source
                if source not in collected_by_source:
                    collected_by_source[source] = []
                collected_by_source[source].extend([d.data for d in data])
            except Exception as e:
                logger.warning("Collector %s/%s failed: %s", name, region, e)

    # Pattern analysis
    current_step += 1
    progress.progress(current_step / total_steps, text="Analyzing patterns...")
    analyzer = PatternAnalyzer()
    pattern_recs = analyzer.analyze(all_collected)

    # AI agent (optional)
    ai_recs = []
    if use_agent:
        current_step += 1
        progress.progress(current_step / total_steps, text="Running AI analysis...")
        try:
            from infra_optimizer.agent.core import InfraOptimizationAgent

            agent = InfraOptimizationAgent()
            ai_recs_raw = asyncio.run(agent.analyze({
                "templates": json.dumps(collected_by_source.get("cloudformation", []), default=str),
                "resources": json.dumps(collected_by_source.get("resource_inventory", []), default=str),
                "costs": json.dumps(collected_by_source.get("cost_explorer", []), default=str),
                "compliance": json.dumps(collected_by_source.get("config_service", []), default=str),
            }))
            from infra_optimizer.engine.recommendations import Recommendation

            for raw in ai_recs_raw:
                try:
                    ai_recs.append(Recommendation(**raw))
                except Exception:
                    pass
        except Exception as e:
            logger.warning("AI agent failed: %s", e)

    # Combine and rank
    all_recs = pattern_recs + ai_recs
    scorer = RecommendationScorer()
    ranked = scorer.rank(all_recs)

    # Estimate monthly cost
    monthly_cost = 0.0
    for item in collected_by_source.get("cost_explorer", []):
        for time_result in item.get("results_by_time", []):
            for group in time_result.get("Groups", []):
                cost = group.get("Metrics", {}).get("UnblendedCost", {})
                try:
                    monthly_cost += float(cost.get("Amount", 0))
                except (ValueError, TypeError):
                    pass

    # Calculate savings
    total_savings = 0.0
    for rec in ranked:
        match = re.search(r"\$?([\d,]+(?:\.\d+)?)", rec.estimated_impact)
        if match:
            total_savings += float(match.group(1).replace(",", ""))

    progress.progress(1.0, text="Done!")

    return AnalysisReport(
        account_id=account_id,
        region=", ".join(regions),
        analyzed_at=datetime.now(timezone.utc).isoformat(),
        total_stacks=len(collected_by_source.get("cloudformation", [])),
        total_resources=sum(
            len(v) for k, v in collected_by_source.items() if k == "resource_inventory"
        ),
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


# --- Sidebar ---
with st.sidebar:
    st.image("https://img.icons8.com/color/96/amazon-web-services.png", width=48)
    st.title("Infra Optimizer")
    st.caption("AI-Powered Infrastructure Analysis")

    st.divider()

    page = st.radio(
        "Navigation",
        ["Overview", "Cost Analysis", "Security Findings", "Recommendations"],
        label_visibility="collapsed",
    )

    st.divider()

    # Analysis controls
    st.subheader("Run Analysis")
    regions = st.multiselect(
        "AWS Regions",
        [
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-west-2", "eu-central-1",
            "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
        ],
        default=["us-east-1"],
    )
    use_agent = st.checkbox("Enable AI Agent (Bedrock)", value=False)

    if st.button("🔍 Analyze My Account", use_container_width=True, type="primary"):
        if not regions:
            st.warning("Select at least one region")
        else:
            try:
                report = run_analysis(regions, use_agent=use_agent)
                st.session_state["report"] = report
                st.success(
                    f"✓ Found {report.summary.total_recommendations} recommendations"
                )
            except Exception as e:
                st.error(f"Analysis failed: {e}")

    st.divider()
    st.caption("Uses your local AWS credentials (~/.aws/credentials or env vars)")


# --- Main content ---
if "report" not in st.session_state:
    st.title("⚡ Infrastructure Optimization Agent")
    st.markdown(
        """
        Analyze your AWS infrastructure for **cost savings**, **security issues**,
        and **performance improvements**.

        ### Getting Started

        1. Configure your AWS credentials (`aws configure` or env vars)
        2. Click **🔍 Analyze My Account** in the sidebar
        3. Review recommendations across all tabs

        The tool scans CloudFormation stacks, Cost Explorer, AWS Config,
        and live resources (EC2, RDS, Lambda, S3) in your account.
        """
    )
    st.stop()

# Route to selected page
report = st.session_state["report"]

if page == "Overview":
    overview.render()
elif page == "Cost Analysis":
    cost_analysis.render()
elif page == "Security Findings":
    security_findings.render()
elif page == "Recommendations":
    recommendations.render()
