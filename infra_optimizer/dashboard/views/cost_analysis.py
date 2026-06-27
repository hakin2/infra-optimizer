"""Cost analysis dashboard page."""

import streamlit as st

from infra_optimizer.engine.recommendations import Category
from infra_optimizer.dashboard.components.filters import load_report


def render() -> None:
    """Render the cost analysis page."""
    report = load_report()
    if not report:
        st.warning("No report data available.")
        return

    st.title("💰 Cost Analysis")

    cost_recs = [r for r in report.recommendations if r.category == Category.COST]

    # Summary metrics
    col1, col2, col3 = st.columns(3)
    col1.metric("Cost Findings", len(cost_recs))
    col2.metric("Estimated Savings", f"${report.summary.total_savings:,.0f}/month")
    col3.metric("Monthly Spend", f"${report.monthly_cost:,.0f}")

    st.divider()

    if not cost_recs:
        st.success("No cost optimization issues found.")
        return

    # Expandable recommendation cards
    for rec in cost_recs:
        severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
            rec.severity.value, "⚪"
        )
        with st.expander(f"{severity_icon} {rec.title}"):
            st.write(rec.description)
            st.caption(f"Current state: {rec.current_state}")
            st.info(f"Recommendation: {rec.recommended_action}")
            st.caption(f"Estimated impact: {rec.estimated_impact} | Effort: {rec.effort}")

            if rec.cfn_fix:
                st.subheader("CloudFormation Fix")
                st.code(rec.cfn_fix, language="yaml")

            st.caption(f"Confidence: {rec.confidence:.0%} | Resources: {', '.join(rec.affected_resources)}")
