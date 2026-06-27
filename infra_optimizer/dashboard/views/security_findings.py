"""Security findings dashboard page."""

import streamlit as st

from infra_optimizer.engine.recommendations import Category, Severity
from infra_optimizer.dashboard.components.filters import load_report


def render() -> None:
    """Render the security findings page."""
    report = load_report()
    if not report:
        st.warning("No report data available.")
        return

    st.title("🔒 Security Findings")

    sec_recs = [r for r in report.recommendations if r.category == Category.SECURITY]

    # Summary
    critical = [r for r in sec_recs if r.severity == Severity.CRITICAL]
    high = [r for r in sec_recs if r.severity == Severity.HIGH]

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Security Findings", len(sec_recs))
    col2.metric("Critical", len(critical), delta_color="inverse")
    col3.metric("High", len(high), delta_color="inverse")

    st.divider()

    # Severity filter
    severity_filter = st.multiselect(
        "Filter by severity",
        ["critical", "high", "medium", "low"],
        default=["critical", "high"],
    )

    filtered = [r for r in sec_recs if r.severity.value in severity_filter]

    if not filtered:
        st.success("No security findings match the selected filters.")
        return

    for rec in filtered:
        severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
            rec.severity.value, "⚪"
        )
        with st.expander(f"{severity_icon} [{rec.severity.value.upper()}] {rec.title}"):
            st.write(rec.description)
            st.caption(f"Current state: {rec.current_state}")
            st.info(f"Recommendation: {rec.recommended_action}")

            if rec.cfn_fix:
                st.subheader("CloudFormation Fix")
                st.code(rec.cfn_fix, language="yaml")

            st.caption(f"Resources: {', '.join(rec.affected_resources)}")
