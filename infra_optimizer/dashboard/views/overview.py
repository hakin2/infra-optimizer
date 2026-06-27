"""Overview dashboard page."""

import pandas as pd
import streamlit as st

from infra_optimizer.dashboard.components.charts import severity_bar_chart
from infra_optimizer.dashboard.components.filters import load_report


def render() -> None:
    """Render the overview page."""
    report = load_report()
    if not report:
        st.warning("No report data available.")
        return

    st.title("📊 Overview")

    # KPI row
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Monthly Spend", f"${report.monthly_cost:,.0f}")
    col2.metric(
        "Potential Savings",
        f"${report.summary.total_savings:,.0f}",
        delta=f"-{report.summary.savings_pct:.0f}%" if report.summary.savings_pct else None,
    )
    col3.metric(
        "Security Findings",
        report.summary.security_count,
        delta=f"{report.summary.critical_count} critical",
        delta_color="inverse",
    )
    col4.metric("Total Recommendations", report.summary.total_recommendations)

    st.divider()

    # Severity distribution
    col_left, col_right = st.columns(2)

    with col_left:
        st.subheader("By Severity")
        severity_bar_chart(report)

    with col_right:
        st.subheader("By Category")
        cat_data = pd.DataFrame(
            {
                "Category": ["Cost", "Security", "Performance"],
                "Count": [
                    report.summary.cost_count,
                    report.summary.security_count,
                    report.summary.performance_count,
                ],
            }
        )
        st.bar_chart(cat_data.set_index("Category"))

    # Top recommendations table
    st.divider()
    st.subheader("Top Recommendations")
    if report.recommendations:
        rows = [
            {
                "Severity": r.severity.value.upper(),
                "Category": r.category.value,
                "Title": r.title,
                "Impact": r.estimated_impact,
                "Effort": r.effort,
            }
            for r in report.recommendations[:10]
        ]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.info("No recommendations found.")
