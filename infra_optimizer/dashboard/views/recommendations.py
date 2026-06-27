"""All recommendations page with filtering and export."""

import csv
import io
import json
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from infra_optimizer.dashboard.components.filters import load_report


def render() -> None:
    """Render the full recommendations page."""
    report = load_report()
    if not report:
        st.warning("No report data available.")
        return

    st.title("📋 All Recommendations")

    recs = report.recommendations
    if not recs:
        st.info("No recommendations available.")
        return

    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        cat_filter = st.multiselect(
            "Category",
            ["cost", "security", "performance"],
            default=["cost", "security", "performance"],
        )
    with col2:
        sev_filter = st.multiselect(
            "Severity",
            ["critical", "high", "medium", "low"],
            default=["critical", "high", "medium", "low"],
        )
    with col3:
        effort_filter = st.multiselect(
            "Effort", ["low", "medium", "high"], default=["low", "medium", "high"]
        )

    filtered = [
        r
        for r in recs
        if r.category.value in cat_filter
        and r.severity.value in sev_filter
        and r.effort in effort_filter
    ]

    st.caption(f"Showing {len(filtered)} of {len(recs)} recommendations")

    # Table view
    if filtered:
        rows = [
            {
                "Severity": r.severity.value.upper(),
                "Category": r.category.value,
                "Title": r.title,
                "Impact": r.estimated_impact,
                "Effort": r.effort,
                "Confidence": f"{r.confidence:.0%}",
                "Resources": ", ".join(r.affected_resources[:3]),
            }
            for r in filtered
        ]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    # Export section
    st.divider()
    st.subheader("📥 Export Report")

    col_json, col_csv = st.columns(2)

    with col_json:
        export_data = {
            "report": {
                "account_id": report.account_id,
                "region": report.region,
                "analyzed_at": report.analyzed_at,
                "monthly_cost": report.monthly_cost,
                "summary": report.summary.model_dump(),
            },
            "recommendations": [r.model_dump() for r in filtered],
        }
        st.download_button(
            "⬇️ Download JSON",
            data=json.dumps(export_data, indent=2, default=str),
            file_name=f"infra-optimizer-report-{datetime.now(timezone.utc).strftime('%Y%m%d')}.json",
            mime="application/json",
            use_container_width=True,
        )

    with col_csv:
        csv_buffer = io.StringIO()
        writer = csv.writer(csv_buffer)
        writer.writerow([
            "Severity", "Category", "Title", "Description",
            "Current State", "Recommended Action", "Impact",
            "Effort", "Confidence", "Affected Resources",
        ])
        for r in filtered:
            writer.writerow([
                r.severity.value.upper(),
                r.category.value,
                r.title,
                r.description,
                r.current_state,
                r.recommended_action,
                r.estimated_impact,
                r.effort,
                f"{r.confidence:.0%}",
                "; ".join(r.affected_resources),
            ])
        st.download_button(
            "⬇️ Download CSV",
            data=csv_buffer.getvalue(),
            file_name=f"infra-optimizer-report-{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv",
            mime="text/csv",
            use_container_width=True,
        )
