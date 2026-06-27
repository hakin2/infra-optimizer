"""Reusable chart components."""

import pandas as pd
import streamlit as st

from infra_optimizer.engine.recommendations import AnalysisReport


def severity_bar_chart(report: AnalysisReport) -> None:
    """Render a severity distribution bar chart."""
    data = pd.DataFrame(
        {
            "Severity": ["Critical", "High", "Medium", "Low"],
            "Count": [
                report.summary.critical_count,
                report.summary.high_count,
                report.summary.medium_count,
                report.summary.low_count,
            ],
        }
    )
    st.bar_chart(data.set_index("Severity"))
