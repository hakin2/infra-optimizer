"""Shared filter and data loading utilities for the dashboard."""

import streamlit as st

from infra_optimizer.engine.recommendations import AnalysisReport


def load_report() -> AnalysisReport | None:
    """Load the analysis report from session state."""
    return st.session_state.get("report")
