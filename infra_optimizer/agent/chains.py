"""Structured analysis chains for targeted analysis without full agent reasoning."""

import logging

from langchain_aws import ChatBedrock
from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.prompts import ChatPromptTemplate

from ..engine.recommendations import Category, Recommendation, Severity

logger = logging.getLogger(__name__)

COST_PROMPT = """\
Analyze the following cost data and return optimization recommendations.
Focus on: unused resources, rightsizing, RI/SP coverage, and storage optimization.

{format_instructions}

Cost Data:
{cost_data}

Resource Inventory:
{resource_inventory}
"""

SECURITY_PROMPT = """\
Analyze the following infrastructure for security issues.
Focus on: overly permissive IAM, public access, missing encryption, and compliance gaps.

{format_instructions}

Compliance Data:
{compliance_data}

Resource Inventory:
{resource_inventory}
"""


class AnalysisChain:
    """Structured chains for specific analysis types."""

    def __init__(
        self,
        model_id: str = "anthropic.claude-3-sonnet-20240229-v1:0",
        region: str = "us-east-1",
    ):
        self.llm = ChatBedrock(
            model_id=model_id,
            region_name=region,
            model_kwargs={"temperature": 0, "max_tokens": 4096},
        )
        self.rec_parser = PydanticOutputParser(pydantic_object=Recommendation)

        self.cost_prompt = ChatPromptTemplate.from_template(COST_PROMPT)
        self.security_prompt = ChatPromptTemplate.from_template(SECURITY_PROMPT)

    async def run_cost_analysis(self, data: dict) -> list[Recommendation]:
        """Run cost-focused analysis chain."""
        chain = self.cost_prompt | self.llm | self.rec_parser
        try:
            result = await chain.ainvoke({
                "cost_data": str(data.get("costs", "")),
                "resource_inventory": str(data.get("resources", "")),
                "format_instructions": self.rec_parser.get_format_instructions(),
            })
            return result if isinstance(result, list) else [result]
        except Exception:
            logger.exception("Cost analysis chain failed")
            return [
                Recommendation(
                    id="cost-chain-error",
                    category=Category.COST,
                    severity=Severity.LOW,
                    title="Cost analysis incomplete",
                    description="The cost analysis chain encountered an error.",
                    current_state="Unknown",
                    recommended_action="Re-run analysis or check input data.",
                    estimated_impact="Unknown",
                    affected_resources=[],
                    confidence=0.0,
                    effort="low",
                )
            ]

    async def run_security_analysis(self, data: dict) -> list[Recommendation]:
        """Run security-focused analysis chain."""
        chain = self.security_prompt | self.llm | self.rec_parser
        try:
            result = await chain.ainvoke({
                "compliance_data": str(data.get("compliance", "")),
                "resource_inventory": str(data.get("resources", "")),
                "format_instructions": self.rec_parser.get_format_instructions(),
            })
            return result if isinstance(result, list) else [result]
        except Exception:
            logger.exception("Security analysis chain failed")
            return [
                Recommendation(
                    id="sec-chain-error",
                    category=Category.SECURITY,
                    severity=Severity.LOW,
                    title="Security analysis incomplete",
                    description="The security analysis chain encountered an error.",
                    current_state="Unknown",
                    recommended_action="Re-run analysis or check input data.",
                    estimated_impact="Unknown",
                    affected_resources=[],
                    confidence=0.0,
                    effort="low",
                )
            ]
