"""LangChain agent setup with Bedrock."""

import json
import logging

from langchain_aws import ChatBedrockConverse
from langgraph.prebuilt import create_react_agent

from .prompts import ANALYSIS_PROMPT, SYSTEM_PROMPT
from .tools import (
    check_security_group_rules,
    get_iam_policy_analysis,
    get_pricing_info,
    get_resource_utilization,
)

logger = logging.getLogger(__name__)


class InfraOptimizationAgent:
    """Orchestrates infrastructure analysis using LangGraph + Bedrock."""

    def __init__(
        self,
        model_id: str = "us.meta.llama3-3-70b-instruct-v1:0",
        region: str = "us-east-1",
        max_iterations: int = 10,
    ):
        self.llm = ChatBedrockConverse(
            model_id=model_id,
            region_name=region,
            temperature=0,
            max_tokens=4096,
        )
        self.tools = [
            get_resource_utilization,
            get_pricing_info,
            check_security_group_rules,
            get_iam_policy_analysis,
        ]
        self.max_iterations = max_iterations
        self.agent = create_react_agent(
            self.llm,
            self.tools,
            prompt=SYSTEM_PROMPT,
        )

    async def analyze(self, collected_data: dict) -> list[dict]:
        """Run the agent against collected infrastructure data.

        Args:
            collected_data: Dict with keys 'templates', 'resources',
                            'costs', 'compliance'.

        Returns:
            List of recommendation dicts.
        """
        input_text = ANALYSIS_PROMPT.format(
            template_body=_truncate(collected_data.get("templates", "N/A")),
            resource_inventory=_truncate(collected_data.get("resources", "N/A")),
            cost_data=_truncate(collected_data.get("costs", "N/A")),
            compliance_data=_truncate(collected_data.get("compliance", "N/A")),
        )

        logger.info("Starting agent analysis (%d chars input)", len(input_text))
        result = await self.agent.ainvoke(
            {"messages": [{"role": "user", "content": input_text}]},
            config={"recursion_limit": self.max_iterations},
        )

        # Extract the final AI message content
        messages = result.get("messages", [])
        output = messages[-1].content if messages else "[]"

        recommendations = self._parse_recommendations(output)

        logger.info("Agent produced %d recommendations", len(recommendations))
        return recommendations

    @staticmethod
    def _parse_recommendations(output: str) -> list[dict]:
        """Extract JSON recommendations from agent output."""
        # Try direct JSON parse
        try:
            parsed = json.loads(output)
            if isinstance(parsed, list):
                return parsed
            return [parsed]
        except json.JSONDecodeError:
            pass

        # Try extracting JSON from markdown code block
        if "```" in output:
            start = output.find("```")
            end = output.find("```", start + 3)
            if end > start:
                block = output[start + 3 : end].strip()
                if block.startswith("json"):
                    block = block[4:].strip()
                try:
                    parsed = json.loads(block)
                    return parsed if isinstance(parsed, list) else [parsed]
                except json.JSONDecodeError:
                    pass

        logger.warning("Could not parse agent output as JSON, returning raw")
        return [{"raw_output": output}]


def _truncate(text: str, max_chars: int = 50_000) -> str:
    """Truncate large payloads to stay within model context limits."""
    if isinstance(text, dict | list):
        text = json.dumps(text, default=str)
    text = str(text)
    if len(text) > max_chars:
        return text[:max_chars] + "\n... [truncated]"
    return text
