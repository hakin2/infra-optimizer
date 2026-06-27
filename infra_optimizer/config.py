"""Application configuration."""

from dataclasses import dataclass, field


@dataclass
class AppConfig:
    """Central configuration for the infra optimizer."""

    # AWS
    default_region: str = "us-east-1"
    bedrock_model_id: str = "us.meta.llama3-3-70b-instruct-v1:0"

    # ECS
    ecs_cluster: str = "infra-optimizer"
    task_definition: str = "infra-optimizer-analyzer"

    # DynamoDB
    results_table: str = "infra-optimizer-results"

    # Analysis
    cost_lookback_days: int = 30
    max_agent_iterations: int = 10

    # Multi-account targets
    target_accounts: list[dict] = field(default_factory=list)
