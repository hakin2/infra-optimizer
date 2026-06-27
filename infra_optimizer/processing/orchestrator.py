"""Multi-account orchestrator — launches ECS Fargate tasks."""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

import boto3

from ..config import AppConfig

logger = logging.getLogger(__name__)


@dataclass
class AccountTarget:
    """Represents an AWS account to analyze."""

    account_id: str
    cross_account_role_arn: str
    regions: list[str] = field(default_factory=lambda: ["us-east-1"])


class MultiAccountOrchestrator:
    """Coordinates parallel analysis across accounts/regions using ECS tasks."""

    def __init__(self, config: AppConfig):
        self.config = config
        self.ecs = boto3.client("ecs")
        self.dynamodb = boto3.resource("dynamodb")
        self.results_table = self.dynamodb.Table(config.results_table)

    def run(self, targets: list[AccountTarget]) -> str:
        """Launch parallel ECS tasks for each account/region combo.

        Returns:
            job_id for tracking.
        """
        job_id = str(uuid4())
        task_arns: list[str] = []

        for target in targets:
            for region in target.regions:
                try:
                    task_arn = self._launch_ecs_task(
                        job_id=job_id,
                        account_id=target.account_id,
                        role_arn=target.cross_account_role_arn,
                        region=region,
                    )
                    task_arns.append(task_arn)
                    logger.info(
                        "Launched task for %s/%s: %s",
                        target.account_id,
                        region,
                        task_arn,
                    )
                except Exception:
                    logger.exception(
                        "Failed to launch task for %s/%s",
                        target.account_id,
                        region,
                    )

        # Store job metadata
        self.results_table.put_item(
            Item={
                "job_id": job_id,
                "account_region": "META",
                "status": "RUNNING",
                "total_tasks": len(task_arns),
                "task_arns": task_arns,
                "started_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        logger.info("Job %s started with %d tasks", job_id, len(task_arns))
        return job_id

    def get_job_status(self, job_id: str) -> dict:
        """Check the status of a running job."""
        resp = self.results_table.get_item(
            Key={"job_id": job_id, "account_region": "META"}
        )
        return resp.get("Item", {"status": "NOT_FOUND"})

    def _launch_ecs_task(
        self, job_id: str, account_id: str, role_arn: str, region: str
    ) -> str:
        response = self.ecs.run_task(
            cluster=self.config.ecs_cluster,
            taskDefinition=self.config.task_definition,
            launchType="FARGATE",
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": ["subnet-placeholder"],
                    "securityGroups": ["sg-placeholder"],
                    "assignPublicIp": "DISABLED",
                }
            },
            overrides={
                "containerOverrides": [
                    {
                        "name": "analyzer",
                        "environment": [
                            {"name": "JOB_ID", "value": job_id},
                            {"name": "TARGET_ACCOUNT", "value": account_id},
                            {"name": "TARGET_ROLE_ARN", "value": role_arn},
                            {"name": "TARGET_REGION", "value": region},
                            {
                                "name": "RESULTS_TABLE",
                                "value": self.config.results_table,
                            },
                        ],
                    }
                ]
            },
        )
        return response["tasks"][0]["taskArn"]
