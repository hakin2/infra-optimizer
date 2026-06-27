"""CloudFormation stack scanner."""

import json
import logging

from .base import BaseCollector, CollectedData

logger = logging.getLogger(__name__)


class CloudFormationCollector(BaseCollector):
    """Scans CFN stacks: templates, resources, drift status, and events."""

    source = "cloudformation"

    async def collect(self, stack_filter: str | None = None) -> list[CollectedData]:
        cfn = self.session.client("cloudformation")
        account_id = self._get_account_id()
        region = self.session.region_name

        paginator = cfn.get_paginator("list_stacks")
        pages = paginator.paginate(
            StackStatusFilter=["CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"]
        )

        results: list[CollectedData] = []
        for page in pages:
            for stack_summary in page["StackSummaries"]:
                stack_name = stack_summary["StackName"]

                if stack_filter and stack_filter not in stack_name:
                    continue

                try:
                    template_resp = cfn.get_template(
                        StackName=stack_name, TemplateStage="Original"
                    )
                    template_body = template_resp["TemplateBody"]
                    if isinstance(template_body, dict):
                        template_body = json.dumps(template_body)

                    resources_resp = cfn.list_stack_resources(StackName=stack_name)
                    resources = resources_resp["StackResourceSummaries"]

                    # Attempt drift detection (may already be in progress)
                    drift_status = "UNKNOWN"
                    try:
                        drift_resp = cfn.describe_stack_drift_detection_status(
                            StackDriftDetectionId=cfn.detect_stack_drift(
                                StackName=stack_name
                            )["StackDriftDetectionId"]
                        )
                        drift_status = drift_resp.get("StackDriftStatus", "UNKNOWN")
                    except Exception:
                        logger.debug("Drift detection unavailable for %s", stack_name)

                    results.append(
                        CollectedData(
                            source=self.source,
                            account_id=account_id,
                            region=region,
                            resource_type="stack",
                            data={
                                "stack_name": stack_name,
                                "template_body": template_body,
                                "resources": [
                                    {
                                        "logical_id": r["LogicalResourceId"],
                                        "physical_id": r.get("PhysicalResourceId"),
                                        "type": r["ResourceType"],
                                        "status": r["ResourceStatus"],
                                    }
                                    for r in resources
                                ],
                                "drift_status": drift_status,
                                "last_updated": str(
                                    stack_summary.get("LastUpdatedTime", "N/A")
                                ),
                            },
                        )
                    )
                except Exception:
                    logger.exception("Failed to collect stack %s", stack_name)

        logger.info("Collected %d stacks from %s/%s", len(results), account_id, region)
        return results
