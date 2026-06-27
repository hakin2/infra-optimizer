"""AWS Config service data collector."""

import logging

from .base import BaseCollector, CollectedData

logger = logging.getLogger(__name__)

# Resource types to inventory
RESOURCE_TYPES = [
    "AWS::EC2::Instance",
    "AWS::EC2::SecurityGroup",
    "AWS::S3::Bucket",
    "AWS::RDS::DBInstance",
    "AWS::Lambda::Function",
    "AWS::IAM::Role",
    "AWS::ECS::Service",
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
]


class ConfigServiceCollector(BaseCollector):
    """Queries AWS Config for compliance status and resource configurations."""

    source = "config_service"

    async def collect(self, **kwargs) -> list[CollectedData]:
        config = self.session.client("config")
        account_id = self._get_account_id()
        region = self.session.region_name

        results: list[CollectedData] = []

        # Compliance summary
        try:
            compliance_resp = config.get_compliance_summary_by_config_rule()
            results.append(
                CollectedData(
                    source=self.source,
                    account_id=account_id,
                    region=region,
                    resource_type="compliance_summary",
                    data={
                        "compliance_summary": compliance_resp.get(
                            "ComplianceSummary", {}
                        )
                    },
                )
            )
        except Exception:
            logger.debug("Config rules not available in %s/%s", account_id, region)

        # Non-compliant resources per rule
        try:
            rules_resp = config.describe_config_rules()
            for rule in rules_resp.get("ConfigRules", []):
                rule_name = rule["ConfigRuleName"]
                try:
                    details = config.get_compliance_details_by_config_rule(
                        ConfigRuleName=rule_name,
                        ComplianceTypes=["NON_COMPLIANT"],
                        Limit=50,
                    )
                    non_compliant = details.get("EvaluationResults", [])
                    if non_compliant:
                        results.append(
                            CollectedData(
                                source=self.source,
                                account_id=account_id,
                                region=region,
                                resource_type="non_compliant_rule",
                                data={
                                    "rule_name": rule_name,
                                    "rule_description": rule.get("Description", ""),
                                    "non_compliant_count": len(non_compliant),
                                    "resources": [
                                        {
                                            "resource_type": e["EvaluationResultIdentifier"][
                                                "EvaluationResultQualifier"
                                            ]["ResourceType"],
                                            "resource_id": e["EvaluationResultIdentifier"][
                                                "EvaluationResultQualifier"
                                            ]["ResourceId"],
                                        }
                                        for e in non_compliant
                                    ],
                                },
                            )
                        )
                except Exception:
                    logger.debug("Failed compliance check for rule %s", rule_name)
        except Exception:
            logger.debug("Could not list config rules in %s/%s", account_id, region)

        logger.info(
            "Collected %d config items from %s/%s", len(results), account_id, region
        )
        return results
