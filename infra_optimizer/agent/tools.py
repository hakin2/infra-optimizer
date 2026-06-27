"""LangChain tools for the optimization agent — AWS lookups."""

from datetime import datetime, timedelta, timezone

import boto3
from langchain_core.tools import tool


@tool
def get_resource_utilization(
    resource_id: str, metric_name: str, namespace: str, period_days: int = 7
) -> dict:
    """Fetch CloudWatch metrics for a resource to assess utilization.

    Args:
        resource_id: The AWS resource ID (e.g. instance ID).
        metric_name: CloudWatch metric name (e.g. CPUUtilization).
        namespace: CloudWatch namespace (e.g. AWS/EC2).
        period_days: Number of days to look back.
    """
    cw = boto3.client("cloudwatch")
    now = datetime.now(timezone.utc)
    response = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=[{"Name": "InstanceId", "Value": resource_id}],
        StartTime=now - timedelta(days=period_days),
        EndTime=now,
        Period=3600,
        Statistics=["Average", "Maximum"],
    )
    datapoints = response.get("Datapoints", [])
    if not datapoints:
        return {"resource_id": resource_id, "metric": metric_name, "data": "no data"}

    avg_values = [d["Average"] for d in datapoints]
    max_values = [d["Maximum"] for d in datapoints]
    return {
        "resource_id": resource_id,
        "metric": metric_name,
        "avg": round(sum(avg_values) / len(avg_values), 2),
        "max": round(max(max_values), 2),
        "datapoint_count": len(datapoints),
    }


@tool
def get_pricing_info(service_code: str, instance_type: str, region: str) -> dict:
    """Look up current AWS pricing for a service/instance type.

    Args:
        service_code: AWS service code (e.g. AmazonEC2).
        instance_type: Instance type (e.g. m5.large).
        region: AWS region name.
    """
    pricing = boto3.client("pricing", region_name="us-east-1")
    response = pricing.get_products(
        ServiceCode=service_code,
        Filters=[
            {"Type": "TERM_MATCH", "Field": "instanceType", "Value": instance_type},
            {"Type": "TERM_MATCH", "Field": "location", "Value": _region_to_location(region)},
            {"Type": "TERM_MATCH", "Field": "operatingSystem", "Value": "Linux"},
            {"Type": "TERM_MATCH", "Field": "tenancy", "Value": "Shared"},
            {"Type": "TERM_MATCH", "Field": "preInstalledSw", "Value": "NA"},
        ],
        MaxResults=1,
    )
    price_list = response.get("PriceList", [])
    if not price_list:
        return {"error": f"No pricing found for {instance_type} in {region}"}

    import json

    product = json.loads(price_list[0])
    on_demand = product.get("terms", {}).get("OnDemand", {})
    for _, term in on_demand.items():
        for _, dim in term.get("priceDimensions", {}).items():
            return {
                "instance_type": instance_type,
                "region": region,
                "price_per_hour": dim["pricePerUnit"].get("USD", "N/A"),
                "unit": dim["unit"],
                "description": dim["description"],
            }
    return {"error": "Could not parse pricing"}


@tool
def check_security_group_rules(security_group_id: str) -> dict:
    """Inspect security group rules for overly permissive access.

    Args:
        security_group_id: The security group ID to analyze.
    """
    ec2 = boto3.client("ec2")
    response = ec2.describe_security_groups(GroupIds=[security_group_id])
    if not response["SecurityGroups"]:
        return {"error": f"Security group {security_group_id} not found"}

    sg = response["SecurityGroups"][0]
    findings = []

    for rule in sg.get("IpPermissions", []):
        for ip_range in rule.get("IpRanges", []):
            if ip_range.get("CidrIp") == "0.0.0.0/0":
                findings.append({
                    "direction": "ingress",
                    "protocol": rule.get("IpProtocol", "all"),
                    "from_port": rule.get("FromPort", "all"),
                    "to_port": rule.get("ToPort", "all"),
                    "issue": "Open to 0.0.0.0/0",
                })

    for rule in sg.get("IpPermissionsEgress", []):
        for ip_range in rule.get("IpRanges", []):
            if ip_range.get("CidrIp") == "0.0.0.0/0" and rule.get("IpProtocol") == "-1":
                findings.append({
                    "direction": "egress",
                    "protocol": "all",
                    "issue": "Unrestricted outbound",
                })

    return {
        "security_group_id": security_group_id,
        "group_name": sg.get("GroupName"),
        "vpc_id": sg.get("VpcId"),
        "findings": findings,
        "total_ingress_rules": len(sg.get("IpPermissions", [])),
        "total_egress_rules": len(sg.get("IpPermissionsEgress", [])),
    }


@tool
def get_iam_policy_analysis(role_name: str) -> dict:
    """Analyze IAM role policies for least-privilege violations.

    Args:
        role_name: The IAM role name to analyze.
    """
    iam = boto3.client("iam")

    # Attached managed policies
    attached = iam.list_attached_role_policies(RoleName=role_name)
    managed_policies = [p["PolicyName"] for p in attached.get("AttachedPolicies", [])]

    # Inline policies
    inline = iam.list_role_policies(RoleName=role_name)
    inline_policies = inline.get("PolicyNames", [])

    findings = []

    # Check for admin/full-access policies
    dangerous_patterns = ["AdministratorAccess", "FullAccess", "PowerUserAccess"]
    for policy_name in managed_policies:
        if any(p in policy_name for p in dangerous_patterns):
            findings.append({
                "policy": policy_name,
                "issue": "Overly broad managed policy attached",
                "severity": "high",
            })

    # Check inline policies for wildcard actions
    for policy_name in inline_policies:
        policy_doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
        for statement in policy_doc["PolicyDocument"].get("Statement", []):
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            resources = statement.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            if "*" in actions and "*" in resources:
                findings.append({
                    "policy": policy_name,
                    "issue": "Wildcard action on wildcard resource",
                    "severity": "critical",
                })

    return {
        "role_name": role_name,
        "managed_policies": managed_policies,
        "inline_policy_count": len(inline_policies),
        "findings": findings,
    }


# --- Helpers ---

_REGION_MAP = {
    "us-east-1": "US East (N. Virginia)",
    "us-west-2": "US West (Oregon)",
    "eu-west-1": "EU (Ireland)",
    "ap-southeast-1": "Asia Pacific (Singapore)",
}


def _region_to_location(region: str) -> str:
    return _REGION_MAP.get(region, region)
