"""Rule-based pattern detection that runs before/alongside the AI agent."""

import logging
from uuid import uuid4

from ..collectors.base import CollectedData
from .recommendations import Category, Recommendation, Severity

logger = logging.getLogger(__name__)

# Old-generation EC2 instance families that should be upgraded
OLD_GEN_FAMILIES = {
    "t1", "t2", "m1", "m2", "m3", "m4",
    "c1", "c3", "c4", "r3", "r4",
    "i2", "d2", "g2", "p2",
}

# Deprecated Lambda runtimes (EOL or approaching)
DEPRECATED_RUNTIMES = {
    "python3.7", "python3.8", "python3.9", "python3.10",
    "nodejs12.x", "nodejs14.x", "nodejs16.x", "nodejs18.x",
    "java8", "java8.al2", "java11",
    "dotnet6", "dotnetcore3.1",
    "ruby2.7", "ruby3.2",
    "go1.x",
}


class PatternAnalyzer:
    """Detects common anti-patterns from collected data without AI.

    Checks 30+ patterns across cost, security, and performance categories.
    """

    def analyze(self, collected: list[CollectedData]) -> list[Recommendation]:
        recs: list[Recommendation] = []
        for item in collected:
            handler = self._handlers.get(item.resource_type)
            if handler:
                recs.extend(handler(item))
        return recs

    @property
    def _handlers(self) -> dict:
        return {
            "ec2_instance": self._check_ec2,
            "s3_bucket": self._check_s3,
            "rds_instance": self._check_rds,
            "non_compliant_rule": self._check_compliance,
            "lambda_function": self._check_lambda,
            "security_group": self._check_security_group,
            "ebs_volume": self._check_ebs,
            "elastic_ip": self._check_eip,
            "load_balancer": self._check_elb,
            "cloudwatch_metrics": self._check_utilization,
            "iam_role": self._check_iam,
            "stack": self._check_cfn_stack,
        }

    # --- EC2 Checks ---
    def _check_ec2(self, item: CollectedData) -> list[Recommendation]:
        recs = []
        data = item.data

        # Stopped instances
        if data.get("state") == "stopped":
            recs.append(
                Recommendation(
                    id=f"ec2-stopped-{uuid4().hex[:8]}",
                    category=Category.COST,
                    severity=Severity.MEDIUM,
                    title=f"Stopped EC2 instance: {data['instance_id']}",
                    description="Instance is stopped but still incurring EBS storage costs.",
                    current_state=f"{data['instance_id']} ({data['instance_type']}) is stopped",
                    recommended_action="Terminate if no longer needed, or create an AMI and terminate.",
                    estimated_impact="$10–50/month EBS savings",
                    affected_resources=[data["instance_id"]],
                    confidence=0.9,
                    effort="low",
                )
            )

        # Old-generation instance types
        instance_type = data.get("instance_type", "")
        family = instance_type.split(".")[0] if "." in instance_type else ""
        if family in OLD_GEN_FAMILIES:
            recs.append(
                Recommendation(
                    id=f"ec2-oldgen-{uuid4().hex[:8]}",
                    category=Category.COST,
                    severity=Severity.MEDIUM,
                    title=f"Old-generation instance type: {data['instance_id']}",
                    description=f"Instance uses {instance_type}, an older generation with worse price/performance.",
                    current_state=f"{data['instance_id']} running {instance_type}",
                    recommended_action=f"Migrate to current-gen equivalent (e.g., t3, m5, c5, r5).",
                    estimated_impact="10–40% cost reduction with better performance",
                    affected_resources=[data["instance_id"]],
                    confidence=0.85,
                    effort="medium",
                )
            )

        # Missing tags (Name tag)
        tags = data.get("tags", {})
        if not tags.get("Name") and data.get("state") == "running":
            recs.append(
                Recommendation(
                    id=f"ec2-notag-{uuid4().hex[:8]}",
                    category=Category.COST,
                    severity=Severity.LOW,
                    title=f"EC2 instance missing Name tag: {data['instance_id']}",
                    description="Instance has no Name tag, making cost allocation and ownership tracking difficult.",
                    current_state=f"{data['instance_id']} has no Name tag",
                    recommended_action="Add Name, Owner, Environment, and CostCenter tags.",
                    estimated_impact="Improved cost visibility and governance",
                    affected_resources=[data["instance_id"]],
                    confidence=0.95,
                    effort="low",
                )
            )

        return recs

    # --- S3 Checks ---
    def _check_s3(self, item: CollectedData) -> list[Recommendation]:
        recs = []
        data = item.data

        if data.get("encryption") == "NONE":
            recs.append(
                Recommendation(
                    id=f"s3-noenc-{uuid4().hex[:8]}",
                    category=Category.SECURITY,
                    severity=Severity.HIGH,
                    title=f"Unencrypted S3 bucket: {data['bucket_name']}",
                    description="Bucket has no default encryption configured.",
                    current_state=f"Bucket {data['bucket_name']} has no encryption",
                    recommended_action="Enable SSE-S3 or SSE-KMS default encryption.",
                    estimated_impact="Security compliance improvement",
                    affected_resources=[data["bucket_name"]],
                    cfn_fix=(
                        "BucketEncryption:\n"
                        "  ServerSideEncryptionConfiguration:\n"
                        "    - ServerSideEncryptionByDefault:\n"
                        "        SSEAlgorithm: aws:kms"
                    ),
                    confidence=1.0,
                    effort="low",
                )
            )

        if data.get("public_access_block") == "PARTIALLY_OPEN":
            recs.append(
                Recommendation(
                    id=f"s3-public-{uuid4().hex[:8]}",
                    category=Category.SECURITY,
                    severity=Severity.CRITICAL,
                    title=f"S3 bucket with incomplete public access block: {data['bucket_name']}",
                    description="Public access block is not fully enabled, risking accidental public exposure.",
                    current_state=f"Bucket {data['bucket_name']} has partial public access block",
                    recommended_action="Enable all four public access block settings.",
                    estimated_impact="Prevents accidental public exposure",
                    affected_resources=[data["bucket_name"]],
                    confidence=1.0,
                    effort="low",
                )
            )

        if data.get("versioning") == "Disabled":
            recs.append(
                Recommendation(
                    id=f"s3-noversion-{uuid4().hex[:8]}",
                    category=Category.SECURITY,
                    severity=Severity.LOW,
                    title=f"S3 bucket without versioning: {data['bucket_name']}",
                    description="Bucket versioning is disabled. Data cannot be recovered from accidental deletes.",
                    current_state=f"Bucket {data['bucket_name']} has versioning disabled",
                    recommended_action="Enable versioning with lifecycle rules to manage storage costs.",
                    estimated_impact="Data protection improvement",
                    affected_resources=[data["bucket_name"]],
                    confidence=0.7,
                    effort="low",
                )
            )

        if not data.get("lifecycle_rules"):
            recs.append(
                Recommendation(
                    id=f"s3-nolifecycle-{uuid4().hex[:8]}",
                    category=Category.COST,
                    severity=Severity.LOW,
                    title=f"S3 bucket without lifecycle policy: {data['bucket_name']}",
                    description="No lifecycle rules configured. Old objects never transition to cheaper storage.",
                    current_state=f"Bucket {data['bucket_name']} has no lifecycle rules",
                    recommended_action="Add lifecycle rules to transition objects to IA/Glacier after 30-90 days.",
                    estimated_impact="20–70% storage cost reduction for aging data",
                    affected_resources=[data["bucket_name"]],
                    confidence=0.6,
                    effort="low",
                )
            )

        return recs

    # --- RDS Checks ---
    def _check_rds(self, item: CollectedData) -> list[Recommendation]:
        recs = []
        data = item.data

        if data.get("publicly_accessible"):
            recs.append(
                Recommendation(
                    id=f"rds-public-{uuid4().hex[:8]}",
                    category=Category.SECURITY,
                    severity=Severity.CRITICAL,
                    title=f"Publicly accessible RDS: {data['db_instance_id']}",
                    description="RDS instance is publicly accessible from the internet.",
                    current_state=f"{data['db_instance_id']} has PubliclyAccessible=true",
                    recommended_action="Set PubliclyAccessible to false and use VPC-internal access.",
                    estimated_impact="Eliminates direct internet exposure",
                    affected_resources=[data["db_instance_id"]],
                    confidence=1.0,
                    effort="medium",
                )
            )

        if not data.get("multi_az"):
            recs.append(
                Recommendation(
                    id=f"rds-noha-{uuid4().hex[:8]}",
                    category=Category.PERFORMANCE,
                    severity=Severity.MEDIUM,
                    title=f"Single-AZ RDS: {data['db_instance_id']}",
                    description="RDS instance is not Multi-AZ, risking downtime on AZ failure.",
                    current_state=f"{data['db_instance_id']} is single-AZ",
                    recommended_action="Enable Multi-AZ for production databases.",
                    estimated_impact="Improved availability (adds ~$50–200/month)",
                    affected_resources=[data["db_instance_id"]],
                    confidence=0.7,
                    effort="medium",
                )
            )

        if not data.get("storage_encrypted"):
            recs.append(
                Recommendation(
                    id=f"rds-noenc-{uuid4().hex[:8]}",
                    category=Category.SECURITY,
                    severity=Severity.HIGH,
                    title=f"Unencrypted RDS instance: {data['db_instance_id']}",
                    description="RDS storage is not encrypted at rest.",
                    current_state=f"{data['db_instance_id']} has StorageEncrypted=false",
                    recommended_action="Create encrypted snapshot, restore from it, and switch over.",
                    estimated_impact="Compliance requirement for most frameworks",
                    affected_resources=[data["db_instance_id"]],
                    confidence=1.0,
                    effort="high",
                )
            )

        # Old-gen RDS instance classes
        db_class = data.get("db_class", "")
        if any(old in db_class for old in ["db.m3", "db.m4", "db.r3", "db.r4", "db.t2"]):
            recs.append(
                Recommendation(
                    id=f"rds-oldgen-{uuid4().hex[:8]}",
                    category=Category.COST,
                    severity=Severity.MEDIUM,
                    title=f"Old-generation RDS class: {data['db_instance_id']}",
                    description=f"Instance uses {db_class}, an older generation with worse price/performance.",
                    current_state=f"{data['db_instance_id']} running {db_class}",
                    recommended_action="Upgrade to current-gen (db.m5, db.r5, db.t3).",
                    estimated_impact="10–30% cost reduction",
                    affected_resources=[data["db_instance_id"]],
                    confidence=0.8,
                    effort="medium",
                )
            )

        return recs

    # --- Lambda Checks ---
    def _check_lambda(self, item: CollectedData) -> list[Recommendation]:
        recs = []
        data = item.data
        runtime = data.get("runtime", "")
        memory = data.get("memory_size", 128)
        timeout = data.get("timeout", 3)
        function_name = data.get("function_name", "unknown")

        if runtime in DEPRECATED_RUNTIMES:
            recs.append(
                Recommendation(
                    id=f"lambda-runtime-{uuid4().hex[:8]}",
                    category=Category.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Lambda using outdated runtime: {function_name}",
                    description=f"Function uses {runtime} which is deprecated or approaching end-of-life.",
                    current_state=f"{function_name} uses runtime {runtime}",
                    recommended_action="Upgrade to the latest supported runtime version.",
                    estimated_impact="Security patches and performance improvements",
                    affected_resources=[function_name],
                    confidence=0.9,
                    effort="medium",
                )
            )

        if memory >= 2048:
            recs.append(
                Recommendation(
                    id=f"lambda-memory-{uuid4().hex[:8]}",
                    category=Category.COST,
                    severity=Severity.LOW,
                    title=f"Lambda with high memory allocation: {function_name}",
                    description=f"Function is allocated {memory}MB. Consider right-sizing.",
                    current_state=f"{function_name} allocated {memory}MB",
                    recommended_action="Use AWS Lambda Power Tuning to find optimal memory setting.",
                    estimated_impact=f"${(memory - 512) * 0.01:.0f}/month potential savings",
                    affected_resources=[function_name],
                    confidence=0.6,
                    effort="low",
                )
            )

        if timeout >= 300:
            recs.append(
                Recommendation(
                    id=f"lambda-timeout-{uuid4().hex[:8]}",
                    category=Category.PERFORMANCE,
                    severity=Severity.LOW,
                    title=f"Lambda with high timeout: {function_name}",
                    description=f"Function timeout is {timeout}s. Long timeouts can mask performance issues.",
                    current_state=f"{function_name} has {timeout}s timeout",
                    recommended_action="Review if the function actually needs this timeout. Consider Step Functions for long workflows.",
                    estimated_impact="Better error detection and cost control",
                    affected_resources=[function_name],
                    confidence=0.5,
                    effort="low",
                )
            )

        return recs

    # --- Security Group Checks ---
    def _check_security_group(self, item: CollectedData) -> list[Recommendation]:
        recs = []
        data = item.data
        sg_id = data.get("group_id", "unknown")

        for rule in data.get("ingress_rules", []):
            cidr = rule.get("cidr", "")
            from_port = rule.get("from_port", 0)
            to_port = rule.get("to_port", 0)

            if cidr == "0.0.0.0/0":
                if from_port <= 22 <= to_port:
                    recs.append(
                        Recommendation(
                            id=f"sg-ssh-open-{uuid4().hex[:8]}",
                            category=Category.SECURITY,
                            severity=Severity.CRITICAL,
                            title=f"SSH open to internet: {sg_id}",
                            description="Security group allows SSH (port 22) from 0.0.0.0/0.",
                            current_state=f"{sg_id} allows TCP/22 from 0.0.0.0/0",
                            recommended_action="Restrict to known CIDR ranges or use SSM Session Manager.",
                            estimated_impact="Eliminates brute-force attack surface",
                            affected_resources=[sg_id],
                            confidence=1.0,
                            effort="low",
                        )
                    )
                elif from_port <= 3389 <= to_port:
                    recs.append(
                        Recommendation(
                            id=f"sg-rdp-open-{uuid4().hex[:8]}",
                            category=Category.SECURITY,
                            severity=Severity.CRITICAL,
                            title=f"RDP open to internet: {sg_id}",
                            description="Security group allows RDP (port 3389) from 0.0.0.0/0.",
                            current_state=f"{sg_id} allows TCP/3389 from 0.0.0.0/0",
                            recommended_action="Restrict to known CIDR ranges or use a bastion/VPN.",
                            estimated_impact="Eliminates remote desktop attack surface",
                            affected_resources=[sg_id],
                            confidence=1.0,
                            effort="low",
                        )
                    )
                elif from_port == 0 and to_port == 65535:
                    recs.append(
                        Recommendation(
                            id=f"sg-allports-{uuid4().hex[:8]}",
                            category=Category.SECURITY,
                            severity=Severity.CRITICAL,
                            title=f"All ports open to internet: {sg_id}",
                            description="Security group allows all TCP ports from 0.0.0.0/0.",
                            current_state=f"{sg_id} allows all ports from 0.0.0.0/0",
                            recommended_action="Restrict to only required ports and source CIDRs.",
                            estimated_impact="Major security risk reduction",
                            affected_resources=[sg_id],
                            confidence=1.0,
                            effort="medium",
                        )
                    )

        return recs

    # --- EBS Volume Checks ---
    def _check_ebs(self, item: CollectedData) -> list[Recommendation]:
        recs = []
        data = item.data
        volume_id = data.get("volume_id", "unknown")

        if data.get("state") == "available":
            recs.append(
                Recommendation(
                    id=f"ebs-unattached-{uuid4().hex[:8]}",
                    category=Category.COST,
                    severity=Severity.MEDIUM,
                    title=f"Unattached EBS volume: {volume_id}",
                    description="EBS volume is not attached to any instance but still incurring charges.",
                    current_state=f"{volume_id} ({data.get('size', '?')}GB {data.get('volume_type', '?')}) is unattached",
                    recommended_action="Snapshot and delete if no longer needed.",
                    estimated_impact=f"${data.get('size', 100) * 0.08:.0f}/month savings",
                    affected_resources=[volume_id],
                    confidence=0.9,
                    effort="low",
                )
            )

        if data.get("volume_type") == "gp2":
            recs.append(
                Recommendation(
                    id=f"ebs-gp2-{uuid4().hex[:8]}",
                    category=Category.COST,
                    severity=Severity.LOW,
                    title=f"EBS volume using gp2: {volume_id}",
                    description="Volume uses gp2 which is older and more expensive than gp3.",
                    current_state=f"{volume_id} is gp2 ({data.get('size', '?')}GB)",
                    recommended_action="Migrate to gp3 for 20% cost savings and better baseline performance.",
                    estimated_impact=f"${data.get('size', 100) * 0.02:.0f}/month savings",
                    affected_resources=[volume_id],
                    confidence=0.9,
                    effort="low",
                )
            )

        if not data.get("encrypted"):
            recs.append(
                Recommendation(
                    id=f"ebs-noenc-{uuid4().hex[:8]}",
                    category=Category.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"Unencrypted EBS volume: {volume_id}",
                    description="EBS volume is not encrypted at rest.",
                    current_state=f"{volume_id} has encryption disabled",
                    recommended_action="Create encrypted snapshot and restore, or enable default encryption.",
                    estimated_impact="Compliance improvement",
                    affected_resources=[volume_id],
                    confidence=1.0,
                    effort="medium",
                )
            )

        return recs

    # --- Elastic IP Checks ---
    def _check_eip(self, item: CollectedData) -> list[Recommendation]:
        recs = []
        data = item.data

        if not data.get("associated"):
            recs.append(
                Recommendation(
                    id=f"eip-unused-{uuid4().hex[:8]}",
                    category=Category.COST,
                    severity=Severity.LOW,
                    title=f"Unused Elastic IP: {data.get('public_ip', 'unknown')}",
                    description="Elastic IP is not associated with any resource. AWS charges for unused EIPs.",
                    current_state=f"EIP {data.get('public_ip')} is unassociated",
                    recommended_action="Release the Elastic IP if no longer needed.",
                    estimated_impact="$3.60/month per unused EIP",
                    affected_resources=[data.get("allocation_id", "unknown")],
                    confidence=1.0,
                    effort="low",
                )
            )

        return recs

    # --- Load Balancer Checks ---
    def _check_elb(self, item: CollectedData) -> list[Recommendation]:
        recs = []
        data = item.data
        lb_name = data.get("name", "unknown")

        if data.get("target_count", 0) == 0:
            recs.append(
                Recommendation(
                    id=f"elb-notargets-{uuid4().hex[:8]}",
                    category=Category.COST,
                    severity=Severity.MEDIUM,
                    title=f"Load balancer with no targets: {lb_name}",
                    description="Load balancer has no registered targets. It's incurring charges without serving traffic.",
                    current_state=f"{lb_name} has 0 healthy targets",
                    recommended_action="Delete if unused, or register targets.",
                    estimated_impact="$16–22/month per idle ALB/NLB",
                    affected_resources=[lb_name],
                    confidence=0.85,
                    effort="low",
                )
            )

        return recs

    # --- CloudWatch Utilization Checks ---
    def _check_utilization(self, item: CollectedData) -> list[Recommendation]:
        recs = []
        data = item.data
        resource_id = data.get("resource_id", "unknown")
        avg_cpu = data.get("avg_cpu", None)

        if avg_cpu is not None and avg_cpu < 5.0:
            recs.append(
                Recommendation(
                    id=f"cw-lowcpu-{uuid4().hex[:8]}",
                    category=Category.COST,
                    severity=Severity.HIGH,
                    title=f"Underutilized instance: {resource_id}",
                    description=f"Average CPU utilization is {avg_cpu:.1f}% over the past 7 days.",
                    current_state=f"{resource_id} averaging {avg_cpu:.1f}% CPU",
                    recommended_action="Downsize instance type or consider Spot/Graviton.",
                    estimated_impact="30–60% cost reduction by right-sizing",
                    affected_resources=[resource_id],
                    confidence=0.8,
                    effort="medium",
                )
            )
        elif avg_cpu is not None and avg_cpu > 90.0:
            recs.append(
                Recommendation(
                    id=f"cw-highcpu-{uuid4().hex[:8]}",
                    category=Category.PERFORMANCE,
                    severity=Severity.HIGH,
                    title=f"Over-utilized instance: {resource_id}",
                    description=f"Average CPU utilization is {avg_cpu:.1f}% — at risk of performance degradation.",
                    current_state=f"{resource_id} averaging {avg_cpu:.1f}% CPU",
                    recommended_action="Upsize instance or add auto-scaling.",
                    estimated_impact="Improved application performance and reliability",
                    affected_resources=[resource_id],
                    confidence=0.8,
                    effort="medium",
                )
            )

        return recs

    # --- IAM Checks ---
    def _check_iam(self, item: CollectedData) -> list[Recommendation]:
        recs = []
        data = item.data
        role_name = data.get("role_name", "unknown")

        for policy in data.get("attached_policies", []):
            if any(p in policy for p in ["AdministratorAccess", "PowerUserAccess"]):
                recs.append(
                    Recommendation(
                        id=f"iam-admin-{uuid4().hex[:8]}",
                        category=Category.SECURITY,
                        severity=Severity.HIGH,
                        title=f"Overly permissive IAM role: {role_name}",
                        description=f"Role has {policy} attached — violates least-privilege principle.",
                        current_state=f"{role_name} has {policy}",
                        recommended_action="Replace with scoped policies granting only required permissions.",
                        estimated_impact="Reduced blast radius from compromised credentials",
                        affected_resources=[role_name],
                        confidence=0.9,
                        effort="high",
                    )
                )

        return recs

    # --- CloudFormation Stack Checks ---
    def _check_cfn_stack(self, item: CollectedData) -> list[Recommendation]:
        recs = []
        data = item.data
        stack_name = data.get("stack_name", "unknown")

        if data.get("drift_status") == "DRIFTED":
            recs.append(
                Recommendation(
                    id=f"cfn-drift-{uuid4().hex[:8]}",
                    category=Category.SECURITY,
                    severity=Severity.MEDIUM,
                    title=f"CloudFormation stack drift detected: {stack_name}",
                    description="Stack resources have drifted from their template definition.",
                    current_state=f"{stack_name} has drifted resources",
                    recommended_action="Investigate drift, update template, or import changes.",
                    estimated_impact="Configuration consistency and auditability",
                    affected_resources=[stack_name],
                    confidence=0.85,
                    effort="medium",
                )
            )

        return recs

    # --- Compliance Checks ---
    def _check_compliance(self, item: CollectedData) -> list[Recommendation]:
        data = item.data
        return [
            Recommendation(
                id=f"config-{uuid4().hex[:8]}",
                category=Category.SECURITY,
                severity=Severity.HIGH,
                title=f"Config rule violation: {data['rule_name']}",
                description=data.get("rule_description", "Non-compliant resources detected."),
                current_state=f"{data['non_compliant_count']} non-compliant resources",
                recommended_action="Review and remediate non-compliant resources.",
                estimated_impact="Compliance improvement",
                affected_resources=[
                    r["resource_id"] for r in data.get("resources", [])
                ],
                confidence=0.95,
                effort="medium",
            )
        ]
