"""Live resource state inventory collector."""

import logging
from datetime import datetime, timedelta, timezone

from .base import BaseCollector, CollectedData

logger = logging.getLogger(__name__)


class ResourceInventoryCollector(BaseCollector):
    """Collects live resource state: EC2, RDS, Lambda, S3, EBS, SGs, EIPs, ELBs, IAM."""

    source = "resource_inventory"

    async def collect(self, **kwargs) -> list[CollectedData]:
        account_id = self._get_account_id()
        region = self.session.region_name
        results: list[CollectedData] = []

        results.extend(await self._collect_ec2(account_id, region))
        results.extend(await self._collect_rds(account_id, region))
        results.extend(await self._collect_lambda(account_id, region))
        results.extend(await self._collect_s3(account_id, region))
        results.extend(await self._collect_ebs(account_id, region))
        results.extend(await self._collect_security_groups(account_id, region))
        results.extend(await self._collect_eips(account_id, region))
        results.extend(await self._collect_elbs(account_id, region))
        results.extend(await self._collect_iam_roles(account_id, region))
        results.extend(await self._collect_cloudwatch_metrics(account_id, region))

        logger.info(
            "Collected %d resources from %s/%s", len(results), account_id, region
        )
        return results

    async def _collect_ec2(self, account_id: str, region: str) -> list[CollectedData]:
        ec2 = self.session.client("ec2")
        results = []
        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        results.append(
                            CollectedData(
                                source=self.source,
                                account_id=account_id,
                                region=region,
                                resource_type="ec2_instance",
                                data={
                                    "instance_id": instance["InstanceId"],
                                    "instance_type": instance["InstanceType"],
                                    "state": instance["State"]["Name"],
                                    "launch_time": str(instance.get("LaunchTime")),
                                    "tags": {
                                        t["Key"]: t["Value"]
                                        for t in instance.get("Tags", [])
                                    },
                                    "vpc_id": instance.get("VpcId"),
                                    "subnet_id": instance.get("SubnetId"),
                                    "security_groups": [
                                        sg["GroupId"]
                                        for sg in instance.get("SecurityGroups", [])
                                    ],
                                },
                            )
                        )
        except Exception:
            logger.exception("Failed to collect EC2 instances")
        return results

    async def _collect_rds(self, account_id: str, region: str) -> list[CollectedData]:
        rds = self.session.client("rds")
        results = []
        try:
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    results.append(
                        CollectedData(
                            source=self.source,
                            account_id=account_id,
                            region=region,
                            resource_type="rds_instance",
                            data={
                                "db_instance_id": db["DBInstanceIdentifier"],
                                "db_class": db["DBInstanceClass"],
                                "engine": db["Engine"],
                                "engine_version": db["EngineVersion"],
                                "multi_az": db["MultiAZ"],
                                "storage_type": db.get("StorageType"),
                                "allocated_storage": db["AllocatedStorage"],
                                "storage_encrypted": db.get("StorageEncrypted", False),
                                "publicly_accessible": db.get(
                                    "PubliclyAccessible", False
                                ),
                            },
                        )
                    )
        except Exception:
            logger.exception("Failed to collect RDS instances")
        return results

    async def _collect_lambda(
        self, account_id: str, region: str
    ) -> list[CollectedData]:
        lam = self.session.client("lambda")
        results = []
        try:
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page["Functions"]:
                    results.append(
                        CollectedData(
                            source=self.source,
                            account_id=account_id,
                            region=region,
                            resource_type="lambda_function",
                            data={
                                "function_name": fn["FunctionName"],
                                "runtime": fn.get("Runtime", "N/A"),
                                "memory_size": fn["MemorySize"],
                                "timeout": fn["Timeout"],
                                "code_size": fn["CodeSize"],
                                "last_modified": fn["LastModified"],
                            },
                        )
                    )
        except Exception:
            logger.exception("Failed to collect Lambda functions")
        return results

    async def _collect_s3(self, account_id: str, region: str) -> list[CollectedData]:
        s3 = self.session.client("s3")
        results = []
        try:
            buckets = s3.list_buckets().get("Buckets", [])
            for bucket in buckets:
                bucket_name = bucket["Name"]
                encryption = "NONE"
                versioning = "Disabled"
                public_access = "UNKNOWN"
                lifecycle_rules = False

                try:
                    enc_resp = s3.get_bucket_encryption(Bucket=bucket_name)
                    rules = enc_resp.get("ServerSideEncryptionConfiguration", {}).get(
                        "Rules", []
                    )
                    if rules:
                        encryption = rules[0]["ApplyServerSideEncryptionByDefault"][
                            "SSEAlgorithm"
                        ]
                except Exception:
                    pass

                try:
                    ver_resp = s3.get_bucket_versioning(Bucket=bucket_name)
                    versioning = ver_resp.get("Status", "Disabled")
                except Exception:
                    pass

                try:
                    pab = s3.get_public_access_block(Bucket=bucket_name)
                    config = pab.get("PublicAccessBlockConfiguration", {})
                    public_access = (
                        "BLOCKED"
                        if all(config.values())
                        else "PARTIALLY_OPEN"
                    )
                except Exception:
                    pass

                try:
                    lc_resp = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                    lifecycle_rules = len(lc_resp.get("Rules", [])) > 0
                except Exception:
                    pass  # No lifecycle config is common

                results.append(
                    CollectedData(
                        source=self.source,
                        account_id=account_id,
                        region=region,
                        resource_type="s3_bucket",
                        data={
                            "bucket_name": bucket_name,
                            "creation_date": str(bucket.get("CreationDate")),
                            "encryption": encryption,
                            "versioning": versioning,
                            "public_access_block": public_access,
                            "lifecycle_rules": lifecycle_rules,
                        },
                    )
                )
        except Exception:
            logger.exception("Failed to collect S3 buckets")
        return results

    async def _collect_ebs(self, account_id: str, region: str) -> list[CollectedData]:
        ec2 = self.session.client("ec2")
        results = []
        try:
            paginator = ec2.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for vol in page["Volumes"]:
                    results.append(
                        CollectedData(
                            source=self.source,
                            account_id=account_id,
                            region=region,
                            resource_type="ebs_volume",
                            data={
                                "volume_id": vol["VolumeId"],
                                "size": vol["Size"],
                                "volume_type": vol["VolumeType"],
                                "state": vol["State"],
                                "encrypted": vol.get("Encrypted", False),
                                "attachments": len(vol.get("Attachments", [])),
                                "iops": vol.get("Iops"),
                                "create_time": str(vol.get("CreateTime")),
                            },
                        )
                    )
        except Exception:
            logger.exception("Failed to collect EBS volumes")
        return results

    async def _collect_security_groups(
        self, account_id: str, region: str
    ) -> list[CollectedData]:
        ec2 = self.session.client("ec2")
        results = []
        try:
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    ingress_rules = []
                    for rule in sg.get("IpPermissions", []):
                        for ip_range in rule.get("IpRanges", []):
                            ingress_rules.append({
                                "cidr": ip_range.get("CidrIp", ""),
                                "from_port": rule.get("FromPort", 0),
                                "to_port": rule.get("ToPort", 65535),
                                "protocol": rule.get("IpProtocol", "-1"),
                            })

                    results.append(
                        CollectedData(
                            source=self.source,
                            account_id=account_id,
                            region=region,
                            resource_type="security_group",
                            data={
                                "group_id": sg["GroupId"],
                                "group_name": sg.get("GroupName", ""),
                                "vpc_id": sg.get("VpcId", ""),
                                "description": sg.get("Description", ""),
                                "ingress_rules": ingress_rules,
                                "ingress_rule_count": len(sg.get("IpPermissions", [])),
                                "egress_rule_count": len(sg.get("IpPermissionsEgress", [])),
                            },
                        )
                    )
        except Exception:
            logger.exception("Failed to collect security groups")
        return results

    async def _collect_eips(self, account_id: str, region: str) -> list[CollectedData]:
        ec2 = self.session.client("ec2")
        results = []
        try:
            resp = ec2.describe_addresses()
            for addr in resp.get("Addresses", []):
                results.append(
                    CollectedData(
                        source=self.source,
                        account_id=account_id,
                        region=region,
                        resource_type="elastic_ip",
                        data={
                            "public_ip": addr.get("PublicIp"),
                            "allocation_id": addr.get("AllocationId"),
                            "associated": bool(addr.get("AssociationId")),
                            "instance_id": addr.get("InstanceId"),
                            "network_interface_id": addr.get("NetworkInterfaceId"),
                        },
                    )
                )
        except Exception:
            logger.exception("Failed to collect Elastic IPs")
        return results

    async def _collect_elbs(self, account_id: str, region: str) -> list[CollectedData]:
        elbv2 = self.session.client("elbv2")
        results = []
        try:
            paginator = elbv2.get_paginator("describe_load_balancers")
            for page in paginator.paginate():
                for lb in page["LoadBalancers"]:
                    lb_arn = lb["LoadBalancerArn"]
                    # Count targets
                    target_count = 0
                    try:
                        tg_resp = elbv2.describe_target_groups(
                            LoadBalancerArn=lb_arn
                        )
                        for tg in tg_resp.get("TargetGroups", []):
                            health_resp = elbv2.describe_target_health(
                                TargetGroupArn=tg["TargetGroupArn"]
                            )
                            target_count += len(
                                health_resp.get("TargetHealthDescriptions", [])
                            )
                    except Exception:
                        pass

                    results.append(
                        CollectedData(
                            source=self.source,
                            account_id=account_id,
                            region=region,
                            resource_type="load_balancer",
                            data={
                                "name": lb.get("LoadBalancerName"),
                                "arn": lb_arn,
                                "type": lb.get("Type"),
                                "scheme": lb.get("Scheme"),
                                "state": lb.get("State", {}).get("Code"),
                                "target_count": target_count,
                                "created_time": str(lb.get("CreatedTime")),
                            },
                        )
                    )
        except Exception:
            logger.exception("Failed to collect load balancers")
        return results

    async def _collect_iam_roles(
        self, account_id: str, region: str
    ) -> list[CollectedData]:
        iam = self.session.client("iam")
        results = []
        try:
            paginator = iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page["Roles"]:
                    role_name = role["RoleName"]
                    # Skip AWS service-linked roles
                    if role.get("Path", "").startswith("/aws-service-role/"):
                        continue

                    attached_policies = []
                    try:
                        pol_resp = iam.list_attached_role_policies(RoleName=role_name)
                        attached_policies = [
                            p["PolicyName"]
                            for p in pol_resp.get("AttachedPolicies", [])
                        ]
                    except Exception:
                        pass

                    results.append(
                        CollectedData(
                            source=self.source,
                            account_id=account_id,
                            region=region,
                            resource_type="iam_role",
                            data={
                                "role_name": role_name,
                                "path": role.get("Path", "/"),
                                "create_date": str(role.get("CreateDate")),
                                "attached_policies": attached_policies,
                                "max_session_duration": role.get("MaxSessionDuration", 3600),
                            },
                        )
                    )
        except Exception:
            logger.exception("Failed to collect IAM roles")
        return results

    async def _collect_cloudwatch_metrics(
        self, account_id: str, region: str
    ) -> list[CollectedData]:
        """Collect CPU utilization metrics for running EC2 instances."""
        ec2 = self.session.client("ec2")
        cw = self.session.client("cloudwatch")
        results = []

        try:
            # Get running instances
            resp = ec2.describe_instances(
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
            )
            instance_ids = []
            for reservation in resp.get("Reservations", []):
                for instance in reservation["Instances"]:
                    instance_ids.append(instance["InstanceId"])

            # Get CPU metrics for each
            now = datetime.now(timezone.utc)
            start = now - timedelta(days=7)

            for instance_id in instance_ids[:20]:  # Limit to avoid throttling
                try:
                    metric_resp = cw.get_metric_statistics(
                        Namespace="AWS/EC2",
                        MetricName="CPUUtilization",
                        Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
                        StartTime=start,
                        EndTime=now,
                        Period=3600,
                        Statistics=["Average", "Maximum"],
                    )
                    datapoints = metric_resp.get("Datapoints", [])
                    if datapoints:
                        avg_cpu = sum(d["Average"] for d in datapoints) / len(datapoints)
                        max_cpu = max(d["Maximum"] for d in datapoints)
                        results.append(
                            CollectedData(
                                source=self.source,
                                account_id=account_id,
                                region=region,
                                resource_type="cloudwatch_metrics",
                                data={
                                    "resource_id": instance_id,
                                    "metric": "CPUUtilization",
                                    "avg_cpu": round(avg_cpu, 2),
                                    "max_cpu": round(max_cpu, 2),
                                    "datapoint_count": len(datapoints),
                                    "period_days": 7,
                                },
                            )
                        )
                except Exception:
                    logger.debug("No metrics for %s", instance_id)

        except Exception:
            logger.exception("Failed to collect CloudWatch metrics")

        return results
