# Infra Optimizer

AI-Powered Infrastructure Optimization Agent — scans your AWS account for cost savings, security issues, and performance improvements.

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Run the dashboard
streamlit run infra_optimizer/dashboard/app.py
```

Then click **"🔍 Analyze My Account"** in the sidebar. The tool uses your local AWS credentials.

## What It Detects

### Cost (13+ rules)
- Stopped EC2 instances still incurring EBS costs
- Old-generation instance types (t2, m4, c4, etc.)
- Unattached EBS volumes
- gp2 volumes (should be gp3)
- Unused Elastic IPs
- Idle load balancers with no targets
- Oversized Lambda memory allocations
- S3 buckets without lifecycle policies

### Security (15+ rules)
- Unencrypted S3 buckets and EBS volumes
- S3 buckets with incomplete public access blocks
- Security groups open to 0.0.0.0/0 (SSH, RDP, all ports)
- Publicly accessible RDS instances
- Unencrypted RDS storage
- IAM roles with AdministratorAccess/PowerUserAccess
- Lambda functions on deprecated runtimes
- CloudFormation stack drift
- AWS Config rule violations
- S3 buckets without versioning

### Performance (5+ rules)
- Underutilized EC2 instances (<5% CPU over 7 days)
- Over-utilized EC2 instances (>90% CPU)
- Single-AZ RDS instances
- Lambda functions with excessive timeouts
- Old-generation RDS instance classes

## Features

- **Multi-region scanning** — analyze resources across multiple AWS regions simultaneously
- **CloudWatch metrics** — real CPU utilization data for right-sizing recommendations
- **AI Agent (optional)** — LangChain + Bedrock for deeper natural-language analysis
- **Export** — download findings as JSON or CSV
- **Pattern-based + AI** — deterministic rules run first, AI agent adds nuanced analysis

## Architecture

- **Collectors** — Scan CFN stacks, AWS Config, Cost Explorer, live resources (EC2, RDS, Lambda, S3, EBS, SGs, EIPs, ELBs, IAM)
- **Engine** — 30+ pattern detection rules, recommendation scoring, priority ranking
- **Agent** — LangChain + Bedrock for AI-powered analysis (optional)
- **Dashboard** — Streamlit UI with Overview, Cost Analysis, Security Findings, Recommendations pages

## Requirements

- Python 3.11+
- AWS credentials with read access (SecurityAudit or ReadOnlyAccess policy recommended)
- For AI agent: Amazon Bedrock model access

## CLI Usage

```bash
# Run analysis without dashboard
python test_local.py

# Run with AI agent
python test_local.py --with-agent
```

## Deploy (Multi-Account)

For running across multiple accounts via ECS Fargate:

```bash
sam build -t infra_optimizer/infra/template.yaml
sam deploy --guided
```
