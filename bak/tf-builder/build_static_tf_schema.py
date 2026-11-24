from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

INPUT_CATALOG = Path("data/aws_terraform_catalog.json")
OUT_DIR = Path("public/tf-schema")

# Comprehensive service-level allowed target mappings (slugified service names)
SERVICE_ALLOWED_TARGETS: dict[str, list[str]] = {
    # Compute & Containers
    "ec2": ["alb", "nlb", "ebs", "eip", "security_group", "subnet", "iam_role", "kms", "cloudwatch"],
    "ec2_elastic_compute_cloud": ["alb", "nlb", "ebs", "eip", "security_group", "subnet", "iam_role", "kms", "cloudwatch"],
    "auto_scaling": ["ec2", "alb", "nlb", "subnet", "security_group", "iam_role", "sns", "cloudwatch"],
    "ecs": ["alb", "nlb", "ecr", "vpc", "subnet", "security_group", "iam_role", "cloudwatch", "secrets_manager"],
    "eks": ["vpc", "subnet", "security_group", "iam_role", "kms", "ebs", "efs", "alb", "nlb", "cloudwatch"],
    "ecr": ["ecs", "eks", "lambda", "codebuild", "iam_role", "kms"],
    "lambda": ["apigateway", "api_gateway_v2", "s3", "dynamodb", "rds", "sqs", "sns", "eventbridge", "iam_role", "security_group", "subnet", "secrets_manager", "kms", "cloudwatch"],
    "batch": ["ec2", "ecs", "vpc", "subnet", "security_group", "iam_role", "s3", "cloudwatch"],
    "lightsail": ["ec2", "s3", "rds", "route53", "cloudfront"],
    "app_runner": ["ecr", "vpc", "security_group", "iam_role", "secrets_manager", "rds", "dynamodb"],
    "elastic_beanstalk": ["ec2", "alb", "nlb", "rds", "s3", "iam_role", "security_group", "vpc"],

    # Storage
    "ebs": ["ec2", "kms", "iam_role"],
    "s3": ["lambda", "ec2", "sagemaker", "emr", "cloudfront", "iam_role", "kms", "sns", "sqs", "eventbridge", "athena", "glue", "redshift"],
    "efs": ["ec2", "ecs", "eks", "lambda", "vpc", "subnet", "security_group", "kms", "iam_role"],
    "fsx": ["ec2", "ecs", "eks", "vpc", "subnet", "security_group", "kms", "iam_role"],
    "glacier": ["s3", "iam_role", "sns", "kms"],
    "backup": ["ec2", "ebs", "rds", "dynamodb", "efs", "fsx", "s3", "iam_role", "kms", "sns"],

    # Networking & Content Delivery
    "vpc": ["subnet", "security_group", "internet_gateway", "nat_gateway", "route_table", "vpc_endpoint", "ec2", "rds", "lambda", "ecs", "eks", "alb", "nlb"],
    "vpc_networking": ["subnet", "security_group", "ec2", "rds", "lambda", "ecs", "eks", "alb", "nlb"],
    "subnet": ["ec2", "alb", "nlb", "rds", "eks", "ecs", "lambda", "nat_gateway", "route_table"],
    "security_group": ["ec2", "lambda", "emr", "rds", "alb", "nlb", "ecs", "eks", "efs", "elasticache"],
    "eip": ["ec2", "nat_gateway", "network_interface", "nlb"],
    "alb": ["ec2", "ecs", "eks", "lambda", "subnet", "security_group", "acm", "wafv2", "route53", "s3"],
    "nlb": ["ec2", "ecs", "eks", "subnet", "security_group", "eip", "acm", "route53"],
    "elb": ["ec2", "subnet", "security_group", "acm", "route53", "s3"],
    "apigateway": ["lambda", "alb", "nlb", "vpc_link", "iam_role", "cognito", "acm", "wafv2", "cloudwatch"],
    "api_gateway_v2": ["lambda", "alb", "nlb", "ecs", "iam_role", "cognito", "acm", "cloudwatch"],
    "cloudfront": ["s3", "alb", "nlb", "apigateway", "acm", "wafv2", "route53", "lambda"],
    "route53": ["alb", "nlb", "cloudfront", "s3", "apigateway", "ec2", "eip", "vpc"],
    "direct_connect": ["vpc", "transit_gateway", "iam_role"],
    "transit_gateway": ["vpc", "direct_connect", "vpn", "route_table"],
    "global_accelerator": ["alb", "nlb", "ec2", "eip"],

    # Databases
    "rds": ["ec2", "lambda", "ecs", "eks", "subnet", "security_group", "iam_role", "kms", "secrets_manager", "cloudwatch"],
    "aurora": ["ec2", "lambda", "ecs", "eks", "subnet", "security_group", "iam_role", "kms", "secrets_manager"],
    "dynamodb": ["lambda", "ec2", "ecs", "eks", "iam_role", "kms", "kinesis", "s3", "cloudwatch"],
    "elasticache": ["ec2", "lambda", "ecs", "eks", "subnet", "security_group", "kms", "sns"],
    "documentdb": ["ec2", "lambda", "ecs", "eks", "subnet", "security_group", "kms", "secrets_manager"],
    "neptune": ["ec2", "lambda", "sagemaker", "subnet", "security_group", "iam_role", "kms", "s3"],
    "redshift": ["s3", "glue", "sagemaker", "vpc", "subnet", "security_group", "iam_role", "kms"],
    "memorydb": ["ec2", "lambda", "ecs", "eks", "subnet", "security_group", "kms"],
    "timestream": ["lambda", "ec2", "iot", "kinesis", "iam_role", "kms", "s3"],

    # Security, Identity & Compliance
    "iam": ["ec2", "lambda", "ecs", "eks", "sagemaker", "emr", "glue", "codebuild", "codepipeline", "s3", "dynamodb", "rds"],
    "iam_role": ["sagemaker", "ec2", "lambda", "ecs", "eks", "emr", "glue", "codebuild", "codepipeline", "step_functions"],
    "kms": ["s3", "ebs", "rds", "dynamodb", "lambda", "eks", "secrets_manager", "sns", "sqs", "cloudwatch", "iam_role"],
    "secrets_manager": ["rds", "lambda", "ecs", "eks", "ec2", "redshift", "documentdb", "kms", "iam_role"],
    "ssm": ["ec2", "lambda", "ecs", "eks", "iam_role", "kms", "sns"],
    "acm": ["alb", "nlb", "cloudfront", "apigateway", "api_gateway_v2", "route53"],
    "wafv2": ["alb", "cloudfront", "apigateway", "cognito"],
    "cognito": ["apigateway", "api_gateway_v2", "alb", "lambda", "iam_role", "ses", "sns"],
    "guardduty": ["s3", "eks", "ec2", "iam_role", "sns", "eventbridge"],
    "security_hub": ["guardduty", "config", "iam_role", "sns", "eventbridge"],

    # Analytics, Big Data & AI/ML
    "emr": ["s3", "ec2", "vpc", "subnet", "security_group", "iam_role", "glue", "kms", "cloudwatch"],
    "sagemaker": ["s3", "ecr", "vpc", "subnet", "security_group", "iam_role", "kms", "lambda", "step_functions", "cloudwatch"],
    "bedrock": ["s3", "lambda", "iam_role", "kms", "opensearch", "cloudwatch"],
    "glue": ["s3", "rds", "redshift", "dynamodb", "iam_role", "kms", "athena", "lake_formation", "cloudwatch"],
    "athena": ["s3", "glue", "iam_role", "kms"],
    "kinesis": ["lambda", "s3", "redshift", "opensearch", "dynamodb", "iam_role", "kms", "cloudwatch"],
    "msk": ["ec2", "lambda", "ecs", "eks", "vpc", "subnet", "security_group", "iam_role", "kms", "s3"],
    "opensearch": ["ec2", "lambda", "kinesis", "s3", "vpc", "subnet", "security_group", "iam_role", "kms", "cognito"],

    # Application Integration & Messaging
    "sqs": ["lambda", "ec2", "ecs", "sns", "eventbridge", "s3", "iam_role", "kms", "cloudwatch"],
    "sns": ["lambda", "sqs", "ec2", "cloudwatch", "s3", "eventbridge", "iam_role", "kms"],
    "eventbridge": ["lambda", "sqs", "sns", "step_functions", "ecs", "codebuild", "iam_role"],
    "step_functions": ["lambda", "ecs", "glue", "sagemaker", "sqs", "sns", "dynamodb", "batch", "iam_role"],
    "mq": ["ec2", "lambda", "ecs", "vpc", "subnet", "security_group", "kms"],

    # Management, Monitoring & DevOps
    "cloudwatch": ["ec2", "lambda", "ecs", "eks", "rds", "alb", "nlb", "sns", "s3", "iam_role", "kms"],
    "cloudtrail": ["s3", "cloudwatch", "sns", "kms", "iam_role"],
    "config": ["s3", "sns", "iam_role", "kms"],
    "codebuild": ["s3", "ecr", "vpc", "subnet", "security_group", "iam_role", "kms", "secrets_manager", "cloudwatch"],
    "codepipeline": ["s3", "codebuild", "codedeploy", "ecs", "lambda", "iam_role", "kms", "sns"],
    "codedeploy": ["ec2", "ecs", "lambda", "alb", "nlb", "s3", "iam_role", "sns"],
}

# Resource-specific overrides where an aws_* resource has narrower/explicit target rules
RESOURCE_ALLOWED_TARGETS: dict[str, list[str]] = {
    "aws_ami": ["ec2", "launch_template", "auto_scaling"],
    "aws_eip": ["ec2", "nat_gateway", "network_interface", "nlb"],
    "aws_ebs_volume": ["ec2"],
    "aws_volume_attachment": ["ec2"],
    "aws_security_group": ["ec2", "lambda", "emr", "rds", "alb", "nlb", "ecs", "eks"],
    "aws_iam_role": ["sagemaker", "ec2", "lambda", "ecs", "eks", "emr", "glue", "codebuild"],
    "aws_subnet": ["vpc", "ec2", "alb", "nlb", "rds", "eks", "ecs"],
}

# Default fallback targets for any remaining AWS services so every .js module has allowedTargets
FALLBACK_ALLOWED_TARGETS: list[str] = ["iam_role", "security_group", "cloudwatch", "s3", "lambda"]


def slugify_service(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", name.strip().lower()).strip("_")
    return slug or "aws_misc"


def resolve_allowed_targets(tf_type: str, service_slug: str) -> list[str]:
    if tf_type in RESOURCE_ALLOWED_TARGETS:
        return list(RESOURCE_ALLOWED_TARGETS[tf_type])
    if service_slug in SERVICE_ALLOWED_TARGETS:
        return list(SERVICE_ALLOWED_TARGETS[service_slug])
    return list(FALLBACK_ALLOWED_TARGETS)


def main() -> None:
    if not INPUT_CATALOG.exists():
        raise FileNotFoundError(f"Missing {INPUT_CATALOG}. Run sync_aws_terraform_docs.py first.")

    raw_data = json.loads(INPUT_CATALOG.read_text(encoding="utf-8"))
    resources: dict[str, dict[str, Any]] = raw_data.get("resources") or {}

    grouped: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    service_display_names: dict[str, str] = {}

    for tf_type, spec in sorted(resources.items()):
        service_label = (spec.get("service") or spec.get("category") or "AWS").strip()
        slug = slugify_service(service_label)
        service_display_names.setdefault(slug, service_label)

        enriched_spec = dict(spec)
        enriched_spec["serviceSlug"] = slug
        enriched_spec["allowedTargets"] = resolve_allowed_targets(tf_type, slug)
        grouped[slug][tf_type] = enriched_spec

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    for old_js in OUT_DIR.glob("*.js"):
        old_js.unlink()

    services_index: dict[str, dict[str, Any]] = {}
    resources_index: dict[str, dict[str, Any]] = {}

    for slug in sorted(grouped.keys()):
        svc_resources = grouped[slug]
        filename = f"{slug}.js"
        svc_label = service_display_names[slug]
        svc_targets = SERVICE_ALLOWED_TARGETS.get(slug, list(FALLBACK_ALLOWED_TARGETS))

        services_index[slug] = {
            "service": svc_label,
            "file": filename,
            "count": len(svc_resources),
            "allowedTargets": svc_targets,
        }

        for tf_type, spec in svc_resources.items():
            resources_index[tf_type] = {
                "service": svc_label,
                "serviceSlug": slug,
                "file": filename,
                "label": spec.get("label") or tf_type,
                "accent": spec.get("accent") or "#8b5cf6",
                "allowedTargets": spec["allowedTargets"],
            }

        js_payload = (
            f"// Auto-generated Terraform AWS schema bundle for {svc_label}\n"
            f"export const service = {json.dumps(svc_label)};\n"
            f"export const serviceSlug = {json.dumps(slug)};\n"
            f"export const allowedTargets = {json.dumps(svc_targets)};\n"
            f"export const resources = {json.dumps(svc_resources, separators=(',', ':'))};\n"
        )
        (OUT_DIR / filename).write_text(js_payload, encoding="utf-8")

    index_payload = {
        "provider": raw_data.get("provider", "hashicorp/aws"),
        "baseUrl": "https://tools.babeh.com/tf-schema",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "totalServices": len(services_index),
        "totalResources": len(resources_index),
        "services": services_index,
        "resources": resources_index,
    }

    index_path = OUT_DIR / "index.json"
    index_path.write_text(json.dumps(index_payload, separators=(",", ":")), encoding="utf-8")

    print(
        f"Generated {index_path} ({index_path.stat().st_size / 1024:.1f} KB) "
        f"and {len(services_index)} enriched service JS modules in {OUT_DIR}/"
    )


if __name__ == "__main__":
    main()
