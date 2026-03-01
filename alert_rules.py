"""
Alert Rules Engine
===================
Flexible alert rule system configurable from the UI.
Rules are stored in config.json under "alert_rules".

Each rule:
  {
    "id": "rule_uuid",
    "name": "High CPU on encoder",
    "enabled": true,
    "service": "ec2",              # ec2, medialive, mediaconnect, cloudfront, ivs, ecs, mediapackage
    "resource_filter": "",         # optional: instance ID, channel ARN, or "*" for all
    "metric": "cpu_utilization",   # metric name
    "operator": ">",              # >, <, >=, <=, ==, !=
    "threshold": 80,
    "severity": "warning",         # info, warning, critical
    "channels": ["email","telegram","whatsapp"],  # which notification channels
    "cooldown_minutes": 15,        # don't re-alert within this window
    "last_triggered": null,
    "trigger_count": 0
  }
"""

import uuid
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional
from config_manager import load_config, save_config

logger = logging.getLogger(__name__)

# ─── Operators ───────────────────────────────────────────────────────────────

OPERATORS = {
    ">": lambda a, b: a > b,
    "<": lambda a, b: a < b,
    ">=": lambda a, b: a >= b,
    "<=": lambda a, b: a <= b,
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    "contains": lambda a, b: str(b).lower() in str(a).lower(),
    "not_contains": lambda a, b: str(b).lower() not in str(a).lower(),
}

# ─── Available metrics per service ───────────────────────────────────────────

SERVICE_METRICS = {
    "ec2": [
        {"id": "cpu_utilization", "name": "CPU Utilization (%)", "type": "number"},
        {"id": "state", "name": "Instance State", "type": "string"},
        {"id": "status_checks", "name": "Status Checks", "type": "string"},
    ],
    "medialive": [
        {"id": "state", "name": "Channel State", "type": "string"},
        {"id": "pipelines_running", "name": "Pipelines Running", "type": "number"},
        {"id": "input_loss", "name": "Input Loss (any pipeline)", "type": "string"},
        {"id": "active_alerts", "name": "Active Alerts Count", "type": "number"},
    ],
    "mediaconnect": [
        {"id": "status", "name": "Flow Status", "type": "string"},
        {"id": "source_health", "name": "Source Health", "type": "string"},
    ],
    "mediapackage": [
        {"id": "status", "name": "Channel Status", "type": "string"},
        {"id": "endpoint_count", "name": "Endpoint Count", "type": "number"},
    ],
    "cloudfront": [
        {"id": "status", "name": "Distribution Status", "type": "string"},
        {"id": "enabled", "name": "Distribution Enabled", "type": "string"},
        {"id": "error_rate_4xx", "name": "4xx Error Rate (%)", "type": "number"},
        {"id": "error_rate_5xx", "name": "5xx Error Rate (%)", "type": "number"},
    ],
    "ivs": [
        {"id": "state", "name": "Channel State", "type": "string"},
        {"id": "stream_health", "name": "Stream Health", "type": "string"},
        {"id": "viewer_count", "name": "Viewer Count", "type": "number"},
    ],
    "ecs": [
        {"id": "running_vs_desired", "name": "Running < Desired", "type": "number"},
        {"id": "status", "name": "Service Status", "type": "string"},
    ],
    "easy_monitor": [
        {"id": "status", "name": "Endpoint Status (up/down/degraded)", "type": "string"},
        {"id": "response_time_ms", "name": "Response Time (ms)", "type": "number"},
        {"id": "status_code", "name": "HTTP Status Code", "type": "number"},
        {"id": "packet_loss", "name": "Packet Loss (%)", "type": "number"},
    ],
    "rds": [
        {"id": "status", "name": "DB Instance Status", "type": "string"},
        {"id": "engine", "name": "Database Engine", "type": "string"},
        {"id": "multi_az", "name": "Multi-AZ Enabled", "type": "string"},
        {"id": "storage_type", "name": "Storage Type", "type": "string"},
    ],
    "lambda_functions": [
        {"id": "state", "name": "Function State", "type": "string"},
        {"id": "runtime", "name": "Runtime", "type": "string"},
        {"id": "memory_mb", "name": "Memory Size (MB)", "type": "number"},
        {"id": "code_size_bytes", "name": "Code Size (bytes)", "type": "number"},
    ],
    "s3": [
        {"id": "name", "name": "Bucket Name", "type": "string"},
    ],
    "sqs": [
        {"id": "approximate_message_count", "name": "Approximate Message Count", "type": "number"},
        {"id": "approximate_not_visible", "name": "Approximate Not Visible", "type": "number"},
    ],
    "route53": [
        {"id": "status", "name": "Health Check Status", "type": "string"},
        {"id": "record_count", "name": "Record Count", "type": "number"},
    ],
    "apigateway": [
        {"id": "endpoint_type", "name": "Endpoint Type", "type": "string"},
    ],
    "vpcs": [
        {"id": "state", "name": "VPC State", "type": "string"},
        {"id": "subnet_count", "name": "Subnet Count", "type": "number"},
    ],
    "load_balancers": [
        {"id": "state", "name": "Load Balancer State", "type": "string"},
        {"id": "type", "name": "Load Balancer Type", "type": "string"},
        {"id": "target_group_count", "name": "Target Group Count", "type": "number"},
    ],
    "elastic_ips": [
        {"id": "is_associated", "name": "Associated", "type": "string"},
    ],
    "nat_gateways": [
        {"id": "state", "name": "NAT Gateway State", "type": "string"},
    ],
    "security_groups": [
        {"id": "inbound_rule_count", "name": "Inbound Rules Count", "type": "number"},
        {"id": "outbound_rule_count", "name": "Outbound Rules Count", "type": "number"},
        {"id": "open_to_world", "name": "Open to World (0.0.0.0/0)", "type": "string"},
    ],
    "vpn_connections": [
        {"id": "state", "name": "VPN Connection State", "type": "string"},
        {"id": "tunnels_up", "name": "Tunnels Up Count", "type": "number"},
    ],
}

# ─── Pre-built rule templates ────────────────────────────────────────────────

RULE_TEMPLATES = [
    {
        "name": "High CPU on any EC2",
        "service": "ec2", "resource_filter": "*",
        "metric": "cpu_utilization", "operator": ">", "threshold": 80,
        "severity": "warning", "cooldown_minutes": 15,
    },
    {
        "name": "EC2 status check failed",
        "service": "ec2", "resource_filter": "*",
        "metric": "status_checks", "operator": "==", "threshold": "impaired",
        "severity": "critical", "cooldown_minutes": 5,
    },
    {
        "name": "MediaLive channel stopped",
        "service": "medialive", "resource_filter": "*",
        "metric": "state", "operator": "!=", "threshold": "RUNNING",
        "severity": "critical", "cooldown_minutes": 5,
    },
    {
        "name": "MediaLive input loss",
        "service": "medialive", "resource_filter": "*",
        "metric": "input_loss", "operator": "==", "threshold": "true",
        "severity": "critical", "cooldown_minutes": 2,
    },
    {
        "name": "MediaConnect flow stopped",
        "service": "mediaconnect", "resource_filter": "*",
        "metric": "status", "operator": "!=", "threshold": "ACTIVE",
        "severity": "critical", "cooldown_minutes": 5,
    },
    {
        "name": "CloudFront high 5xx errors",
        "service": "cloudfront", "resource_filter": "*",
        "metric": "error_rate_5xx", "operator": ">", "threshold": 5,
        "severity": "warning", "cooldown_minutes": 15,
    },
    {
        "name": "CloudFront high 4xx errors",
        "service": "cloudfront", "resource_filter": "*",
        "metric": "error_rate_4xx", "operator": ">", "threshold": 10,
        "severity": "warning", "cooldown_minutes": 15,
    },
    {
        "name": "IVS stream unhealthy",
        "service": "ivs", "resource_filter": "*",
        "metric": "stream_health", "operator": "==", "threshold": "UNHEALTHY",
        "severity": "critical", "cooldown_minutes": 5,
    },
    {
        "name": "IVS low viewer count",
        "service": "ivs", "resource_filter": "*",
        "metric": "viewer_count", "operator": "<", "threshold": 1,
        "severity": "info", "cooldown_minutes": 30,
    },
    {
        "name": "ECS tasks not running",
        "service": "ecs", "resource_filter": "*",
        "metric": "running_vs_desired", "operator": "<", "threshold": 0,
        "severity": "critical", "cooldown_minutes": 5,
    },
    {
        "name": "Endpoint down",
        "service": "easy_monitor", "resource_filter": "*",
        "metric": "status", "operator": "==", "threshold": "down",
        "severity": "critical", "cooldown_minutes": 2,
    },
    {
        "name": "Endpoint slow (>2s)",
        "service": "easy_monitor", "resource_filter": "*",
        "metric": "response_time_ms", "operator": ">", "threshold": 2000,
        "severity": "warning", "cooldown_minutes": 10,
    },
    {
        "name": "RDS instance unhealthy",
        "service": "rds", "resource_filter": "*",
        "metric": "status", "operator": "!=", "threshold": "available",
        "severity": "critical", "cooldown_minutes": 5,
    },
    {
        "name": "SQS queue backlog",
        "service": "sqs", "resource_filter": "*",
        "metric": "approximate_message_count", "operator": ">", "threshold": 1000,
        "severity": "warning", "cooldown_minutes": 15,
    },
    {
        "name": "Security group open to world",
        "service": "security_groups", "resource_filter": "*",
        "metric": "open_to_world", "operator": "==", "threshold": "true",
        "severity": "warning", "cooldown_minutes": 15,
    },
    {
        "name": "NAT gateway down",
        "service": "nat_gateways", "resource_filter": "*",
        "metric": "state", "operator": "!=", "threshold": "available",
        "severity": "critical", "cooldown_minutes": 5,
    },
]


# ─── Rule CRUD ───────────────────────────────────────────────────────────────

def get_rules() -> list:
    config = load_config()
    return config.get("alert_rules", [])


def save_rules(rules: list):
    config = load_config()
    config["alert_rules"] = rules
    save_config(config)


def add_rule(rule_data: dict) -> dict:
    rules = get_rules()
    rule = {
        "id": str(uuid.uuid4())[:8],
        "name": rule_data.get("name", "Untitled Rule"),
        "enabled": rule_data.get("enabled", True),
        "service": rule_data.get("service", "ec2"),
        "resource_filter": rule_data.get("resource_filter", "*"),
        "metric": rule_data.get("metric", ""),
        "operator": rule_data.get("operator", ">"),
        "threshold": rule_data.get("threshold", 0),
        "severity": rule_data.get("severity", "warning"),
        "channels": rule_data.get("channels", ["email", "telegram", "whatsapp"]),
        "cooldown_minutes": rule_data.get("cooldown_minutes", 15),
        "last_triggered": None,
        "trigger_count": 0,
    }
    rules.append(rule)
    save_rules(rules)
    return rule


def update_rule(rule_id: str, updates: dict) -> Optional[dict]:
    rules = get_rules()
    for i, r in enumerate(rules):
        if r["id"] == rule_id:
            allowed = {"name", "enabled", "service", "resource_filter", "metric",
                       "operator", "threshold", "severity", "channels", "cooldown_minutes", "remediation"}
            filtered = {k: v for k, v in updates.items() if k in allowed}
            rules[i].update(filtered)
            save_rules(rules)
            return rules[i]
    return None


def delete_rule(rule_id: str) -> bool:
    rules = get_rules()
    new_rules = [r for r in rules if r["id"] != rule_id]
    if len(new_rules) < len(rules):
        save_rules(new_rules)
        return True
    return False


def add_template(template_index: int) -> Optional[dict]:
    if 0 <= template_index < len(RULE_TEMPLATES):
        tpl = RULE_TEMPLATES[template_index].copy()
        tpl["channels"] = ["email", "telegram", "whatsapp"]
        return add_rule(tpl)
    return None


# ─── Rule Evaluation ─────────────────────────────────────────────────────────

def _extract_metric_value(resource: dict, metric: str, service: str):
    """Extract a metric value from a resource data dict."""
    # Direct key match
    if metric in resource:
        return resource[metric]

    # Computed metrics
    if service == "ecs" and metric == "running_vs_desired":
        running = resource.get("running", 0)
        desired = resource.get("desired", 1)
        return running - desired

    return None


def evaluate_rules(infra_data: dict) -> list:
    """
    Evaluate all enabled rules against current infrastructure data.
    Returns list of triggered alerts:
      [{"rule": rule_dict, "resource": resource_id, "value": actual_value, "message": str}]
    """
    rules = get_rules()
    triggered = []
    now = datetime.now(timezone.utc)

    # Map service names to infra data keys
    service_data_map = {
        "ec2": infra_data.get("ec2", {}).get("instances", []),
        "medialive": infra_data.get("medialive", {}).get("channels", []),
        "mediaconnect": infra_data.get("mediaconnect", {}).get("flows", []),
        "mediapackage": infra_data.get("mediapackage", {}).get("channels", []),
        "cloudfront": infra_data.get("cloudfront", {}).get("distributions", []),
        "ivs": infra_data.get("ivs", {}).get("channels", []),
        "ecs": infra_data.get("ecs_services", []),
        "easy_monitor": infra_data.get("easy_monitor", {}).get("endpoints", []),
        "rds": infra_data.get("rds", {}).get("items", []),
        "lambda_functions": infra_data.get("lambda_functions", {}).get("items", []),
        "s3": infra_data.get("s3", {}).get("items", []),
        "sqs": infra_data.get("sqs", {}).get("items", []),
        "route53": infra_data.get("route53", {}).get("items", []),
        "apigateway": infra_data.get("apigateway", {}).get("items", []),
        "vpcs": infra_data.get("vpcs", {}).get("items", []),
        "load_balancers": infra_data.get("load_balancers", {}).get("items", []),
        "elastic_ips": infra_data.get("elastic_ips", {}).get("items", []),
        "nat_gateways": infra_data.get("nat_gateways", {}).get("items", []),
        "security_groups": infra_data.get("security_groups", {}).get("items", []),
        "vpn_connections": infra_data.get("vpn_connections", {}).get("items", []),
    }

    for rule in rules:
        if not rule.get("enabled", True):
            continue

        # Check cooldown
        last = rule.get("last_triggered")
        if last:
            try:
                last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
                cooldown = timedelta(minutes=rule.get("cooldown_minutes", 15))
                if now - last_dt < cooldown:
                    continue
            except (ValueError, TypeError):
                pass

        service = rule.get("service", "")
        resources = service_data_map.get(service, [])
        metric = rule.get("metric", "")
        operator = rule.get("operator", ">")
        threshold = rule.get("threshold")
        resource_filter = rule.get("resource_filter", "*")
        op_func = OPERATORS.get(operator)

        if not op_func:
            continue

        for res in resources:
            # Resource filter
            res_id = (
                res.get("instance_id") or res.get("channel_id") or
                res.get("flow_arn") or res.get("distribution_id") or
                res.get("name") or res.get("service") or "unknown"
            )
            if resource_filter and resource_filter != "*":
                if resource_filter not in str(res_id) and resource_filter not in str(res.get("name", "")):
                    continue

            value = _extract_metric_value(res, metric, service)
            if value is None:
                continue

            # Normalize booleans to lowercase strings for consistent comparison
            if isinstance(value, bool):
                value = str(value).lower()
            if isinstance(threshold, bool):
                threshold = str(threshold).lower()

            # Coerce types for comparison
            try:
                if isinstance(threshold, (int, float)) and not isinstance(value, str):
                    value = float(value)
                    threshold_cmp = float(threshold)
                else:
                    value = str(value)
                    threshold_cmp = str(threshold)
            except (ValueError, TypeError):
                continue

            if op_func(value, threshold_cmp):
                res_name = res.get("name", res_id)
                severity_emoji = {"critical": "🔴", "warning": "🟡", "info": "🔵"}.get(rule.get("severity"), "⚪")
                msg = (
                    f"{severity_emoji} [{rule.get('severity', 'warning').upper()}] {rule.get('name', 'Alert')}\n"
                    f"Resource: {res_name} ({res_id})\n"
                    f"Metric: {metric} = {value} (threshold: {operator} {threshold})"
                )
                triggered.append({
                    "rule": rule,
                    "resource_id": res_id,
                    "resource_name": res_name,
                    "value": value,
                    "message": msg,
                })

    # Update trigger timestamps
    if triggered:
        all_rules = get_rules()
        triggered_ids = {t["rule"]["id"] for t in triggered}
        for r in all_rules:
            if r["id"] in triggered_ids:
                r["last_triggered"] = now.isoformat()
                r["trigger_count"] = r.get("trigger_count", 0) + 1
        save_rules(all_rules)

    return triggered
