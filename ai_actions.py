"""
AI Actions — Registry of actions the AI assistant can propose and execute
==========================================================================
Each action defines what the AI can do, its risk level, required parameters,
and how it maps to backend functions. The AI proposes actions, the user
confirms, and the dashboard executes them.
"""

import logging

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# ACTION REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════

ACTION_REGISTRY = [
    # ── EC2 / Cloud Actions ──
    {
        "id": "build_aws_ami",
        "name": "Build AWS AMI",
        "category": "image_build",
        "risk": "high",
        "description": "Create a reusable AMI from a running EC2 media instance. "
                       "Stops the instance, snapshots it, and creates the AMI.",
        "params": [
            {"name": "instance_id", "type": "string", "required": True, "description": "EC2 instance ID to image"},
            {"name": "name", "type": "string", "required": True, "description": "Name for the AMI"},
            {"name": "description", "type": "string", "required": False, "description": "AMI description"},
            {"name": "region", "type": "string", "required": False, "description": "AWS region"},
        ],
        "confirm_message": "This will stop the instance and create an AMI. The instance will be stopped during the process.",
    },
    {
        "id": "launch_ec2_media",
        "name": "Launch EC2 Media Instance",
        "category": "cloud",
        "risk": "high",
        "description": "Launch a new EC2 instance from a media template. "
                       "Includes provisioning scripts for encoding, streaming, GPU, and more.",
        "params": [
            {"name": "template_id", "type": "string", "required": True, "description": "Template ID (e.g. ec2_encoding)"},
            {"name": "region", "type": "string", "required": False, "description": "AWS region"},
            {"name": "instance_type", "type": "string", "required": False, "description": "Override instance type"},
            {"name": "key_name", "type": "string", "required": False, "description": "SSH key pair name"},
            {"name": "security_group_id", "type": "string", "required": False, "description": "Security group ID"},
            {"name": "build_ami", "type": "boolean", "required": False, "description": "Tag for AMI building"},
            {"name": "instance_name", "type": "string", "required": False, "description": "Custom instance name"},
        ],
        "confirm_message": "This will launch a new EC2 instance which will incur AWS charges.",
    },
    {
        "id": "list_ec2_media",
        "name": "List EC2 Media Instances",
        "category": "cloud",
        "risk": "low",
        "description": "List all dashboard-managed EC2 media instances with their status, IPs, and template info.",
        "params": [
            {"name": "region", "type": "string", "required": False, "description": "AWS region (default: primary region)"},
        ],
        "confirm_message": None,  # Low risk — no confirmation needed
    },
    # ── Monitoring Actions ──
    {
        "id": "check_status",
        "name": "Check Infrastructure Status",
        "category": "monitoring",
        "risk": "low",
        "description": "Run a full infrastructure check across all monitored AWS services.",
        "params": [],
        "confirm_message": None,
    },
    {
        "id": "add_alert_rule",
        "name": "Add Alert Rule",
        "category": "alerts",
        "risk": "medium",
        "description": "Create a new alert rule for monitoring a specific metric.",
        "params": [
            {"name": "name", "type": "string", "required": True, "description": "Rule name"},
            {"name": "service", "type": "string", "required": True, "description": "AWS service (ec2, medialive, etc.)"},
            {"name": "metric", "type": "string", "required": True, "description": "Metric to monitor"},
            {"name": "operator", "type": "string", "required": True, "description": "Comparison operator"},
            {"name": "threshold", "type": "number", "required": True, "description": "Threshold value"},
            {"name": "severity", "type": "string", "required": False, "description": "warning or critical"},
        ],
        "confirm_message": "This will create a new alert rule.",
    },
    {
        "id": "add_endpoint_monitor",
        "name": "Add Endpoint Monitor",
        "category": "monitoring",
        "risk": "low",
        "description": "Add a new endpoint monitor (HTTP, TCP, ping, or JSON API).",
        "params": [
            {"name": "name", "type": "string", "required": True, "description": "Endpoint name"},
            {"name": "type", "type": "string", "required": True, "description": "http, tcp, ping, or json_api"},
            {"name": "url", "type": "string", "required": False, "description": "URL for HTTP/JSON monitors"},
            {"name": "host", "type": "string", "required": False, "description": "Host for TCP/ping monitors"},
            {"name": "port", "type": "number", "required": False, "description": "Port for TCP monitors"},
        ],
        "confirm_message": None,
    },
    {
        "id": "test_notification",
        "name": "Test Notification Channel",
        "category": "notifications",
        "risk": "low",
        "description": "Send a test notification via email, Telegram, Slack, or WhatsApp.",
        "params": [
            {"name": "channel", "type": "string", "required": True, "description": "email, telegram, slack, or whatsapp"},
        ],
        "confirm_message": None,
    },
    {
        "id": "run_endpoint_check",
        "name": "Run Endpoint Checks",
        "category": "monitoring",
        "risk": "low",
        "description": "Run all configured endpoint health checks immediately.",
        "params": [],
        "confirm_message": None,
    },
    {
        "id": "ec2_instance_action",
        "name": "EC2 Instance Action",
        "category": "cloud",
        "risk": "high",
        "description": "Start, stop, reboot, or terminate an EC2 instance.",
        "params": [
            {"name": "instance_id", "type": "string", "required": True, "description": "EC2 instance ID"},
            {"name": "action", "type": "string", "required": True, "description": "start, stop, reboot, or terminate"},
            {"name": "region", "type": "string", "required": False, "description": "AWS region"},
        ],
        "confirm_message": "This will perform an action on the EC2 instance.",
    },
    {
        "id": "list_custom_amis",
        "name": "List Custom AMIs",
        "category": "cloud",
        "risk": "low",
        "description": "List all custom AMIs owned by this account.",
        "params": [
            {"name": "region", "type": "string", "required": False, "description": "AWS region"},
        ],
        "confirm_message": None,
    },
    {
        "id": "deregister_ami",
        "name": "Deregister AMI",
        "category": "cloud",
        "risk": "high",
        "description": "Delete a custom AMI and its associated snapshots.",
        "params": [
            {"name": "ami_id", "type": "string", "required": True, "description": "AMI ID to deregister"},
            {"name": "region", "type": "string", "required": False, "description": "AWS region"},
        ],
        "confirm_message": "This will permanently delete the AMI and its snapshots.",
    },
    {
        "id": "describe_infrastructure",
        "name": "Describe Infrastructure",
        "category": "monitoring",
        "risk": "low",
        "description": "Get a summary of all monitored infrastructure components.",
        "params": [],
        "confirm_message": None,
    },
    {
        "id": "check_medialive",
        "name": "Check MediaLive Channels",
        "category": "monitoring",
        "risk": "low",
        "description": "Check the status of all MediaLive channels.",
        "params": [],
        "confirm_message": None,
    },
    {
        "id": "check_mediaconnect",
        "name": "Check MediaConnect Flows",
        "category": "monitoring",
        "risk": "low",
        "description": "Check the status of all MediaConnect flows.",
        "params": [],
        "confirm_message": None,
    },
    {
        "id": "check_cloudfront",
        "name": "Check CloudFront Distributions",
        "category": "monitoring",
        "risk": "low",
        "description": "Check CloudFront distribution health and error rates.",
        "params": [],
        "confirm_message": None,
    },
    {
        "id": "check_ecs",
        "name": "Check ECS Services",
        "category": "monitoring",
        "risk": "low",
        "description": "Check ECS cluster and service health.",
        "params": [],
        "confirm_message": None,
    },
    {
        "id": "check_ivs",
        "name": "Check IVS Channels",
        "category": "monitoring",
        "risk": "low",
        "description": "Check IVS channel status and stream health.",
        "params": [],
        "confirm_message": None,
    },
    {
        "id": "get_cost_summary",
        "name": "Get Cost Summary",
        "category": "monitoring",
        "risk": "low",
        "description": "Get a summary of current AWS costs by service.",
        "params": [
            {"name": "days", "type": "number", "required": False, "description": "Number of days to look back (default 30)"},
        ],
        "confirm_message": None,
    },
    {
        "id": "update_monitoring_config",
        "name": "Update Monitoring Config",
        "category": "config",
        "risk": "medium",
        "description": "Update monitoring settings like check interval, CPU threshold, or enabled services.",
        "params": [
            {"name": "setting", "type": "string", "required": True, "description": "Setting name"},
            {"name": "value", "type": "string", "required": True, "description": "New value"},
        ],
        "confirm_message": "This will update the monitoring configuration.",
    },
    {
        "id": "list_alert_rules",
        "name": "List Alert Rules",
        "category": "alerts",
        "risk": "low",
        "description": "List all configured alert rules with their status.",
        "params": [],
        "confirm_message": None,
    },
    {
        "id": "delete_alert_rule",
        "name": "Delete Alert Rule",
        "category": "alerts",
        "risk": "medium",
        "description": "Delete an existing alert rule.",
        "params": [
            {"name": "rule_id", "type": "string", "required": True, "description": "Rule ID to delete"},
        ],
        "confirm_message": "This will permanently delete the alert rule.",
    },
    {
        "id": "toggle_service_monitoring",
        "name": "Toggle Service Monitoring",
        "category": "config",
        "risk": "medium",
        "description": "Enable or disable monitoring for a specific AWS service.",
        "params": [
            {"name": "service", "type": "string", "required": True, "description": "Service name (ec2, medialive, etc.)"},
            {"name": "enabled", "type": "boolean", "required": True, "description": "Enable or disable"},
        ],
        "confirm_message": "This will change which services are monitored.",
    },
    {
        "id": "list_ec2_templates",
        "name": "List EC2 Media Templates",
        "category": "cloud",
        "risk": "low",
        "description": "List all available EC2 media instance templates (Linux and Windows).",
        "params": [],
        "confirm_message": None,
    },
    {
        "id": "get_vpc_info",
        "name": "Get VPC Info",
        "category": "cloud",
        "risk": "low",
        "description": "List security groups and key pairs available for EC2 launches.",
        "params": [
            {"name": "region", "type": "string", "required": False, "description": "AWS region"},
        ],
        "confirm_message": None,
    },
    # ── Incident Management Actions ──
    {
        "id": "list_incidents",
        "name": "List Incidents",
        "category": "incidents",
        "risk": "low",
        "description": "List current incidents, optionally filtered by status or severity.",
        "params": [
            {"name": "status", "type": "string", "required": False, "description": "Filter: open, acknowledged, or resolved"},
            {"name": "severity", "type": "string", "required": False, "description": "Filter: critical, warning, or info"},
        ],
        "confirm_message": None,
    },
    {
        "id": "acknowledge_incident",
        "name": "Acknowledge Incident",
        "category": "incidents",
        "risk": "medium",
        "description": "Acknowledge an open incident and optionally assign it to someone.",
        "params": [
            {"name": "incident_id", "type": "number", "required": True, "description": "Incident ID to acknowledge"},
            {"name": "assigned_to", "type": "string", "required": False, "description": "Person to assign the incident to"},
        ],
        "confirm_message": "This will acknowledge the incident.",
    },
    {
        "id": "resolve_incident",
        "name": "Resolve Incident",
        "category": "incidents",
        "risk": "medium",
        "description": "Resolve an open or acknowledged incident with an optional resolution note.",
        "params": [
            {"name": "incident_id", "type": "number", "required": True, "description": "Incident ID to resolve"},
            {"name": "resolution_note", "type": "string", "required": False, "description": "Resolution note"},
        ],
        "confirm_message": "This will resolve the incident.",
    },
    # ── AWS Services ──
    {
        "id": "check_rds",
        "name": "Check RDS Instances",
        "category": "monitoring",
        "risk": "low",
        "description": "Check all RDS database instances, engine, status, and multi-AZ.",
        "params": [],
        "confirm_message": None,
    },
    {
        "id": "check_lambda",
        "name": "Check Lambda Functions",
        "category": "monitoring",
        "risk": "low",
        "description": "Check all Lambda functions, runtime, memory, and code size.",
        "params": [],
        "confirm_message": None,
    },
    {
        "id": "check_s3",
        "name": "Check S3 Buckets",
        "category": "monitoring",
        "risk": "low",
        "description": "Check all S3 storage buckets.",
        "params": [],
        "confirm_message": None,
    },
    {
        "id": "check_sqs",
        "name": "Check SQS Queues",
        "category": "monitoring",
        "risk": "low",
        "description": "Check SQS message queues and message counts.",
        "params": [],
        "confirm_message": None,
    },
    {
        "id": "check_route53",
        "name": "Check Route53 DNS",
        "category": "monitoring",
        "risk": "low",
        "description": "Check Route53 hosted zones and health checks.",
        "params": [],
        "confirm_message": None,
    },
    {
        "id": "check_apigateway",
        "name": "Check API Gateway",
        "category": "monitoring",
        "risk": "low",
        "description": "Check API Gateway REST APIs and endpoint types.",
        "params": [],
        "confirm_message": None,
    },
    # ── Networking ──
    {
        "id": "check_vpcs",
        "name": "Check VPCs",
        "category": "monitoring",
        "risk": "low",
        "description": "Check VPCs, subnets, CIDR blocks, and state.",
        "params": [],
        "confirm_message": None,
    },
    {
        "id": "check_load_balancers",
        "name": "Check Load Balancers",
        "category": "monitoring",
        "risk": "low",
        "description": "Check ALB/NLB load balancers, targets, and health.",
        "params": [],
        "confirm_message": None,
    },
    {
        "id": "check_elastic_ips",
        "name": "Check Elastic IPs",
        "category": "monitoring",
        "risk": "low",
        "description": "Check Elastic IP addresses and their associations.",
        "params": [],
        "confirm_message": None,
    },
    {
        "id": "check_nat_gateways",
        "name": "Check NAT Gateways",
        "category": "monitoring",
        "risk": "low",
        "description": "Check NAT gateways state, subnet, and public IPs.",
        "params": [],
        "confirm_message": None,
    },
    {
        "id": "check_security_groups",
        "name": "Check Security Groups",
        "category": "monitoring",
        "risk": "low",
        "description": "Check security groups, rules, and open-to-world detection.",
        "params": [],
        "confirm_message": None,
    },
    {
        "id": "check_vpn_connections",
        "name": "Check VPN Connections",
        "category": "monitoring",
        "risk": "low",
        "description": "Check site-to-site VPN connections, tunnel status, and transit gateways.",
        "params": [],
        "confirm_message": None,
    },
    # ── Logs ──
    {
        "id": "search_logs",
        "name": "Search CloudWatch Logs",
        "category": "monitoring",
        "risk": "low",
        "description": "Search CloudWatch log groups using Insights queries.",
        "params": [
            {"name": "group", "type": "string", "required": True, "description": "Log group name"},
            {"name": "query", "type": "string", "required": False, "description": "CloudWatch Insights query"},
            {"name": "hours_back", "type": "number", "required": False, "description": "Hours to look back (default 1)"},
        ],
        "confirm_message": None,
    },
    # ── Costs ──
    {
        "id": "get_daily_costs",
        "name": "Get Daily Costs",
        "category": "monitoring",
        "risk": "low",
        "description": "Get daily AWS cost breakdown by service.",
        "params": [
            {"name": "days", "type": "number", "required": False, "description": "Number of days (default 30)"},
        ],
        "confirm_message": None,
    },
    {
        "id": "get_budget_status",
        "name": "Get Budget Status",
        "category": "monitoring",
        "risk": "low",
        "description": "Get AWS Budgets status and usage percentages.",
        "params": [],
        "confirm_message": None,
    },
    # ── Schedules ──
    {
        "id": "list_schedules",
        "name": "List Schedules",
        "category": "schedules",
        "risk": "low",
        "description": "List all configured scheduled actions.",
        "params": [],
        "confirm_message": None,
    },
    {
        "id": "create_schedule",
        "name": "Create Schedule",
        "category": "schedules",
        "risk": "medium",
        "description": "Create a new scheduled action with a cron expression.",
        "params": [
            {"name": "name", "type": "string", "required": True, "description": "Schedule name"},
            {"name": "action_id", "type": "string", "required": True, "description": "Action to execute"},
            {"name": "cron_expression", "type": "string", "required": True, "description": "Cron expression (min hour day month weekday)"},
            {"name": "action_params", "type": "object", "required": False, "description": "Action parameters"},
            {"name": "description", "type": "string", "required": False, "description": "Schedule description"},
        ],
        "confirm_message": "This will create a recurring scheduled action.",
    },
    {
        "id": "delete_schedule",
        "name": "Delete Schedule",
        "category": "schedules",
        "risk": "medium",
        "description": "Delete a scheduled action.",
        "params": [
            {"name": "schedule_id", "type": "number", "required": True, "description": "Schedule ID to delete"},
        ],
        "confirm_message": "This will permanently delete the schedule.",
    },
    # ── GCP ──
    {
        "id": "list_gce_instances",
        "name": "List GCE Instances",
        "category": "cloud",
        "risk": "low",
        "description": "List all Google Compute Engine virtual machines.",
        "params": [
            {"name": "region", "type": "string", "required": False, "description": "GCP region filter"},
        ],
        "confirm_message": None,
    },
    {
        "id": "launch_gce_instance",
        "name": "Launch GCE Instance",
        "category": "cloud",
        "risk": "high",
        "description": "Launch a new Google Compute Engine instance.",
        "params": [
            {"name": "name", "type": "string", "required": True, "description": "Instance name"},
            {"name": "zone", "type": "string", "required": True, "description": "GCP zone (e.g. us-central1-a)"},
            {"name": "machine_type", "type": "string", "required": True, "description": "Machine type (e.g. n2-standard-4)"},
            {"name": "image_project", "type": "string", "required": False, "description": "Image project (default ubuntu-os-cloud)"},
            {"name": "image_family", "type": "string", "required": False, "description": "Image family (default ubuntu-2204-lts)"},
        ],
        "confirm_message": "This will launch a new GCE instance which will incur Google Cloud charges.",
    },
    {
        "id": "gce_instance_action",
        "name": "GCE Instance Action",
        "category": "cloud",
        "risk": "high",
        "description": "Start, stop, reset, or delete a GCE instance.",
        "params": [
            {"name": "instance_name", "type": "string", "required": True, "description": "Instance name"},
            {"name": "zone", "type": "string", "required": True, "description": "GCP zone"},
            {"name": "action", "type": "string", "required": True, "description": "start, stop, reset, or delete"},
        ],
        "confirm_message": "This will perform an action on the GCE instance.",
    },
    {
        "id": "check_gke_clusters",
        "name": "Check GKE Clusters",
        "category": "monitoring",
        "risk": "low",
        "description": "Check Google Kubernetes Engine clusters.",
        "params": [],
        "confirm_message": None,
    },
    {
        "id": "check_cloud_run",
        "name": "Check Cloud Run Services",
        "category": "monitoring",
        "risk": "low",
        "description": "Check Google Cloud Run services.",
        "params": [
            {"name": "region", "type": "string", "required": False, "description": "GCP region filter"},
        ],
        "confirm_message": None,
    },
]


def get_action(action_id):
    """Look up an action by ID."""
    for action in ACTION_REGISTRY:
        if action["id"] == action_id:
            return action
    return None


def get_actions_by_category(category):
    """Get all actions in a category."""
    return [a for a in ACTION_REGISTRY if a["category"] == category]


def get_actions_by_risk(risk):
    """Get all actions at a specific risk level."""
    return [a for a in ACTION_REGISTRY if a["risk"] == risk]


def get_action_summary():
    """Get a summary for the AI system prompt."""
    lines = []
    for action in ACTION_REGISTRY:
        params = ", ".join(p["name"] for p in action.get("params", []) if p.get("required"))
        risk_label = f"[{action['risk'].upper()}]"
        lines.append(f"- {action['id']}: {action['name']} {risk_label} — {action['description']}"
                     + (f" (requires: {params})" if params else ""))
    return "\n".join(lines)
