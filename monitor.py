"""
AWS Infrastructure + Video Engineering Monitor
=================================================
Monitors EC2, deployments, ECS, and AWS media services.
Evaluates custom alert rules and dispatches to all notification channels.
"""

import json
import logging
import re
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional

import boto3
from botocore.exceptions import ClientError

from config_manager import load_config
from email_notifier import send_email
from telegram_notifier import send_telegram
from slack_notifier import send_slack
from discord_notifier import send_discord
from teams_notifier import send_teams
from video_monitor import (
    check_medialive, check_mediaconnect, check_mediapackage,
    check_cloudfront, check_ivs,
)
try:
    from aws_services_monitor import (
        check_rds, check_lambda, check_s3, check_sqs, check_route53, check_apigateway,
        check_vpcs, check_load_balancers, check_elastic_ips, check_nat_gateways,
        check_security_groups, check_vpn_connections,
    )
    _AWS_SERVICES_AVAILABLE = True
except ImportError:
    _AWS_SERVICES_AVAILABLE = False
from alert_rules import evaluate_rules
from easy_monitor import run_endpoint_checks

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def _sanitize_error(e):
    msg = str(e)
    msg = re.sub(r"(AKIA|ASIA|AIDA|AROA|AIPA)[A-Z0-9]{12,}", "****", msg)
    msg = re.sub(r"\b\d{12}\b", "****", msg)
    msg = re.sub(r"arn:aws:[a-zA-Z0-9_-]+:[a-z0-9-]*:\d{12}:[^\s,\"']+", "arn:aws:****", msg)
    return msg


# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class InstanceStatus:
    instance_id: str
    name: str
    state: str
    instance_type: str
    public_ip: Optional[str]
    private_ip: Optional[str]
    az: str
    launch_time: str
    status_checks: str
    cpu_utilization: Optional[float] = None
    uptime_hours: Optional[float] = None
    uptime_display: str = ""
    region: str = ""
    alerts: list = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return self.state == "running" and self.status_checks == "ok" and len(self.alerts) == 0


def _calc_uptime(launch_time) -> tuple:
    """Calculate uptime from launch_time. Returns (hours_float, display_string)."""
    if not launch_time:
        return None, ""
    try:
        if hasattr(launch_time, 'timestamp'):
            lt = launch_time
        else:
            lt = datetime.fromisoformat(str(launch_time).replace("Z", "+00:00"))
        delta = datetime.now(timezone.utc) - lt
        total_hours = delta.total_seconds() / 3600
        days = delta.days
        hours = int((delta.seconds // 3600))
        minutes = int((delta.seconds % 3600) // 60)
        if days > 0:
            display = f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            display = f"{hours}h {minutes}m"
        else:
            display = f"{minutes}m"
        return round(total_hours, 1), display
    except Exception:
        return None, ""


@dataclass
class DeploymentStatus:
    deployment_id: str
    application: str
    group: str
    status: str
    create_time: str
    complete_time: Optional[str] = None
    error_info: Optional[str] = None
    region: str = ""


# ─── AWS Clients ─────────────────────────────────────────────────────────────

def _get_boto_kwargs(config: dict, region: str = None) -> dict:
    kwargs = {"region_name": region or config["aws"]["region"]}
    if config["aws"]["access_key_id"] and config["aws"]["secret_access_key"]:
        kwargs["aws_access_key_id"] = config["aws"]["access_key_id"]
        kwargs["aws_secret_access_key"] = config["aws"]["secret_access_key"]
    return kwargs


# ─── EC2 Monitoring ─────────────────────────────────────────────────────────

def get_instance_name(instance: dict) -> str:
    for tag in instance.get("Tags", []):
        if tag["Key"] == "Name":
            return tag["Value"]
    return "(no name)"


def get_cpu_utilization(config, instance_id: str, minutes: int = 10, region: str = None) -> Optional[float]:
    cw = boto3.client("cloudwatch", **_get_boto_kwargs(config, region))
    try:
        response = cw.get_metric_statistics(
            Namespace="AWS/EC2", MetricName="CPUUtilization",
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            StartTime=datetime.now(timezone.utc) - timedelta(minutes=minutes),
            EndTime=datetime.now(timezone.utc), Period=300, Statistics=["Average"],
        )
        dps = response.get("Datapoints", [])
        if dps:
            return round(sorted(dps, key=lambda x: x["Timestamp"])[-1]["Average"], 2)
    except ClientError as e:
        logger.warning(f"Could not get CPU for {instance_id}: {_sanitize_error(e)}")
    return None


def check_ec2_instances(config, region: str = None) -> list[InstanceStatus]:
    ec2 = boto3.client("ec2", **_get_boto_kwargs(config, region))
    instances = []
    cpu_threshold = config["monitoring"]["cpu_threshold"]

    try:
        paginator = ec2.get_paginator('describe_instances')
        reservations = []
        for page in paginator.paginate():
            reservations.extend(page.get("Reservations", []))
    except ClientError as e:
        logger.error(f"Failed to describe instances: {_sanitize_error(e)}")
        return []

    all_ids, raw = [], []
    for res in reservations:
        for inst in res.get("Instances", []):
            all_ids.append(inst["InstanceId"])
            raw.append(inst)

    # Batch status checks
    status_map = {}
    if all_ids:
        try:
            status_paginator = ec2.get_paginator('describe_instance_status')
            for page in status_paginator.paginate(InstanceIds=all_ids, IncludeAllInstances=True):
                for s in page.get("InstanceStatuses", []):
                    iid = s["InstanceId"]
                    sys_s = s.get("SystemStatus", {}).get("Status", "unknown")
                    inst_s = s.get("InstanceStatus", {}).get("Status", "unknown")
                    if sys_s == "ok" and inst_s == "ok": status_map[iid] = "ok"
                    elif "initializing" in (sys_s, inst_s): status_map[iid] = "initializing"
                    else: status_map[iid] = "impaired"
        except ClientError:
            pass

    uptime_alert_hours = config["monitoring"].get("uptime_alert_hours", 0)

    for inst in raw:
        iid = inst["InstanceId"]
        state = inst["State"]["Name"]
        sc = status_map.get(iid, "unknown")
        cpu = get_cpu_utilization(config, iid, region=region) if state == "running" else None

        # Calculate uptime for running instances
        uptime_hours, uptime_display = (None, "")
        if state == "running" and inst.get("LaunchTime"):
            uptime_hours, uptime_display = _calc_uptime(inst["LaunchTime"])

        alerts = []
        if state not in ("running", "stopped"):
            alerts.append(f"Instance state: {state}")
        if sc == "impaired":
            alerts.append("Status check FAILED")
        if cpu is not None and cpu > cpu_threshold:
            alerts.append(f"High CPU: {cpu}%")
        if uptime_alert_hours > 0 and uptime_hours is not None and uptime_hours > uptime_alert_hours:
            alerts.append(f"Running for {uptime_display} (>{uptime_alert_hours}h limit)")

        instances.append(InstanceStatus(
            instance_id=iid, name=get_instance_name(inst), state=state,
            instance_type=inst.get("InstanceType", "unknown"),
            public_ip=inst.get("PublicIpAddress"), private_ip=inst.get("PrivateIpAddress"),
            az=inst.get("Placement", {}).get("AvailabilityZone", "unknown"),
            launch_time=inst.get("LaunchTime", "").isoformat() if inst.get("LaunchTime") else "",
            status_checks=sc, cpu_utilization=cpu,
            uptime_hours=uptime_hours, uptime_display=uptime_display,
            region=region or config["aws"]["region"],
            alerts=alerts,
        ))
    return instances


# ─── CodeDeploy ──────────────────────────────────────────────────────────────

def check_deployments(config, hours: int = 24, region: str = None) -> list[DeploymentStatus]:
    cd = boto3.client("codedeploy", **_get_boto_kwargs(config, region))
    deployments = []
    try:
        apps = cd.list_applications().get("applications", [])
        for app_name in apps:
            groups = cd.list_deployment_groups(applicationName=app_name).get("deploymentGroups", [])
            for group_name in groups:
                dep_list = cd.list_deployments(
                    applicationName=app_name, deploymentGroupName=group_name,
                    createTimeRange={
                        "start": datetime.now(timezone.utc) - timedelta(hours=hours),
                        "end": datetime.now(timezone.utc),
                    },
                ).get("deployments", [])
                for dep_id in dep_list[:5]:
                    info = cd.get_deployment(deploymentId=dep_id).get("deploymentInfo", {})
                    error = info.get("errorInformation", {}).get("message") if info.get("errorInformation") else None
                    deployments.append(DeploymentStatus(
                        deployment_id=dep_id, application=app_name, group=group_name,
                        status=info.get("status", "Unknown"),
                        create_time=info.get("createTime", "").isoformat() if info.get("createTime") else "",
                        complete_time=info.get("completeTime", "").isoformat() if info.get("completeTime") else None,
                        error_info=error,
                        region=region or config["aws"]["region"],
                    ))
    except ClientError as e:
        logger.warning(f"CodeDeploy check failed: {_sanitize_error(e)}")
    return deployments


# ─── ECS ─────────────────────────────────────────────────────────────────────

def check_ecs_services(config, region: str = None) -> list[dict]:
    ecs = boto3.client("ecs", **_get_boto_kwargs(config, region))
    services = []
    try:
        paginator = ecs.get_paginator('list_clusters')
        cluster_arns = []
        for page in paginator.paginate():
            cluster_arns.extend(page.get("clusterArns", []))
        for cluster_arn in cluster_arns:
            svc_paginator = ecs.get_paginator('list_services')
            svc_arns = []
            for page in svc_paginator.paginate(cluster=cluster_arn):
                svc_arns.extend(page.get("serviceArns", []))
            if not svc_arns: continue
            all_services = []
            for i in range(0, len(svc_arns), 10):
                batch = svc_arns[i:i+10]
                resp = ecs.describe_services(cluster=cluster_arn, services=batch)
                all_services.extend(resp.get("services", []))
            svcs = all_services
            for svc in svcs:
                healthy = svc.get("runningCount", 0) >= svc.get("desiredCount", 1)
                services.append({
                    "cluster": cluster_arn.split("/")[-1],
                    "service": svc.get("serviceName", "unknown"),
                    "name": svc.get("serviceName", "unknown"),
                    "desired": svc.get("desiredCount", 0),
                    "running": svc.get("runningCount", 0),
                    "pending": svc.get("pendingCount", 0),
                    "status": svc.get("status", "unknown"),
                    "healthy": healthy,
                    "region": region or config["aws"]["region"],
                })
    except ClientError as e:
        logger.warning(f"ECS check failed: {_sanitize_error(e)}")
    return services


# ─── Notifications ───────────────────────────────────────────────────────────

def send_whatsapp(message: str, config: Optional[dict] = None) -> bool:
    if config is None: config = load_config()
    wh = config["notifications"]["channels"]["whatsapp"]
    if not wh["enabled"]: return False
    sid, token = wh["twilio_account_sid"], wh["twilio_auth_token"]
    if not sid or not token or not wh["to_number"]:
        logger.warning("Twilio not configured")
        return False
    try:
        from twilio.rest import Client
        client = Client(sid, token)
        msg = client.messages.create(body=message, from_=wh["from_number"], to=wh["to_number"])
        logger.info(f"WhatsApp sent: {msg.sid}")
        return True
    except Exception as e:
        logger.error(f"WhatsApp send failed: {_sanitize_error(e)}")
        return False


def send_to_channels(subject: str, body: str, config: dict, channels: Optional[list] = None) -> dict:
    """Send to specific channels or all enabled channels."""
    results = {}
    all_channels = config["notifications"]["channels"]

    if channels is None:
        target = [ch for ch in all_channels if all_channels[ch].get("enabled", False)]
    else:
        target = channels

    if "whatsapp" in target:
        results["whatsapp"] = send_whatsapp(body, config)
    if "email" in target:
        results["email"] = send_email(subject, body, config)
    if "telegram" in target:
        results["telegram"] = send_telegram(body, config)
    if "slack" in target:
        results["slack"] = send_slack(body, config)
    if "discord" in target:
        results["discord"] = send_discord(body, config)
    if "teams" in target:
        results["teams"] = send_teams(body, config)

    return results


def send_notifications(subject: str, body: str, config: Optional[dict] = None) -> dict:
    if config is None: config = load_config()
    if not config["notifications"]["enabled"]:
        return {"whatsapp": False, "email": False, "telegram": False, "reason": "disabled"}
    return send_to_channels(subject, body, config)


# ─── Alert Formatting ────────────────────────────────────────────────────────

def format_alert_message(instances, deployments, media_data=None, endpoint_data=None, config=None) -> Optional[str]:
    lines = []
    notif = (config or {}).get("notifications", {})

    problem = [i for i in instances if not i.healthy and i.state != "stopped"]
    if problem and notif.get("on_ec2_issues", True):
        lines.append("[ALERT] *EC2 Issues*")
        for inst in problem:
            lines.append(f"• {inst.name} ({inst.instance_id}): {', '.join(inst.alerts)}")
        lines.append("")

    failed = [d for d in deployments if d.status in ("Failed", "Stopped")]
    if failed and notif.get("on_deploy_failures", True):
        lines.append("[ALERT] *Deployment Failures*")
        for dep in failed:
            lines.append(f"• {dep.application}/{dep.group}: {dep.status}")
            if dep.error_info:
                lines.append(f"  Error: {dep.error_info[:200]}")
        lines.append("")

    # Media service alerts
    if media_data and notif.get("on_media_issues", True):
        ml = media_data.get("medialive", {})
        if ml.get("channels"):
            unhealthy = [c for c in ml["channels"] if not c["healthy"] and c["state"] == "RUNNING"]
            if unhealthy:
                lines.append("[ALERT] *MediaLive Issues*")
                for ch in unhealthy:
                    issues = []
                    if ch["input_loss"]: issues.append("INPUT LOSS")
                    if ch["active_alerts"]: issues.append(f"{ch['active_alerts']} alerts")
                    lines.append(f"• {ch['name']}: {', '.join(issues) or 'unhealthy'}")
                lines.append("")

        mc = media_data.get("mediaconnect", {})
        if mc.get("flows"):
            down = [f for f in mc["flows"] if not f["healthy"]]
            if down:
                lines.append("[ALERT] *MediaConnect Issues*")
                for f in down:
                    lines.append(f"• {f['name']}: {f['status']}")
                lines.append("")

        cf = media_data.get("cloudfront", {})
        if cf.get("distributions"):
            bad = [d for d in cf["distributions"] if not d["healthy"]]
            if bad:
                lines.append("[ALERT] *CloudFront Issues*")
                for d in bad:
                    lines.append(f"• {d['name']}: 5xx={d['error_rate_5xx']}%")
                lines.append("")

    # Easy Monitor endpoint alerts
    if endpoint_data and endpoint_data.get("endpoints"):
        down_eps = [e for e in endpoint_data["endpoints"] if e["status"] in ("down", "degraded")]
        if down_eps:
            lines.append("[ALERT] *Endpoint Issues*")
            for ep in down_eps:
                status_label = "DOWN" if ep["status"] == "down" else "DEGRADED"
                err = ep.get("error", "")
                rt = ep.get("response_time_ms", 0)
                detail = err if err else f"{rt}ms"
                lines.append(f"• {ep['endpoint_name']} [{status_label}]: {detail}")
            lines.append("")

    if lines:
        return f"AWS Alert — {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n" + "\n".join(lines)
    return None


# ─── Daily Summary ──────────────────────────────────────────────────────────

def generate_daily_summary(summary: dict) -> str:
    """Build a plain-text daily infrastructure digest."""
    lines = ["*Daily Infrastructure Summary*", ""]

    ec2 = summary.get("ec2", {})
    lines.append(f"EC2: {ec2.get('running', 0)} running / {ec2.get('total', 0)} total, {ec2.get('healthy', 0)} healthy")

    dep = summary.get("deployments", {})
    if dep.get("total", 0):
        lines.append(f"Deployments (24h): {dep.get('succeeded', 0)} succeeded, {dep.get('failed', 0)} failed")

    ecs = summary.get("ecs_services", [])
    if ecs:
        healthy_ecs = len([s for s in ecs if s.get("healthy")])
        lines.append(f"ECS: {healthy_ecs}/{len(ecs)} services healthy")

    for svc, label in [("medialive", "MediaLive"), ("mediaconnect", "MediaConnect"),
                        ("cloudfront", "CloudFront"), ("ivs", "IVS")]:
        data = summary.get(svc, {})
        items = data.get("channels", data.get("flows", data.get("distributions", data.get("streams", []))))
        if items:
            healthy = len([i for i in items if i.get("healthy")])
            lines.append(f"{label}: {healthy}/{len(items)} healthy")

    em = summary.get("easy_monitor", {})
    if em.get("total", 0):
        lines.append(f"Endpoints: {em.get('up', 0)}/{em.get('total', 0)} up")

    rules = summary.get("rule_alerts", [])
    if rules:
        lines.append(f"\nAlert rules triggered: {len(rules)}")
        for r in rules[:5]:
            lines.append(f"• {r['rule_name']}: {r['message'][:100]}")

    lines.append(f"\nGenerated {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}")
    return "\n".join(lines)


def send_daily_summary() -> None:
    """Run a full check and send the summary to all enabled channels."""
    config = load_config()
    notif = config.get("notifications", {})
    if not notif.get("enabled") or not notif.get("send_daily_summary"):
        return
    try:
        summary = run_check(send_alerts=False)
        body = generate_daily_summary(summary)
        send_to_channels("AWS Daily Summary", body, config)
        logger.info("Daily summary sent")
    except Exception as e:
        logger.error(f"Daily summary failed: {_sanitize_error(e)}")


# ─── Summary + Main Check ───────────────────────────────────────────────────

def generate_summary(instances, deployments, ecs_services, media_data=None) -> dict:
    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ec2": {
            "total": len(instances),
            "running": len([i for i in instances if i.state == "running"]),
            "healthy": len([i for i in instances if i.healthy]),
            "alerts": len([i for i in instances if i.alerts]),
            "instances": [asdict(i) for i in instances],
        },
        "deployments": {
            "total": len(deployments),
            "succeeded": len([d for d in deployments if d.status == "Succeeded"]),
            "failed": len([d for d in deployments if d.status == "Failed"]),
            "in_progress": len([d for d in deployments if d.status == "InProgress"]),
            "items": [asdict(d) for d in deployments],
        },
        "ecs_services": ecs_services,
    }

    if media_data:
        summary.update(media_data)

    return summary


def _merge_media(media_data, key, new_data, list_key):
    """Merge media service results from multiple regions."""
    if key not in media_data:
        media_data[key] = new_data
        return
    existing = media_data[key]
    existing[list_key].extend(new_data.get(list_key, []))
    for k in ("total", "running", "healthy", "live"):
        if k in new_data:
            existing[k] = existing.get(k, 0) + new_data[k]


def run_check(send_alerts: bool = True) -> dict:
    config = load_config()
    mon = config["monitoring"]
    regions = config["aws"].get("regions", [config["aws"]["region"]])
    logger.info(f"Running AWS health check across {len(regions)} region(s)...")

    all_instances = []
    all_deployments = []
    all_ecs_services = []
    media_data = {}

    for region in regions:
        if mon["monitor_ec2"]:
            all_instances.extend(check_ec2_instances(config, region=region))
        if mon["monitor_codedeploy"]:
            all_deployments.extend(check_deployments(config, hours=mon["deployment_lookback_hours"], region=region))
        if mon["monitor_ecs"]:
            all_ecs_services.extend(check_ecs_services(config, region=region))
        if mon.get("monitor_medialive"):
            ml = check_medialive(config, region=region)
            for ch in ml.get("channels", []): ch["region"] = region
            _merge_media(media_data, "medialive", ml, "channels")
        if mon.get("monitor_mediaconnect"):
            mc = check_mediaconnect(config, region=region)
            for f in mc.get("flows", []): f["region"] = region
            _merge_media(media_data, "mediaconnect", mc, "flows")
        if mon.get("monitor_mediapackage"):
            mp = check_mediapackage(config, region=region)
            for ch in mp.get("channels", []): ch["region"] = region
            _merge_media(media_data, "mediapackage", mp, "channels")
        if mon.get("monitor_cloudfront"):
            cf = check_cloudfront(config, region=region)
            for d in cf.get("distributions", []): d["region"] = region
            _merge_media(media_data, "cloudfront", cf, "distributions")
        if mon.get("monitor_ivs"):
            ivs = check_ivs(config, region=region)
            for ch in ivs.get("channels", []): ch["region"] = region
            _merge_media(media_data, "ivs", ivs, "channels")

        # AWS Services + Networking monitors
        if _AWS_SERVICES_AVAILABLE:
            if mon.get("monitor_rds"):
                rds_data = check_rds(config, region=region)
                for item in rds_data.get("items", []): item["region"] = region
                _merge_media(media_data, "rds", rds_data, "items")
            if mon.get("monitor_lambda"):
                lam_data = check_lambda(config, region=region)
                for item in lam_data.get("items", []): item["region"] = region
                _merge_media(media_data, "lambda_functions", lam_data, "items")
            if mon.get("monitor_s3"):
                s3_data = check_s3(config, region=region)
                for item in s3_data.get("items", []): item["region"] = region
                _merge_media(media_data, "s3", s3_data, "items")
            if mon.get("monitor_sqs"):
                sqs_data = check_sqs(config, region=region)
                for item in sqs_data.get("items", []): item["region"] = region
                _merge_media(media_data, "sqs", sqs_data, "items")
            if mon.get("monitor_route53"):
                r53_data = check_route53(config, region=region)
                for item in r53_data.get("items", []): item["region"] = region
                _merge_media(media_data, "route53", r53_data, "items")
            if mon.get("monitor_apigateway"):
                apigw_data = check_apigateway(config, region=region)
                for item in apigw_data.get("items", []): item["region"] = region
                _merge_media(media_data, "apigateway", apigw_data, "items")
            if mon.get("monitor_vpc"):
                vpc_data = check_vpcs(config, region=region)
                for item in vpc_data.get("items", []): item["region"] = region
                _merge_media(media_data, "vpcs", vpc_data, "items")
            if mon.get("monitor_elb"):
                elb_data = check_load_balancers(config, region=region)
                for item in elb_data.get("items", []): item["region"] = region
                _merge_media(media_data, "load_balancers", elb_data, "items")
            if mon.get("monitor_eip"):
                eip_data = check_elastic_ips(config, region=region)
                for item in eip_data.get("items", []): item["region"] = region
                _merge_media(media_data, "elastic_ips", eip_data, "items")
            if mon.get("monitor_nat"):
                nat_data = check_nat_gateways(config, region=region)
                for item in nat_data.get("items", []): item["region"] = region
                _merge_media(media_data, "nat_gateways", nat_data, "items")
            if mon.get("monitor_security_groups"):
                sg_data = check_security_groups(config, region=region)
                for item in sg_data.get("items", []): item["region"] = region
                _merge_media(media_data, "security_groups", sg_data, "items")
            if mon.get("monitor_vpn"):
                vpn_data = check_vpn_connections(config, region=region)
                for item in vpn_data.get("items", []): item["region"] = region
                _merge_media(media_data, "vpn_connections", vpn_data, "items")

    instances = all_instances
    deployments = all_deployments
    ecs_services = all_ecs_services

    summary = generate_summary(instances, deployments, ecs_services, media_data)

    # Easy Monitor endpoint checks
    endpoint_results = run_endpoint_checks()
    if endpoint_results["total"] > 0:
        summary["easy_monitor"] = endpoint_results

    if send_alerts:
        # Built-in alerts
        alert_msg = format_alert_message(instances, deployments, media_data, endpoint_results, config)
        if alert_msg:
            results = send_notifications("AWS Infrastructure Alert", alert_msg, config)
            summary["notification_results"] = results

        # Custom alert rules
        rule_alerts = evaluate_rules(summary)
        if rule_alerts:
            summary["rule_alerts"] = [
                {"rule_id": a["rule"]["id"], "rule_name": a["rule"]["name"],
                 "resource": a["resource_name"], "value": a["value"],
                 "severity": a["rule"]["severity"], "message": a["message"]}
                for a in rule_alerts
            ]
            # Send rule alerts per their configured channels
            for alert in rule_alerts:
                rule = alert["rule"]
                channels = rule.get("channels", ["email", "telegram", "whatsapp"])
                send_to_channels(
                    f"Alert: {rule['name']}",
                    alert["message"],
                    config,
                    channels=channels,
                )

        if not alert_msg and not rule_alerts:
            logger.info("All systems healthy — no alerts")

    return summary


if __name__ == "__main__":
    result = run_check()
    print(json.dumps(result, indent=2, default=str))
