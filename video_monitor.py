"""
Video Engineering AWS Monitors
================================
Monitors AWS media services critical for live video workflows:
  - MediaLive      — Live encoding channels, pipeline health, input status
  - MediaConnect   — Reliable video transport flows (SRT, RIST, Zixi)
  - MediaPackage   — Origin/packaging for HLS, DASH, CMAF
  - CloudFront     — CDN distributions, error rates, cache stats
  - IVS            — Interactive Video Service channels and streams

All configurable from the Settings UI via monitoring toggles.
"""

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def _sanitize_error(e):
    msg = str(e)
    msg = re.sub(r"(AKIA|ASIA|AIDA|AROA|AIPA)[A-Z0-9]{12,}", "****", msg)
    msg = re.sub(r"\b\d{12}\b", "****", msg)
    msg = re.sub(r"arn:aws:[a-zA-Z0-9_-]+:[a-z0-9-]*:\d{12}:[^\s,\"']+", "arn:aws:****", msg)
    return msg


def _get_boto_kwargs(config: dict, region: str = None) -> dict:
    kwargs = {"region_name": region or config["aws"]["region"]}
    if config["aws"]["access_key_id"] and config["aws"]["secret_access_key"]:
        kwargs["aws_access_key_id"] = config["aws"]["access_key_id"]
        kwargs["aws_secret_access_key"] = config["aws"]["secret_access_key"]
    return kwargs


# ═════════════════════════════════════════════════════════════════════════════
# AWS MEDIALIVE
# ═════════════════════════════════════════════════════════════════════════════

def check_medialive(config: dict, region: str = None) -> dict:
    """
    Check all MediaLive channels: state, pipeline status, inputs, alerts.
    """
    client = boto3.client("medialive", **_get_boto_kwargs(config, region))
    cw = boto3.client("cloudwatch", **_get_boto_kwargs(config, region))
    channels = []

    try:
        paginator = client.get_paginator("list_channels")
        for page in paginator.paginate():
            for ch in page.get("Channels", []):
                channel_id = ch["Id"]
                name = ch.get("Name", channel_id)
                state = ch.get("State", "UNKNOWN")

                # Get detailed info
                pipeline_details = []
                alerts_detail = []
                input_attachments = []
                try:
                    detail = client.describe_channel(ChannelId=channel_id)
                    pipeline_details = detail.get("PipelineDetails", [])
                    input_attachments = [
                        {
                            "name": ia.get("InputAttachmentName", ""),
                            "input_id": ia.get("InputId", ""),
                        }
                        for ia in detail.get("InputAttachments", [])
                    ]
                    # Channel-level alerts
                    for pd in pipeline_details:
                        for alert in pd.get("ActiveAlerts", []):
                            alerts_detail.append({
                                "pipeline": pd.get("PipelineId", ""),
                                "message": alert.get("AlertMessage", ""),
                                "code": alert.get("AlertCode", ""),
                            })
                except ClientError:
                    pass

                pipelines_running = sum(
                    1 for p in pipeline_details
                    if p.get("ActiveInputAttachmentName")
                )

                # Check for input loss via CloudWatch
                input_loss = False
                try:
                    resp = cw.get_metric_statistics(
                        Namespace="MediaLive",
                        MetricName="InputVideoFrameRate",
                        Dimensions=[{"Name": "ChannelId", "Value": channel_id}, {"Name": "Pipeline", "Value": "0"}],
                        StartTime=datetime.now(timezone.utc) - timedelta(minutes=5),
                        EndTime=datetime.now(timezone.utc),
                        Period=60,
                        Statistics=["Average"],
                    )
                    dps = resp.get("Datapoints", [])
                    if dps:
                        latest = sorted(dps, key=lambda x: x["Timestamp"])[-1]
                        if latest["Average"] < 1.0:
                            input_loss = True
                    elif state == "RUNNING":
                        input_loss = True  # No data while running = likely loss
                except ClientError:
                    pass

                channels.append({
                    "channel_id": channel_id,
                    "name": name,
                    "state": state,
                    "pipelines_running": pipelines_running,
                    "pipeline_count": len(pipeline_details),
                    "pipeline_details": [
                        {
                            "pipeline_id": p.get("PipelineId", ""),
                            "active_input": p.get("ActiveInputAttachmentName", ""),
                            "active_input_switch_action": p.get("ActiveInputSwitchActionName", ""),
                        }
                        for p in pipeline_details
                    ],
                    "input_attachments": input_attachments,
                    "input_loss": input_loss,
                    "alerts_detail": alerts_detail,
                    "active_alerts": len(alerts_detail),
                    "healthy": state == "RUNNING" and not input_loss and len(alerts_detail) == 0,
                })

    except ClientError as e:
        logger.warning(f"MediaLive check failed: {_sanitize_error(e)}")

    return {
        "total": len(channels),
        "running": sum(1 for c in channels if c["state"] == "RUNNING"),
        "healthy": sum(1 for c in channels if c["healthy"]),
        "alerts": sum(c["active_alerts"] for c in channels),
        "channels": channels,
    }


# ═════════════════════════════════════════════════════════════════════════════
# AWS MEDIACONNECT
# ═════════════════════════════════════════════════════════════════════════════

def check_mediaconnect(config: dict, region: str = None) -> dict:
    """Check MediaConnect flows: status, source health, outputs."""
    client = boto3.client("mediaconnect", **_get_boto_kwargs(config, region))
    flows = []

    try:
        paginator = client.get_paginator("list_flows")
        for page in paginator.paginate():
            for flow_item in page.get("Flows", []):
                flow_arn = flow_item["FlowArn"]
                name = flow_item.get("Name", flow_arn.split("/")[-1])
                status = flow_item.get("Status", "UNKNOWN")

                # Get detail for source info
                source_info = {}
                outputs_info = []
                try:
                    detail = client.describe_flow(FlowArn=flow_arn)
                    flow_detail = detail.get("Flow", {})
                    source = flow_detail.get("Source", {})
                    source_info = {
                        "name": source.get("Name", ""),
                        "protocol": source.get("Transport", {}).get("Protocol", "unknown"),
                        "ip": source.get("IngestIp", ""),
                        "port": source.get("IngestPort", ""),
                        "whitelist_cidr": source.get("WhitelistCidr", ""),
                    }
                    for out in flow_detail.get("Outputs", []):
                        outputs_info.append({
                            "name": out.get("Name", ""),
                            "protocol": out.get("Transport", {}).get("Protocol", "unknown") if out.get("Transport") else "unknown",
                            "destination": out.get("Destination", ""),
                            "port": out.get("Port", ""),
                        })
                except ClientError:
                    pass

                flows.append({
                    "flow_arn": flow_arn,
                    "name": name,
                    "status": status,
                    "source": source_info,
                    "source_health": "HEALTHY" if status == "ACTIVE" else "UNKNOWN",
                    "outputs": outputs_info,
                    "output_count": len(outputs_info),
                    "healthy": status == "ACTIVE",
                })

    except ClientError as e:
        logger.warning(f"MediaConnect check failed: {_sanitize_error(e)}")

    return {
        "total": len(flows),
        "active": sum(1 for f in flows if f["status"] == "ACTIVE"),
        "healthy": sum(1 for f in flows if f["healthy"]),
        "flows": flows,
    }


# ═════════════════════════════════════════════════════════════════════════════
# AWS MEDIAPACKAGE
# ═════════════════════════════════════════════════════════════════════════════

def check_mediapackage(config: dict, region: str = None) -> dict:
    """Check MediaPackage channels and origin endpoints."""
    client = boto3.client("mediapackage", **_get_boto_kwargs(config, region))
    channels = []

    try:
        resp = client.list_channels(MaxResults=100)
        for ch in resp.get("Channels", []):
            ch_id = ch["Id"]

            # List endpoints for this channel
            endpoints = []
            try:
                ep_resp = client.list_origin_endpoints(ChannelId=ch_id, MaxResults=100)
                for ep in ep_resp.get("OriginEndpoints", []):
                    endpoints.append({
                        "id": ep["Id"],
                        "url": ep.get("Url", ""),
                        "manifest_name": ep.get("ManifestName", ""),
                        "packaging": (
                            "HLS" if ep.get("HlsPackage") else
                            "DASH" if ep.get("DashPackage") else
                            "CMAF" if ep.get("CmafPackage") else
                            "MSS" if ep.get("MssPackage") else "unknown"
                        ),
                        "startover_window": ep.get("StartoverWindowSeconds", 0),
                        "time_delay": ep.get("TimeDelaySeconds", 0),
                    })
            except ClientError:
                pass

            channels.append({
                "channel_id": ch_id,
                "name": ch.get("Description", ch_id),
                "status": "ACTIVE",  # MediaPackage channels are always active
                "ingest_endpoints": [
                    {"url": ie.get("Url", ""), "username": ie.get("Username", "")}
                    for ie in ch.get("HlsIngest", {}).get("IngestEndpoints", [])
                ],
                "endpoints": endpoints,
                "endpoint_count": len(endpoints),
                "healthy": len(endpoints) > 0,
            })

    except ClientError as e:
        logger.warning(f"MediaPackage check failed: {_sanitize_error(e)}")

    return {
        "total": len(channels),
        "with_endpoints": sum(1 for c in channels if c["endpoint_count"] > 0),
        "channels": channels,
    }


# ═════════════════════════════════════════════════════════════════════════════
# CLOUDFRONT CDN
# ═════════════════════════════════════════════════════════════════════════════

def check_cloudfront(config: dict, region: str = None) -> dict:
    """Check CloudFront distributions: status, error rates."""
    client = boto3.client("cloudfront", **_get_boto_kwargs(config, region))
    cw = boto3.client("cloudwatch", **_get_boto_kwargs(config, region))
    distributions = []

    try:
        paginator = client.get_paginator("list_distributions")
        for page in paginator.paginate():
            dist_list = page.get("DistributionList", {})
            for dist in dist_list.get("Items", []):
                dist_id = dist["Id"]
                domain = dist.get("DomainName", "")
                status = dist.get("Status", "Unknown")
                enabled = dist.get("Enabled", False)

                # Get error rates from CloudWatch
                error_4xx = 0.0
                error_5xx = 0.0
                requests_count = 0
                try:
                    for metric_name, target in [("4xxErrorRate", "error_4xx"), ("5xxErrorRate", "error_5xx"), ("Requests", "requests")]:
                        resp = cw.get_metric_statistics(
                            Namespace="AWS/CloudFront",
                            MetricName=metric_name,
                            Dimensions=[
                                {"Name": "DistributionId", "Value": dist_id},
                                {"Name": "Region", "Value": "Global"},
                            ],
                            StartTime=datetime.now(timezone.utc) - timedelta(minutes=15),
                            EndTime=datetime.now(timezone.utc),
                            Period=300,
                            Statistics=["Average" if "Error" in metric_name else "Sum"],
                        )
                        dps = resp.get("Datapoints", [])
                        if dps:
                            latest = sorted(dps, key=lambda x: x["Timestamp"])[-1]
                            val = latest.get("Average", latest.get("Sum", 0))
                            if target == "error_4xx": error_4xx = round(val, 2)
                            elif target == "error_5xx": error_5xx = round(val, 2)
                            elif target == "requests": requests_count = int(val)
                except ClientError:
                    pass

                # Origins summary
                origins = []
                for origin in dist.get("Origins", {}).get("Items", []):
                    origins.append({
                        "id": origin.get("Id", ""),
                        "domain": origin.get("DomainName", ""),
                        "path": origin.get("OriginPath", ""),
                    })

                distributions.append({
                    "distribution_id": dist_id,
                    "name": dist.get("Comment", dist_id) or dist_id,
                    "domain": domain,
                    "status": status,
                    "enabled": "true" if enabled else "false",
                    "error_rate_4xx": error_4xx,
                    "error_rate_5xx": error_5xx,
                    "requests_15m": requests_count,
                    "origins": origins,
                    "healthy": status == "Deployed" and enabled and error_5xx < 5,
                })

    except ClientError as e:
        logger.warning(f"CloudFront check failed: {_sanitize_error(e)}")

    return {
        "total": len(distributions),
        "deployed": sum(1 for d in distributions if d["status"] == "Deployed"),
        "healthy": sum(1 for d in distributions if d["healthy"]),
        "distributions": distributions,
    }


# ═════════════════════════════════════════════════════════════════════════════
# AMAZON IVS (Interactive Video Service)
# ═════════════════════════════════════════════════════════════════════════════

def check_ivs(config: dict, region: str = None) -> dict:
    """Check IVS channels: state, active streams, stream health."""
    client = boto3.client("ivs", **_get_boto_kwargs(config, region))
    channels = []

    try:
        resp = client.list_channels(maxResults=100)
        for ch_summary in resp.get("channels", []):
            ch_arn = ch_summary["arn"]
            name = ch_summary.get("name", ch_arn.split("/")[-1])

            detail = {}
            try:
                detail = client.get_channel(arn=ch_arn).get("channel", {})
            except ClientError:
                pass

            # Check for active stream
            stream_info = {}
            stream_health = "NO_STREAM"
            viewer_count = 0
            try:
                stream_resp = client.get_stream(channelArn=ch_arn)
                stream = stream_resp.get("stream", {})
                if stream:
                    stream_health = stream.get("health", "UNKNOWN")
                    viewer_count = stream.get("viewerCount", 0)
                    stream_info = {
                        "state": stream.get("state", ""),
                        "health": stream_health,
                        "viewer_count": viewer_count,
                        "start_time": stream.get("startTime", "").isoformat() if stream.get("startTime") else "",
                    }
            except client.exceptions.ChannelNotBroadcasting:
                stream_health = "OFFLINE"
            except ClientError:
                pass

            channels.append({
                "channel_id": ch_arn.split("/")[-1],
                "arn": ch_arn,
                "name": name,
                "state": "LIVE" if stream_info.get("state") == "LIVE" else "OFFLINE",
                "latency_mode": detail.get("latencyMode", ""),
                "type": detail.get("type", ""),
                "ingest_endpoint": detail.get("ingestEndpoint", ""),
                "playback_url": detail.get("playbackUrl", ""),
                "stream": stream_info,
                "stream_health": stream_health,
                "viewer_count": viewer_count,
                "healthy": stream_health in ("HEALTHY", "OFFLINE", "NO_STREAM"),
            })

    except ClientError as e:
        logger.warning(f"IVS check failed: {_sanitize_error(e)}")

    return {
        "total": len(channels),
        "live": sum(1 for c in channels if c["state"] == "LIVE"),
        "healthy": sum(1 for c in channels if c["healthy"]),
        "total_viewers": sum(c["viewer_count"] for c in channels),
        "channels": channels,
    }
