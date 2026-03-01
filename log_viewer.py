"""
CloudWatch Logs Viewer for the AWS Video Engineering Dashboard
================================================================
Provides functions for browsing and searching CloudWatch Logs directly
from the dashboard UI:

  - list_log_groups    — Enumerate log groups (optionally filtered by prefix)
  - list_log_streams   — List recent log streams within a group
  - get_log_events     — Fetch log events from a specific stream
  - search_logs        — Run CloudWatch Logs Insights queries with polling

All functions accept a *config* dict whose ``config["aws"]`` block carries
region, access_key_id, and secret_access_key — the same structure used by
every other module in this project.
"""

import logging
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Helper — build boto3 client kwargs from the shared config dict
# ─────────────────────────────────────────────────────────────────────────────

def _get_boto_kwargs(config: dict, region: str = None) -> dict:
    """Return the keyword arguments needed to construct a boto3 client.

    Mirrors the identical helper in ``aws_services_monitor.py`` so that
    credentials and region handling stay consistent across the whole dashboard.
    """
    aws = config.get("aws", {})
    kwargs = {"region_name": region or aws.get("region", "eu-west-2")}
    ak = aws.get("access_key_id", "")
    sk = aws.get("secret_access_key", "")
    if ak and sk:
        kwargs["aws_access_key_id"] = ak
        kwargs["aws_secret_access_key"] = sk
    return kwargs


# ═════════════════════════════════════════════════════════════════════════════
# 1. LIST LOG GROUPS
# ═════════════════════════════════════════════════════════════════════════════

def list_log_groups(config: dict, region: str = None, prefix: str = "") -> list:
    """List CloudWatch log groups, optionally filtered by a name prefix.

    Parameters
    ----------
    config : dict
        Dashboard configuration (must contain ``config["aws"]``).
    region : str, optional
        AWS region override.  Falls back to ``config["aws"]["region"]``.
    prefix : str
        If provided, only groups whose name starts with this prefix are
        returned.

    Returns
    -------
    list[dict]
        Up to 50 log groups, each with keys:
        ``name``, ``arn``, ``stored_bytes``, ``retention_days``,
        ``creation_time``.
    """
    client = boto3.client("logs", **_get_boto_kwargs(config, region))
    groups = []

    try:
        api_kwargs = {"limit": 50}
        if prefix:
            api_kwargs["logGroupNamePrefix"] = prefix

        resp = client.describe_log_groups(**api_kwargs)
        for g in resp.get("logGroups", []):
            groups.append({
                "name": g.get("logGroupName", ""),
                "arn": "",  # Removed to prevent account ID leakage
                "stored_bytes": g.get("storedBytes", 0),
                "retention_days": g.get("retentionInDays"),
                "creation_time": g.get("creationTime"),
            })
    except ClientError as e:
        logger.warning("Failed to list log groups: %s", e)

    return groups


# ═════════════════════════════════════════════════════════════════════════════
# 2. LIST LOG STREAMS
# ═════════════════════════════════════════════════════════════════════════════

def list_log_streams(
    config: dict,
    region: str = None,
    group: str = "",
    prefix: str = "",
    limit: int = 20,
) -> list:
    """List log streams within a log group, ordered by most recent event.

    Parameters
    ----------
    config : dict
        Dashboard configuration.
    region : str, optional
        AWS region override.
    group : str
        Name of the CloudWatch log group.
    prefix : str
        If provided, only streams whose name starts with this prefix are
        returned.
    limit : int
        Maximum number of streams to return (capped at 50).

    Returns
    -------
    list[dict]
        Log streams with keys: ``name``, ``first_event_time``,
        ``last_event_time``, ``stored_bytes``.
    """
    client = boto3.client("logs", **_get_boto_kwargs(config, region))
    streams = []
    limit = min(limit, 50)

    try:
        api_kwargs = {
            "logGroupName": group,
            "orderBy": "LastEventTime",
            "descending": True,
            "limit": limit,
        }
        if prefix:
            api_kwargs["logStreamNamePrefix"] = prefix
            api_kwargs["orderBy"] = "LogStreamName"

        resp = client.describe_log_streams(**api_kwargs)
        for s in resp.get("logStreams", []):
            streams.append({
                "name": s.get("logStreamName", ""),
                "first_event_time": s.get("firstEventTimestamp"),
                "last_event_time": s.get("lastEventTimestamp"),
                "stored_bytes": s.get("storedBytes", 0),
            })
    except ClientError as e:
        logger.warning("Failed to list log streams for group %s: %s", group, e)

    return streams


# ═════════════════════════════════════════════════════════════════════════════
# 3. GET LOG EVENTS
# ═════════════════════════════════════════════════════════════════════════════

def get_log_events(
    config: dict,
    region: str = None,
    group: str = "",
    stream: str = "",
    start_time: int = None,
    end_time: int = None,
    limit: int = 100,
) -> list:
    """Retrieve log events from a specific stream (newest first).

    Parameters
    ----------
    config : dict
        Dashboard configuration.
    region : str, optional
        AWS region override.
    group : str
        Log group name.
    stream : str
        Log stream name.
    start_time : int, optional
        Start of the time range in **epoch milliseconds**.
    end_time : int, optional
        End of the time range in **epoch milliseconds**.
    limit : int
        Maximum number of events to return (capped at 500).

    Returns
    -------
    list[dict]
        Events with keys: ``timestamp``, ``message``, ``ingestion_time``.
    """
    client = boto3.client("logs", **_get_boto_kwargs(config, region))
    events = []
    limit = min(limit, 500)

    try:
        api_kwargs = {
            "logGroupName": group,
            "logStreamName": stream,
            "limit": limit,
            "startFromHead": False,
        }
        if start_time is not None:
            api_kwargs["startTime"] = start_time
        if end_time is not None:
            api_kwargs["endTime"] = end_time

        resp = client.get_log_events(**api_kwargs)
        for evt in resp.get("events", []):
            events.append({
                "timestamp": evt.get("timestamp"),
                "message": evt.get("message", ""),
                "ingestion_time": evt.get("ingestionTime"),
            })
    except ClientError as e:
        logger.warning(
            "Failed to get log events for %s / %s: %s", group, stream, e
        )

    return events


# ═════════════════════════════════════════════════════════════════════════════
# 4. SEARCH LOGS (CloudWatch Logs Insights)
# ═════════════════════════════════════════════════════════════════════════════

def search_logs(
    config: dict,
    region: str = None,
    group: str = "",
    query: str = "",
    start_time: int = None,
    end_time: int = None,
) -> list:
    """Run a CloudWatch Logs Insights query and wait for results.

    Parameters
    ----------
    config : dict
        Dashboard configuration.
    region : str, optional
        AWS region override.
    group : str
        Log group name to query.
    query : str
        A Logs Insights query string.  If empty, a sensible default is used
        that returns the 100 most recent events with timestamp and message.
    start_time : int, optional
        Start of the time range in **epoch seconds**.  Defaults to one hour
        ago.
    end_time : int, optional
        End of the time range in **epoch seconds**.  Defaults to now.

    Returns
    -------
    list[dict]
        Each result row as a dict whose keys are the field names returned by
        the query (e.g. ``@timestamp``, ``@message``).
    """
    client = boto3.client("logs", **_get_boto_kwargs(config, region))
    results = []

    if not query:
        query = (
            "fields @timestamp, @message "
            "| sort @timestamp desc "
            "| limit 100"
        )

    now_epoch = int(datetime.now(timezone.utc).timestamp())
    if start_time is None:
        start_time = now_epoch - 3600  # 1 hour ago
    if end_time is None:
        end_time = now_epoch

    try:
        start_resp = client.start_query(
            logGroupName=group,
            startTime=start_time,
            endTime=end_time,
            queryString=query,
        )
        query_id = start_resp["queryId"]

        # Poll for results — up to 30 seconds
        deadline = time.monotonic() + 30
        status = "Scheduled"
        query_results = []

        while status in ("Scheduled", "Running") and time.monotonic() < deadline:
            time.sleep(0.5)
            result_resp = client.get_query_results(queryId=query_id)
            status = result_resp.get("status", "Unknown")
            query_results = result_resp.get("results", [])

        # Each result row is a list of {field, value} dicts — flatten to dict
        for row in query_results:
            results.append({
                field["field"]: field["value"]
                for field in row
            })

    except ClientError as e:
        logger.warning("Logs Insights query failed for group %s: %s", group, e)

    return results
