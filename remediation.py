"""
Auto-Remediation Module
========================
Automatic remediation actions for the AWS Video Engineering Dashboard.
When an alert rule fires, the system can automatically take corrective action
such as rebooting an EC2 instance, restarting a MediaLive channel, scaling an
ECS service, or purging an SQS queue.

This module provides:
- A set of built-in remediation presets (REMEDIATION_PRESETS).
- A gating function (should_remediate) that enforces cooldowns and execution
  caps before allowing an action to proceed.
- Logging helpers that persist every remediation attempt to a local SQLite
  database so operators can audit what happened and when.
- Simple stats for the dashboard overview.

No extra dependencies — sqlite3 and json are in the Python stdlib.
"""

import json
import os
import sqlite3
import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

DATA_DIR = os.environ.get("DATA_DIR", os.path.dirname(__file__))
DB_PATH = os.path.join(DATA_DIR, "remediation.db")

# ---------------------------------------------------------------------------
# Presets
# ---------------------------------------------------------------------------

REMEDIATION_PRESETS = [
    {
        "id": "reboot_ec2",
        "name": "Reboot EC2 Instance",
        "action": "ec2_instance_action",
        "params": {"action": "reboot"},
        "description": "Reboot the EC2 instance when status check fails",
    },
    {
        "id": "restart_medialive",
        "name": "Restart MediaLive Channel",
        "action": "restart_medialive",
        "params": {},
        "description": "Stop and restart a MediaLive channel",
    },
    {
        "id": "scale_ecs",
        "name": "Scale ECS Service",
        "action": "scale_ecs_service",
        "params": {"desired_count": 2},
        "description": "Scale ECS service to desired count",
    },
    {
        "id": "purge_sqs",
        "name": "Purge SQS Queue",
        "action": "purge_sqs_queue",
        "params": {},
        "description": "Purge all messages from an SQS queue",
    },
]

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------


def _get_conn():
    """Get a SQLite connection with the remediation_log table created on first use."""
    is_new = not os.path.exists(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    if is_new:
        os.chmod(DB_PATH, 0o600)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""CREATE TABLE IF NOT EXISTS remediation_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        action_id TEXT NOT NULL,
        params TEXT NOT NULL DEFAULT '{}',
        result TEXT NOT NULL DEFAULT '{}',
        success INTEGER NOT NULL DEFAULT 0,
        incident_id INTEGER
    )""")
    return conn


def _row_to_dict(row):
    """Convert a sqlite3.Row to a plain dict, deserialising JSON columns."""
    if row is None:
        return None
    d = dict(row)
    # Deserialise JSON text columns back to Python objects.
    for col in ("params", "result"):
        if col in d and isinstance(d[col], str):
            try:
                d[col] = json.loads(d[col])
            except (json.JSONDecodeError, TypeError):
                pass
    # Represent the boolean-ish integer as a real bool.
    if "success" in d:
        d["success"] = bool(d["success"])
    return d


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------


def should_remediate(rule, log_entries):
    """Decide whether automatic remediation should proceed for *rule*.

    Parameters
    ----------
    rule : dict
        The alert rule dict.  Expected to contain a ``remediation`` key whose
        value is a dict with at least ``enabled`` (bool).  Optional keys are
        ``max_executions`` (int) and ``cooldown_minutes`` (int).
    log_entries : list[dict]
        Previous remediation log entries for the same rule, most-recent first.

    Returns
    -------
    bool
        ``True`` if it is safe to execute remediation; ``False`` otherwise.
    """
    try:
        remediation_cfg = rule.get("remediation")
        if not remediation_cfg or not remediation_cfg.get("enabled"):
            return False

        max_executions = remediation_cfg.get("max_executions")
        if max_executions is not None and len(log_entries) >= max_executions:
            logger.info(
                "Remediation blocked for rule %s: max_executions (%d) reached",
                rule.get("id", "?"),
                max_executions,
            )
            return False

        cooldown_minutes = remediation_cfg.get("cooldown_minutes")
        if cooldown_minutes is not None and log_entries:
            last_ts = log_entries[0].get("timestamp")
            if last_ts:
                last_dt = datetime.fromisoformat(last_ts)
                # Ensure timezone-aware comparison.
                if last_dt.tzinfo is None:
                    last_dt = last_dt.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                if now - last_dt < timedelta(minutes=cooldown_minutes):
                    logger.info(
                        "Remediation blocked for rule %s: cooldown (%d min) not elapsed",
                        rule.get("id", "?"),
                        cooldown_minutes,
                    )
                    return False

        return True
    except Exception as e:
        logger.error("Error in should_remediate: %s", e)
        return False


def log_remediation(rule_id, action_id, params, result, success, incident_id=None):
    """Record a remediation execution in the database.

    Parameters
    ----------
    rule_id : str
        Identifier of the alert rule that triggered remediation.
    action_id : str
        Identifier of the remediation action performed.
    params : dict
        Parameters passed to the action.
    result : dict
        Outcome / response data from the action.
    success : bool
        Whether the action completed successfully.
    incident_id : int or None
        Optional linked incident ID.

    Returns
    -------
    dict or None
        The newly created log entry, or ``None`` on error.
    """
    conn = None
    try:
        conn = _get_conn()
        now = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(
            """INSERT INTO remediation_log
               (timestamp, rule_id, action_id, params, result, success, incident_id)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                now,
                rule_id,
                action_id,
                json.dumps(params if params else {}),
                json.dumps(result if result else {}),
                1 if success else 0,
                incident_id,
            ),
        )
        conn.commit()
        entry_id = cur.lastrowid
        row = conn.execute(
            "SELECT * FROM remediation_log WHERE id = ?", (entry_id,)
        ).fetchone()
        logger.info(
            "Logged remediation #%d: rule=%s action=%s success=%s",
            entry_id,
            rule_id,
            action_id,
            success,
        )
        return _row_to_dict(row)
    except Exception as e:
        logger.error("Failed to log remediation: %s", e)
        return None
    finally:
        if conn:
            conn.close()


def get_remediation_log(rule_id=None, limit=50):
    """Retrieve recent remediation log entries.

    Parameters
    ----------
    rule_id : str or None
        If provided, only return entries for this rule.
    limit : int
        Maximum number of entries to return (capped at 200).

    Returns
    -------
    list[dict]
        Log entries, most recent first.
    """
    conn = None
    try:
        conn = _get_conn()
        limit = max(1, min(int(limit), 200))
        if rule_id:
            rows = conn.execute(
                "SELECT * FROM remediation_log WHERE rule_id = ? ORDER BY id DESC LIMIT ?",
                (rule_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM remediation_log ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [_row_to_dict(r) for r in rows]
    except Exception as e:
        logger.error("Failed to get remediation log: %s", e)
        return []
    finally:
        if conn:
            conn.close()


def get_remediation_stats():
    """Return high-level remediation statistics.

    Returns
    -------
    dict
        Keys: ``total``, ``successful``, ``failed``, ``last_24h``.
    """
    conn = None
    try:
        conn = _get_conn()
        total = conn.execute(
            "SELECT COUNT(*) AS cnt FROM remediation_log"
        ).fetchone()["cnt"]
        successful = conn.execute(
            "SELECT COUNT(*) AS cnt FROM remediation_log WHERE success = 1"
        ).fetchone()["cnt"]
        failed = conn.execute(
            "SELECT COUNT(*) AS cnt FROM remediation_log WHERE success = 0"
        ).fetchone()["cnt"]
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        last_24h = conn.execute(
            "SELECT COUNT(*) AS cnt FROM remediation_log WHERE timestamp >= ?",
            (cutoff,),
        ).fetchone()["cnt"]
        return {
            "total": total,
            "successful": successful,
            "failed": failed,
            "last_24h": last_24h,
        }
    except Exception as e:
        logger.error("Failed to get remediation stats: %s", e)
        return {"total": 0, "successful": 0, "failed": 0, "last_24h": 0}
    finally:
        if conn:
            conn.close()
