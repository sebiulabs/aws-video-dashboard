"""
History Database
=================
SQLite storage for check snapshots. Stores minimal metrics per check
and auto-prunes to keep the last 2000 entries (~10-20 days at 5-min interval).
No extra dependencies — sqlite3 is in the Python stdlib.
"""

import os
import json
import sqlite3
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

DATA_DIR = os.environ.get("DATA_DIR", os.path.dirname(__file__))
DB_PATH = os.path.join(DATA_DIR, "history.db")
MAX_ENTRIES = 2000


def _get_conn():
    is_new = not os.path.exists(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    if is_new:
        try:
            os.chmod(DB_PATH, 0o600)
        except OSError:
            pass  # Windows
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""CREATE TABLE IF NOT EXISTS checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        summary TEXT NOT NULL
    )""")
    return conn


def _avg_cpu(summary):
    instances = summary.get("ec2", {}).get("instances", [])
    cpus = [i["cpu_utilization"] for i in instances if i.get("cpu_utilization") is not None]
    return round(sum(cpus) / len(cpus), 1) if cpus else None


def save_snapshot(summary: dict):
    """Save a minimal metrics snapshot from a check result."""
    conn = None
    try:
        conn = _get_conn()
        ts = summary.get("timestamp", datetime.now(timezone.utc).isoformat())
        mini = {
            "ec2_total": summary.get("ec2", {}).get("total", 0),
            "ec2_running": summary.get("ec2", {}).get("running", 0),
            "ec2_healthy": summary.get("ec2", {}).get("healthy", 0),
            "ec2_alerts": summary.get("ec2", {}).get("alerts", 0),
            "deploy_failed": summary.get("deployments", {}).get("failed", 0),
            "ecs_total": len(summary.get("ecs_services", [])),
            "ecs_healthy": len([s for s in summary.get("ecs_services", []) if s.get("healthy")]),
            "endpoints_total": summary.get("easy_monitor", {}).get("total", 0),
            "endpoints_up": summary.get("easy_monitor", {}).get("up", 0),
            "avg_cpu": _avg_cpu(summary),
        }
        conn.execute("INSERT INTO checks (timestamp, summary) VALUES (?, ?)",
                      (ts, json.dumps(mini)))
        conn.execute(
            "DELETE FROM checks WHERE id NOT IN "
            "(SELECT id FROM checks ORDER BY id DESC LIMIT ?)",
            (MAX_ENTRIES,))
        conn.commit()
    except Exception as e:
        logger.error(f"Failed to save snapshot: {e}")
    finally:
        if conn:
            conn.close()


def get_history(limit: int = 500) -> list:
    """Return recent snapshots, oldest first."""
    conn = None
    try:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT timestamp, summary FROM checks ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [{"timestamp": r[0], **json.loads(r[1])} for r in reversed(rows)]
    except Exception as e:
        logger.error(f"Failed to read history: {e}")
        return []
    finally:
        if conn:
            conn.close()
