"""
Schedule Manager
=================
SQLite-backed scheduled actions module for the AWS Video Engineering Dashboard.
Manages cron-based scheduled actions such as nightly backups, morning instance
starts, periodic health checks, and other recurring automation tasks.
Each schedule maps to an action in the ai_actions ACTION_REGISTRY and stores
its parameters, cron expression, and run history.
No extra dependencies — sqlite3 is in the Python stdlib.
"""

import json
import os
import re
import sqlite3
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_CRON_FIELD_RE = re.compile(r'^(\*|\d+(-\d+)?(,\d+(-\d+)?)*)(/\d+)?$')

def _validate_cron(expr):
    """Validate a basic cron expression (5 fields: min hour dom month dow)."""
    if not expr or not isinstance(expr, str):
        return False
    parts = expr.strip().split()
    if len(parts) != 5:
        return False
    for part in parts:
        if not _CRON_FIELD_RE.match(part):
            return False
    return True

DATA_DIR = os.environ.get("DATA_DIR", os.path.dirname(__file__))
DB_PATH = os.path.join(DATA_DIR, "schedules.db")

CRON_PRESETS = [
    {"id": "daily_8am", "name": "Daily at 08:00", "cron": "0 8 * * *"},
    {"id": "daily_11pm", "name": "Daily at 23:00", "cron": "0 23 * * *"},
    {"id": "weekdays_8am", "name": "Weekdays at 08:00", "cron": "0 8 * * 1-5"},
    {"id": "weekdays_11pm", "name": "Weekdays at 23:00", "cron": "0 23 * * 1-5"},
    {"id": "hourly", "name": "Every Hour", "cron": "0 * * * *"},
    {"id": "every_6h", "name": "Every 6 Hours", "cron": "0 */6 * * *"},
    {"id": "weekly_sunday", "name": "Weekly Sunday 02:00", "cron": "0 2 * * 0"},
    {"id": "monthly_1st", "name": "Monthly 1st at 02:00", "cron": "0 2 1 * *"},
]


def _get_conn():
    """Get a SQLite connection with tables created on first use."""
    is_new = not os.path.exists(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    if is_new:
        try:
            os.chmod(DB_PATH, 0o600)
        except OSError:
            pass  # Windows
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""CREATE TABLE IF NOT EXISTS schedules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        action_id TEXT NOT NULL,
        action_params TEXT,
        cron_expression TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        created_at TEXT,
        last_run TEXT,
        next_run TEXT,
        run_count INTEGER DEFAULT 0
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS schedule_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        schedule_id INTEGER NOT NULL,
        started_at TEXT,
        completed_at TEXT,
        success INTEGER,
        result TEXT,
        FOREIGN KEY (schedule_id) REFERENCES schedules(id)
    )""")
    return conn


def _row_to_dict(row):
    """Convert a sqlite3.Row to a plain dict."""
    if row is None:
        return None
    return dict(row)


def create_schedule(name, action_id, action_params, cron_expression,
                    description=""):
    """Create a new scheduled action and return it as a dict."""
    if not _validate_cron(cron_expression):
        logger.warning(f"Invalid cron expression rejected: {cron_expression!r}")
        return None
    conn = None
    try:
        conn = _get_conn()
        now = datetime.now(timezone.utc).isoformat()
        params_json = json.dumps(action_params) if action_params is not None else '{}'
        cur = conn.execute(
            """INSERT INTO schedules
               (name, description, action_id, action_params,
                cron_expression, enabled, created_at, run_count)
               VALUES (?, ?, ?, ?, ?, 1, ?, 0)""",
            (name, description, action_id, params_json,
             cron_expression, now),
        )
        conn.commit()
        schedule_id = cur.lastrowid
        row = conn.execute("SELECT * FROM schedules WHERE id = ?",
                           (schedule_id,)).fetchone()
        logger.info(f"Created schedule #{schedule_id}: {name}")
        return _row_to_dict(row)
    except Exception as e:
        logger.error(f"Failed to create schedule: {e}")
        return None
    finally:
        if conn:
            conn.close()


def get_schedules(enabled_only=False):
    """Return a list of all schedules, optionally filtered to enabled only."""
    conn = None
    try:
        conn = _get_conn()
        if enabled_only:
            rows = conn.execute(
                "SELECT * FROM schedules WHERE enabled = 1 ORDER BY id DESC"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM schedules ORDER BY id DESC"
            ).fetchall()
        return [_row_to_dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Failed to get schedules: {e}")
        return []
    finally:
        if conn:
            conn.close()


def get_schedule(schedule_id):
    """Return a single schedule dict or None if not found."""
    conn = None
    try:
        conn = _get_conn()
        row = conn.execute("SELECT * FROM schedules WHERE id = ?",
                           (schedule_id,)).fetchone()
        return _row_to_dict(row)
    except Exception as e:
        logger.error(f"Failed to get schedule {schedule_id}: {e}")
        return None
    finally:
        if conn:
            conn.close()


def update_schedule(schedule_id, updates):
    """Update fields on a schedule. Returns the updated dict or None."""
    if "cron_expression" in updates and not _validate_cron(updates["cron_expression"]):
        logger.warning(f"Invalid cron expression rejected: {updates['cron_expression']!r}")
        return None
    conn = None
    try:
        conn = _get_conn()
        # Only allow updating known columns
        allowed = {"name", "description", "action_id", "action_params",
                    "cron_expression", "enabled"}
        set_clauses = []
        params = []
        for key, value in updates.items():
            if key not in allowed:
                continue
            if key == "action_params" and not isinstance(value, str):
                value = json.dumps(value)
            set_clauses.append(f"{key} = ?")
            params.append(value)
        if not set_clauses:
            return get_schedule(schedule_id)
        params.append(schedule_id)
        conn.execute(
            f"UPDATE schedules SET {', '.join(set_clauses)} WHERE id = ?",
            params,
        )
        conn.commit()
        row = conn.execute("SELECT * FROM schedules WHERE id = ?",
                           (schedule_id,)).fetchone()
        logger.info(f"Updated schedule #{schedule_id}")
        return _row_to_dict(row)
    except Exception as e:
        logger.error(f"Failed to update schedule {schedule_id}: {e}")
        return None
    finally:
        if conn:
            conn.close()


def delete_schedule(schedule_id):
    """Delete a schedule and its run history. Returns True on success."""
    conn = None
    try:
        conn = _get_conn()
        conn.execute("DELETE FROM schedule_runs WHERE schedule_id = ?",
                     (schedule_id,))
        conn.execute("DELETE FROM schedules WHERE id = ?",
                     (schedule_id,))
        conn.commit()
        logger.info(f"Deleted schedule #{schedule_id}")
        return True
    except Exception as e:
        logger.error(f"Failed to delete schedule {schedule_id}: {e}")
        return False
    finally:
        if conn:
            conn.close()


def toggle_schedule(schedule_id):
    """Flip a schedule between enabled and disabled. Returns updated dict."""
    conn = None
    try:
        conn = _get_conn()
        row = conn.execute("SELECT * FROM schedules WHERE id = ?",
                           (schedule_id,)).fetchone()
        if row is None:
            return None
        new_enabled = 0 if row["enabled"] else 1
        conn.execute("UPDATE schedules SET enabled = ? WHERE id = ?",
                     (new_enabled, schedule_id))
        conn.commit()
        row = conn.execute("SELECT * FROM schedules WHERE id = ?",
                           (schedule_id,)).fetchone()
        state = "enabled" if new_enabled else "disabled"
        logger.info(f"Toggled schedule #{schedule_id} to {state}")
        return _row_to_dict(row)
    except Exception as e:
        logger.error(f"Failed to toggle schedule {schedule_id}: {e}")
        return None
    finally:
        if conn:
            conn.close()


def log_run(schedule_id, success, result):
    """Record a schedule run and update the parent schedule. Returns run dict."""
    conn = None
    try:
        conn = _get_conn()
        now = datetime.now(timezone.utc).isoformat()
        result_json = json.dumps(result) if not isinstance(result, str) else result
        cur = conn.execute(
            """INSERT INTO schedule_runs
               (schedule_id, started_at, completed_at, success, result)
               VALUES (?, ?, ?, ?, ?)""",
            (schedule_id, now, now, 1 if success else 0, result_json),
        )
        conn.commit()
        run_id = cur.lastrowid
        # Update parent schedule counters
        conn.execute(
            """UPDATE schedules
               SET last_run = ?, run_count = run_count + 1
               WHERE id = ?""",
            (now, schedule_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM schedule_runs WHERE id = ?",
                           (run_id,)).fetchone()
        logger.info(f"Logged run #{run_id} for schedule #{schedule_id} "
                     f"(success={success})")
        return _row_to_dict(row)
    except Exception as e:
        logger.error(f"Failed to log run for schedule {schedule_id}: {e}")
        return None
    finally:
        if conn:
            conn.close()


def get_runs(schedule_id, limit=20):
    """Return recent runs for a schedule, newest first."""
    conn = None
    try:
        conn = _get_conn()
        limit = max(1, min(int(limit), 500))
        rows = conn.execute(
            """SELECT * FROM schedule_runs
               WHERE schedule_id = ?
               ORDER BY id DESC LIMIT ?""",
            (schedule_id, limit),
        ).fetchall()
        return [_row_to_dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Failed to get runs for schedule {schedule_id}: {e}")
        return []
    finally:
        if conn:
            conn.close()


def get_schedule_stats():
    """Return aggregate stats: total, enabled, disabled, and runs_today."""
    conn = None
    try:
        conn = _get_conn()
        total = conn.execute(
            "SELECT COUNT(*) as cnt FROM schedules"
        ).fetchone()["cnt"]
        enabled = conn.execute(
            "SELECT COUNT(*) as cnt FROM schedules WHERE enabled = 1"
        ).fetchone()["cnt"]
        disabled = total - enabled
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        runs_today = conn.execute(
            "SELECT COUNT(*) as cnt FROM schedule_runs WHERE started_at LIKE ?",
            (f"{today}%",),
        ).fetchone()["cnt"]
        return {
            "total": total,
            "enabled": enabled,
            "disabled": disabled,
            "runs_today": runs_today,
        }
    except Exception as e:
        logger.error(f"Failed to get schedule stats: {e}")
        return {"total": 0, "enabled": 0, "disabled": 0, "runs_today": 0}
    finally:
        if conn:
            conn.close()
