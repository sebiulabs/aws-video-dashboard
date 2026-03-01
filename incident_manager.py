"""
Incident Manager
=================
SQLite-backed incident tracking for the AWS Video Engineering Dashboard.
Creates and manages incidents triggered by alert rules, with support for
acknowledgement, resolution, notes timeline, and deduplication.
No extra dependencies — sqlite3 is in the Python stdlib.
"""

import os
import sqlite3
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

DATA_DIR = os.environ.get("DATA_DIR", os.path.dirname(__file__))
DB_PATH = os.path.join(DATA_DIR, "incidents.db")


def _get_conn():
    """Get a SQLite connection with tables created on first use."""
    is_new = not os.path.exists(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    if is_new:
        os.chmod(DB_PATH, 0o600)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'warning',
        status TEXT NOT NULL DEFAULT 'open',
        assigned_to TEXT,
        alert_rule_id TEXT,
        resource_id TEXT,
        trigger_message TEXT,
        created_at TEXT NOT NULL,
        acknowledged_at TEXT,
        resolved_at TEXT,
        resolution_note TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS incident_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id INTEGER NOT NULL,
        note TEXT NOT NULL,
        author TEXT DEFAULT 'system',
        created_at TEXT NOT NULL,
        FOREIGN KEY (incident_id) REFERENCES incidents(id)
    )""")
    return conn


def _row_to_dict(row):
    """Convert a sqlite3.Row to a plain dict."""
    if row is None:
        return None
    return dict(row)


def create_incident(title, severity="warning", alert_rule_id=None,
                    resource_id=None, trigger_message=None):
    """Create a new incident and return it as a dict."""
    conn = None
    try:
        conn = _get_conn()
        now = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(
            """INSERT INTO incidents
               (title, severity, status, alert_rule_id, resource_id,
                trigger_message, created_at)
               VALUES (?, ?, 'open', ?, ?, ?, ?)""",
            (title, severity, alert_rule_id, resource_id, trigger_message, now),
        )
        conn.commit()
        incident_id = cur.lastrowid
        row = conn.execute("SELECT * FROM incidents WHERE id = ?",
                           (incident_id,)).fetchone()
        logger.info(f"Created incident #{incident_id}: {title}")
        return _row_to_dict(row)
    except Exception as e:
        logger.error(f"Failed to create incident: {e}")
        return None
    finally:
        if conn:
            conn.close()


def get_incidents(status=None, severity=None, limit=50):
    """Return a list of incidents, optionally filtered by status/severity."""
    conn = None
    try:
        conn = _get_conn()
        clauses = []
        params = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        limit = max(1, min(int(limit), 500))
        params.append(limit)
        rows = conn.execute(
            f"SELECT * FROM incidents{where} ORDER BY id DESC LIMIT ?",
            params,
        ).fetchall()
        return [_row_to_dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Failed to get incidents: {e}")
        return []
    finally:
        if conn:
            conn.close()


def get_incident(incident_id):
    """Return a single incident dict with its notes list included."""
    conn = None
    try:
        conn = _get_conn()
        row = conn.execute("SELECT * FROM incidents WHERE id = ?",
                           (incident_id,)).fetchone()
        if row is None:
            return None
        incident = _row_to_dict(row)
        notes = conn.execute(
            "SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY id ASC",
            (incident_id,),
        ).fetchall()
        incident["notes"] = [_row_to_dict(n) for n in notes]
        return incident
    except Exception as e:
        logger.error(f"Failed to get incident {incident_id}: {e}")
        return None
    finally:
        if conn:
            conn.close()


def acknowledge_incident(incident_id, assigned_to=None):
    """Mark an incident as acknowledged. Optionally assign it."""
    conn = None
    try:
        conn = _get_conn()
        now = datetime.now(timezone.utc).isoformat()
        cursor = conn.execute(
            """UPDATE incidents
               SET status = 'acknowledged', acknowledged_at = ?,
                   assigned_to = COALESCE(?, assigned_to)
               WHERE id = ? AND status = 'open'""",
            (now, assigned_to, incident_id),
        )
        conn.commit()
        if cursor.rowcount == 0:
            conn.close()
            return None
        # Add a system note
        note_text = "Incident acknowledged"
        if assigned_to:
            note_text += f" and assigned to {assigned_to}"
        conn.execute(
            "INSERT INTO incident_notes (incident_id, note, author, created_at) VALUES (?, ?, 'system', ?)",
            (incident_id, note_text, now),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM incidents WHERE id = ?",
                           (incident_id,)).fetchone()
        logger.info(f"Acknowledged incident #{incident_id}")
        return _row_to_dict(row)
    except Exception as e:
        logger.error(f"Failed to acknowledge incident {incident_id}: {e}")
        return None
    finally:
        if conn:
            conn.close()


def resolve_incident(incident_id, resolution_note=""):
    """Mark an incident as resolved with an optional note."""
    conn = None
    try:
        conn = _get_conn()
        now = datetime.now(timezone.utc).isoformat()
        cursor = conn.execute(
            """UPDATE incidents
               SET status = 'resolved', resolved_at = ?, resolution_note = ?
               WHERE id = ? AND status IN ('open', 'acknowledged')""",
            (now, resolution_note, incident_id),
        )
        conn.commit()
        if cursor.rowcount == 0:
            conn.close()
            return None
        # Add a system note
        note_text = "Incident resolved"
        if resolution_note:
            note_text += f": {resolution_note}"
        conn.execute(
            "INSERT INTO incident_notes (incident_id, note, author, created_at) VALUES (?, ?, 'system', ?)",
            (incident_id, note_text, now),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM incidents WHERE id = ?",
                           (incident_id,)).fetchone()
        logger.info(f"Resolved incident #{incident_id}")
        return _row_to_dict(row)
    except Exception as e:
        logger.error(f"Failed to resolve incident {incident_id}: {e}")
        return None
    finally:
        if conn:
            conn.close()


def add_note(incident_id, note, author="system"):
    """Add a note to an incident timeline. Returns the note dict."""
    conn = None
    try:
        conn = _get_conn()
        now = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(
            "INSERT INTO incident_notes (incident_id, note, author, created_at) VALUES (?, ?, ?, ?)",
            (incident_id, note, author, now),
        )
        conn.commit()
        note_id = cur.lastrowid
        row = conn.execute("SELECT * FROM incident_notes WHERE id = ?",
                           (note_id,)).fetchone()
        return _row_to_dict(row)
    except Exception as e:
        logger.error(f"Failed to add note to incident {incident_id}: {e}")
        return None
    finally:
        if conn:
            conn.close()


def find_open_incident(alert_rule_id, resource_id):
    """Find an existing open/acknowledged incident for the same alert+resource (dedup)."""
    conn = None
    try:
        conn = _get_conn()
        row = conn.execute(
            """SELECT * FROM incidents
               WHERE alert_rule_id = ? AND resource_id = ?
                 AND status IN ('open', 'acknowledged')
               ORDER BY id DESC LIMIT 1""",
            (alert_rule_id, resource_id),
        ).fetchone()
        return _row_to_dict(row)
    except Exception as e:
        logger.error(f"Failed to find open incident: {e}")
        return None
    finally:
        if conn:
            conn.close()


def get_incident_stats():
    """Return counts of incidents by status."""
    conn = None
    try:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT status, COUNT(*) as cnt FROM incidents GROUP BY status"
        ).fetchall()
        stats = {"open": 0, "acknowledged": 0, "resolved": 0}
        for r in rows:
            stats[r["status"]] = r["cnt"]
        return stats
    except Exception as e:
        logger.error(f"Failed to get incident stats: {e}")
        return {"open": 0, "acknowledged": 0, "resolved": 0}
    finally:
        if conn:
            conn.close()
