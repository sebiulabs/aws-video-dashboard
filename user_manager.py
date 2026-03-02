"""
User Manager
=============
SQLite-backed multi-user RBAC module for the AWS Video Engineering Dashboard.
Provides user creation, authentication, role-based permission checks, and
migration from legacy single-user config.  Passwords are hashed with werkzeug.
No extra dependencies beyond werkzeug (already required by Flask) and the
Python stdlib.
"""

import os
import re
import sqlite3
import logging
from datetime import datetime, timezone

from werkzeug.security import generate_password_hash, check_password_hash

logger = logging.getLogger(__name__)

DATA_DIR = os.environ.get("DATA_DIR", os.path.dirname(__file__))
DB_PATH = os.path.join(DATA_DIR, "users.db")

ROLES = {
    "admin": {"level": 3, "description": "Full access — manage users, settings, and infrastructure"},
    "operator": {"level": 2, "description": "View + manage infrastructure, acknowledge incidents"},
    "viewer": {"level": 1, "description": "Read-only access to dashboards and monitoring"},
}


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

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
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'viewer',
        email TEXT,
        created_at TEXT NOT NULL,
        last_login TEXT
    )""")
    return conn


def _row_to_dict(row):
    """Convert a sqlite3.Row to a plain dict, excluding password_hash."""
    if row is None:
        return None
    d = dict(row)
    d.pop("password_hash", None)
    return d


def _row_to_dict_full(row):
    """Convert a sqlite3.Row to a plain dict, INCLUDING password_hash (for
    internal authentication use only)."""
    if row is None:
        return None
    return dict(row)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
_PASSWORD_RE = re.compile(r"^(?=.*[A-Za-z])(?=.*[0-9]).{8,}$")


def _validate_username(username):
    """Return True if username is 3-30 alphanumeric/underscore characters."""
    return bool(_USERNAME_RE.match(username))


def _validate_password(password):
    """Return True if password is 8+ chars containing letters and numbers."""
    return bool(_PASSWORD_RE.match(password))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_user(username, password, role="viewer", email=""):
    """Create a new user and return the user dict (without password_hash).

    Returns None on validation failure or if the username already exists.
    """
    conn = None
    try:
        if role not in ROLES:
            logger.warning(f"Invalid role '{role}' for new user '{username}'")
            return None

        if not _validate_username(username):
            logger.warning(
                f"Invalid username '{username}': must be 3-30 alphanumeric/underscore characters"
            )
            return None

        if not _validate_password(password):
            logger.warning(
                "Invalid password: must be 8+ characters with at least one letter and one number"
            )
            return None

        conn = _get_conn()
        now = datetime.now(timezone.utc).isoformat()
        hashed = generate_password_hash(password)
        cur = conn.execute(
            """INSERT INTO users (username, password_hash, role, email, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (username, hashed, role, email, now),
        )
        conn.commit()
        user_id = cur.lastrowid
        row = conn.execute("SELECT * FROM users WHERE id = ?",
                           (user_id,)).fetchone()
        logger.info(f"Created user '{username}' with role '{role}' (id={user_id})")
        return _row_to_dict(row)
    except sqlite3.IntegrityError:
        logger.warning(f"Username '{username}' already exists")
        return None
    except Exception as e:
        logger.error(f"Failed to create user '{username}': {e}")
        return None
    finally:
        if conn:
            conn.close()


def get_users():
    """Return a list of all user dicts (without password_hash)."""
    conn = None
    try:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT * FROM users ORDER BY id ASC"
        ).fetchall()
        return [_row_to_dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Failed to get users: {e}")
        return []
    finally:
        if conn:
            conn.close()


def get_user(user_id):
    """Return a single user dict (without password_hash), or None."""
    conn = None
    try:
        conn = _get_conn()
        row = conn.execute("SELECT * FROM users WHERE id = ?",
                           (user_id,)).fetchone()
        return _row_to_dict(row)
    except Exception as e:
        logger.error(f"Failed to get user {user_id}: {e}")
        return None
    finally:
        if conn:
            conn.close()


def get_user_by_username(username):
    """Return a single user dict WITH password_hash (for authentication).

    Returns None if the user does not exist.
    """
    conn = None
    try:
        conn = _get_conn()
        row = conn.execute("SELECT * FROM users WHERE username = ?",
                           (username,)).fetchone()
        return _row_to_dict_full(row)
    except Exception as e:
        logger.error(f"Failed to get user by username '{username}': {e}")
        return None
    finally:
        if conn:
            conn.close()


def authenticate(username, password):
    """Verify credentials and return the user dict (without password_hash).

    Updates last_login on success.  Returns None on failure.
    """
    conn = None
    try:
        user = get_user_by_username(username)
        if user is None:
            logger.info(f"Authentication failed: user '{username}' not found")
            return None

        if not check_password_hash(user["password_hash"], password):
            logger.info(f"Authentication failed: wrong password for '{username}'")
            return None

        # Update last_login
        conn = _get_conn()
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (now, user["id"]),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM users WHERE id = ?",
                           (user["id"],)).fetchone()
        logger.info(f"User '{username}' authenticated successfully")
        return _row_to_dict(row)
    except Exception as e:
        logger.error(f"Authentication error for '{username}': {e}")
        return None
    finally:
        if conn:
            conn.close()


def update_user(user_id, updates):
    """Update a user's role, email, and/or password.

    ``updates`` is a dict with optional keys: role, email, password.
    The username cannot be changed.  Returns the updated user dict
    (without password_hash), or None on failure.
    """
    conn = None
    try:
        conn = _get_conn()
        row = conn.execute("SELECT * FROM users WHERE id = ?",
                           (user_id,)).fetchone()
        if row is None:
            logger.warning(f"Cannot update user {user_id}: not found")
            return None

        sets = []
        params = []

        if "role" in updates:
            if updates["role"] not in ROLES:
                logger.warning(f"Invalid role '{updates['role']}' in update")
                return None
            sets.append("role = ?")
            params.append(updates["role"])

        if "email" in updates:
            email = updates["email"]
            if email and (len(email) > 254 or "@" not in email):
                return None  # invalid email
            sets.append("email = ?")
            params.append(email or "")

        if "password" in updates:
            if not _validate_password(updates["password"]):
                logger.warning("Invalid password in update: must be 8+ chars with letters and numbers")
                return None
            sets.append("password_hash = ?")
            params.append(generate_password_hash(updates["password"]))

        if not sets:
            logger.info(f"No valid fields to update for user {user_id}")
            return _row_to_dict(row)

        params.append(user_id)
        conn.execute(
            f"UPDATE users SET {', '.join(sets)} WHERE id = ?",
            params,
        )
        conn.commit()
        row = conn.execute("SELECT * FROM users WHERE id = ?",
                           (user_id,)).fetchone()
        logger.info(f"Updated user {user_id}: fields={list(updates.keys())}")
        return _row_to_dict(row)
    except Exception as e:
        logger.error(f"Failed to update user {user_id}: {e}")
        return None
    finally:
        if conn:
            conn.close()


def delete_user(user_id):
    """Delete a user by id.  Prevents deleting the last admin.

    Returns True on success, False on failure.
    """
    conn = None
    try:
        conn = _get_conn()
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM users WHERE id = ?",
                           (user_id,)).fetchone()
        if row is None:
            conn.rollback()
            logger.warning(f"Cannot delete user {user_id}: not found")
            return False

        # Prevent deleting the last admin
        if row["role"] == "admin":
            admin_count = conn.execute(
                "SELECT COUNT(*) as cnt FROM users WHERE role = 'admin'"
            ).fetchone()["cnt"]
            if admin_count <= 1:
                conn.rollback()
                logger.warning("Cannot delete the last admin user")
                return False

        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        logger.info(f"Deleted user {user_id} ('{row['username']}')")
        return True
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Failed to delete user {user_id}: {e}")
        return False
    finally:
        if conn:
            conn.close()


def check_permission(user_role, required_role):
    """Return True if user_role level >= required_role level.

    Unknown roles are treated as having level 0 (no access).
    """
    try:
        user_level = ROLES.get(user_role, {}).get("level", 0)
        required_level = ROLES.get(required_role, {}).get("level", 0)
        return user_level >= required_level
    except Exception as e:
        logger.error(f"Permission check error: {e}")
        return False


def migrate_from_config(config):
    """Migrate from legacy single-user config to the users database.

    Called on first run.  If no users exist yet:
    - If config has auth.username + auth.password_hash, create an admin
      user with those credentials (the hash is inserted directly).
    - Otherwise, create a default admin/admin user and log a warning.
    """
    conn = None
    try:
        conn = _get_conn()
        count = conn.execute("SELECT COUNT(*) as cnt FROM users").fetchone()["cnt"]
        if count > 0:
            logger.debug("Users already exist, skipping migration")
            return

        auth = config.get("auth", {}) if config else {}
        now = datetime.now(timezone.utc).isoformat()

        if auth.get("username") and auth.get("password_hash"):
            username = auth["username"]
            password_hash = auth["password_hash"]
            conn.execute(
                """INSERT INTO users (username, password_hash, role, email, created_at)
                   VALUES (?, ?, 'admin', '', ?)""",
                (username, password_hash, now),
            )
            conn.commit()
            logger.info(f"Migrated admin user '{username}' from config")
        else:
            import secrets
            default_password = secrets.token_urlsafe(16)
            default_hash = generate_password_hash(default_password)
            conn.execute(
                """INSERT INTO users (username, password_hash, role, email, created_at)
                   VALUES ('admin', ?, 'admin', '', ?)""",
                (default_hash, now),
            )
            conn.commit()
            logger.warning("No auth config found -- created default admin user. Check stdout for initial password.")
            # Also print to stdout for first-run visibility
            print(f"\n{'='*60}")
            print(f"  DEFAULT ADMIN CREDENTIALS (change immediately!)")
            print(f"  Username: admin")
            print(f"  Password: {default_password}")
            print(f"{'='*60}\n")
    except Exception as e:
        logger.error(f"Failed to migrate users from config: {e}")
    finally:
        if conn:
            conn.close()


def get_user_stats():
    """Return a dict with total user count and per-role breakdowns."""
    conn = None
    try:
        conn = _get_conn()
        total = conn.execute(
            "SELECT COUNT(*) as cnt FROM users"
        ).fetchone()["cnt"]
        rows = conn.execute(
            "SELECT role, COUNT(*) as cnt FROM users GROUP BY role"
        ).fetchall()
        by_role = {role: 0 for role in ROLES}
        for r in rows:
            by_role[r["role"]] = r["cnt"]
        return {"total": total, "by_role": by_role}
    except Exception as e:
        logger.error(f"Failed to get user stats: {e}")
        return {"total": 0, "by_role": {role: 0 for role in ROLES}}
    finally:
        if conn:
            conn.close()
