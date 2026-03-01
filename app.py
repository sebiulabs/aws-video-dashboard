"""
AWS Video Engineering Dashboard — Flask App
=============================================
Full web dashboard with 4 pages:
  1. Dashboard — EC2, deployments, ECS, MediaLive, MediaConnect, CloudFront, IVS
  2. Alerts — Easy alert rule builder with templates
  3. AI Assistant — OpenRouter-powered infrastructure Q&A
  4. Settings — All config: AWS, monitoring toggles, email/WhatsApp/Telegram, AI

Run:  python app.py
Visit: http://localhost:5000
"""

import json
import os
from datetime import datetime
import uuid
from flask import Flask, Response, jsonify, render_template_string, request, session, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from config_manager import load_config, save_config, update_config, get_masked_config
from monitor import run_check, send_whatsapp, send_notifications, send_daily_summary
from email_notifier import send_email
from telegram_notifier import send_telegram
from slack_notifier import send_slack
from discord_notifier import send_discord
from teams_notifier import send_teams
from openrouter_ai import query_openrouter, get_available_models
from history_db import save_snapshot, get_history
from alert_rules import (
    get_rules, add_rule, update_rule, delete_rule, add_template,
    SERVICE_METRICS, RULE_TEMPLATES,
)
from easy_monitor import (
    get_endpoints, add_endpoint, update_endpoint, delete_endpoint,
    check_single_endpoint, run_endpoint_checks, ENDPOINT_TEMPLATES,
)

try:
    from ec2_manager import (
        EC2_MEDIA_TEMPLATES, WINDOWS_EC2_TEMPLATES,
        check_ec2_instances, launch_ec2_instance, ec2_instance_action,
        terminate_ec2_instance, create_ami_from_instance, list_custom_amis,
        deregister_ami, list_security_groups, list_key_pairs,
    )
    _EC2_AVAILABLE = True
except ImportError:
    _EC2_AVAILABLE = False
    EC2_MEDIA_TEMPLATES = []
    WINDOWS_EC2_TEMPLATES = []

try:
    from ai_actions import ACTION_REGISTRY, get_action
except ImportError:
    ACTION_REGISTRY = []
    def get_action(x): return None

try:
    from incident_manager import (
        create_incident, get_incidents, get_incident, acknowledge_incident,
        resolve_incident, add_note, find_open_incident, get_incident_stats,
    )
    _INCIDENTS_AVAILABLE = True
except ImportError:
    _INCIDENTS_AVAILABLE = False

try:
    from aws_services_monitor import (
        check_rds, check_lambda, check_s3, check_sqs, check_route53, check_apigateway,
        check_vpcs, check_load_balancers, check_elastic_ips, check_nat_gateways,
        check_security_groups as check_security_groups_monitor, check_vpn_connections,
    )
    _AWS_SERVICES_AVAILABLE = True
except ImportError:
    _AWS_SERVICES_AVAILABLE = False

try:
    from log_viewer import list_log_groups, list_log_streams, get_log_events, search_logs
    _LOGS_AVAILABLE = True
except ImportError:
    _LOGS_AVAILABLE = False

try:
    from cost_dashboard import get_daily_costs, get_monthly_summary, get_service_breakdown, get_budget_status
    _COSTS_AVAILABLE = True
except ImportError:
    _COSTS_AVAILABLE = False

try:
    from remediation import should_remediate, log_remediation, get_remediation_log, get_remediation_stats, REMEDIATION_PRESETS
    _REMEDIATION_AVAILABLE = True
except ImportError:
    _REMEDIATION_AVAILABLE = False
    REMEDIATION_PRESETS = []

try:
    from schedule_manager import (
        create_schedule, get_schedules, get_schedule, update_schedule,
        delete_schedule, toggle_schedule, log_run, get_runs, get_schedule_stats,
        CRON_PRESETS,
    )
    _SCHEDULES_AVAILABLE = True
except ImportError:
    _SCHEDULES_AVAILABLE = False
    CRON_PRESETS = []

try:
    from user_manager import (
        create_user, get_users, get_user, get_user_by_username,
        authenticate as user_authenticate,
        update_user, delete_user, check_permission, migrate_from_config,
        get_user_stats, ROLES,
    )
    _USERS_AVAILABLE = True
except ImportError:
    _USERS_AVAILABLE = False
    ROLES = {}

try:
    from gcp_manager import (
        check_gce_instances, check_gke_clusters, check_cloud_run, check_gcs_buckets,
        launch_gce_instance, gce_instance_action, create_gce_image,
        GCE_MEDIA_TEMPLATES, _GCP_AVAILABLE,
    )
except ImportError:
    _GCP_AVAILABLE = False
    GCE_MEDIA_TEMPLATES = []

app = Flask(__name__)

# Stable secret key — persist to file so sessions survive restarts
_SECRET_KEY_PATH = os.path.join(os.environ.get("DATA_DIR", os.path.dirname(__file__)), ".flask_secret")
def _get_secret_key():
    env_key = os.environ.get("FLASK_SECRET_KEY")
    if env_key:
        return env_key
    if os.path.exists(_SECRET_KEY_PATH):
        with open(_SECRET_KEY_PATH, "r") as f:
            return f.read().strip()
    key = os.urandom(32).hex()
    with open(_SECRET_KEY_PATH, "w") as f:
        f.write(key)
    os.chmod(_SECRET_KEY_PATH, 0o600)
    return key

app.secret_key = _get_secret_key()
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"
from datetime import timedelta
app.permanent_session_lifetime = timedelta(hours=8)

last_check = {"data": None, "timestamp": None}
ai_conversations = {}  # session-less conversation store (keyed by simple ID)
_AI_CONV_MAX = 50  # Maximum concurrent conversations

# Login rate limiting — per-IP attempt tracking
import time as _time
_login_attempts = {}  # ip -> [timestamp, ...]
_LOGIN_MAX = 5        # max attempts
_LOGIN_WINDOW = 300   # 5-minute window
_RATE_LIMIT_MAX_IPS = 10000  # cap to prevent memory exhaustion

# EC2 rate limiting — prevent spamming expensive operations
_ec2_rate = {}  # ip -> [timestamp, ...]
_EC2_RATE_MAX = 10    # max EC2 ops per window
_EC2_RATE_WINDOW = 300  # 5-minute window

def _prune_rate_dict(d, window):
    """Remove expired entries and cap dict size to prevent memory exhaustion."""
    now = _time.time()
    expired = [ip for ip, ts in d.items() if not any(now - t < window for t in ts)]
    for ip in expired:
        del d[ip]
    # Hard cap: if still too large, drop oldest entries
    if len(d) > _RATE_LIMIT_MAX_IPS:
        sorted_ips = sorted(d.keys(), key=lambda ip: max(d[ip]) if d[ip] else 0)
        for ip in sorted_ips[:len(d) - _RATE_LIMIT_MAX_IPS]:
            del d[ip]

def _check_ec2_rate_limit():
    """Return error response if EC2 rate limit exceeded, else None."""
    ip = request.remote_addr or "unknown"
    now = _time.time()
    # Periodic cleanup every 100 entries
    if len(_ec2_rate) > 100:
        _prune_rate_dict(_ec2_rate, _EC2_RATE_WINDOW)
    attempts = _ec2_rate.get(ip, [])
    attempts = [t for t in attempts if now - t < _EC2_RATE_WINDOW]
    if len(attempts) >= _EC2_RATE_MAX:
        return jsonify({"ok": False, "error": "Rate limit exceeded. Too many EC2 operations."}), 429
    attempts.append(now)
    _ec2_rate[ip] = attempts
    return None


def _safe_int(val, default=0, min_val=None, max_val=None):
    try:
        v = int(val)
    except (TypeError, ValueError):
        return default
    if min_val is not None: v = max(v, min_val)
    if max_val is not None: v = min(v, max_val)
    return v


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )
    return response


@app.before_request
def require_login():
    # CSRF check — state-changing requests must have JSON content type + origin
    if request.method in ("POST", "PUT", "DELETE") and request.path.startswith("/api/"):
        ct = request.content_type or ""
        if "application/json" not in ct:
            return jsonify({"error": "invalid content type"}), 400
        # Origin / Referer check to prevent cross-site requests
        origin = request.headers.get("Origin", "")
        referer = request.headers.get("Referer", "")
        if origin:
            from urllib.parse import urlparse
            origin_host = urlparse(origin).netloc.split(":")[0]
            request_host = request.host.split(":")[0]
            if origin_host and origin_host != request_host:
                return jsonify({"error": "cross-origin request blocked"}), 403
        elif not referer:
            return jsonify({"error": "missing origin header"}), 403

    auth = load_config().get("auth", {})
    if not auth.get("password_hash"):
        return None
    if request.endpoint in ("page_login", "api_login", "health_check"):
        return None
    if not session.get("logged_in"):
        if request.path.startswith("/api/"):
            return jsonify({"error": "unauthorized"}), 401
        return redirect("/login")


def _require_role(min_role):
    """Check that the current session user has at least min_role level.
    Returns an error response if insufficient, or None if OK."""
    if not _USERS_AVAILABLE:
        return None  # RBAC module not loaded — allow (legacy mode)
    # If no auth is configured (no password hash), skip RBAC
    auth = load_config().get("auth", {})
    if not auth.get("password_hash"):
        return None
    user_role = session.get("user_role", "viewer")
    if not check_permission(user_role, min_role):
        return jsonify({"ok": False, "error": "Insufficient permissions"}), 403
    return None


def scheduled_check():
    result = run_check(send_alerts=True)
    last_check["data"] = result
    last_check["timestamp"] = datetime.utcnow().isoformat()
    save_snapshot(result)

    # Create incidents from triggered alert rules + auto-remediate
    if _INCIDENTS_AVAILABLE:
        # Build a lookup of rules by ID for remediation checks
        rules_by_id = {}
        if _REMEDIATION_AVAILABLE:
            try:
                rules_by_id = {r["id"]: r for r in get_rules()}
            except Exception:
                pass

        for ra in result.get("rule_alerts", []):
            rule_id = ra.get("rule_id", "")
            resource = ra.get("resource", "")
            existing = find_open_incident(rule_id, resource)
            incident = existing
            if not existing:
                incident = create_incident(
                    title=ra.get("rule_name", "Alert") + " triggered",
                    severity=ra.get("severity", "warning"),
                    alert_rule_id=rule_id,
                    resource_id=resource,
                    trigger_message=ra.get("message", ""),
                )

            # Auto-remediation
            if _REMEDIATION_AVAILABLE and rule_id in rules_by_id:
                rule = rules_by_id[rule_id]
                rem_cfg = rule.get("remediation", {})
                if rem_cfg.get("enabled"):
                    try:
                        past_log = get_remediation_log(rule_id=rule_id, limit=50)
                        if should_remediate(rule, past_log):
                            action_id = rem_cfg.get("action", "")
                            params = rem_cfg.get("params", {})
                            config = load_config()
                            rem_result = _execute_action(action_id, params, config)
                            success = rem_result.get("ok", False) if isinstance(rem_result, dict) else False
                            incident_id = incident.get("id") if incident else None
                            log_remediation(rule_id, action_id, params, rem_result, success, incident_id)
                            if incident and _INCIDENTS_AVAILABLE:
                                add_note(
                                    incident["id"],
                                    f"Auto-remediation executed: {action_id} — {'success' if success else 'failed'}",
                                    author="system",
                                )
                            _audit_logger.info(
                                "[REMEDIATION] rule=%s action=%s success=%s", rule_id, action_id, success
                            )
                    except Exception as e:
                        _logging.getLogger(__name__).error("Remediation failed for rule %s: %s", rule_id, e)


# ═════════════════════════════════════════════════════════════════════════════
# AUTH
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/login")
def page_login():
    return render_template_string("""<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login — AWS Video Dashboard</title>""" + SHARED_STYLES + """
<style>.login-box{max-width:360px;margin:80px auto;background:#161b22;border:1px solid #21262d;border-radius:8px;padding:30px}
.login-box h2{text-align:center;color:#58a6ff;margin-bottom:20px;font-size:1.1rem}</style>
</head><body>
<div class="login-box">
    <h2>AWS Video Dashboard</h2>
    <div class="field"><label>Username</label><input type="text" id="user" autofocus></div>
    <div class="field"><label>Password</label><input type="password" id="pass" onkeydown="if(event.key==='Enter')doLogin()"></div>
    <div id="err" style="color:#f85149;font-size:.82rem;margin:8px 0;display:none"></div>
    <button class="btn p" onclick="doLogin()" style="width:100%;margin-top:12px;justify-content:center">Login</button>
</div>
<script>
async function doLogin(){
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({username:document.getElementById('user').value,password:document.getElementById('pass').value})});
    const j=await r.json();
    if(j.ok){window.location='/'}
    else{const e=document.getElementById('err');e.textContent=j.error||'Invalid credentials';e.style.display='block'}
}
</script></body></html>""")

@app.route("/api/login", methods=["POST"])
def api_login():
    ip = request.remote_addr or "unknown"
    now = _time.time()
    # Periodic cleanup to prevent memory exhaustion
    if len(_login_attempts) > 100:
        _prune_rate_dict(_login_attempts, _LOGIN_WINDOW)
    # Rate limiting
    attempts = _login_attempts.get(ip, [])
    attempts = [t for t in attempts if now - t < _LOGIN_WINDOW]
    if len(attempts) >= _LOGIN_MAX:
        return jsonify({"ok": False, "error": "Too many attempts. Try again later."}), 429
    data = request.json or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # Try multi-user auth first
    authenticated_user = None
    if _USERS_AVAILABLE:
        authenticated_user = user_authenticate(username, password)

    # Fall back to legacy single-user auth
    if not authenticated_user:
        auth = load_config().get("auth", {})
        if (username == auth.get("username", "admin") and
                auth.get("password_hash") and
                check_password_hash(auth.get("password_hash", ""), password)):
            authenticated_user = {"username": username, "role": "admin", "id": 0}

    if authenticated_user:
        _login_attempts.pop(ip, None)
        session.clear()
        session.permanent = True
        session["logged_in"] = True
        session["user_id"] = authenticated_user.get("id", 0)
        session["username"] = authenticated_user.get("username", "admin")
        session["user_role"] = authenticated_user.get("role", "admin")
        return jsonify({"ok": True, "username": authenticated_user.get("username"),
                        "role": authenticated_user.get("role")})

    attempts.append(now)
    _login_attempts[ip] = attempts
    return jsonify({"ok": False, "error": "Invalid credentials"}), 401

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})


# ═════════════════════════════════════════════════════════════════════════════
# API ROUTES
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/health")
def health_check():
    return jsonify({"status": "ok"}), 200


@app.route("/api/status")
def api_status():
    if last_check["data"] is None:
        try:
            scheduled_check()
        except Exception:
            last_check["data"] = {"ec2": {"total": 0, "running": 0, "healthy": 0, "alerts": 0, "instances": []},
                                  "deployments": {"total": 0, "succeeded": 0, "failed": 0, "in_progress": 0, "items": []},
                                  "ecs_services": []}
            last_check["timestamp"] = datetime.utcnow().isoformat()
    return jsonify(last_check)

@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    rbac = _require_role("operator")
    if rbac: return rbac
    try:
        scheduled_check()
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Refresh failed: {e}")
        return jsonify({"status": "error", "message": "Check failed. See server logs."})
    return jsonify({"status": "ok", "timestamp": last_check["timestamp"]})


# ─── History ─────────────────────────────────────────────────────────────────

@app.route("/api/history")
def api_history():
    limit = request.args.get("limit", 500, type=int)
    return jsonify({"history": get_history(max(1, min(limit, 2000)))})


# ─── Config ──────────────────────────────────────────────────────────────────

@app.route("/api/config", methods=["GET"])
def api_get_config():
    rbac = _require_role("operator")
    if rbac: return rbac
    return jsonify(get_masked_config())

@app.route("/api/config", methods=["POST"])
def api_save_config():
    rbac = _require_role("admin")
    if rbac: return rbac
    incoming = request.json
    current = load_config()

    def preserve_masked(inc, cur, keys):
        for key in keys:
            if key in inc and isinstance(inc[key], str) and "••••" in inc[key]:
                inc[key] = cur.get(key, "")

    if "aws" in incoming:
        preserve_masked(incoming["aws"], current["aws"], ["access_key_id", "secret_access_key"])
    if "ai" in incoming:
        preserve_masked(incoming["ai"], current["ai"], ["openrouter_api_key"])
    if "notifications" in incoming and "channels" in incoming["notifications"]:
        ch = incoming["notifications"]["channels"]
        preserve_masked(ch.get("whatsapp", {}), current["notifications"]["channels"]["whatsapp"],
                        ["twilio_account_sid", "twilio_auth_token"])
        preserve_masked(ch.get("email", {}), current["notifications"]["channels"]["email"], ["smtp_password"])
        preserve_masked(ch.get("telegram", {}), current["notifications"]["channels"]["telegram"], ["bot_token"])
        preserve_masked(ch.get("slack", {}), current["notifications"]["channels"].get("slack", {}), ["webhook_url"])
        preserve_masked(ch.get("discord", {}), current["notifications"]["channels"].get("discord", {}), ["webhook_url"])
        preserve_masked(ch.get("teams", {}), current["notifications"]["channels"].get("teams", {}), ["webhook_url"])
        em = ch.get("email", {})
        if "to_addresses" in em and isinstance(em["to_addresses"], str):
            em["to_addresses"] = [a.strip() for a in em["to_addresses"].split(",") if a.strip()]

    # Auth — hash password, never store plaintext
    if "auth" in incoming:
        auth_in = incoming["auth"]
        new_pass = auth_in.pop("password", "")
        auth_in.pop("password2", None)
        current_pass = auth_in.pop("current_password", "")
        if new_pass:
            existing_hash = current.get("auth", {}).get("password_hash", "")
            if existing_hash:
                if not current_pass or not check_password_hash(existing_hash, current_pass):
                    return jsonify({"error": "Current password is incorrect"}), 403
            if len(new_pass) < 8:
                return jsonify({"error": "Password must be at least 8 characters"}), 400
            if not _re.search(r"[A-Za-z]", new_pass) or not _re.search(r"\d", new_pass):
                return jsonify({"error": "Password must contain both letters and numbers"}), 400
            auth_in["password_hash"] = generate_password_hash(new_pass)
        else:
            auth_in["password_hash"] = current.get("auth", {}).get("password_hash", "")

    updated = update_config(incoming)
    # Reschedule if interval changed
    if _scheduler and "monitoring" in incoming:
        new_interval = max(10, incoming["monitoring"].get("check_interval_seconds", 300))
        try:
            _scheduler.reschedule_job("main_check", trigger="interval", seconds=new_interval)
        except Exception:
            pass
    return jsonify({"status": "ok", "config": get_masked_config()})


# ─── Test Notifications ──────────────────────────────────────────────────────

@app.route("/api/test/whatsapp", methods=["POST"])
def api_test_whatsapp():
    rbac = _require_role("operator")
    if rbac: return rbac
    return jsonify({"sent": send_whatsapp("Test — WhatsApp is working!", load_config())})

@app.route("/api/test/email", methods=["POST"])
def api_test_email():
    rbac = _require_role("operator")
    if rbac: return rbac
    return jsonify({"sent": send_email("AWS Dashboard Test", "Email notifications working!", load_config())})

@app.route("/api/test/telegram", methods=["POST"])
def api_test_telegram():
    rbac = _require_role("operator")
    if rbac: return rbac
    return jsonify({"sent": send_telegram("Test — Telegram is working!", load_config())})

@app.route("/api/test/slack", methods=["POST"])
def api_test_slack():
    rbac = _require_role("operator")
    if rbac: return rbac
    return jsonify({"sent": send_slack("Test — Slack is working!", load_config())})

@app.route("/api/test/discord", methods=["POST"])
def api_test_discord():
    rbac = _require_role("operator")
    if rbac: return rbac
    return jsonify({"sent": send_discord("Test — Discord is working!", load_config())})

@app.route("/api/test/teams", methods=["POST"])
def api_test_teams():
    rbac = _require_role("operator")
    if rbac: return rbac
    return jsonify({"sent": send_teams("Test — Microsoft Teams is working!", load_config())})


# ─── Alert Rules API ────────────────────────────────────────────────────────

@app.route("/api/rules", methods=["GET"])
def api_get_rules():
    return jsonify({"rules": get_rules(), "metrics": SERVICE_METRICS, "templates": RULE_TEMPLATES})

@app.route("/api/rules", methods=["POST"])
def api_add_rule():
    rbac = _require_role("operator")
    if rbac: return rbac
    rule = add_rule(request.json or {})
    return jsonify({"status": "ok", "rule": rule})

@app.route("/api/rules/<rule_id>", methods=["PUT"])
def api_update_rule(rule_id):
    rbac = _require_role("operator")
    if rbac: return rbac
    rule = update_rule(rule_id, request.json or {})
    return jsonify({"status": "ok" if rule else "not_found", "rule": rule})

@app.route("/api/rules/<rule_id>", methods=["DELETE"])
def api_delete_rule(rule_id):
    rbac = _require_role("operator")
    if rbac: return rbac
    ok = delete_rule(rule_id)
    return jsonify({"status": "ok" if ok else "not_found"})

@app.route("/api/rules/template", methods=["POST"])
def api_add_template():
    rbac = _require_role("operator")
    if rbac: return rbac
    idx = request.json.get("index", 0)
    rule = add_template(idx)
    return jsonify({"status": "ok" if rule else "invalid_index", "rule": rule})


# ─── Incidents API ─────────────────────────────────────────────────────────

@app.route("/api/incidents")
def api_get_incidents():
    if not _INCIDENTS_AVAILABLE:
        return jsonify({"incidents": [], "error": "Incident manager not available"})
    status = request.args.get("status")
    severity = request.args.get("severity")
    limit = request.args.get("limit", 50, type=int)
    return jsonify({"incidents": get_incidents(status=status, severity=severity, limit=limit)})

@app.route("/api/incidents/stats")
def api_incident_stats():
    if not _INCIDENTS_AVAILABLE:
        return jsonify({"open": 0, "acknowledged": 0, "resolved": 0})
    return jsonify(get_incident_stats())

@app.route("/api/incidents/<int:id>")
def api_get_incident(id):
    if not _INCIDENTS_AVAILABLE:
        return jsonify({"error": "Incident manager not available"}), 503
    incident = get_incident(id)
    if not incident:
        return jsonify({"error": "not found"}), 404
    return jsonify({"incident": incident})

@app.route("/api/incidents/<int:id>/acknowledge", methods=["POST"])
def api_acknowledge_incident(id):
    rbac = _require_role("operator")
    if rbac: return rbac
    if not _INCIDENTS_AVAILABLE:
        return jsonify({"ok": False, "error": "Incident manager not available"}), 503
    data = request.json or {}
    result = acknowledge_incident(id, assigned_to=data.get("assigned_to"))
    if not result:
        return jsonify({"ok": False, "error": "not found or already resolved"}), 404
    return jsonify({"ok": True, "incident": result})

@app.route("/api/incidents/<int:id>/assign", methods=["POST"])
def api_assign_incident(id):
    rbac = _require_role("operator")
    if rbac: return rbac
    if not _INCIDENTS_AVAILABLE:
        return jsonify({"ok": False, "error": "Incident manager not available"}), 503
    data = request.json or {}
    assigned_to = data.get("assigned_to", "")
    if not assigned_to:
        return jsonify({"ok": False, "error": "assigned_to required"}), 400
    result = acknowledge_incident(id, assigned_to=assigned_to)
    if not result:
        return jsonify({"ok": False, "error": "not found or already resolved"}), 404
    return jsonify({"ok": True, "incident": result})

@app.route("/api/incidents/<int:id>/resolve", methods=["POST"])
def api_resolve_incident(id):
    rbac = _require_role("operator")
    if rbac: return rbac
    if not _INCIDENTS_AVAILABLE:
        return jsonify({"ok": False, "error": "Incident manager not available"}), 503
    data = request.json or {}
    result = resolve_incident(id, resolution_note=data.get("resolution_note", ""))
    if not result:
        return jsonify({"ok": False, "error": "not found or already resolved"}), 404
    return jsonify({"ok": True, "incident": result})

@app.route("/api/incidents/<int:id>/note", methods=["POST"])
def api_add_incident_note(id):
    rbac = _require_role("operator")
    if rbac: return rbac
    if not _INCIDENTS_AVAILABLE:
        return jsonify({"ok": False, "error": "Incident manager not available"}), 503
    data = request.json or {}
    note_text = data.get("note", "")
    if not note_text:
        return jsonify({"ok": False, "error": "note required"}), 400
    if len(note_text) > 5000:
        return jsonify({"ok": False, "error": "note too long (max 5000 chars)"}), 400
    result = add_note(id, note_text, author=session.get("username", "user"))
    if not result:
        return jsonify({"ok": False, "error": "failed to add note"}), 500
    return jsonify({"ok": True, "note": result})


# ─── Logs API ──────────────────────────────────────────────────────────────

@app.route("/api/logs/groups")
def api_log_groups():
    if not _LOGS_AVAILABLE:
        return jsonify({"ok": False, "error": "Log viewer not available"}), 503
    config = load_config()
    region = _validate_region(request.args.get("region"))
    prefix = request.args.get("prefix", "")
    groups = list_log_groups(config, region=region, prefix=prefix)
    return jsonify({"ok": True, "groups": groups})

@app.route("/api/logs/streams")
def api_log_streams():
    if not _LOGS_AVAILABLE:
        return jsonify({"ok": False, "error": "Log viewer not available"}), 503
    config = load_config()
    region = _validate_region(request.args.get("region"))
    group = request.args.get("group", "")
    if not group:
        return jsonify({"ok": False, "error": "group parameter required"}), 400
    if len(group) > 512:
        return jsonify({"ok": False, "error": "Log group name too long"}), 400
    prefix = request.args.get("prefix", "")[:256]
    limit = _safe_int(request.args.get("limit", 20), default=20, min_val=1, max_val=50)
    streams = list_log_streams(config, region=region, group=group, prefix=prefix, limit=limit)
    return jsonify({"ok": True, "streams": streams})

@app.route("/api/logs/events")
def api_log_events():
    if not _LOGS_AVAILABLE:
        return jsonify({"ok": False, "error": "Log viewer not available"}), 503
    config = load_config()
    region = _validate_region(request.args.get("region"))
    group = request.args.get("group", "")
    stream = request.args.get("stream", "")
    if not group or not stream:
        return jsonify({"ok": False, "error": "group and stream parameters required"}), 400
    limit = _safe_int(request.args.get("limit", 100), default=100, min_val=1, max_val=500)
    start_time = request.args.get("start_time", type=int)
    end_time = request.args.get("end_time", type=int)
    events = get_log_events(config, region=region, group=group, stream=stream,
                            start_time=start_time, end_time=end_time, limit=limit)
    return jsonify({"ok": True, "events": events})

@app.route("/api/logs/search", methods=["POST"])
def api_log_search():
    if not _LOGS_AVAILABLE:
        return jsonify({"ok": False, "error": "Log viewer not available"}), 503
    config = load_config()
    data = request.json or {}
    region = _validate_region(data.get("region"))
    group = data.get("group", "")
    if not group:
        return jsonify({"ok": False, "error": "group required"}), 400
    if len(group) > 512:
        return jsonify({"ok": False, "error": "Log group name too long"}), 400
    query = data.get("query", "")
    if len(query) > 10000:
        return jsonify({"ok": False, "error": "Query too long (max 10000 chars)"}), 400
    start_time = data.get("start_time")
    end_time = data.get("end_time")
    # Cap time range to 7 days max to prevent expensive queries
    if start_time and end_time:
        try:
            if int(end_time) - int(start_time) > 7 * 86400:
                start_time = int(end_time) - 7 * 86400
        except (ValueError, TypeError):
            pass
    results = search_logs(config, region=region, group=group, query=query,
                          start_time=start_time, end_time=end_time)
    return jsonify({"ok": True, "results": results})


# ─── Costs API ─────────────────────────────────────────────────────────────

@app.route("/api/costs/daily")
def api_costs_daily():
    if not _COSTS_AVAILABLE:
        return jsonify({"ok": False, "error": "Cost dashboard not available"}), 503
    config = load_config()
    days = _safe_int(request.args.get("days", 30), default=30, min_val=1, max_val=90)
    return jsonify({"ok": True, **get_daily_costs(config, days=days)})

@app.route("/api/costs/monthly")
def api_costs_monthly():
    if not _COSTS_AVAILABLE:
        return jsonify({"ok": False, "error": "Cost dashboard not available"}), 503
    config = load_config()
    months = _safe_int(request.args.get("months", 6), default=6, min_val=1, max_val=12)
    return jsonify({"ok": True, **get_monthly_summary(config, months=months)})

@app.route("/api/costs/services")
def api_costs_services():
    if not _COSTS_AVAILABLE:
        return jsonify({"ok": False, "error": "Cost dashboard not available"}), 503
    config = load_config()
    days = _safe_int(request.args.get("days", 30), default=30, min_val=1, max_val=90)
    return jsonify({"ok": True, **get_service_breakdown(config, days=days)})

@app.route("/api/costs/budgets")
def api_costs_budgets():
    if not _COSTS_AVAILABLE:
        return jsonify({"ok": False, "error": "Cost dashboard not available"}), 503
    config = load_config()
    return jsonify({"ok": True, **get_budget_status(config)})


# ─── Remediation API ──────────────────────────────────────────────────────

@app.route("/api/remediation/presets")
def api_remediation_presets():
    return jsonify({"ok": True, "presets": REMEDIATION_PRESETS})

@app.route("/api/remediation/log")
def api_remediation_log_list():
    if not _REMEDIATION_AVAILABLE:
        return jsonify({"ok": False, "error": "Remediation not available"}), 503
    rule_id = request.args.get("rule_id")
    limit = _safe_int(request.args.get("limit", 50), default=50, min_val=1, max_val=200)
    return jsonify({"ok": True, "entries": get_remediation_log(rule_id=rule_id, limit=limit)})

@app.route("/api/remediation/stats")
def api_remediation_stats_route():
    if not _REMEDIATION_AVAILABLE:
        return jsonify({"ok": False, "error": "Remediation not available"}), 503
    return jsonify({"ok": True, **get_remediation_stats()})


# ─── Schedules API ─────────────────────────────────────────────────────────

@app.route("/api/schedules", methods=["GET"])
def api_get_schedules():
    if not _SCHEDULES_AVAILABLE:
        return jsonify({"ok": False, "error": "Schedule manager not available"}), 503
    enabled_only = request.args.get("enabled_only", "false").lower() == "true"
    return jsonify({"ok": True, "schedules": get_schedules(enabled_only=enabled_only)})

@app.route("/api/schedules", methods=["POST"])
def api_create_schedule():
    rbac = _require_role("operator")
    if rbac: return rbac
    if not _SCHEDULES_AVAILABLE:
        return jsonify({"ok": False, "error": "Schedule manager not available"}), 503
    data = request.json or {}
    name = data.get("name", "")
    if not name:
        return jsonify({"ok": False, "error": "name required"}), 400
    if len(name) > 100:
        return jsonify({"ok": False, "error": "name too long (max 100 chars)"}), 400
    description = data.get("description", "")
    if len(description) > 500:
        return jsonify({"ok": False, "error": "description too long (max 500 chars)"}), 400
    action_id = data.get("action_id", "")
    if not action_id:
        return jsonify({"ok": False, "error": "action_id required"}), 400
    cron = data.get("cron_expression", "")
    if not cron:
        return jsonify({"ok": False, "error": "cron_expression required"}), 400
    result = create_schedule(name, action_id, data.get("action_params", {}),
                            cron, description)
    if not result:
        return jsonify({"ok": False, "error": "Failed to create schedule"}), 500
    _sync_schedule_jobs()
    return jsonify({"ok": True, "schedule": result})

@app.route("/api/schedules/<int:schedule_id>", methods=["GET"])
def api_get_schedule(schedule_id):
    if not _SCHEDULES_AVAILABLE:
        return jsonify({"ok": False, "error": "Schedule manager not available"}), 503
    s = get_schedule(schedule_id)
    if not s:
        return jsonify({"ok": False, "error": "Schedule not found"}), 404
    return jsonify({"ok": True, "schedule": s})

@app.route("/api/schedules/<int:schedule_id>", methods=["PUT"])
def api_update_schedule(schedule_id):
    rbac = _require_role("operator")
    if rbac: return rbac
    if not _SCHEDULES_AVAILABLE:
        return jsonify({"ok": False, "error": "Schedule manager not available"}), 503
    data = request.json or {}
    result = update_schedule(schedule_id, data)
    if not result:
        return jsonify({"ok": False, "error": "Schedule not found"}), 404
    return jsonify({"ok": True, "schedule": result})

@app.route("/api/schedules/<int:schedule_id>", methods=["DELETE"])
def api_delete_schedule(schedule_id):
    rbac = _require_role("admin")
    if rbac: return rbac
    if not _SCHEDULES_AVAILABLE:
        return jsonify({"ok": False, "error": "Schedule manager not available"}), 503
    ok = delete_schedule(schedule_id)
    _sync_schedule_jobs()
    return jsonify({"ok": ok})

@app.route("/api/schedules/<int:schedule_id>/toggle", methods=["POST"])
def api_toggle_schedule(schedule_id):
    rbac = _require_role("operator")
    if rbac: return rbac
    if not _SCHEDULES_AVAILABLE:
        return jsonify({"ok": False, "error": "Schedule manager not available"}), 503
    result = toggle_schedule(schedule_id)
    if not result:
        return jsonify({"ok": False, "error": "Schedule not found"}), 404
    _sync_schedule_jobs()
    return jsonify({"ok": True, "schedule": result})

@app.route("/api/schedules/<int:schedule_id>/runs")
def api_schedule_runs(schedule_id):
    if not _SCHEDULES_AVAILABLE:
        return jsonify({"ok": False, "error": "Schedule manager not available"}), 503
    limit = _safe_int(request.args.get("limit", 20), default=20, min_val=1, max_val=100)
    return jsonify({"ok": True, "runs": get_runs(schedule_id, limit=limit)})

@app.route("/api/schedules/stats")
def api_schedule_stats():
    if not _SCHEDULES_AVAILABLE:
        return jsonify({"ok": False, "error": "Schedule manager not available"}), 503
    return jsonify({"ok": True, **get_schedule_stats()})

@app.route("/api/schedules/presets")
def api_schedule_presets():
    return jsonify({"ok": True, "presets": CRON_PRESETS})


# ─── Users / RBAC API ─────────────────────────────────────────────────────

@app.route("/api/users", methods=["GET"])
def api_get_users():
    rbac = _require_role("admin")
    if rbac: return rbac
    if not _USERS_AVAILABLE:
        return jsonify({"ok": False, "error": "User manager not available"}), 503
    return jsonify({"ok": True, "users": get_users()})

@app.route("/api/users", methods=["POST"])
def api_create_user():
    rbac = _require_role("admin")
    if rbac: return rbac
    if not _USERS_AVAILABLE:
        return jsonify({"ok": False, "error": "User manager not available"}), 503
    data = request.json or {}
    username = data.get("username", "")
    password = data.get("password", "")
    role = data.get("role", "viewer")
    email = data.get("email", "")
    if not username or not password:
        return jsonify({"ok": False, "error": "username and password required"}), 400
    if len(email) > 200:
        return jsonify({"ok": False, "error": "email too long (max 200 chars)"}), 400
    result = create_user(username, password, role=role, email=email)
    if not result:
        return jsonify({"ok": False, "error": "Failed to create user (username may exist or validation failed)"}), 400
    _audit("user_create", f"user={username} role={role}", "medium")
    return jsonify({"ok": True, "user": result})

@app.route("/api/users/<int:user_id>", methods=["PUT"])
def api_update_user(user_id):
    rbac = _require_role("admin")
    if rbac: return rbac
    if not _USERS_AVAILABLE:
        return jsonify({"ok": False, "error": "User manager not available"}), 503
    data = request.json or {}
    result = update_user(user_id, data)
    if not result:
        return jsonify({"ok": False, "error": "User not found or validation failed"}), 404
    _audit("user_update", f"user_id={user_id}", "medium")
    return jsonify({"ok": True, "user": result})

@app.route("/api/users/<int:user_id>", methods=["DELETE"])
def api_delete_user(user_id):
    rbac = _require_role("admin")
    if rbac: return rbac
    if not _USERS_AVAILABLE:
        return jsonify({"ok": False, "error": "User manager not available"}), 503
    ok = delete_user(user_id)
    if not ok:
        return jsonify({"ok": False, "error": "Cannot delete (last admin or not found)"}), 400
    _audit("user_delete", f"user_id={user_id}", "high")
    return jsonify({"ok": ok})

@app.route("/api/users/stats")
def api_user_stats():
    rbac = _require_role("admin")
    if rbac: return rbac
    if not _USERS_AVAILABLE:
        return jsonify({"ok": False, "error": "User manager not available"}), 503
    return jsonify({"ok": True, **get_user_stats()})

@app.route("/api/users/me/password", methods=["POST"])
def api_change_my_password():
    """Let any authenticated user change their own password."""
    if not _USERS_AVAILABLE:
        return jsonify({"ok": False, "error": "User manager not available"}), 503
    if not session.get("logged_in"):
        return jsonify({"ok": False, "error": "Not authenticated"}), 401
    data = request.json or {}
    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")
    if not current_password or not new_password:
        return jsonify({"ok": False, "error": "current_password and new_password required"}), 400
    # Validate new password: 8+ chars with letters and numbers
    import re as _re
    if not _re.match(r'^(?=.*[A-Za-z])(?=.*[0-9]).{8,}$', new_password):
        return jsonify({"ok": False, "error": "New password must be 8+ characters with at least one letter and one number"}), 400
    # Verify current password
    username = session.get("username", "")
    user = get_user_by_username(username)
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404
    if not check_password_hash(user["password_hash"], current_password):
        return jsonify({"ok": False, "error": "Current password is incorrect"}), 403
    # Update password
    result = update_user(user["id"], {"password": new_password})
    if not result:
        return jsonify({"ok": False, "error": "Failed to update password"}), 500
    _audit("password_change", f"user={username}", "medium")
    return jsonify({"ok": True, "message": "Password changed successfully"})


# ─── GCP API ───────────────────────────────────────────────────────────────

@app.route("/api/cloud/gcp/instances")
def api_gcp_instances():
    if not _GCP_AVAILABLE:
        return jsonify({"ok": False, "error": "GCP not available"}), 503
    config = load_config()
    region = request.args.get("region")
    return jsonify({"ok": True, **check_gce_instances(config, region=region)})

@app.route("/api/cloud/gcp/clusters")
def api_gcp_clusters():
    if not _GCP_AVAILABLE:
        return jsonify({"ok": False, "error": "GCP not available"}), 503
    config = load_config()
    return jsonify({"ok": True, **check_gke_clusters(config)})

@app.route("/api/cloud/gcp/cloud-run")
def api_gcp_cloud_run():
    if not _GCP_AVAILABLE:
        return jsonify({"ok": False, "error": "GCP not available"}), 503
    config = load_config()
    region = request.args.get("region")
    return jsonify({"ok": True, **check_cloud_run(config, region=region)})

@app.route("/api/cloud/gcp/buckets")
def api_gcp_buckets():
    if not _GCP_AVAILABLE:
        return jsonify({"ok": False, "error": "GCP not available"}), 503
    config = load_config()
    return jsonify({"ok": True, **check_gcs_buckets(config)})

@app.route("/api/cloud/gcp/launch", methods=["POST"])
def api_gcp_launch():
    rbac = _require_role("operator")
    if rbac: return rbac
    if not _GCP_AVAILABLE:
        return jsonify({"ok": False, "error": "GCP not available"}), 503
    config = load_config()
    data = request.json or {}
    name = data.get("name", "")
    zone = data.get("zone", "")
    machine_type = data.get("machine_type", "")
    image_project = data.get("image_project", "ubuntu-os-cloud")
    image_family = data.get("image_family", "ubuntu-2204-lts")
    startup_script = data.get("startup_script", "")
    if not _validate_gcp_name(name):
        return jsonify({"ok": False, "error": "Invalid instance name"}), 400
    if not _validate_gcp_zone(zone):
        return jsonify({"ok": False, "error": "Invalid GCP zone"}), 400
    if not machine_type or not _VALID_GCP_MACHINE_TYPES.match(machine_type):
        return jsonify({"ok": False, "error": "Invalid machine type"}), 400
    if not image_project or not _VALID_GCP_IMAGE_REF.match(image_project):
        return jsonify({"ok": False, "error": "Invalid image_project"}), 400
    if not image_family or not _VALID_GCP_IMAGE_REF.match(image_family):
        return jsonify({"ok": False, "error": "Invalid image_family"}), 400
    if len(startup_script) > 10000:
        return jsonify({"ok": False, "error": "startup_script too long (max 10000 chars)"}), 400
    _audit("gcp_launch", f"name={name}", "high")
    result = launch_gce_instance(config, name, zone, machine_type,
                                 image_project, image_family, startup_script)
    return jsonify(result)

@app.route("/api/cloud/gcp/<instance_name>/action", methods=["POST"])
def api_gcp_action(instance_name):
    rbac = _require_role("operator")
    if rbac: return rbac
    if not _GCP_AVAILABLE:
        return jsonify({"ok": False, "error": "GCP not available"}), 503
    if not _validate_gcp_name(instance_name):
        return jsonify({"ok": False, "error": "Invalid instance name"}), 400
    config = load_config()
    data = request.json or {}
    action = data.get("action", "")
    zone = data.get("zone", "")
    if action not in _VALID_GCP_ACTIONS:
        return jsonify({"ok": False, "error": f"Invalid action. Must be one of: {', '.join(sorted(_VALID_GCP_ACTIONS))}"}), 400
    if not _validate_gcp_zone(zone):
        return jsonify({"ok": False, "error": "Invalid GCP zone"}), 400
    _audit("gcp_action", f"instance={instance_name} action={action}", "high")
    return jsonify(gce_instance_action(config, instance_name, zone, action))

@app.route("/api/cloud/gcp/templates")
def api_gcp_templates():
    return jsonify({"ok": True, "templates": GCE_MEDIA_TEMPLATES})

@app.route("/api/cloud/gcp/image", methods=["POST"])
def api_gcp_image():
    rbac = _require_role("operator")
    if rbac: return rbac
    if not _GCP_AVAILABLE:
        return jsonify({"ok": False, "error": "GCP not available"}), 503
    config = load_config()
    data = request.json or {}
    source_instance = data.get("source_instance", "")
    zone = data.get("zone", "")
    image_name = data.get("image_name", "")
    if not _validate_gcp_name(source_instance):
        return jsonify({"ok": False, "error": "Invalid source_instance name"}), 400
    if not _validate_gcp_zone(zone):
        return jsonify({"ok": False, "error": "Invalid GCP zone"}), 400
    if not _validate_gcp_name(image_name):
        return jsonify({"ok": False, "error": "Invalid image_name"}), 400
    _audit("gcp_image", f"source={source_instance}", "high")
    return jsonify(create_gce_image(config, source_instance, zone, image_name))


# ─── AI Assistant API ────────────────────────────────────────────────────────

@app.route("/api/ai/query", methods=["POST"])
def api_ai_query():
    data = request.json or {}
    message = data.get("message", "")
    conv_id = data.get("conversation_id", "default")
    model_override = data.get("model", "")

    if not message:
        return jsonify({"error": "No message provided"}), 400
    if len(message) > 5000:
        return jsonify({"error": "Message too long (max 5000 chars)"}), 400

    config = load_config()
    # Apply model override from frontend selector
    if model_override:
        config = dict(config)
        config["ai"] = dict(config.get("ai", {}))
        config["ai"]["model"] = model_override
    infra = last_check.get("data") or {}

    # Get/create conversation history (cap total conversations)
    if conv_id not in ai_conversations:
        if len(ai_conversations) >= _AI_CONV_MAX:
            # Remove oldest conversation
            oldest_key = next(iter(ai_conversations))
            ai_conversations.pop(oldest_key, None)
        ai_conversations[conv_id] = []

    result = query_openrouter(message, infra, config, ai_conversations[conv_id])

    # Store in history
    ai_conversations[conv_id].append({"role": "user", "content": message})
    if result.get("response"):
        ai_conversations[conv_id].append({"role": "assistant", "content": result["response"]})

    # Keep last 20 messages
    ai_conversations[conv_id] = ai_conversations[conv_id][-20:]

    return jsonify(result)

@app.route("/api/ai/models", methods=["GET"])
def api_ai_models():
    return jsonify({"models": get_available_models()})

@app.route("/api/ai/clear", methods=["POST"])
def api_ai_clear():
    conv_id = (request.json or {}).get("conversation_id", "default")
    ai_conversations.pop(conv_id, None)
    return jsonify({"status": "ok"})


# ─── Easy Monitor Endpoints API ─────────────────────────────────────────────

@app.route("/api/endpoints", methods=["GET"])
def api_get_endpoints():
    return jsonify({"endpoints": get_endpoints(), "templates": ENDPOINT_TEMPLATES})

@app.route("/api/endpoints", methods=["POST"])
def api_add_endpoint():
    rbac = _require_role("operator")
    if rbac: return rbac
    data = request.json or {}
    if isinstance(data.get("tags"), str):
        data["tags"] = [t.strip() for t in data["tags"].split(",") if t.strip()]
    ep = add_endpoint(data)
    return jsonify({"status": "ok", "endpoint": ep})

@app.route("/api/endpoints/<ep_id>", methods=["PUT"])
def api_update_endpoint(ep_id):
    rbac = _require_role("operator")
    if rbac: return rbac
    data = request.json or {}
    if isinstance(data.get("tags"), str):
        data["tags"] = [t.strip() for t in data["tags"].split(",") if t.strip()]
    ep = update_endpoint(ep_id, data)
    return jsonify({"status": "ok" if ep else "not_found", "endpoint": ep})

@app.route("/api/endpoints/<ep_id>", methods=["DELETE"])
def api_delete_endpoint(ep_id):
    rbac = _require_role("operator")
    if rbac: return rbac
    ok = delete_endpoint(ep_id)
    return jsonify({"status": "ok" if ok else "not_found"})

@app.route("/api/endpoints/<ep_id>/check", methods=["POST"])
def api_check_endpoint(ep_id):
    """Run a single endpoint check on demand."""
    endpoints = get_endpoints()
    for ep in endpoints:
        if ep["id"] == ep_id:
            result = check_single_endpoint(ep)
            # Persist result
            update_endpoint(ep_id, {"last_result": result})
            return jsonify({"status": "ok", "result": result})
    return jsonify({"status": "not_found"}), 404

@app.route("/api/endpoints/check-all", methods=["POST"])
def api_check_all_endpoints():
    """Run all endpoint checks now."""
    rbac = _require_role("operator")
    if rbac: return rbac
    results = run_endpoint_checks()
    return jsonify({"status": "ok", "results": results})


# ─── Input Validation Helpers ────────────────────────────────────────────────

import re as _re

_VALID_AWS_REGIONS = {
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "ca-central-1", "eu-west-1", "eu-west-2", "eu-west-3",
    "eu-central-1", "eu-north-1", "ap-south-1", "ap-southeast-1",
    "ap-southeast-2", "ap-northeast-1", "ap-northeast-2",
    "sa-east-1", "me-south-1", "af-south-1",
}
_RE_INSTANCE_ID = _re.compile(r"^i-[a-f0-9]{8,17}$")
_RE_AMI_ID = _re.compile(r"^ami-[a-f0-9]{8,17}$")
_VALID_EC2_ACTIONS = {"start", "stop", "reboot", "terminate"}
_VALID_INSTANCE_TYPES = _re.compile(r"^[a-z][a-z0-9]*\.[a-z0-9]+$")

def _validate_region(region):
    if not region:
        return None
    if region not in _VALID_AWS_REGIONS:
        return None
    return region

def _validate_instance_id(instance_id):
    if not instance_id or not _RE_INSTANCE_ID.match(instance_id):
        return False
    return True

def _validate_ami_id(ami_id):
    if not ami_id or not _RE_AMI_ID.match(ami_id):
        return False
    return True

# GCP validation
_VALID_GCP_ZONES = _re.compile(r'^[a-z]+-[a-z]+\d+-[a-z]$')  # e.g. us-central1-a
_VALID_GCP_MACHINE_TYPES = _re.compile(r'^[a-z][a-z0-9]*-[a-z]+-[a-z0-9]+$')  # e.g. n2-standard-8, e2-micro, c2d-standard-4
_VALID_GCP_ACTIONS = {'start', 'stop', 'reset', 'delete'}
_VALID_GCP_NAME = _re.compile(r'^[a-z][a-z0-9-]{0,62}$')  # GCP resource naming
_VALID_GCP_IMAGE_REF = _re.compile(r'^[a-z][a-z0-9-]+$')  # image_project / image_family

def _validate_gcp_zone(zone):
    if not zone or not _VALID_GCP_ZONES.match(zone):
        return False
    return True

def _validate_gcp_name(name):
    if not name or not _VALID_GCP_NAME.match(name):
        return False
    return True


# ─── EC2 Media Instances API ─────────────────────────────────────────────────

@app.route("/api/cloud/ec2/instances")
def api_ec2_instances():
    if not _EC2_AVAILABLE:
        return jsonify({"ok": False, "error": "EC2 manager not available", "instances": []})
    config = load_config()
    region = _validate_region(request.args.get("region"))
    return jsonify(check_ec2_instances(config, region))

@app.route("/api/cloud/ec2/templates")
def api_ec2_templates():
    return jsonify({
        "ok": True,
        "linux": EC2_MEDIA_TEMPLATES,
        "windows": WINDOWS_EC2_TEMPLATES,
        "total": len(EC2_MEDIA_TEMPLATES) + len(WINDOWS_EC2_TEMPLATES),
    })

@app.route("/api/cloud/ec2/launch", methods=["POST"])
def api_ec2_launch():
    rbac = _require_role("operator")
    if rbac: return rbac
    if not _EC2_AVAILABLE:
        return jsonify({"ok": False, "error": "EC2 manager not available"})
    rl = _check_ec2_rate_limit()
    if rl: return rl
    config = load_config()
    params = request.json or {}
    # Validate template_id exists
    all_tpl_ids = [t["id"] for t in EC2_MEDIA_TEMPLATES + WINDOWS_EC2_TEMPLATES]
    if params.get("template_id") not in all_tpl_ids:
        return jsonify({"ok": False, "error": "Invalid template_id"}), 400
    if params.get("region"):
        params["region"] = _validate_region(params["region"])
    if params.get("instance_type") and not _VALID_INSTANCE_TYPES.match(params["instance_type"]):
        return jsonify({"ok": False, "error": "Invalid instance_type format"}), 400
    _audit("ec2_launch", f"template={params.get('template_id')} type={params.get('instance_type')}", "high")
    return jsonify(launch_ec2_instance(config, params))

@app.route("/api/cloud/ec2/<instance_id>/action", methods=["POST"])
def api_ec2_action(instance_id):
    rbac = _require_role("operator")
    if rbac: return rbac
    if not _EC2_AVAILABLE:
        return jsonify({"ok": False, "error": "EC2 manager not available"})
    rl = _check_ec2_rate_limit()
    if rl: return rl
    if not _validate_instance_id(instance_id):
        return jsonify({"ok": False, "error": "Invalid instance ID format"}), 400
    config = load_config()
    data = request.json or {}
    action = data.get("action", "")
    if action not in _VALID_EC2_ACTIONS:
        return jsonify({"ok": False, "error": f"Invalid action. Must be one of: {', '.join(_VALID_EC2_ACTIONS)}"}), 400
    region = _validate_region(data.get("region"))
    _audit(f"ec2_{action}", f"instance={instance_id}", "high")
    if action == "terminate":
        return jsonify(terminate_ec2_instance(config, instance_id, region))
    return jsonify(ec2_instance_action(config, instance_id, action, region))

@app.route("/api/cloud/ec2/ami/build", methods=["POST"])
def api_ec2_ami_build():
    """Launch an instance tagged for AMI building."""
    rbac = _require_role("operator")
    if rbac: return rbac
    if not _EC2_AVAILABLE:
        return jsonify({"ok": False, "error": "EC2 manager not available"})
    rl = _check_ec2_rate_limit()
    if rl: return rl
    config = load_config()
    params = request.json or {}
    all_tpl_ids = [t["id"] for t in EC2_MEDIA_TEMPLATES + WINDOWS_EC2_TEMPLATES]
    if params.get("template_id") not in all_tpl_ids:
        return jsonify({"ok": False, "error": "Invalid template_id"}), 400
    if params.get("region"):
        params["region"] = _validate_region(params["region"])
    params["build_ami"] = True
    return jsonify(launch_ec2_instance(config, params))

@app.route("/api/cloud/ec2/ami/create", methods=["POST"])
def api_ec2_ami_create():
    """Stop instance and create AMI from it."""
    rbac = _require_role("operator")
    if rbac: return rbac
    if not _EC2_AVAILABLE:
        return jsonify({"ok": False, "error": "EC2 manager not available"})
    rl = _check_ec2_rate_limit()
    if rl: return rl
    config = load_config()
    data = request.json or {}
    instance_id = data.get("instance_id", "")
    name = data.get("name", "")
    description = data.get("description")
    region = _validate_region(data.get("region"))
    if not _validate_instance_id(instance_id):
        return jsonify({"ok": False, "error": "Invalid instance ID format"}), 400
    if not name or len(name) > 128 or not _re.match(r"^[a-zA-Z0-9][a-zA-Z0-9 _./-]*$", name):
        return jsonify({"ok": False, "error": "Invalid AMI name (alphanumeric, 1-128 chars)"}), 400
    _audit("ami_create", f"instance={instance_id} name={name}", "high")
    return jsonify(create_ami_from_instance(config, instance_id, name, description, region))

@app.route("/api/cloud/ec2/amis")
def api_ec2_amis():
    if not _EC2_AVAILABLE:
        return jsonify({"ok": False, "error": "EC2 manager not available", "amis": []})
    config = load_config()
    region = _validate_region(request.args.get("region"))
    return jsonify(list_custom_amis(config, region))

@app.route("/api/cloud/ec2/ami/<ami_id>/deregister", methods=["POST"])
def api_ec2_ami_deregister(ami_id):
    rbac = _require_role("operator")
    if rbac: return rbac
    if not _EC2_AVAILABLE:
        return jsonify({"ok": False, "error": "EC2 manager not available"})
    rl = _check_ec2_rate_limit()
    if rl: return rl
    if not _validate_ami_id(ami_id):
        return jsonify({"ok": False, "error": "Invalid AMI ID format"}), 400
    config = load_config()
    data = request.json or {}
    region = _validate_region(data.get("region"))
    _audit("ami_deregister", f"ami={ami_id}", "high")
    return jsonify(deregister_ami(config, ami_id, region))

@app.route("/api/cloud/ec2/vpc-info")
def api_ec2_vpc_info():
    if not _EC2_AVAILABLE:
        return jsonify({"ok": False, "error": "EC2 manager not available"})
    config = load_config()
    region = _validate_region(request.args.get("region"))
    sgs = list_security_groups(config, region) if _EC2_AVAILABLE else {"security_groups": []}
    kps = list_key_pairs(config, region) if _EC2_AVAILABLE else {"key_pairs": []}
    return jsonify({
        "ok": True,
        "security_groups": sgs.get("security_groups", []),
        "key_pairs": kps.get("key_pairs", []),
        "region": region,
    })

# ─── Audit Logging ──────────────────────────────────────────────────────────

import logging as _logging
_audit_logger = _logging.getLogger("audit")
_audit_handler = _logging.FileHandler(os.path.join(os.path.dirname(__file__), "audit.log"))
_audit_handler.setFormatter(_logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
_audit_logger.addHandler(_audit_handler)
_audit_logger.setLevel(_logging.INFO)

def _audit(action, detail="", risk="low"):
    ip = request.remote_addr if request else "system"
    user = session.get("username", "anonymous") if session.get("logged_in") else "anonymous"
    _audit_logger.info(f"[{risk.upper()}] user={user} ip={ip} action={action} {detail}")


# ─── AI Agent Mode — Autonomous Multi-Step Execution ────────────────────────

_agent_tasks = {}  # task_id -> task state dict
_AGENT_TASK_MAX = 100  # Maximum concurrent/stored tasks
_AGENT_TASK_TTL = 3600  # 1 hour TTL for completed tasks

def _cleanup_agent_tasks():
    """Remove completed/stopped/error tasks older than TTL and cap total size."""
    now = _time.time()
    to_remove = []
    for tid, t in _agent_tasks.items():
        if t.get("status") in ("complete", "stopped", "error"):
            if now - t.get("started_at", 0) > _AGENT_TASK_TTL:
                to_remove.append(tid)
    for tid in to_remove:
        _agent_tasks.pop(tid, None)
    # Hard cap: remove oldest if still over limit
    if len(_agent_tasks) > _AGENT_TASK_MAX:
        sorted_tasks = sorted(_agent_tasks.items(), key=lambda x: x[1].get("started_at", 0))
        for tid, _ in sorted_tasks[:len(_agent_tasks) - _AGENT_TASK_MAX]:
            _agent_tasks.pop(tid, None)


def _format_sse(event_type, data):
    """Format a Server-Sent Event."""
    return f"event: {event_type}\ndata: {json.dumps(data, default=str)}\n\n"


def _parse_action_proposals(text):
    """Extract ACTION_PROPOSAL JSON objects from AI response text."""
    proposals = []
    for line in text.split("\n"):
        line = line.strip()
        if line.startswith("ACTION_PROPOSAL:"):
            json_str = line[len("ACTION_PROPOSAL:"):].strip()
            try:
                proposal = json.loads(json_str)
                if "action" in proposal:
                    proposals.append(proposal)
            except (json.JSONDecodeError, ValueError):
                pass
    return proposals


def _parse_agent_plan(text):
    """Extract AGENT_PLAN list from AI response."""
    for line in text.split("\n"):
        line = line.strip()
        if line.startswith("AGENT_PLAN:"):
            json_str = line[len("AGENT_PLAN:"):].strip()
            try:
                plan = json.loads(json_str)
                if isinstance(plan, list):
                    return plan
            except (json.JSONDecodeError, ValueError):
                pass
    return None


def _parse_agent_complete(text):
    """Extract AGENT_COMPLETE summary from AI response."""
    for line in text.split("\n"):
        line = line.strip()
        if line.startswith("AGENT_COMPLETE:"):
            summary = line[len("AGENT_COMPLETE:"):].strip().strip('"\'')
            return summary
    return None


def _parse_agent_error(text):
    """Extract AGENT_ERROR message from AI response."""
    for line in text.split("\n"):
        line = line.strip()
        if line.startswith("AGENT_ERROR:"):
            msg = line[len("AGENT_ERROR:"):].strip().strip('"\'')
            return msg
    return None


def _strip_markers(text):
    """Remove ACTION_PROPOSAL/AGENT_PLAN/AGENT_COMPLETE/AGENT_ERROR lines from display text."""
    lines = []
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped.startswith(("ACTION_PROPOSAL:", "AGENT_PLAN:", "AGENT_COMPLETE:", "AGENT_ERROR:")):
            continue
        lines.append(line)
    return "\n".join(lines).strip()


@app.route("/api/ai/agent/start", methods=["POST"])
def api_ai_agent_start():
    """Start an autonomous agent task. Returns task_id for SSE streaming."""
    rbac = _require_role("operator")
    if rbac: return rbac
    _cleanup_agent_tasks()
    data = request.json or {}
    message = data.get("message", "").strip()
    if not message:
        return jsonify({"ok": False, "error": "No message provided"}), 400
    if len(message) > 2000:
        return jsonify({"ok": False, "error": "Message too long (max 2000 chars)"}), 400

    task_id = str(uuid.uuid4())
    _agent_tasks[task_id] = {
        "status": "running",
        "message": message,
        "conversation": [],
        "steps": [],
        "pending_action": None,
        "approved": None,  # None=waiting, True=approved, False=rejected
        "stop_flag": False,
        "started_at": _time.time(),
    }
    _audit("agent_start", f"task={task_id} msg={message[:80]}", "medium")
    return jsonify({"ok": True, "task_id": task_id})


@app.route("/api/ai/agent/events/<task_id>")
def api_ai_agent_events(task_id):
    """SSE stream of agent execution events."""
    task = _agent_tasks.get(task_id)
    if not task:
        return jsonify({"ok": False, "error": "Unknown task"}), 404

    config = load_config()
    infra = last_check.get("data") or {}
    max_steps = 20
    max_time = 300  # 5 minutes

    def generate():
        steps_taken = 0
        conversation = task["conversation"]
        user_message = task["message"]

        while steps_taken < max_steps:
            # Check stop flag
            if task.get("stop_flag"):
                yield _format_sse("stopped", {})
                task["status"] = "stopped"
                return

            # Check timeout
            elapsed = _time.time() - task["started_at"]
            if elapsed > max_time:
                yield _format_sse("complete", {"summary": "Maximum time reached", "steps_taken": steps_taken, "duration_ms": int(elapsed * 1000)})
                task["status"] = "complete"
                return

            # Step 1: Query AI
            yield _format_sse("thinking", {"step": steps_taken + 1})

            # Build the message to send
            if steps_taken == 0:
                msg_to_send = user_message
            else:
                # The conversation already has context from previous steps
                msg_to_send = None  # We'll use conversation history only

            try:
                if msg_to_send:
                    result = query_openrouter(msg_to_send, infra, config, conversation, agent_mode=True)
                    conversation.append({"role": "user", "content": msg_to_send})
                else:
                    # Continue — the last message in conversation is the action result feedback
                    result = query_openrouter("Continue with the next step.", infra, config, conversation, agent_mode=True)
                    conversation.append({"role": "user", "content": "Continue with the next step."})
            except Exception as e:
                yield _format_sse("error", {"message": f"AI query failed: {str(e)}"})
                task["status"] = "error"
                return

            if result.get("error") and result["error"] != None:
                yield _format_sse("error", {"message": result.get("response", "AI error")})
                task["status"] = "error"
                return

            ai_text = result.get("response", "")
            conversation.append({"role": "assistant", "content": ai_text})

            # Keep conversation bounded
            if len(conversation) > 40:
                conversation[:] = conversation[-30:]

            # Step 2: Parse markers
            plan = _parse_agent_plan(ai_text)
            if plan:
                yield _format_sse("plan", {"steps": plan})

            complete_summary = _parse_agent_complete(ai_text)
            error_msg = _parse_agent_error(ai_text)

            # Send clean AI text (without markers)
            clean_text = _strip_markers(ai_text)
            if clean_text:
                yield _format_sse("ai_response", {
                    "content": clean_text,
                    "model": result.get("model", ""),
                    "tokens": result.get("tokens", 0),
                })

            # Check for completion/error
            if complete_summary:
                elapsed = _time.time() - task["started_at"]
                yield _format_sse("complete", {"summary": complete_summary, "steps_taken": steps_taken, "duration_ms": int(elapsed * 1000)})
                task["status"] = "complete"
                return

            if error_msg:
                yield _format_sse("error", {"message": error_msg})
                task["status"] = "error"
                return

            # Step 3: Parse and execute action proposals
            proposals = _parse_action_proposals(ai_text)

            if not proposals:
                # No proposals and no completion marker — nudge AI or complete
                steps_taken += 1
                if steps_taken >= 3:
                    # After 3 turns with no actions, assume done
                    elapsed = _time.time() - task["started_at"]
                    yield _format_sse("complete", {"summary": "Agent finished (no more actions to take)", "steps_taken": steps_taken, "duration_ms": int(elapsed * 1000)})
                    task["status"] = "complete"
                    return
                conversation.append({"role": "user", "content": "Please propose your next action using ACTION_PROPOSAL format, or say AGENT_COMPLETE if you are done."})
                continue

            # Execute first proposal (one at a time per protocol)
            proposal = proposals[0]
            action_id = proposal.get("action", "")
            params = proposal.get("params", {})
            reason = proposal.get("reason", "")

            # Look up action metadata
            action_meta = get_action(action_id) if get_action else None
            if not action_meta:
                yield _format_sse("action_proposed", {"action_id": action_id, "params": params, "reason": reason, "risk": "unknown", "name": action_id, "status": "invalid"})
                conversation.append({"role": "user", "content": f"Action '{action_id}' is not a valid action. Use one from the available actions list."})
                steps_taken += 1
                continue

            risk = action_meta.get("risk", "low")
            action_name = action_meta.get("name", action_id)

            yield _format_sse("action_proposed", {
                "action_id": action_id,
                "params": params,
                "reason": reason,
                "risk": risk,
                "name": action_name,
            })

            # Medium and high-risk actions need approval
            if risk in ("medium", "high"):
                task["pending_action"] = {"action_id": action_id, "params": params, "reason": reason}
                task["approved"] = None
                yield _format_sse("awaiting_approval", {
                    "action_id": action_id,
                    "params": params,
                    "reason": reason,
                    "risk": risk,
                    "name": action_name,
                    "confirm_message": action_meta.get("confirm_message", f"Execute {action_name}?"),
                })

                # Poll for approval
                while task["approved"] is None:
                    if task.get("stop_flag"):
                        yield _format_sse("stopped", {})
                        task["status"] = "stopped"
                        return
                    yield _format_sse("heartbeat", {})
                    _time.sleep(0.3)

                if not task["approved"]:
                    yield _format_sse("rejected", {"action_id": action_id})
                    conversation.append({"role": "user", "content": f"User REJECTED the action '{action_name}'. Please adjust your plan or say AGENT_COMPLETE."})
                    task["pending_action"] = None
                    steps_taken += 1
                    continue

                yield _format_sse("approved", {"action_id": action_id})
                task["pending_action"] = None

            # Execute the action
            yield _format_sse("executing", {"action_id": action_id, "name": action_name})
            _audit(f"agent_action:{action_id}", f"task={task_id} risk={risk} params={list(params.keys())}", risk)

            try:
                action_result = _execute_action(action_id, params, config)
            except Exception as e:
                action_result = {"ok": False, "error": str(e)}

            yield _format_sse("action_result", {
                "action_id": action_id,
                "name": action_name,
                "ok": action_result.get("ok", False),
                "message": action_result.get("message", ""),
                "data": action_result.get("data"),
                "error": action_result.get("error"),
            })

            # Feed result back to AI
            result_summary = json.dumps(action_result, default=str)
            if len(result_summary) > 3000:
                result_summary = result_summary[:3000] + "...(truncated)"
            conversation.append({"role": "user", "content": f"Action result for '{action_name}':\n{result_summary}"})

            steps_taken += 1

        # Max steps reached
        elapsed = _time.time() - task["started_at"]
        yield _format_sse("complete", {"summary": "Maximum steps reached", "steps_taken": steps_taken, "duration_ms": int(elapsed * 1000)})
        task["status"] = "complete"

    return Response(generate(), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    })


@app.route("/api/ai/agent/<task_id>/approve", methods=["POST"])
def api_ai_agent_approve(task_id):
    """Approve or reject a pending high-risk action."""
    rbac = _require_role("operator")
    if rbac: return rbac
    task = _agent_tasks.get(task_id)
    if not task:
        return jsonify({"ok": False, "error": "Unknown task"}), 404
    data = request.json or {}
    task["approved"] = data.get("approved", True)
    return jsonify({"ok": True})


@app.route("/api/ai/agent/<task_id>/stop", methods=["POST"])
def api_ai_agent_stop(task_id):
    """Stop a running agent task."""
    rbac = _require_role("operator")
    if rbac: return rbac
    task = _agent_tasks.get(task_id)
    if not task:
        return jsonify({"ok": False, "error": "Unknown task"}), 404
    task["stop_flag"] = True
    _audit("agent_stop", f"task={task_id}", "low")
    return jsonify({"ok": True})


# ─── AI Action Executors ────────────────────────────────────────────────────

@app.route("/api/ai/actions", methods=["GET"])
def api_ai_actions():
    return jsonify({"actions": ACTION_REGISTRY, "count": len(ACTION_REGISTRY)})

@app.route("/api/ai/actions/execute", methods=["POST"])
def api_ai_action_execute():
    rbac = _require_role("operator")
    if rbac: return rbac
    data = request.json or {}
    action_id = data.get("action_id", "")
    params = data.get("params", {})

    action = get_action(action_id) if get_action else None
    if not action:
        return jsonify({"ok": False, "error": f"Unknown action: {action_id}"})

    # High-risk actions require admin role
    if action.get("risk") == "high":
        rbac = _require_role("admin")
        if rbac: return rbac

    # Audit log all action executions
    _audit(f"ai_action:{action_id}", f"risk={action.get('risk','?')} params={list(params.keys())}", action.get("risk", "low"))

    config = load_config()
    try:
        result = _execute_action(action_id, params, config)
        return jsonify(result)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


def _get_cost_explorer(config, params):
    """Query AWS Cost Explorer for a cost summary."""
    import boto3
    from datetime import datetime, timedelta
    days = int(params.get("days", 30))
    days = max(1, min(days, 365))
    aws = config.get("aws", {})
    kwargs = {"region_name": "us-east-1"}
    ak = aws.get("access_key_id", "")
    sk = aws.get("secret_access_key", "")
    if ak and sk and "••••" not in ak and "••••" not in sk:
        kwargs["aws_access_key_id"] = ak
        kwargs["aws_secret_access_key"] = sk
    ce = boto3.client("ce", **kwargs)
    end = datetime.utcnow().strftime("%Y-%m-%d")
    start = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    resp = ce.get_cost_and_usage(
        TimePeriod={"Start": start, "End": end},
        Granularity="MONTHLY",
        Metrics=["UnblendedCost"],
        GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
    )
    services = []
    for period in resp.get("ResultsByTime", []):
        for group in period.get("Groups", []):
            services.append({
                "service": group["Keys"][0],
                "cost": group["Metrics"]["UnblendedCost"]["Amount"],
                "unit": group["Metrics"]["UnblendedCost"]["Unit"],
            })
    return {"ok": True, "services": services, "period": f"{start} to {end}", "message": f"Cost summary for last {days} days"}


def _execute_action(action_id, params, config):
    """Route action execution to the appropriate backend function."""
    if action_id == "build_aws_ami":
        if not _EC2_AVAILABLE:
            return {"ok": False, "error": "EC2 manager not available"}
        return create_ami_from_instance(
            config,
            params.get("instance_id", ""),
            params.get("name", ""),
            params.get("description"),
            params.get("region"),
        )
    elif action_id == "launch_ec2_media":
        if not _EC2_AVAILABLE:
            return {"ok": False, "error": "EC2 manager not available"}
        return launch_ec2_instance(config, params)
    elif action_id == "list_ec2_media":
        if not _EC2_AVAILABLE:
            return {"ok": False, "error": "EC2 manager not available"}
        return check_ec2_instances(config, params.get("region"))
    elif action_id == "check_status":
        try:
            scheduled_check()
            return {"ok": True, "message": "Infrastructure check complete", "data": last_check.get("data")}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    elif action_id == "run_endpoint_check":
        results = run_endpoint_checks()
        return {"ok": True, "results": results}
    elif action_id == "list_alert_rules":
        from alert_rules import get_rules
        return {"ok": True, "rules": get_rules()}
    elif action_id == "list_ec2_templates":
        return {"ok": True, "linux": EC2_MEDIA_TEMPLATES, "windows": WINDOWS_EC2_TEMPLATES}
    elif action_id == "ec2_instance_action":
        if not _EC2_AVAILABLE:
            return {"ok": False, "error": "EC2 manager not available"}
        instance_id = params.get("instance_id", "")
        action = params.get("action", "")
        if not _validate_instance_id(instance_id):
            return {"ok": False, "error": "Invalid instance ID format"}
        if action not in _VALID_EC2_ACTIONS:
            return {"ok": False, "error": f"Invalid action. Must be one of: {', '.join(_VALID_EC2_ACTIONS)}"}
        region = _validate_region(params.get("region"))
        if action == "terminate":
            return terminate_ec2_instance(config, instance_id, region)
        return ec2_instance_action(config, instance_id, action, region)
    elif action_id == "list_custom_amis":
        if not _EC2_AVAILABLE:
            return {"ok": False, "error": "EC2 manager not available"}
        return list_custom_amis(config, params.get("region"))
    elif action_id == "deregister_ami":
        if not _EC2_AVAILABLE:
            return {"ok": False, "error": "EC2 manager not available"}
        ami_id = params.get("ami_id", "")
        if not _validate_ami_id(ami_id):
            return {"ok": False, "error": "Invalid AMI ID format"}
        return deregister_ami(config, ami_id, _validate_region(params.get("region")))
    elif action_id == "get_vpc_info":
        if not _EC2_AVAILABLE:
            return {"ok": False, "error": "EC2 manager not available"}
        sgs = list_security_groups(config, params.get("region"))
        kps = list_key_pairs(config, params.get("region"))
        return {"ok": True, "security_groups": sgs.get("security_groups", []), "key_pairs": kps.get("key_pairs", [])}
    elif action_id == "add_alert_rule":
        rule = add_rule(params)
        return {"ok": True, "rule": rule, "message": f"Alert rule '{rule.get('name')}' created"}
    elif action_id == "delete_alert_rule":
        ok = delete_rule(params.get("rule_id", ""))
        return {"ok": ok, "message": "Rule deleted" if ok else "Rule not found"}
    elif action_id == "add_endpoint_monitor":
        ep = add_endpoint(params)
        return {"ok": True, "endpoint": ep, "message": f"Endpoint '{ep.get('name')}' added"}
    elif action_id == "test_notification":
        channel = params.get("channel", "")
        if channel == "email":
            sent = send_email("AWS Dashboard Test", "Email notifications working!", config)
        elif channel == "telegram":
            sent = send_telegram("Test — Telegram is working!", config)
        elif channel == "slack":
            sent = send_slack("Test — Slack is working!", config)
        elif channel == "discord":
            sent = send_discord("Test — Discord is working!", config)
        elif channel == "teams":
            sent = send_teams("Test — Microsoft Teams is working!", config)
        elif channel == "whatsapp":
            sent = send_whatsapp("Test — WhatsApp is working!", config)
        else:
            return {"ok": False, "error": f"Unknown channel: {channel}"}
        return {"ok": sent, "message": f"{channel} test {'sent' if sent else 'failed'}"}
    elif action_id == "describe_infrastructure":
        data = last_check.get("data") or {}
        return {"ok": True, "data": data, "message": "Current infrastructure snapshot"}
    elif action_id in ("check_medialive", "check_mediaconnect", "check_cloudfront", "check_ecs", "check_ivs"):
        try:
            scheduled_check()
            data = last_check.get("data") or {}
            service_map = {
                "check_medialive": "medialive",
                "check_mediaconnect": "mediaconnect",
                "check_cloudfront": "cloudfront",
                "check_ecs": "ecs_services",
                "check_ivs": "ivs",
            }
            key = service_map.get(action_id, "")
            return {"ok": True, "data": data.get(key, {}), "message": f"{key} check complete"}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    elif action_id in ("check_rds", "check_lambda", "check_s3", "check_sqs", "check_route53",
                        "check_apigateway", "check_vpcs", "check_load_balancers", "check_elastic_ips",
                        "check_nat_gateways", "check_security_groups", "check_vpn_connections"):
        if not _AWS_SERVICES_AVAILABLE:
            return {"ok": False, "error": "AWS services monitor not available"}
        try:
            fn_map = {
                "check_rds": check_rds,
                "check_lambda": check_lambda,
                "check_s3": check_s3,
                "check_sqs": check_sqs,
                "check_route53": check_route53,
                "check_apigateway": check_apigateway,
                "check_vpcs": check_vpcs,
                "check_load_balancers": check_load_balancers,
                "check_elastic_ips": check_elastic_ips,
                "check_nat_gateways": check_nat_gateways,
                "check_security_groups": check_security_groups_monitor,
                "check_vpn_connections": check_vpn_connections,
            }
            fn = fn_map[action_id]
            result = fn(config, region=params.get("region"))
            return {"ok": True, "data": result, "message": f"{action_id} check complete"}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    elif action_id == "get_cost_summary":
        try:
            ce = _get_cost_explorer(config, params)
            return ce
        except Exception as e:
            return {"ok": False, "error": str(e), "message": "Cost Explorer requires the ce:GetCostAndUsage permission"}
    elif action_id == "update_monitoring_config":
        _ALLOWED_MONITORING_SETTINGS = {
            "check_interval_seconds", "cpu_threshold", "deployment_lookback_hours",
            "uptime_alert_hours",
        }
        setting = params.get("setting", "")
        value = params.get("value")
        if not setting:
            return {"ok": False, "error": "Setting name required"}
        if setting not in _ALLOWED_MONITORING_SETTINGS:
            return {"ok": False, "error": f"Setting '{setting}' not allowed. Allowed: {', '.join(sorted(_ALLOWED_MONITORING_SETTINGS))}"}
        # Coerce numeric values
        try:
            value = float(value) if "." in str(value) else int(value)
        except (ValueError, TypeError):
            return {"ok": False, "error": f"Invalid value for {setting}"}
        update_config({"monitoring": {setting: value}})
        return {"ok": True, "message": f"Updated monitoring.{setting} = {value}"}
    elif action_id == "toggle_service_monitoring":
        _ALLOWED_SERVICES = {
            "ec2", "codedeploy", "ecs", "medialive", "mediaconnect", "mediapackage",
            "cloudfront", "ivs", "rds", "lambda", "s3", "sqs", "route53", "apigateway",
            "vpc", "elb", "eip", "nat", "security_groups", "vpn",
        }
        service = params.get("service", "")
        if service not in _ALLOWED_SERVICES:
            return {"ok": False, "error": f"Unknown service. Allowed: {', '.join(sorted(_ALLOWED_SERVICES))}"}
        enabled = bool(params.get("enabled", True))
        key = f"monitor_{service}"
        update_config({"monitoring": {key: enabled}})
        return {"ok": True, "message": f"{'Enabled' if enabled else 'Disabled'} {service} monitoring"}
    elif action_id == "list_incidents":
        if not _INCIDENTS_AVAILABLE:
            return {"ok": False, "error": "Incident manager not available"}
        incidents = get_incidents(status=params.get("status"), severity=params.get("severity"))
        return {"ok": True, "incidents": incidents, "message": f"Found {len(incidents)} incident(s)"}
    elif action_id == "acknowledge_incident":
        if not _INCIDENTS_AVAILABLE:
            return {"ok": False, "error": "Incident manager not available"}
        result = acknowledge_incident(int(params.get("incident_id", 0)), assigned_to=params.get("assigned_to"))
        if not result:
            return {"ok": False, "error": "Incident not found or already resolved"}
        return {"ok": True, "incident": result, "message": f"Incident #{result['id']} acknowledged"}
    elif action_id == "resolve_incident":
        if not _INCIDENTS_AVAILABLE:
            return {"ok": False, "error": "Incident manager not available"}
        result = resolve_incident(int(params.get("incident_id", 0)), resolution_note=params.get("resolution_note", ""))
        if not result:
            return {"ok": False, "error": "Incident not found or already resolved"}
        return {"ok": True, "incident": result, "message": f"Incident #{result['id']} resolved"}
    elif action_id == "search_logs":
        if not _LOGS_AVAILABLE:
            return {"ok": False, "error": "Log viewer not available"}
        try:
            import time as _t
            group = params.get("group", "")
            query = params.get("query", "")
            hours = int(params.get("hours_back", 1))
            hours = max(1, min(hours, 168))
            now = int(_t.time())
            start = now - (hours * 3600)
            results = search_logs(config, group=group, query=query, start_time=start, end_time=now)
            return {"ok": True, "results": results, "message": f"Found {len(results)} log entries"}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    elif action_id == "get_daily_costs":
        if not _COSTS_AVAILABLE:
            return {"ok": False, "error": "Cost dashboard not available"}
        try:
            days = int(params.get("days", 30))
            return {"ok": True, **get_daily_costs(config, days=days)}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    elif action_id == "get_budget_status":
        if not _COSTS_AVAILABLE:
            return {"ok": False, "error": "Cost dashboard not available"}
        try:
            return {"ok": True, **get_budget_status(config)}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    elif action_id == "list_schedules":
        if not _SCHEDULES_AVAILABLE:
            return {"ok": False, "error": "Schedule manager not available"}
        return {"ok": True, "schedules": get_schedules(), "message": f"Found {len(get_schedules())} schedule(s)"}
    elif action_id == "create_schedule":
        if not _SCHEDULES_AVAILABLE:
            return {"ok": False, "error": "Schedule manager not available"}
        result = create_schedule(params.get("name", ""), params.get("action_id", ""),
                                params.get("action_params", {}), params.get("cron_expression", ""),
                                params.get("description", ""))
        return {"ok": bool(result), "schedule": result, "message": "Schedule created" if result else "Failed"}
    elif action_id == "delete_schedule":
        if not _SCHEDULES_AVAILABLE:
            return {"ok": False, "error": "Schedule manager not available"}
        ok = delete_schedule(int(params.get("schedule_id", 0)))
        return {"ok": ok, "message": "Schedule deleted" if ok else "Not found"}
    elif action_id == "list_gce_instances":
        if not _GCP_AVAILABLE:
            return {"ok": False, "error": "GCP not available"}
        return {"ok": True, **check_gce_instances(config, region=params.get("region"))}
    elif action_id == "launch_gce_instance":
        if not _GCP_AVAILABLE:
            return {"ok": False, "error": "GCP not available"}
        name = params.get("name", "")
        zone = params.get("zone", "")
        if not _validate_gcp_name(name):
            return {"ok": False, "error": "Invalid GCP instance name"}
        if not _validate_gcp_zone(zone):
            return {"ok": False, "error": "Invalid GCP zone"}
        return launch_gce_instance(config, name, zone,
                                   params.get("machine_type", ""), params.get("image_project", "ubuntu-os-cloud"),
                                   params.get("image_family", "ubuntu-2204-lts"))
    elif action_id == "gce_instance_action":
        if not _GCP_AVAILABLE:
            return {"ok": False, "error": "GCP not available"}
        instance_name = params.get("instance_name", "")
        zone = params.get("zone", "")
        action = params.get("action", "")
        if not _validate_gcp_name(instance_name):
            return {"ok": False, "error": "Invalid GCP instance name"}
        if not _validate_gcp_zone(zone):
            return {"ok": False, "error": "Invalid GCP zone"}
        if action not in _VALID_GCP_ACTIONS:
            return {"ok": False, "error": f"Invalid action. Must be one of: {', '.join(sorted(_VALID_GCP_ACTIONS))}"}
        return gce_instance_action(config, instance_name, zone, action)
    elif action_id == "check_gke_clusters":
        if not _GCP_AVAILABLE:
            return {"ok": False, "error": "GCP not available"}
        return {"ok": True, **check_gke_clusters(config)}
    elif action_id == "check_cloud_run":
        if not _GCP_AVAILABLE:
            return {"ok": False, "error": "GCP not available"}
        return {"ok": True, **check_cloud_run(config, region=params.get("region"))}
    else:
        return {"ok": False, "error": f"Action '{action_id}' not yet implemented"}


# ═════════════════════════════════════════════════════════════════════════════
# SHARED HTML / CSS
# ═════════════════════════════════════════════════════════════════════════════

SHARED_STYLES = """<script>function esc(s){if(s==null)return'';const d=document.createElement('div');d.textContent=String(s);return d.innerHTML}</script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f1117;color:#e1e4e8;padding:0}
a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}
code{background:#161b22;padding:2px 6px;border-radius:4px;font-size:0.85em;color:#f0883e}
.topnav{display:flex;align-items:center;gap:8px;padding:10px 20px;background:#161b22;border-bottom:1px solid #21262d;flex-wrap:wrap}
.topnav .logo{font-weight:700;font-size:1rem;color:#58a6ff;margin-right:12px}
.topnav a.nl{color:#8b949e;font-size:0.85rem;padding:5px 10px;border-radius:6px;transition:.15s}
.topnav a.nl:hover,.topnav a.nl.active{color:#e1e4e8;background:#21262d;text-decoration:none}
.container{max-width:1280px;margin:0 auto;padding:20px}
.btn{padding:7px 14px;border:1px solid #30363d;background:#21262d;color:#c9d1d9;border-radius:6px;cursor:pointer;font-size:.82rem;transition:.15s;display:inline-flex;align-items:center;gap:5px}
.btn:hover{background:#30363d}.btn.p{background:#238636;border-color:#2ea043;color:#fff}.btn.p:hover{background:#2ea043}
.btn.d{background:#da3633;border-color:#f85149;color:#fff}.btn.sm{padding:4px 8px;font-size:.75rem}
.btn:disabled{opacity:.5;cursor:not-allowed}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:20px}
.card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px}
.card .lb{font-size:.75rem;color:#8b949e;text-transform:uppercase;letter-spacing:.04em}
.card .vl{font-size:1.6rem;font-weight:700;margin-top:3px}
.green{color:#3fb950}.red{color:#f85149}.yellow{color:#d29922}.blue{color:#58a6ff}
.section{margin-bottom:20px}.section h2{font-size:1rem;margin-bottom:10px;color:#c9d1d9}
table{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #21262d;border-radius:8px;overflow:hidden}
th{background:#21262d;text-align:left;padding:8px 12px;font-size:.75rem;color:#8b949e;text-transform:uppercase}
td{padding:8px 12px;border-top:1px solid #21262d;font-size:.85rem}
tr:hover td{background:#1c2128}
.badge{display:inline-block;padding:2px 7px;border-radius:10px;font-size:.72rem;font-weight:600}
.badge.ok{background:#0d4429;color:#3fb950}.badge.warn{background:#3d2e00;color:#d29922}
.badge.error{background:#490202;color:#f85149}.badge.info{background:#0c2d6b;color:#58a6ff}
.badge.off{background:#21262d;color:#8b949e}
.toast{position:fixed;bottom:20px;right:20px;padding:10px 18px;border-radius:8px;font-size:.85rem;z-index:1000;transform:translateY(80px);opacity:0;transition:.3s}
.toast.show{transform:translateY(0);opacity:1}
.toast.success{background:#0d4429;color:#3fb950;border:1px solid #238636}
.toast.error{background:#490202;color:#f85149;border:1px solid #da3633}
.toast.info{background:#0c2d6b;color:#58a6ff;border:1px solid #1f6feb}
.panel{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:20px;margin-bottom:16px}
.panel h3{font-size:.9rem;color:#58a6ff;margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid #21262d;display:flex;align-items:center;gap:8px}
.field{margin-bottom:12px}
.field label{display:block;font-size:.75rem;color:#8b949e;margin-bottom:3px;text-transform:uppercase;letter-spacing:.03em}
.field input,.field select,.field textarea{width:100%;padding:7px 10px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#e1e4e8;font-size:.85rem;font-family:inherit}
.field input:focus,.field select:focus,.field textarea:focus{outline:none;border-color:#58a6ff;box-shadow:0 0 0 2px rgba(88,166,255,.15)}
.field .hint{font-size:.7rem;color:#484f58;margin-top:2px}
.toggle-row{display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid #21262d}
.toggle-row:last-child{border-bottom:none}
.switch{position:relative;width:40px;height:22px;flex-shrink:0}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;inset:0;background:#30363d;border-radius:22px;cursor:pointer;transition:.2s}
.slider::before{content:"";position:absolute;width:16px;height:16px;left:3px;bottom:3px;background:#8b949e;border-radius:50%;transition:.2s}
.switch input:checked+.slider{background:#238636}
.switch input:checked+.slider::before{transform:translateX(18px);background:#fff}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:900px){.grid2{grid-template-columns:1fr}}
.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}
@media(max-width:1000px){.grid3{grid-template-columns:1fr 1fr}}
@media(max-width:700px){.grid3{grid-template-columns:1fr}}
</style>"""

def nav(active):
    pages = [("Dashboard", "/", "dashboard"), ("Cloud", "/cloud", "cloud"), ("Monitors", "/monitors", "monitors"),
             ("Incidents", "/incidents", "incidents"), ("Alerts", "/alerts", "alerts"),
             ("Logs", "/logs", "logs"), ("Costs", "/costs", "costs"), ("Schedules", "/schedules", "schedules"),
             ("AI Assistant", "/ai", "ai"), ("Settings", "/settings", "settings")]
    links = "".join(f'<a href="{url}" class="nl {"active" if key==active else ""}">{name}</a>' for name, url, key in pages)
    logout = '<a href="#" class="nl" onclick="fetch(\'/api/logout\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:\'{}\'}).then(()=>location=\'/login\')" style="margin-left:auto;font-size:.78rem">Logout</a>'
    return f'<nav class="topnav"><span class="logo">AWS Video Dashboard</span>{links}{logout}</nav>'


# ═════════════════════════════════════════════════════════════════════════════
# 1. DASHBOARD PAGE — Unified command centre
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/")
def page_dashboard():
    return render_template_string("""<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AWS Video Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js" integrity="sha384-vsrfeLOOY6KuIYKDlmVH5UiBmgIdB1oEf7p01YgWHuqmOHfZr374+odEv96n9tNC" crossorigin="anonymous"></script>
""" + SHARED_STYLES + """
<style>
.health-bar{display:flex;gap:6px;margin-bottom:20px;flex-wrap:wrap}
.health-pill{padding:8px 16px;border-radius:8px;border:1px solid #21262d;background:#161b22;cursor:pointer;transition:.15s;text-decoration:none;display:flex;align-items:center;gap:8px}
.health-pill:hover{border-color:#58a6ff;background:#1c2128;text-decoration:none}
.health-pill .dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.health-pill .dot.g{background:#3fb950}.health-pill .dot.r{background:#f85149}.health-pill .dot.y{background:#d29922}.health-pill .dot.b{background:#58a6ff}.health-pill .dot.off{background:#484f58}
.health-pill .hl{font-size:.85rem;font-weight:600;color:#e1e4e8}
.health-pill .sub{font-size:.72rem;color:#8b949e}
.dash-grid{display:grid;grid-template-columns:2fr 1fr;gap:16px}
@media(max-width:1000px){.dash-grid{grid-template-columns:1fr}}
.quick-actions{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.quick-actions a,.quick-actions button{padding:6px 14px;border-radius:6px;font-size:.8rem;border:1px solid #21262d;background:#161b22;color:#8b949e;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;gap:5px;transition:.15s}
.quick-actions a:hover,.quick-actions button:hover{border-color:#58a6ff;color:#58a6ff;text-decoration:none}
.sidebar-panel{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px;margin-bottom:12px}
.sidebar-panel h4{font-size:.82rem;color:#58a6ff;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center}
.mini-chat{display:flex;gap:6px;margin-top:8px}
.mini-chat input{flex:1;padding:6px 10px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#e1e4e8;font-size:.82rem}
.mini-chat input:focus{outline:none;border-color:#58a6ff}
.ai-response{font-size:.82rem;color:#c9d1d9;margin-top:8px;padding:10px;background:#0d1117;border:1px solid #21262d;border-radius:6px;max-height:200px;overflow-y:auto;display:none}
.issue-row{display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid #21262d;font-size:.82rem}
.issue-row:last-child{border-bottom:none}
.section-collapse{cursor:pointer;user-select:none}
.section-collapse:hover{color:#58a6ff}
</style>
</head><body>
""" + nav("dashboard") + """
<div class="container">

<!-- Header -->
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
    <div>
        <h1 style="font-size:1.3rem;color:#c9d1d9"><span id="si" style="display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:8px"></span>System Overview</h1>
        <div style="font-size:.75rem;color:#8b949e;margin-top:3px">Updated: <span id="ts">—</span> · Auto-refreshes every 60s</div>
    </div>
    <div style="display:flex;gap:8px">
        <button class="btn" onclick="refresh()" id="btn-refresh">Refresh</button>
    </div>
</div>

<!-- Health Bar — clickable pills linking to relevant pages -->
<div class="health-bar" id="health-bar"></div>

<!-- Quick Actions -->
<div class="quick-actions" id="quick-actions">
    <a href="/monitors">Manage Endpoints</a>
    <a href="/alerts">Alert Rules</a>
    <a href="/ai">AI Assistant</a>
    <a href="/settings">Settings</a>
    <button onclick="refresh()">Force Check</button>
</div>

<!-- Main Grid: Left=data, Right=sidebar -->
<div class="dash-grid">
<div>
    <!-- Active Issues Banner -->
    <div id="issues-banner" style="display:none;border-color:#f85149" class="panel">
        <h3 style="color:#f85149">Active Issues</h3>
        <div id="issues-list"></div>
    </div>

    <!-- Sections: each collapsible -->
    <div id="sec-ec2" class="section"></div>
    <div id="sec-deploy" class="section"></div>
    <div id="sec-ecs" class="section"></div>
    <div id="sec-medialive" class="section"></div>
    <div id="sec-mediaconnect" class="section"></div>
    <div id="sec-cloudfront" class="section"></div>
    <div id="sec-ivs" class="section"></div>
    <div id="sec-rds" class="section"></div>
    <div id="sec-lambda" class="section"></div>
    <div id="sec-s3" class="section"></div>
    <div id="sec-sqs" class="section"></div>
    <div id="sec-route53" class="section"></div>
    <div id="sec-apigateway" class="section"></div>
    <div id="sec-vpcs" class="section"></div>
    <div id="sec-elb" class="section"></div>
    <div id="sec-eip" class="section"></div>
    <div id="sec-nat" class="section"></div>
    <div id="sec-sg" class="section"></div>
    <div id="sec-vpn" class="section"></div>
    <div id="sec-endpoints" class="section"></div>
</div>

<!-- Sidebar -->
<div>
    <!-- Trend Chart -->
    <div class="sidebar-panel">
        <h4>Trend (24h)</h4>
        <canvas id="history-chart" height="180"></canvas>
    </div>

    <!-- AI Quick Ask -->
    <div class="sidebar-panel">
        <h4>Quick Ask <a href="/ai" style="font-size:.72rem;font-weight:normal">Open full chat →</a></h4>
        <div class="mini-chat">
            <input type="text" id="ai-input" placeholder="Ask about your infra..." onkeydown="if(event.key==='Enter')quickAsk()">
            <button class="btn sm p" onclick="quickAsk()">Ask</button>
        </div>
        <div id="ai-response" class="ai-response"></div>
    </div>

    <!-- Alert Rules Summary -->
    <div class="sidebar-panel">
        <h4>Alert Rules <a href="/alerts" style="font-size:.72rem;font-weight:normal">Manage →</a></h4>
        <div id="rules-summary" style="font-size:.82rem;color:#8b949e">Loading...</div>
    </div>

    <!-- Triggered Alerts -->
    <div class="sidebar-panel" id="triggered-panel" style="display:none">
        <h4 style="color:#f0883e">Triggered Rules</h4>
        <div id="triggered-list"></div>
    </div>

    <!-- Notification Channels -->
    <div class="sidebar-panel">
        <h4>Channels <a href="/settings" style="font-size:.72rem;font-weight:normal">Configure →</a></h4>
        <div id="channels-status" style="font-size:.82rem;color:#8b949e">Loading...</div>
    </div>

    <!-- Endpoint Monitors Summary -->
    <div class="sidebar-panel">
        <h4>Endpoints <a href="/monitors" style="font-size:.72rem;font-weight:normal">Manage →</a></h4>
        <div id="ep-summary" style="font-size:.82rem;color:#8b949e">Loading...</div>
    </div>
</div>
</div>
</div>
<div id="toast" class="toast"></div>

<script>
function toast(m,t='info'){const e=document.getElementById('toast');e.textContent=m;e.className='toast '+t+' show';setTimeout(()=>e.classList.remove('show'),3000)}
function bg(t,c){return `<span class="badge ${esc(c)}">${esc(t)}</span>`}
function stBg(s){return bg(s,{running:'ok',stopped:'off',terminated:'error',pending:'warn'}[s]||'info')}
function dpBg(s){return bg(s,{Succeeded:'ok',Failed:'error',InProgress:'warn',Stopped:'error'}[s]||'info')}

async function fetchStatus(){try{const r=await fetch('/api/status');const j=await r.json();render(j);loadSidebar(j)}catch(e){console.error(e)}}
async function refresh(){document.getElementById('btn-refresh').textContent='...';await fetch('/api/refresh',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});await fetchStatus();document.getElementById('btn-refresh').textContent='Refresh';toast('Refreshed','success')}

// ── AI Quick Ask ──
async function quickAsk(){
    const input=document.getElementById('ai-input');
    const msg=input.value.trim();if(!msg)return;
    const resp=document.getElementById('ai-response');
    resp.style.display='block';resp.innerHTML='<span style="color:#8b949e">Thinking...</span>';
    input.value='';
    try{
        const r=await fetch('/api/ai/query',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:msg,conversation_id:'dashboard_quick'})});
        const j=await r.json();
        resp.innerHTML=j.response?esc(j.response).replace(/\\n/g,'<br>').replace(/\*\*([^*]+)\*\*/g,'<b>$1</b>'):'<span style="color:#f85149">No response</span>';
        if(j.error==='no_api_key')resp.innerHTML='<span style="color:#d29922">Add your OpenRouter API key in <a href="/settings">Settings</a></span>';
    }catch(e){resp.innerHTML='<span style="color:#f85149">Error</span>'}
}

// ── Sidebar data ──
async function loadSidebar(statusData){
    // Rules summary
    try{
        const r=await fetch('/api/rules');const j=await r.json();
        const rules=j.rules||[];
        const enabled=rules.filter(r=>r.enabled).length;
        document.getElementById('rules-summary').innerHTML=rules.length?
            `${enabled} active / ${rules.length} total<br><span style="font-size:.72rem">${rules.filter(r=>r.severity==='critical'&&r.enabled).length} critical, ${rules.filter(r=>r.severity==='warning'&&r.enabled).length} warning</span>`:
            '<a href="/alerts">Add your first alert rule →</a>';
    }catch(e){}

    // Channels
    try{
        const r=await fetch('/api/config');const c=await r.json();
        const ch=c.notifications?.channels||{};
        const items=[];
        if(ch.email?.enabled)items.push(bg('Email','ok'));else items.push(bg('Email','off'));
        if(ch.whatsapp?.enabled)items.push(bg('WhatsApp','ok'));else items.push(bg('WhatsApp','off'));
        if(ch.telegram?.enabled)items.push(bg('Telegram','ok'));else items.push(bg('Telegram','off'));
        const master=c.notifications?.enabled;
        document.getElementById('channels-status').innerHTML=
            (master?'<span class="green" style="font-size:.75rem">● Notifications ON</span>':'<span class="red" style="font-size:.75rem">● Notifications OFF</span>')+
            '<div style="margin-top:6px;display:flex;gap:4px;flex-wrap:wrap">'+items.join('')+'</div>';
    }catch(e){}

    // Endpoint summary
    try{
        const r=await fetch('/api/endpoints');const j=await r.json();
        const eps=j.endpoints||[];
        if(!eps.length){document.getElementById('ep-summary').innerHTML='<a href="/monitors">Add your first endpoint →</a>';return}
        const up=eps.filter(e=>e.last_result?.status==='up').length;
        const down=eps.filter(e=>e.last_result?.status==='down').length;
        const unk=eps.filter(e=>!e.last_result).length;
        document.getElementById('ep-summary').innerHTML=
            `<span class="${down>0?'red':'green'}" style="font-weight:600">${up}/${eps.length} up</span>`+
            (down?` · <span class="red">${down} down</span>`:'')+
            (unk?` · <span style="color:#484f58">${unk} unchecked</span>`:'')+
            `<div style="margin-top:6px">${eps.slice(0,5).map(e=>{const s=e.last_result?.status||'unknown';return `<div class="issue-row"><span class="dot" style="width:6px;height:6px;border-radius:50%;background:${s==='up'?'#3fb950':s==='down'?'#f85149':'#484f58'}"></span>${esc(e.name)}</div>`}).join('')}${eps.length>5?`<div style="font-size:.72rem;color:#484f58;margin-top:4px">+${eps.length-5} more</div>`:''}</div>`;
    }catch(e){}
}

function render(j){
    const d=j.data;if(!d)return;
    document.getElementById('ts').textContent=new Date(j.timestamp).toLocaleString();

    // ── Collect all issues for the health bar and issues banner ──
    const issues=[];
    const ecAlerts=d.ec2.alerts||0;
    const depFails=d.deployments.failed||0;
    if(ecAlerts)issues.push(...d.ec2.instances.filter(i=>i.alerts&&i.alerts.length).map(i=>({svc:'EC2',name:i.name,detail:i.alerts.join(', ')})));
    if(depFails)issues.push(...d.deployments.items.filter(x=>x.status==='Failed').map(x=>({svc:'Deploy',name:x.application,detail:x.status})));
    const ml=d.medialive;if(ml&&ml.channels){ml.channels.filter(c=>!c.healthy&&c.state==='RUNNING').forEach(c=>issues.push({svc:'MediaLive',name:c.name,detail:c.input_loss?'Input Loss':'Unhealthy'}))}
    const mc=d.mediaconnect;if(mc&&mc.flows){mc.flows.filter(f=>!f.healthy).forEach(f=>issues.push({svc:'MediaConnect',name:f.name,detail:f.status}))}
    const cf=d.cloudfront;if(cf&&cf.distributions){cf.distributions.filter(x=>!x.healthy).forEach(x=>issues.push({svc:'CloudFront',name:x.name,detail:'5xx='+x.error_rate_5xx+'%'}))}
    const em=d.easy_monitor;if(em&&em.endpoints){em.endpoints.filter(e=>e.status!=='up').forEach(e=>issues.push({svc:'Endpoint',name:e.endpoint_name,detail:e.error||e.status}))}

    const totalIssues=issues.length;
    document.getElementById('si').style.background=totalIssues>0?'#f85149':'#3fb950';

    // ── Health Bar ──
    let hb='';
    // EC2
    const ecOk=d.ec2.healthy,ecTot=d.ec2.running;
    hb+=`<a class="health-pill" href="#sec-ec2"><span class="dot ${ecAlerts?'r':ecTot?'g':'off'}"></span><div><div class="hl">EC2</div><div class="sub">${ecOk}/${ecTot} healthy</div></div></a>`;
    // Deploys
    hb+=`<a class="health-pill" href="#sec-deploy"><span class="dot ${depFails?'r':d.deployments.succeeded?'g':'off'}"></span><div><div class="hl">Deploys</div><div class="sub">${d.deployments.succeeded} ok / ${depFails} fail</div></div></a>`;
    // Media services
    if(ml)hb+=`<a class="health-pill" href="#sec-medialive"><span class="dot ${ml.healthy<ml.running?'r':ml.running?'g':'off'}"></span><div><div class="hl">MediaLive</div><div class="sub">${ml.healthy}/${ml.running} ok</div></div></a>`;
    if(mc)hb+=`<a class="health-pill" href="#sec-mediaconnect"><span class="dot ${mc.flows.some(f=>!f.healthy)?'r':'g'}"></span><div><div class="hl">MediaConnect</div><div class="sub">${mc.total} flows</div></div></a>`;
    if(cf)hb+=`<a class="health-pill" href="#sec-cloudfront"><span class="dot ${cf.healthy<cf.total?'y':cf.total?'g':'off'}"></span><div><div class="hl">CloudFront</div><div class="sub">${cf.healthy}/${cf.total}</div></div></a>`;
    if(d.ivs)hb+=`<a class="health-pill" href="#sec-ivs"><span class="dot ${d.ivs.healthy<d.ivs.total?'r':'b'}"></span><div><div class="hl">IVS</div><div class="sub">${d.ivs.live} live</div></div></a>`;
    // AWS Services
    const rds=d.rds;if(rds&&rds.items&&rds.items.length)hb+=`<a class="health-pill" href="#sec-rds"><span class="dot ${rds.healthy<rds.total?'y':rds.total?'g':'off'}"></span><div><div class="hl">RDS</div><div class="sub">${rds.healthy}/${rds.total}</div></div></a>`;
    const lam=d.lambda_functions;if(lam&&lam.items&&lam.items.length)hb+=`<a class="health-pill" href="#sec-lambda"><span class="dot ${lam.healthy<lam.total?'y':'g'}"></span><div><div class="hl">Lambda</div><div class="sub">${lam.total} fn</div></div></a>`;
    const s3d=d.s3;if(s3d&&s3d.items&&s3d.items.length)hb+=`<a class="health-pill" href="#sec-s3"><span class="dot g"></span><div><div class="hl">S3</div><div class="sub">${s3d.total} buckets</div></div></a>`;
    const sqsd=d.sqs;if(sqsd&&sqsd.items&&sqsd.items.length)hb+=`<a class="health-pill" href="#sec-sqs"><span class="dot g"></span><div><div class="hl">SQS</div><div class="sub">${sqsd.total} queues</div></div></a>`;
    const r53=d.route53;if(r53&&r53.items&&r53.items.length)hb+=`<a class="health-pill" href="#sec-route53"><span class="dot g"></span><div><div class="hl">Route53</div><div class="sub">${r53.total} zones</div></div></a>`;
    const apigw=d.apigateway;if(apigw&&apigw.items&&apigw.items.length)hb+=`<a class="health-pill" href="#sec-apigateway"><span class="dot g"></span><div><div class="hl">API GW</div><div class="sub">${apigw.total} APIs</div></div></a>`;
    // Networking
    const vpcs=d.vpcs;if(vpcs&&vpcs.items&&vpcs.items.length)hb+=`<a class="health-pill" href="#sec-vpcs"><span class="dot ${vpcs.healthy<vpcs.total?'y':'g'}"></span><div><div class="hl">VPCs</div><div class="sub">${vpcs.total}</div></div></a>`;
    const elbs=d.load_balancers;if(elbs&&elbs.items&&elbs.items.length)hb+=`<a class="health-pill" href="#sec-elb"><span class="dot ${elbs.healthy<elbs.total?'r':elbs.total?'g':'off'}"></span><div><div class="hl">ELB</div><div class="sub">${elbs.healthy}/${elbs.total}</div></div></a>`;
    const eips=d.elastic_ips;if(eips&&eips.items&&eips.items.length)hb+=`<a class="health-pill" href="#sec-eip"><span class="dot g"></span><div><div class="hl">EIPs</div><div class="sub">${eips.total}</div></div></a>`;
    const nats=d.nat_gateways;if(nats&&nats.items&&nats.items.length)hb+=`<a class="health-pill" href="#sec-nat"><span class="dot ${nats.healthy<nats.total?'y':'g'}"></span><div><div class="hl">NAT GW</div><div class="sub">${nats.healthy}/${nats.total}</div></div></a>`;
    const sgs=d.security_groups;if(sgs&&sgs.items&&sgs.items.length)hb+=`<a class="health-pill" href="#sec-sg"><span class="dot ${sgs.healthy<sgs.total?'r':'g'}"></span><div><div class="hl">SGs</div><div class="sub">${sgs.healthy}/${sgs.total}</div></div></a>`;
    const vpns=d.vpn_connections;if(vpns&&vpns.items&&vpns.items.length)hb+=`<a class="health-pill" href="#sec-vpn"><span class="dot ${vpns.healthy<vpns.total?'r':'g'}"></span><div><div class="hl">VPN</div><div class="sub">${vpns.healthy}/${vpns.total}</div></div></a>`;
    // Endpoints
    if(em&&em.total)hb+=`<a class="health-pill" href="#sec-endpoints"><span class="dot ${em.down?'r':em.degraded?'y':'g'}"></span><div><div class="hl">Endpoints</div><div class="sub">${em.up}/${em.total} up</div></div></a>`;

    document.getElementById('health-bar').innerHTML=hb;

    // ── Issues Banner ──
    if(totalIssues>0){
        document.getElementById('issues-banner').style.display='block';
        document.getElementById('issues-list').innerHTML=issues.map(i=>
            `<div class="issue-row">${bg(i.svc,'error')} <b>${esc(i.name)}</b> <span style="color:#8b949e">${esc(i.detail)}</span></div>`
        ).join('');
    }else{document.getElementById('issues-banner').style.display='none'}

    // ── Triggered rules ──
    if(d.rule_alerts&&d.rule_alerts.length){
        document.getElementById('triggered-panel').style.display='block';
        document.getElementById('triggered-list').innerHTML=d.rule_alerts.map(a=>
            `<div class="issue-row">${a.severity==='critical'?bg('CRIT','error'):a.severity==='warning'?bg('WARN','warn'):bg('INFO','info')} ${esc(a.rule_name)} <span style="color:#8b949e;font-size:.75rem">${esc(a.resource)}</span></div>`
        ).join('');
    }else{document.getElementById('triggered-panel').style.display='none'}

    // ── Data Tables ──
    if(d.ec2.instances.length){document.getElementById('sec-ec2').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ EC2 Instances (${d.ec2.running})</h2><table><thead><tr><th>Name</th><th>Region</th><th>ID</th><th>Type</th><th>State</th><th>Uptime</th><th>Health</th><th>CPU</th><th>IP</th></tr></thead><tbody>${d.ec2.instances.map(i=>{const ut=i.uptime_display||'—';const utH=i.uptime_hours||0;const utClass=utH>72?'red':utH>24?'yellow':'green';return`<tr><td><b>${esc(i.name)}</b></td><td style="font-size:.75rem;color:#8b949e">${esc(i.region)||'—'}</td><td style="font-family:monospace;font-size:.78rem">${esc(i.instance_id)}</td><td>${esc(i.instance_type)}</td><td>${stBg(i.state)}</td><td class="${i.state==='running'?utClass:''}" style="font-weight:600">${i.state==='running'?esc(ut):'—'}</td><td>${i.status_checks==='ok'?bg('OK','ok'):i.status_checks==='impaired'?bg('FAIL','error'):bg(i.status_checks,'warn')}</td><td>${i.cpu_utilization!==null?i.cpu_utilization+'%':'—'}</td><td style="font-family:monospace;font-size:.78rem">${esc(i.public_ip||i.private_ip||'—')}</td></tr>`}).join('')}</tbody></table>`}else{document.getElementById('sec-ec2').innerHTML=''}

    if(d.deployments.items.length){document.getElementById('sec-deploy').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ Deployments (${d.deployments.total})</h2><table><thead><tr><th>App</th><th>Group</th><th>Status</th><th>Time</th></tr></thead><tbody>${d.deployments.items.map(x=>`<tr><td>${esc(x.application)}</td><td>${esc(x.group)}</td><td>${dpBg(x.status)}</td><td>${new Date(x.create_time).toLocaleString()}</td></tr>`).join('')}</tbody></table>`}else{document.getElementById('sec-deploy').innerHTML=''}

    // ECS Services
    const ecs = d.ecs_services || [];
    if(ecs.length > 0){
        document.getElementById('sec-ecs').innerHTML = '<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display===\'none\'?\'\':\'none\'">▾ ECS Services ('+ecs.length+')</h2>' +
            '<div>' + ecs.map(s => '<div style="display:flex;align-items:center;gap:8px;padding:8px 12px;border-bottom:1px solid #21262d;background:#161b22"><span class="dot" style="width:8px;height:8px;border-radius:50%;background:'+(s.running_count>=s.desired_count?'#3fb950':'#f85149')+'"></span>' +
            '<div><div style="font-weight:600;font-size:.85rem">'+esc(s.service_name||s.name||'unknown')+'</div>' +
            '<div style="font-size:.75rem;color:#8b949e">Running: '+s.running_count+'/'+s.desired_count+'</div></div></div>').join('') + '</div>';
    }else{document.getElementById('sec-ecs').innerHTML=''}

    if(d.medialive&&d.medialive.channels.length){document.getElementById('sec-medialive').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ MediaLive (${d.medialive.running} running)</h2><table><thead><tr><th>Channel</th><th>State</th><th>Pipelines</th><th>Input</th><th>Alerts</th></tr></thead><tbody>${d.medialive.channels.map(ch=>`<tr><td><b>${esc(ch.name)}</b></td><td>${ch.state==='RUNNING'?bg('RUNNING','ok'):bg(ch.state,'warn')}</td><td>${ch.pipelines_running}/${ch.pipeline_count}</td><td>${ch.input_loss?bg('LOSS','error'):bg('OK','ok')}</td><td>${ch.active_alerts>0?bg(ch.active_alerts,'error'):'—'}</td></tr>`).join('')}</tbody></table>`}else{document.getElementById('sec-medialive').innerHTML=''}

    if(d.mediaconnect&&d.mediaconnect.flows.length){document.getElementById('sec-mediaconnect').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ MediaConnect (${d.mediaconnect.total} flows)</h2><table><thead><tr><th>Flow</th><th>Status</th><th>Protocol</th><th>Outputs</th></tr></thead><tbody>${d.mediaconnect.flows.map(f=>`<tr><td><b>${esc(f.name)}</b></td><td>${f.status==='ACTIVE'?bg('ACTIVE','ok'):bg(f.status,'error')}</td><td>${f.source?.protocol||'—'}</td><td>${f.output_count}</td></tr>`).join('')}</tbody></table>`}else{document.getElementById('sec-mediaconnect').innerHTML=''}

    if(d.cloudfront&&d.cloudfront.distributions.length){document.getElementById('sec-cloudfront').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ CloudFront (${d.cloudfront.total})</h2><table><thead><tr><th>Name</th><th>Domain</th><th>Status</th><th>4xx%</th><th>5xx%</th><th>Req/15m</th></tr></thead><tbody>${d.cloudfront.distributions.map(x=>`<tr><td><b>${esc(x.name)}</b></td><td style="font-family:monospace;font-size:.78rem">${esc(x.domain)}</td><td>${x.healthy?bg('OK','ok'):bg(x.status,'warn')}</td><td>${x.error_rate_4xx}</td><td class="${x.error_rate_5xx>5?'red':''}">${x.error_rate_5xx}</td><td>${x.requests_15m}</td></tr>`).join('')}</tbody></table>`}else{document.getElementById('sec-cloudfront').innerHTML=''}

    if(d.ivs&&d.ivs.channels.length){document.getElementById('sec-ivs').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ IVS (${d.ivs.live} live)</h2><table><thead><tr><th>Channel</th><th>State</th><th>Health</th><th>Viewers</th></tr></thead><tbody>${d.ivs.channels.map(ch=>`<tr><td><b>${esc(ch.name)}</b></td><td>${ch.state==='LIVE'?bg('LIVE','ok'):bg('OFF','off')}</td><td>${ch.stream_health==='HEALTHY'?bg('OK','ok'):ch.stream_health==='UNHEALTHY'?bg('BAD','error'):bg(ch.stream_health,'off')}</td><td>${ch.viewer_count}</td></tr>`).join('')}</tbody></table>`}else{document.getElementById('sec-ivs').innerHTML=''}

    // AWS Services tables
    if(rds&&rds.items&&rds.items.length){document.getElementById('sec-rds').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ RDS (${rds.total})</h2><table><thead><tr><th>Instance</th><th>Engine</th><th>Status</th><th>Multi-AZ</th><th>Storage</th><th>Endpoint</th></tr></thead><tbody>${rds.items.map(i=>`<tr><td><b>${esc(i.instance_id)}</b></td><td>${esc(i.engine)} ${esc(i.engine_version)}</td><td>${i.status==='available'?bg('available','ok'):bg(i.status,'warn')}</td><td>${i.multi_az?bg('Yes','ok'):bg('No','off')}</td><td>${i.storage_allocated_gb} GB</td><td style="font-family:monospace;font-size:.75rem">${esc(i.endpoint)||'—'}</td></tr>`).join('')}</tbody></table>`}else{document.getElementById('sec-rds').innerHTML=''}

    if(lam&&lam.items&&lam.items.length){document.getElementById('sec-lambda').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ Lambda (${lam.total})</h2><table><thead><tr><th>Function</th><th>Runtime</th><th>Memory</th><th>Timeout</th><th>Code Size</th><th>State</th></tr></thead><tbody>${lam.items.map(i=>`<tr><td><b>${esc(i.function_name)}</b></td><td>${esc(i.runtime)}</td><td>${i.memory_mb} MB</td><td>${i.timeout_seconds}s</td><td>${(i.code_size_bytes/1024).toFixed(0)} KB</td><td>${i.healthy?bg('Active','ok'):bg(i.state,'warn')}</td></tr>`).join('')}</tbody></table>`}else{document.getElementById('sec-lambda').innerHTML=''}

    if(s3d&&s3d.items&&s3d.items.length){document.getElementById('sec-s3').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ S3 (${s3d.total} buckets)</h2><table><thead><tr><th>Bucket Name</th><th>Created</th></tr></thead><tbody>${s3d.items.map(i=>`<tr><td><b>${esc(i.bucket_name)}</b></td><td>${i.creation_date?new Date(i.creation_date).toLocaleDateString():'—'}</td></tr>`).join('')}</tbody></table>`}else{document.getElementById('sec-s3').innerHTML=''}

    if(sqsd&&sqsd.items&&sqsd.items.length){document.getElementById('sec-sqs').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ SQS (${sqsd.total} queues)</h2><table><thead><tr><th>Queue</th><th>Messages</th><th>In Flight</th></tr></thead><tbody>${sqsd.items.map(i=>`<tr><td><b>${esc(i.queue_name)}</b></td><td>${i.approximate_message_count}</td><td>${i.approximate_not_visible_count}</td></tr>`).join('')}</tbody></table>`}else{document.getElementById('sec-sqs').innerHTML=''}

    if(r53&&r53.items&&r53.items.length){document.getElementById('sec-route53').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ Route53 (${r53.total} zones)</h2><table><thead><tr><th>Zone</th><th>Records</th><th>Private</th></tr></thead><tbody>${(r53.zones||r53.items).map(i=>`<tr><td><b>${esc(i.zone_name||i.zone_id||'')}</b></td><td>${i.record_count||0}</td><td>${i.is_private?'Yes':'No'}</td></tr>`).join('')}</tbody></table>`}else{document.getElementById('sec-route53').innerHTML=''}

    if(apigw&&apigw.items&&apigw.items.length){document.getElementById('sec-apigateway').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ API Gateway (${apigw.total})</h2><table><thead><tr><th>API Name</th><th>ID</th><th>Type</th><th>Created</th></tr></thead><tbody>${apigw.items.map(i=>`<tr><td><b>${esc(i.api_name)}</b></td><td style="font-family:monospace;font-size:.78rem">${esc(i.api_id)}</td><td>${esc(i.endpoint_type)}</td><td>${i.created_date?new Date(i.created_date).toLocaleDateString():'—'}</td></tr>`).join('')}</tbody></table>`}else{document.getElementById('sec-apigateway').innerHTML=''}

    // Networking tables
    if(vpcs&&vpcs.items&&vpcs.items.length){document.getElementById('sec-vpcs').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ VPCs (${vpcs.total})</h2><table><thead><tr><th>VPC ID</th><th>Name</th><th>CIDR</th><th>State</th><th>Default</th><th>Subnets</th></tr></thead><tbody>${vpcs.items.map(i=>`<tr><td style="font-family:monospace;font-size:.78rem">${esc(i.vpc_id)}</td><td><b>${esc(i.name)||'—'}</b></td><td>${esc(i.cidr)}</td><td>${i.state==='available'?bg('available','ok'):bg(i.state,'warn')}</td><td>${i.is_default?'Yes':'No'}</td><td>${i.subnet_count}</td></tr>`).join('')}</tbody></table>`}else{document.getElementById('sec-vpcs').innerHTML=''}

    if(elbs&&elbs.items&&elbs.items.length){document.getElementById('sec-elb').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ Load Balancers (${elbs.total})</h2><table><thead><tr><th>Name</th><th>Type</th><th>State</th><th>DNS</th><th>Targets</th><th>Healthy</th></tr></thead><tbody>${elbs.items.map(i=>`<tr><td><b>${esc(i.lb_name)}</b></td><td>${bg(i.lb_type,'info')}</td><td>${i.state==='active'?bg('active','ok'):bg(i.state,'warn')}</td><td style="font-family:monospace;font-size:.72rem;max-width:200px;overflow:hidden;text-overflow:ellipsis">${esc(i.dns_name)}</td><td>${i.target_count}</td><td>${i.healthy_targets}/${i.target_count}</td></tr>`).join('')}</tbody></table>`}else{document.getElementById('sec-elb').innerHTML=''}

    if(eips&&eips.items&&eips.items.length){document.getElementById('sec-eip').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ Elastic IPs (${eips.total})</h2><table><thead><tr><th>Public IP</th><th>Allocation ID</th><th>Instance</th><th>ENI</th><th>Domain</th></tr></thead><tbody>${eips.items.map(i=>`<tr><td style="font-family:monospace">${esc(i.public_ip)}</td><td style="font-family:monospace;font-size:.78rem">${esc(i.allocation_id)}</td><td>${esc(i.instance_id)||'—'}</td><td style="font-size:.78rem">${esc(i.network_interface_id)||'—'}</td><td>${esc(i.domain)}</td></tr>`).join('')}</tbody></table>`}else{document.getElementById('sec-eip').innerHTML=''}

    if(nats&&nats.items&&nats.items.length){document.getElementById('sec-nat').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ NAT Gateways (${nats.total})</h2><table><thead><tr><th>NAT GW ID</th><th>State</th><th>Subnet</th><th>Public IP</th><th>VPC</th></tr></thead><tbody>${nats.items.map(i=>`<tr><td style="font-family:monospace;font-size:.78rem">${esc(i.nat_gateway_id)}</td><td>${i.state==='available'?bg('available','ok'):bg(i.state,'warn')}</td><td style="font-family:monospace;font-size:.78rem">${esc(i.subnet_id)}</td><td style="font-family:monospace">${esc(i.public_ip)||'—'}</td><td style="font-family:monospace;font-size:.78rem">${esc(i.vpc_id)}</td></tr>`).join('')}</tbody></table>`}else{document.getElementById('sec-nat').innerHTML=''}

    if(sgs&&sgs.items&&sgs.items.length){document.getElementById('sec-sg').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ Security Groups (${sgs.total})</h2><table><thead><tr><th>SG ID</th><th>Name</th><th>VPC</th><th>Inbound</th><th>Outbound</th><th>Open?</th></tr></thead><tbody>${sgs.items.map(i=>`<tr><td style="font-family:monospace;font-size:.78rem">${esc(i.sg_id)}</td><td><b>${esc(i.sg_name)}</b></td><td style="font-family:monospace;font-size:.78rem">${esc(i.vpc_id)}</td><td>${i.inbound_rule_count}</td><td>${i.outbound_rule_count}</td><td>${i.has_open_to_world?bg('OPEN','error'):bg('OK','ok')}</td></tr>`).join('')}</tbody></table>`}else{document.getElementById('sec-sg').innerHTML=''}

    if(vpns&&vpns.items&&vpns.items.length){document.getElementById('sec-vpn').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ VPN Connections (${vpns.total})</h2><table><thead><tr><th>VPN ID</th><th>Name</th><th>State</th><th>Tunnels</th><th>Customer GW</th></tr></thead><tbody>${vpns.items.map(i=>`<tr><td style="font-family:monospace;font-size:.78rem">${esc(i.vpn_connection_id)}</td><td><b>${esc(i.name)||'—'}</b></td><td>${i.state==='available'?bg('available','ok'):bg(i.state,'warn')}</td><td>${i.tunnels_up}/${i.tunnel_count} UP</td><td style="font-family:monospace;font-size:.78rem">${esc(i.customer_gateway_id)}</td></tr>`).join('')}</tbody></table>`}else{document.getElementById('sec-vpn').innerHTML=''}

    if(em&&em.endpoints.length){document.getElementById('sec-endpoints').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ Endpoints (${em.up}/${em.total} up)</h2><table><thead><tr><th>Name</th><th>Type</th><th>Status</th><th>Response</th><th>Error</th></tr></thead><tbody>${em.endpoints.map(e=>`<tr><td><b>${esc(e.endpoint_name)}</b></td><td>${bg(e.endpoint_type,'info')}</td><td>${e.status==='up'?bg('UP','ok'):e.status==='degraded'?bg('DEGRADED','warn'):bg('DOWN','error')}</td><td>${e.response_time_ms?e.response_time_ms+'ms':'—'}</td><td style="font-size:.78rem;color:#f85149;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(e.error)||'—'}</td></tr>`).join('')}</tbody></table>`}else{document.getElementById('sec-endpoints').innerHTML=''}
}

fetchStatus();loadHistory();setInterval(fetchStatus,60000);

// ── Trend Chart ──
let _histChart=null;
async function loadHistory(){
    try{
        const r=await fetch('/api/history?limit=288');
        const j=await r.json();const h=j.history||[];
        if(!h.length)return;
        const labels=h.map(p=>{const d=new Date(p.timestamp);return d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})});
        const ctx=document.getElementById('history-chart');
        if(!ctx)return;
        if(_histChart)_histChart.destroy();
        _histChart=new Chart(ctx,{type:'line',data:{labels,datasets:[
            {label:'EC2 Running',data:h.map(p=>p.ec2_running),borderColor:'#58a6ff',backgroundColor:'rgba(88,166,255,.1)',fill:true,tension:.3,pointRadius:0},
            {label:'EC2 Healthy',data:h.map(p=>p.ec2_healthy),borderColor:'#3fb950',backgroundColor:'rgba(63,185,80,.1)',fill:true,tension:.3,pointRadius:0},
            {label:'Avg CPU %',data:h.map(p=>p.avg_cpu),borderColor:'#d29922',tension:.3,pointRadius:0,yAxisID:'y1'}
        ]},options:{responsive:true,interaction:{intersect:false,mode:'index'},
            plugins:{legend:{labels:{color:'#8b949e',font:{size:10}}}},
            scales:{x:{ticks:{color:'#484f58',maxTicksAutoSkip:true,maxRotation:0,font:{size:9}},grid:{color:'#21262d'}},
                y:{ticks:{color:'#484f58'},grid:{color:'#21262d'},title:{display:true,text:'Count',color:'#8b949e',font:{size:10}}},
                y1:{position:'right',ticks:{color:'#484f58'},grid:{display:false},title:{display:true,text:'CPU %',color:'#8b949e',font:{size:10}},min:0,max:100}
        }}});
    }catch(e){console.error('History load failed',e)}
}
</script></body></html>""")


# ═════════════════════════════════════════════════════════════════════════════
# 1b. MONITORS PAGE — Easy endpoint monitoring
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/monitors")
def page_monitors():
    return render_template_string("""<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Monitors — AWS Video Dashboard</title>""" + SHARED_STYLES + """
<style>
.ep-card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:14px;margin-bottom:10px;display:grid;grid-template-columns:1fr auto;gap:10px;align-items:center}
.ep-card.down{border-color:#f85149}.ep-card.degraded{border-color:#d29922}
.ep-status{display:flex;align-items:center;gap:8px}
.ep-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.ep-dot.up{background:#3fb950}.ep-dot.down{background:#f85149}.ep-dot.degraded{background:#d29922}.ep-dot.unknown{background:#484f58}
.tpl-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:10px;margin-bottom:16px}
.tpl-card{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:12px;cursor:pointer;transition:.15s}
.tpl-card:hover{border-color:#58a6ff;background:#161b22}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;display:none;align-items:center;justify-content:center}
.modal-bg.show{display:flex}
.modal{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:24px;width:560px;max-width:95vw;max-height:90vh;overflow-y:auto}
.modal h3{margin-bottom:16px;color:#c9d1d9}
.type-fields{display:none}.type-fields.active{display:block}
</style>
</head><body>
""" + nav("monitors") + """
<div class="container">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
    <h1 style="font-size:1.2rem;color:#c9d1d9">Endpoint Monitors</h1>
    <div style="display:flex;gap:8px">
        <button class="btn" onclick="checkAll()" id="btn-check-all">Check All Now</button>
        <button class="btn p" onclick="showAddModal()">+ Add Endpoint</button>
    </div>
</div>

<!-- Summary Cards -->
<div class="cards" id="summary-cards"></div>

<!-- Quick Templates -->
<div class="panel">
    <h3>Quick Add Templates</h3>
    <p style="font-size:.78rem;color:#8b949e;margin-bottom:10px">Click to add — edit the URL/host after</p>
    <div class="tpl-grid" id="templates"></div>
</div>

<!-- Endpoint list -->
<div id="ep-list"></div>

<!-- Add/Edit Modal -->
<div id="modal" class="modal-bg" onclick="if(event.target===this)closeModal()">
<div class="modal">
    <h3 id="modal-title">Add Endpoint</h3>
    <div class="field"><label>Name</label><input type="text" id="ep-name" placeholder="e.g. HLS Origin, SRT Ingest"></div>
    <div class="field"><label>Type</label>
        <select id="ep-type" onchange="toggleType()">
            <option value="http">HTTP/HTTPS (URL check)</option>
            <option value="tcp">TCP Port (SRT, RTMP, etc.)</option>
            <option value="json_api">JSON API (extract metric)</option>
            <option value="ping">Ping (ICMP)</option>
        </select>
    </div>

    <!-- HTTP fields -->
    <div id="f-http" class="type-fields active">
        <div class="field"><label>URL</label><input type="text" id="ep-url" placeholder="https://origin.example.com/live/index.m3u8"></div>
        <div class="grid2">
            <div class="field"><label>Method</label><select id="ep-method"><option value="GET">GET</option><option value="HEAD">HEAD</option><option value="POST">POST</option></select></div>
            <div class="field"><label>Expected Status</label><input type="number" id="ep-status" value="200"></div>
        </div>
        <div class="field"><label>Body Contains (optional)</label><input type="text" id="ep-body" placeholder="e.g. #EXTM3U for HLS">
            <div class="hint">Check that the response body includes this string</div></div>
    </div>

    <!-- TCP fields -->
    <div id="f-tcp" class="type-fields">
        <div class="grid2">
            <div class="field"><label>Host</label><input type="text" id="ep-host" placeholder="ingest.example.com"></div>
            <div class="field"><label>Port</label><input type="number" id="ep-port" placeholder="9000"></div>
        </div>
    </div>

    <!-- JSON API fields -->
    <div id="f-json" class="type-fields">
        <div class="field"><label>URL</label><input type="text" id="ep-json-url" placeholder="https://api.example.com/health"></div>
        <div class="field"><label>JSON Path</label><input type="text" id="ep-json-path" placeholder="status.healthy">
            <div class="hint">Dot-notation path to extract, e.g. <code>data.encoder.fps</code></div></div>
        <div class="field"><label>Expected Status</label><input type="number" id="ep-json-status" value="200"></div>
    </div>

    <!-- Ping fields -->
    <div id="f-ping" class="type-fields">
        <div class="field"><label>Host</label><input type="text" id="ep-ping-host" placeholder="origin.example.com"></div>
    </div>

    <div class="grid2">
        <div class="field"><label>Timeout (seconds)</label><input type="number" id="ep-timeout" value="10" min="1" max="30"></div>
        <div class="field"><label>Tags (comma-sep)</label><input type="text" id="ep-tags" placeholder="streaming, srt, ingest"></div>
    </div>

    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px">
        <button class="btn" onclick="closeModal()">Cancel</button>
        <button class="btn p" id="modal-save" onclick="saveEndpoint()">Add Endpoint</button>
    </div>
</div>
</div>
</div>
<div id="toast" class="toast"></div>

<script>
let editingId=null;
function toast(m,t='info'){const e=document.getElementById('toast');e.textContent=m;e.className='toast '+t+' show';setTimeout(()=>e.classList.remove('show'),3000)}
function bg(t,c){return `<span class="badge ${esc(c)}">${esc(t)}</span>`}

function toggleType(){
    document.querySelectorAll('.type-fields').forEach(el=>el.classList.remove('active'));
    const t=document.getElementById('ep-type').value;
    const map={http:'f-http',tcp:'f-tcp',json_api:'f-json',ping:'f-ping'};
    document.getElementById(map[t]).classList.add('active');
}

function showAddModal(){
    editingId=null;
    document.getElementById('modal-title').textContent='Add Endpoint';
    document.getElementById('modal-save').textContent='Add Endpoint';
    ['ep-name','ep-url','ep-body','ep-host','ep-json-url','ep-json-path','ep-ping-host','ep-tags'].forEach(id=>{const e=document.getElementById(id);if(e)e.value=''});
    document.getElementById('ep-type').value='http';
    document.getElementById('ep-method').value='GET';
    document.getElementById('ep-status').value='200';
    document.getElementById('ep-json-status').value='200';
    document.getElementById('ep-port').value='';
    document.getElementById('ep-timeout').value='10';
    toggleType();
    document.getElementById('modal').classList.add('show');
}

function showEditModal(ep){
    editingId=ep.id;
    document.getElementById('modal-title').textContent='Edit Endpoint';
    document.getElementById('modal-save').textContent='Save Changes';
    document.getElementById('ep-name').value=ep.name||'';
    document.getElementById('ep-type').value=ep.type||'http';
    toggleType();
    document.getElementById('ep-url').value=ep.url||'';
    document.getElementById('ep-method').value=ep.method||'GET';
    document.getElementById('ep-status').value=ep.expected_status||200;
    document.getElementById('ep-body').value=ep.body_contains||'';
    document.getElementById('ep-host').value=ep.host||'';
    document.getElementById('ep-port').value=ep.port||'';
    document.getElementById('ep-json-url').value=ep.type==='json_api'?ep.url:'';
    document.getElementById('ep-json-path').value=ep.json_path||'';
    document.getElementById('ep-json-status').value=ep.expected_status||200;
    document.getElementById('ep-ping-host').value=ep.type==='ping'?ep.host:'';
    document.getElementById('ep-timeout').value=ep.timeout_seconds||10;
    document.getElementById('ep-tags').value=(ep.tags||[]).join(', ');
    document.getElementById('modal').classList.add('show');
}
function closeModal(){document.getElementById('modal').classList.remove('show')}

function gatherEndpoint(){
    const type=document.getElementById('ep-type').value;
    const base={
        name:document.getElementById('ep-name').value,
        type:type,
        enabled:true,
        timeout_seconds:parseInt(document.getElementById('ep-timeout').value)||10,
        tags:document.getElementById('ep-tags').value,
    };
    if(type==='http'){
        base.url=document.getElementById('ep-url').value;
        base.method=document.getElementById('ep-method').value;
        base.expected_status=parseInt(document.getElementById('ep-status').value)||200;
        base.body_contains=document.getElementById('ep-body').value;
    }else if(type==='tcp'){
        base.host=document.getElementById('ep-host').value;
        base.port=parseInt(document.getElementById('ep-port').value)||0;
    }else if(type==='json_api'){
        base.url=document.getElementById('ep-json-url').value;
        base.json_path=document.getElementById('ep-json-path').value;
        base.expected_status=parseInt(document.getElementById('ep-json-status').value)||200;
    }else if(type==='ping'){
        base.host=document.getElementById('ep-ping-host').value;
    }
    return base;
}

async function saveEndpoint(){
    const data=gatherEndpoint();
    if(!data.name){toast('Give it a name','error');return}
    if(editingId){
        await fetch('/api/endpoints/'+editingId,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
        toast('Endpoint updated','success');
    }else{
        await fetch('/api/endpoints',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
        toast('Endpoint added','success');
    }
    closeModal();loadEndpoints();
}

async function deleteEndpoint(id){
    if(!confirm('Delete this endpoint?'))return;
    await fetch('/api/endpoints/'+id,{method:'DELETE',headers:{'Content-Type':'application/json'}});
    toast('Deleted','success');loadEndpoints();
}

async function toggleEndpoint(id,enabled){
    await fetch('/api/endpoints/'+id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:!enabled})});
    loadEndpoints();
}

async function checkOne(id){
    toast('Checking...','info');
    const r=await fetch('/api/endpoints/'+id+'/check',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
    const j=await r.json();
    if(j.result)toast(j.result.status==='up'?'UP — '+j.result.response_time_ms+'ms':'Status: '+j.result.status,j.result.status==='up'?'success':'error');
    loadEndpoints();
}

async function checkAll(){
    const btn=document.getElementById('btn-check-all');btn.disabled=true;btn.textContent='Checking...';
    await fetch('/api/endpoints/check-all',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
    btn.disabled=false;btn.textContent='Check All Now';
    toast('All checks complete','success');loadEndpoints();
}

async function addTemplate(idx){
    const tpls=(await(await fetch('/api/endpoints')).json()).templates;
    if(!tpls[idx])return;
    const t=tpls[idx];
    await fetch('/api/endpoints',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(t)});
    toast('Template added — edit the URL/host','success');loadEndpoints();
}

async function loadEndpoints(){
    const data=await(await fetch('/api/endpoints')).json();
    const eps=data.endpoints||[];
    const tpls=data.templates||[];

    // Summary
    const up=eps.filter(e=>e.last_result&&e.last_result.status==='up').length;
    const down=eps.filter(e=>e.last_result&&e.last_result.status==='down').length;
    const deg=eps.filter(e=>e.last_result&&e.last_result.status==='degraded').length;
    const unk=eps.filter(e=>!e.last_result).length;
    document.getElementById('summary-cards').innerHTML=`
        <div class="card"><div class="lb">Total</div><div class="vl blue">${eps.length}</div></div>
        <div class="card"><div class="lb">Up</div><div class="vl green">${up}</div></div>
        <div class="card"><div class="lb">Down</div><div class="vl ${down>0?'red':'green'}">${down}</div></div>
        <div class="card"><div class="lb">Degraded</div><div class="vl ${deg>0?'yellow':'green'}">${deg}</div></div>
        <div class="card"><div class="lb">Unchecked</div><div class="vl" style="color:#8b949e">${unk}</div></div>`;

    // Templates
    document.getElementById('templates').innerHTML=tpls.map((t,i)=>`
        <div class="tpl-card" onclick="addTemplate(${i})">
            <div style="font-weight:600;font-size:.85rem">${esc(t.name)}</div>
            <div style="font-size:.75rem;color:#8b949e">${esc(t.type)} ${t.host?esc(t.host)+':'+t.port:esc(t.url)||''}</div>
            <div style="margin-top:4px">${(t.tags||[]).map(tg=>'<span class="badge off" style="font-size:.65rem;margin-right:2px">'+esc(tg)+'</span>').join('')}</div>
        </div>`).join('');

    // Endpoint list
    if(!eps.length){
        document.getElementById('ep-list').innerHTML='<div style="text-align:center;padding:40px;color:#8b949e">No endpoints configured. Add one above or use a template.</div>';
        return;
    }

    document.getElementById('ep-list').innerHTML=eps.map(ep=>{
        const r=ep.last_result;
        const st=r?r.status:'unknown';
        const typeLabel={http:'HTTP',tcp:'TCP',json_api:'JSON API',ping:'PING'}[ep.type]||ep.type;
        const target=ep.url||((ep.host||'')+(ep.port?':'+ep.port:''));

        return `<div class="ep-card ${st==='down'?'down':st==='degraded'?'degraded':''}">
            <div>
                <div class="ep-status">
                    <span class="ep-dot ${st}"></span>
                    <b style="font-size:.9rem">${esc(ep.name)}</b>
                    ${bg(typeLabel,'info')}
                    ${st==='up'?bg('UP','ok'):st==='down'?bg('DOWN','error'):st==='degraded'?bg('DEGRADED','warn'):bg('UNCHECKED','off')}
                    ${r&&r.response_time_ms?`<span style="font-size:.78rem;color:#8b949e">${r.response_time_ms}ms</span>`:''}
                </div>
                <div style="font-size:.78rem;color:#484f58;margin-top:4px;font-family:monospace">${esc(target)}</div>
                ${r&&r.error?`<div style="font-size:.75rem;color:#f85149;margin-top:2px">${esc(r.error)}</div>`:''}
                <div style="margin-top:4px">${(ep.tags||[]).map(t=>'<span class="badge off" style="font-size:.65rem;margin-right:2px">'+esc(t)+'</span>').join('')}
                ${r?`<span style="font-size:.7rem;color:#484f58;margin-left:8px">${new Date(r.checked_at).toLocaleTimeString()}</span>`:''}</div>
            </div>
            <div style="display:flex;gap:5px;align-items:center">
                <button class="btn sm" onclick="checkOne('${ep.id}')" title="Check now">Check</button>
                <label class="switch"><input type="checkbox" ${ep.enabled?'checked':''} onchange="toggleEndpoint('${ep.id}',${ep.enabled})"><span class="slider"></span></label>
                <button class="btn sm" onclick='showEditModal(${JSON.stringify(ep).replace(/'/g,"&#39;")})'>Edit</button>
                <button class="btn sm d" onclick="deleteEndpoint('${ep.id}')">×</button>
            </div>
        </div>`;
    }).join('');
}

loadEndpoints();
</script></body></html>""")


# ═════════════════════════════════════════════════════════════════════════════
# INCIDENTS PAGE
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/incidents")
def page_incidents():
    return render_template_string("""<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Incidents — AWS Video Dashboard</title>""" + SHARED_STYLES + """
<style>
.stat-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:20px}
.stat-card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px;text-align:center}
.stat-card .vl{font-size:1.8rem;font-weight:700;margin:4px 0}
.stat-card .lb{font-size:.75rem;color:#8b949e;text-transform:uppercase;letter-spacing:.04em}
.stat-card.open{border-color:#f85149}.stat-card.ack{border-color:#d29922}.stat-card.resolved{border-color:#3fb950}
.filter-bar{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.filter-bar select{padding:6px 10px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#e1e4e8;font-size:.82rem}
.filter-bar select:focus{outline:none;border-color:#58a6ff}
.inc-table{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #21262d;border-radius:8px;overflow:hidden}
.inc-table th{background:#21262d;text-align:left;padding:8px 12px;font-size:.75rem;color:#8b949e;text-transform:uppercase}
.inc-table td{padding:8px 12px;border-top:1px solid #21262d;font-size:.85rem}
.inc-table tr{cursor:pointer;transition:.1s}.inc-table tr:hover td{background:#1c2128}
.sev-badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.72rem;font-weight:600}
.sev-badge.critical{background:#490202;color:#f85149}
.sev-badge.warning{background:#3d2e00;color:#d29922}
.sev-badge.info{background:#0c2d6b;color:#58a6ff}
.status-badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.72rem;font-weight:600}
.status-badge.open{background:#490202;color:#f85149}
.status-badge.acknowledged{background:#3d2e00;color:#d29922}
.status-badge.resolved{background:#0d4429;color:#3fb950}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;display:none;align-items:center;justify-content:center}
.modal-bg.show{display:flex}
.modal{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:24px;width:640px;max-width:95vw;max-height:90vh;overflow-y:auto}
.modal h3{margin-bottom:16px;color:#c9d1d9}
.detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px}
.detail-grid .dl{font-size:.72rem;color:#8b949e;text-transform:uppercase}.detail-grid .dv{font-size:.85rem;color:#e1e4e8;margin-bottom:8px}
.timeline{margin:16px 0;border-left:2px solid #21262d;padding-left:16px}
.timeline-item{margin-bottom:12px;position:relative}
.timeline-item::before{content:'';position:absolute;left:-21px;top:4px;width:10px;height:10px;border-radius:50%;background:#30363d;border:2px solid #21262d}
.timeline-item .t-time{font-size:.7rem;color:#484f58}.timeline-item .t-author{font-size:.72rem;color:#8b949e;font-weight:600}
.timeline-item .t-note{font-size:.82rem;color:#c9d1d9;margin-top:2px}
.note-form{display:flex;gap:8px;margin-top:12px}
.note-form input{flex:1;padding:7px 10px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#e1e4e8;font-size:.82rem}
.note-form input:focus{outline:none;border-color:#58a6ff}
</style>
</head><body>
""" + nav("incidents") + """
<div class="container">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
    <h1 style="font-size:1.2rem;color:#c9d1d9">Incident Management</h1>
</div>

<!-- Stats Cards -->
<div class="stat-cards">
    <div class="stat-card open"><div class="lb">Open</div><div class="vl red" id="s-open">0</div></div>
    <div class="stat-card ack"><div class="lb">Acknowledged</div><div class="vl yellow" id="s-ack">0</div></div>
    <div class="stat-card resolved"><div class="lb">Resolved</div><div class="vl green" id="s-resolved">0</div></div>
</div>

<!-- Filter Bar -->
<div class="filter-bar">
    <select id="f-status" onchange="loadIncidents()">
        <option value="">All Statuses</option>
        <option value="open">Open</option>
        <option value="acknowledged">Acknowledged</option>
        <option value="resolved">Resolved</option>
    </select>
    <select id="f-severity" onchange="loadIncidents()">
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="warning">Warning</option>
        <option value="info">Info</option>
    </select>
</div>

<!-- Incidents Table -->
<table class="inc-table">
<thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Assigned To</th><th>Created</th><th>Actions</th></tr></thead>
<tbody id="inc-body"><tr><td colspan="7" style="text-align:center;color:#8b949e;padding:30px">Loading...</td></tr></tbody>
</table>

<!-- Detail Modal -->
<div id="modal" class="modal-bg" onclick="if(event.target===this)closeModal()">
<div class="modal">
    <h3 id="m-title">Incident Detail</h3>
    <div class="detail-grid" id="m-details"></div>
    <div id="m-trigger" style="margin-bottom:12px"></div>
    <h4 style="font-size:.82rem;color:#58a6ff;margin-bottom:8px">Timeline</h4>
    <div class="timeline" id="m-timeline"></div>
    <div class="note-form">
        <input type="text" id="m-note" placeholder="Add a note..." onkeydown="if(event.key==='Enter')addNote()">
        <button class="btn" onclick="addNote()">Add Note</button>
    </div>
    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px" id="m-actions"></div>
</div>
</div>
</div>
<div id="toast" class="toast"></div>

<script>
let currentId=null;
function toast(m,t='info'){const e=document.getElementById('toast');e.textContent=m;e.className='toast '+t+' show';setTimeout(()=>e.classList.remove('show'),3000)}

async function loadStats(){
    try{
        const r=await fetch('/api/incidents/stats');
        const d=await r.json();
        document.getElementById('s-open').textContent=d.open||0;
        document.getElementById('s-ack').textContent=d.acknowledged||0;
        document.getElementById('s-resolved').textContent=d.resolved||0;
    }catch(e){console.error('Stats error',e)}
}

async function loadIncidents(){
    const status=document.getElementById('f-status').value;
    const severity=document.getElementById('f-severity').value;
    let url='/api/incidents?limit=100';
    if(status)url+='&status='+status;
    if(severity)url+='&severity='+severity;
    try{
        const r=await fetch(url);
        const d=await r.json();
        const tb=document.getElementById('inc-body');
        if(!d.incidents||d.incidents.length===0){
            tb.innerHTML='<tr><td colspan="7" style="text-align:center;color:#8b949e;padding:30px">No incidents found</td></tr>';
            return;
        }
        tb.innerHTML=d.incidents.map(i=>`<tr onclick="showDetail(${i.id})">
            <td>#${esc(String(i.id))}</td>
            <td>${esc(i.title)}</td>
            <td><span class="sev-badge ${esc(i.severity)}">${esc(i.severity)}</span></td>
            <td><span class="status-badge ${esc(i.status)}">${esc(i.status)}</span></td>
            <td>${esc(i.assigned_to||'—')}</td>
            <td style="font-size:.78rem;color:#8b949e">${esc(i.created_at?i.created_at.replace('T',' ').slice(0,19):'')}</td>
            <td onclick="event.stopPropagation()">
                ${i.status==='open'?`<button class="btn sm" onclick="ackIncident(${i.id})">Ack</button>`:''}
                ${i.status!=='resolved'?`<button class="btn sm" onclick="resolveIncident(${i.id})">Resolve</button>`:''}
            </td>
        </tr>`).join('');
    }catch(e){console.error('Load error',e)}
}

async function showDetail(id){
    currentId=id;
    try{
        const r=await fetch('/api/incidents/'+id);
        const d=await r.json();
        if(!d.incident){toast('Incident not found','error');return}
        const i=d.incident;
        document.getElementById('m-title').textContent='Incident #'+i.id+': '+i.title;
        document.getElementById('m-details').innerHTML=`
            <div><div class="dl">Severity</div><div class="dv"><span class="sev-badge ${esc(i.severity)}">${esc(i.severity)}</span></div></div>
            <div><div class="dl">Status</div><div class="dv"><span class="status-badge ${esc(i.status)}">${esc(i.status)}</span></div></div>
            <div><div class="dl">Assigned To</div><div class="dv">${esc(i.assigned_to||'Unassigned')}</div></div>
            <div><div class="dl">Alert Rule ID</div><div class="dv">${esc(i.alert_rule_id||'—')}</div></div>
            <div><div class="dl">Resource</div><div class="dv">${esc(i.resource_id||'—')}</div></div>
            <div><div class="dl">Created</div><div class="dv">${esc(i.created_at?i.created_at.replace('T',' ').slice(0,19):'')}</div></div>
            ${i.acknowledged_at?`<div><div class="dl">Acknowledged</div><div class="dv">${esc(i.acknowledged_at.replace('T',' ').slice(0,19))}</div></div>`:''}
            ${i.resolved_at?`<div><div class="dl">Resolved</div><div class="dv">${esc(i.resolved_at.replace('T',' ').slice(0,19))}</div></div>`:''}
        `;
        document.getElementById('m-trigger').innerHTML=i.trigger_message?
            `<div style="padding:10px;background:#0d1117;border:1px solid #21262d;border-radius:6px;font-size:.82rem;color:#c9d1d9"><strong style="color:#8b949e">Trigger:</strong> ${esc(i.trigger_message)}</div>`:'';
        const tl=document.getElementById('m-timeline');
        tl.innerHTML=(i.notes||[]).map(n=>`<div class="timeline-item">
            <div class="t-time">${esc(n.created_at?n.created_at.replace('T',' ').slice(0,19):'')}</div>
            <div class="t-author">${esc(n.author)}</div>
            <div class="t-note">${esc(n.note)}</div>
        </div>`).join('')||(('<div style="color:#484f58;font-size:.82rem">No notes yet</div>'));
        const acts=document.getElementById('m-actions');
        let btns='<button class="btn" onclick="closeModal()">Close</button>';
        if(i.status==='open')btns=`<button class="btn p" onclick="ackIncident(${i.id})">Acknowledge</button>`+btns;
        if(i.status!=='resolved')btns=`<button class="btn" style="background:#238636;border-color:#2ea043;color:#fff" onclick="resolvePrompt(${i.id})">Resolve</button>`+btns;
        acts.innerHTML=btns;
        document.getElementById('modal').classList.add('show');
    }catch(e){console.error('Detail error',e)}
}

function closeModal(){document.getElementById('modal').classList.remove('show');currentId=null}

async function ackIncident(id){
    const assigned=prompt('Assign to (optional, press Cancel to skip):');
    const body=assigned?{assigned_to:assigned}:{};
    try{
        const r=await fetch('/api/incidents/'+id+'/acknowledge',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
        const d=await r.json();
        if(d.ok){toast('Incident acknowledged','success');loadIncidents();loadStats();if(currentId===id)showDetail(id)}
        else toast(d.error||'Failed','error');
    }catch(e){toast('Error','error')}
}

async function resolvePrompt(id){
    const note=prompt('Resolution note (optional):');
    if(note===null)return;
    await doResolve(id,note);
}

async function resolveIncident(id){await doResolve(id,'')}

async function doResolve(id,note){
    try{
        const r=await fetch('/api/incidents/'+id+'/resolve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({resolution_note:note||''})});
        const d=await r.json();
        if(d.ok){toast('Incident resolved','success');loadIncidents();loadStats();if(currentId===id)showDetail(id)}
        else toast(d.error||'Failed','error');
    }catch(e){toast('Error','error')}
}

async function addNote(){
    if(!currentId)return;
    const inp=document.getElementById('m-note');
    const note=inp.value.trim();
    if(!note)return;
    try{
        const r=await fetch('/api/incidents/'+currentId+'/note',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({note:note,author:'user'})});
        const d=await r.json();
        if(d.ok){inp.value='';showDetail(currentId)}
        else toast(d.error||'Failed','error');
    }catch(e){toast('Error','error')}
}

loadStats();loadIncidents();
</script></body></html>""")


# ═════════════════════════════════════════════════════════════════════════════
# 2. ALERTS PAGE
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/alerts")
def page_alerts():
    return render_template_string("""<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Alerts — AWS Video Dashboard</title>""" + SHARED_STYLES + """
<style>
.rule-card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px;margin-bottom:12px;display:grid;grid-template-columns:1fr auto;gap:12px;align-items:start}
.rule-card.disabled{opacity:.5}
.rule-meta{display:flex;gap:8px;flex-wrap:wrap;margin-top:6px}
.tpl-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:10px;margin-bottom:20px}
.tpl-card{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:14px;cursor:pointer;transition:.15s}
.tpl-card:hover{border-color:#58a6ff;background:#161b22}
.tpl-card .tname{font-weight:600;font-size:.9rem;margin-bottom:4px}
.tpl-card .tdesc{font-size:.78rem;color:#8b949e}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;display:none;align-items:center;justify-content:center}
.modal-bg.show{display:flex}
.modal{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:24px;width:520px;max-width:95vw;max-height:90vh;overflow-y:auto}
.modal h3{margin-bottom:16px;color:#c9d1d9}
</style>
</head><body>
""" + nav("alerts") + """
<div class="container">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
    <h1 style="font-size:1.2rem;color:#c9d1d9">Alert Rules</h1>
    <button class="btn p" onclick="showAddModal()">+ New Rule</button>
</div>

<!-- Quick Templates -->
<div class="panel">
    <h3>Quick Start Templates</h3>
    <p style="font-size:.8rem;color:#8b949e;margin-bottom:12px">Click to add a pre-configured alert rule instantly</p>
    <div id="templates" class="tpl-grid"></div>
</div>

<!-- Active Rules -->
<div id="rules-list"></div>

<!-- Add/Edit Modal -->
<div id="modal" class="modal-bg" onclick="if(event.target===this)closeModal()">
<div class="modal">
    <h3 id="modal-title">New Alert Rule</h3>
    <div class="field"><label>Rule Name</label><input type="text" id="r-name" placeholder="e.g. High CPU on encoder"></div>
    <div class="grid2">
        <div class="field"><label>Service</label>
            <select id="r-service" onchange="updateMetrics()">
                <option value="ec2">EC2</option><option value="medialive">MediaLive</option>
                <option value="mediaconnect">MediaConnect</option><option value="mediapackage">MediaPackage</option>
                <option value="cloudfront">CloudFront</option><option value="ivs">IVS</option>
                <option value="ecs">ECS</option>
                <option value="easy_monitor">Easy Monitor (endpoints)</option>
            </select>
        </div>
        <div class="field"><label>Metric</label><select id="r-metric"></select></div>
    </div>
    <div class="grid3">
        <div class="field"><label>Operator</label>
            <select id="r-op"><option value=">">&gt;</option><option value="<">&lt;</option>
            <option value=">=">&gt;=</option><option value="<=">&lt;=</option>
            <option value="==">==</option><option value="!=">!=</option>
            <option value="contains">contains</option><option value="not_contains">not contains</option></select>
        </div>
        <div class="field"><label>Threshold</label><input type="text" id="r-threshold" placeholder="80"></div>
        <div class="field"><label>Severity</label>
            <select id="r-severity"><option value="info">Info</option><option value="warning" selected>Warning</option><option value="critical">Critical</option></select>
        </div>
    </div>
    <div class="grid2">
        <div class="field"><label>Resource Filter</label><input type="text" id="r-filter" placeholder="* (all)" value="*">
            <div class="hint">Instance ID, channel name, or * for all</div></div>
        <div class="field"><label>Cooldown (minutes)</label><input type="number" id="r-cooldown" value="15" min="1"></div>
    </div>
    <div class="field"><label>Notify Via</label>
        <div style="display:flex;gap:16px;margin-top:6px">
            <label style="font-size:.85rem;display:flex;align-items:center;gap:4px"><input type="checkbox" id="r-ch-email" checked> Email</label>
            <label style="font-size:.85rem;display:flex;align-items:center;gap:4px"><input type="checkbox" id="r-ch-telegram" checked> Telegram</label>
            <label style="font-size:.85rem;display:flex;align-items:center;gap:4px"><input type="checkbox" id="r-ch-whatsapp" checked> WhatsApp</label>
        </div>
    </div>
    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px">
        <button class="btn" onclick="closeModal()">Cancel</button>
        <button class="btn p" id="modal-save" onclick="saveRule()">Add Rule</button>
    </div>
</div>
</div>
</div>
<div id="toast" class="toast"></div>

<script>
let allMetrics={},editingId=null;
function toast(m,t='info'){const e=document.getElementById('toast');e.textContent=m;e.className='toast '+t+' show';setTimeout(()=>e.classList.remove('show'),3000)}

function updateMetrics(){
    const svc=document.getElementById('r-service').value;
    const sel=document.getElementById('r-metric');
    sel.innerHTML='';
    (allMetrics[svc]||[]).forEach(m=>{sel.innerHTML+=`<option value="${esc(m.id)}">${esc(m.name)}</option>`});
}

function showAddModal(){
    editingId=null;
    document.getElementById('modal-title').textContent='New Alert Rule';
    document.getElementById('modal-save').textContent='Add Rule';
    document.getElementById('r-name').value='';
    document.getElementById('r-service').value='ec2';
    document.getElementById('r-op').value='>';
    document.getElementById('r-threshold').value='';
    document.getElementById('r-severity').value='warning';
    document.getElementById('r-filter').value='*';
    document.getElementById('r-cooldown').value='15';
    document.getElementById('r-ch-email').checked=true;
    document.getElementById('r-ch-telegram').checked=true;
    document.getElementById('r-ch-whatsapp').checked=true;
    updateMetrics();
    document.getElementById('modal').classList.add('show');
}

function showEditModal(rule){
    editingId=rule.id;
    document.getElementById('modal-title').textContent='Edit Rule';
    document.getElementById('modal-save').textContent='Save Changes';
    document.getElementById('r-name').value=rule.name;
    document.getElementById('r-service').value=rule.service;
    updateMetrics();
    document.getElementById('r-metric').value=rule.metric;
    document.getElementById('r-op').value=rule.operator;
    document.getElementById('r-threshold').value=rule.threshold;
    document.getElementById('r-severity').value=rule.severity;
    document.getElementById('r-filter').value=rule.resource_filter||'*';
    document.getElementById('r-cooldown').value=rule.cooldown_minutes;
    const ch=rule.channels||[];
    document.getElementById('r-ch-email').checked=ch.includes('email');
    document.getElementById('r-ch-telegram').checked=ch.includes('telegram');
    document.getElementById('r-ch-whatsapp').checked=ch.includes('whatsapp');
    document.getElementById('modal').classList.add('show');
}

function closeModal(){document.getElementById('modal').classList.remove('show')}

function gatherRule(){
    const channels=[];
    if(document.getElementById('r-ch-email').checked)channels.push('email');
    if(document.getElementById('r-ch-telegram').checked)channels.push('telegram');
    if(document.getElementById('r-ch-whatsapp').checked)channels.push('whatsapp');
    let thresh=document.getElementById('r-threshold').value;
    if(!isNaN(thresh)&&thresh!=='')thresh=parseFloat(thresh);
    return{
        name:document.getElementById('r-name').value,
        service:document.getElementById('r-service').value,
        metric:document.getElementById('r-metric').value,
        operator:document.getElementById('r-op').value,
        threshold:thresh,
        severity:document.getElementById('r-severity').value,
        resource_filter:document.getElementById('r-filter').value,
        cooldown_minutes:parseInt(document.getElementById('r-cooldown').value)||15,
        channels:channels,
        enabled:true,
    }
}

async function saveRule(){
    const data=gatherRule();
    if(!data.name){toast('Give the rule a name','error');return}
    if(editingId){
        await fetch('/api/rules/'+editingId,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
        toast('Rule updated','success');
    }else{
        await fetch('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
        toast('Rule added','success');
    }
    closeModal();loadRules();
}

async function deleteRule(id){
    if(!confirm('Delete this rule?'))return;
    await fetch('/api/rules/'+id,{method:'DELETE',headers:{'Content-Type':'application/json'}});
    toast('Rule deleted','success');loadRules();
}

async function toggleRule(id,enabled){
    await fetch('/api/rules/'+id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:!enabled})});
    loadRules();
}

async function addTemplate(idx){
    await fetch('/api/rules/template',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({index:idx})});
    toast('Template added','success');loadRules();
}

function sevBadge(s){return s==='critical'?'<span class="badge error">CRITICAL</span>':s==='warning'?'<span class="badge warn">WARNING</span>':'<span class="badge info">INFO</span>'}

async function loadRules(){
    const res=await fetch('/api/rules');
    const data=await res.json();
    allMetrics=data.metrics;

    // Templates
    document.getElementById('templates').innerHTML=data.templates.map((t,i)=>`
        <div class="tpl-card" onclick="addTemplate(${i})">
            <div class="tname">${esc(t.name)}</div>
            <div class="tdesc">${esc(t.service)} → ${esc(t.metric)} ${esc(t.operator)} ${t.threshold} (${esc(t.severity)})</div>
        </div>`).join('');

    // Rules
    const rules=data.rules;
    if(!rules.length){
        document.getElementById('rules-list').innerHTML='<div style="text-align:center;padding:40px;color:#8b949e">No alert rules configured. Add one above or click a template.</div>';
        return;
    }
    document.getElementById('rules-list').innerHTML=rules.map(r=>`
        <div class="rule-card ${r.enabled?'':'disabled'}">
            <div>
                <div style="font-weight:600;font-size:.9rem">${esc(r.name)}</div>
                <div class="rule-meta">
                    ${sevBadge(r.severity)}
                    <span class="badge info">${esc(r.service)}</span>
                    <span style="font-size:.78rem;color:#8b949e">${esc(r.metric)} ${esc(r.operator)} ${esc(r.threshold)}</span>
                    <span style="font-size:.78rem;color:#484f58">cooldown: ${r.cooldown_minutes}m</span>
                    ${r.trigger_count?`<span style="font-size:.78rem;color:#f0883e">triggered ${r.trigger_count}x</span>`:''}
                </div>
                <div style="font-size:.75rem;color:#484f58;margin-top:4px">→ ${(r.channels||[]).map(c=>esc(c)).join(', ')} ${r.resource_filter&&r.resource_filter!=='*'?'| filter: '+esc(r.resource_filter):''}</div>
            </div>
            <div style="display:flex;gap:6px;align-items:center">
                <label class="switch"><input type="checkbox" ${r.enabled?'checked':''} onchange="toggleRule('${r.id}',${r.enabled})"><span class="slider"></span></label>
                <button class="btn sm" onclick='showEditModal(${JSON.stringify(r).replace(/'/g,"&#39;")})'>Edit</button>
                <button class="btn sm d" onclick="deleteRule('${r.id}')">×</button>
            </div>
        </div>`).join('');
}

loadRules();
</script></body></html>""")


# ═════════════════════════════════════════════════════════════════════════════
# LOGS PAGE — CloudWatch Log Viewer
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/logs")
def page_logs():
    return render_template_string("""<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Logs — AWS Video Dashboard</title>""" + SHARED_STYLES + """
<style>
.log-layout{display:grid;grid-template-columns:300px 1fr;gap:16px;height:calc(100vh - 120px)}
@media(max-width:900px){.log-layout{grid-template-columns:1fr;height:auto}}
.log-sidebar{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:14px;overflow-y:auto;max-height:calc(100vh - 130px)}
.log-main{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:14px;overflow-y:auto;max-height:calc(100vh - 130px)}
.log-group{padding:8px 10px;border-radius:6px;cursor:pointer;font-size:.82rem;color:#c9d1d9;border-bottom:1px solid #21262d;word-break:break-all}
.log-group:hover,.log-group.active{background:#1c2128;color:#58a6ff}
.log-stream{padding:6px 10px;border-radius:4px;cursor:pointer;font-size:.78rem;color:#8b949e;margin-left:8px}
.log-stream:hover,.log-stream.active{background:#1c2128;color:#c9d1d9}
.log-event{padding:4px 8px;font-size:.78rem;font-family:'SFMono-Regular',Consolas,monospace;border-bottom:1px solid #0d1117;white-space:pre-wrap;word-break:break-all;line-height:1.4}
.log-event .ts{color:#8b949e;margin-right:8px;user-select:none}
.log-event.error{color:#f85149;background:#1a0000}.log-event.warn{color:#d29922;background:#1a1500}.log-event.info{color:#58a6ff}
.log-search{display:flex;gap:8px;margin-bottom:12px}
.log-search input{flex:1;padding:7px 10px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#e1e4e8;font-size:.82rem}
.log-search input:focus{outline:none;border-color:#58a6ff}
.sidebar-search{margin-bottom:10px}
.sidebar-search input{width:100%;padding:6px 8px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#e1e4e8;font-size:.8rem}
.time-range{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap}
.time-btn{padding:4px 10px;border:1px solid #30363d;background:#21262d;color:#8b949e;border-radius:4px;cursor:pointer;font-size:.75rem}
.time-btn:hover,.time-btn.active{background:#30363d;color:#c9d1d9;border-color:#58a6ff}
</style>
</head><body>""" + nav("logs") + """
<div class="container">
<h1 style="font-size:1.3rem;margin-bottom:14px">CloudWatch Logs</h1>
<div class="log-layout">
  <div class="log-sidebar">
    <div class="sidebar-search"><input type="text" id="groupFilter" placeholder="Filter log groups..." oninput="filterGroups()"></div>
    <div id="groupList"><div style="color:#8b949e;font-size:.82rem;padding:10px">Loading log groups...</div></div>
    <div id="streamList" style="margin-top:12px;display:none"></div>
  </div>
  <div class="log-main">
    <div class="log-search">
      <input type="text" id="searchQuery" placeholder="CloudWatch Insights query or keyword...">
      <button class="btn p" onclick="searchLogs()">Search</button>
    </div>
    <div class="time-range">
      <button class="time-btn active" onclick="setTimeRange(1,this)">1h</button>
      <button class="time-btn" onclick="setTimeRange(3,this)">3h</button>
      <button class="time-btn" onclick="setTimeRange(12,this)">12h</button>
      <button class="time-btn" onclick="setTimeRange(24,this)">24h</button>
      <button class="time-btn" onclick="setTimeRange(72,this)">3d</button>
      <button class="time-btn" onclick="setTimeRange(168,this)">7d</button>
    </div>
    <div id="logTitle" style="font-size:.85rem;color:#58a6ff;margin-bottom:8px"></div>
    <div id="logEvents" style="font-size:.82rem;color:#8b949e">Select a log group and stream to view events</div>
  </div>
</div>
</div>
<script>
let currentGroup='',currentStream='',allGroups=[],timeRangeHours=1;
async function loadGroups(){
  const r=await fetch('/api/logs/groups');const d=await r.json();
  if(!d.ok){document.getElementById('groupList').innerHTML='<div style="color:#f85149;padding:10px">'+esc(d.error)+'</div>';return}
  allGroups=d.groups||[];renderGroups(allGroups);
}
function renderGroups(groups){
  const el=document.getElementById('groupList');
  if(!groups.length){el.innerHTML='<div style="color:#8b949e;padding:10px">No log groups found</div>';return}
  el.innerHTML=groups.map(g=>'<div class="log-group'+(g.name===currentGroup?' active':'')+'" onclick="selectGroup(decodeURIComponent(\''+encodeURIComponent(g.name)+'\'))">'+esc(g.name)+'<div style="font-size:.7rem;color:#484f58;margin-top:2px">'+(g.stored_bytes?(g.stored_bytes/1024/1024).toFixed(1)+'MB':'')+'</div></div>').join('');
}
function filterGroups(){
  const q=document.getElementById('groupFilter').value.toLowerCase();
  renderGroups(allGroups.filter(g=>g.name.toLowerCase().includes(q)));
}
async function selectGroup(name){
  currentGroup=name;currentStream='';renderGroups(allGroups);
  const sl=document.getElementById('streamList');sl.style.display='block';
  sl.innerHTML='<div style="color:#8b949e;font-size:.78rem;padding:6px">Loading streams...</div>';
  const r=await fetch('/api/logs/streams?group='+encodeURIComponent(name));const d=await r.json();
  if(!d.ok){sl.innerHTML='<div style="color:#f85149;padding:6px">Error</div>';return}
  const streams=d.streams||[];
  if(!streams.length){sl.innerHTML='<div style="color:#8b949e;font-size:.78rem;padding:6px">No streams</div>';return}
  sl.innerHTML='<div style="font-size:.72rem;color:#8b949e;padding:4px;text-transform:uppercase">Streams</div>'+
    streams.map(s=>'<div class="log-stream" onclick="selectStream(decodeURIComponent(\''+encodeURIComponent(s.name)+'\'))">'+esc(s.name)+'</div>').join('');
}
async function selectStream(name){
  currentStream=name;
  document.getElementById('logTitle').textContent=currentGroup+' / '+name;
  const el=document.getElementById('logEvents');el.innerHTML='<div style="color:#8b949e">Loading events...</div>';
  const now=Date.now();const start=now-(timeRangeHours*3600000);
  const r=await fetch('/api/logs/events?group='+encodeURIComponent(currentGroup)+'&stream='+encodeURIComponent(name)+'&start_time='+start+'&end_time='+now);
  const d=await r.json();
  if(!d.ok){el.innerHTML='<div style="color:#f85149">Error loading events</div>';return}
  renderEvents(d.events||[]);
}
function renderEvents(events){
  const el=document.getElementById('logEvents');
  if(!events.length){el.innerHTML='<div style="color:#8b949e">No events in this time range</div>';return}
  el.innerHTML=events.map(e=>{
    const ts=new Date(e.timestamp).toLocaleTimeString();
    const msg=e.message||'';
    let cls='';if(/error|exception|fatal/i.test(msg))cls='error';else if(/warn/i.test(msg))cls='warn';else if(/info/i.test(msg))cls='info';
    return '<div class="log-event '+cls+'"><span class="ts">'+ts+'</span>'+esc(msg)+'</div>';
  }).join('');
}
async function searchLogs(){
  const query=document.getElementById('searchQuery').value;
  if(!currentGroup){alert('Select a log group first');return}
  const el=document.getElementById('logEvents');el.innerHTML='<div style="color:#8b949e">Searching...</div>';
  document.getElementById('logTitle').textContent='Search: '+currentGroup;
  const now=Math.floor(Date.now()/1000);const start=now-(timeRangeHours*3600);
  const r=await fetch('/api/logs/search',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({group:currentGroup,query:query,start_time:start,end_time:now})});
  const d=await r.json();
  if(!d.ok){el.innerHTML='<div style="color:#f85149">Search error: '+esc(d.error)+'</div>';return}
  const results=d.results||[];
  if(!results.length){el.innerHTML='<div style="color:#8b949e">No results found</div>';return}
  el.innerHTML=results.map(r=>{
    const ts=r['@timestamp']||'';const msg=r['@message']||JSON.stringify(r);
    let cls='';if(/error|exception/i.test(msg))cls='error';else if(/warn/i.test(msg))cls='warn';
    return '<div class="log-event '+cls+'"><span class="ts">'+ts+'</span>'+esc(msg)+'</div>';
  }).join('');
}
function setTimeRange(hours,btn){
  timeRangeHours=hours;
  document.querySelectorAll('.time-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  if(currentStream)selectStream(currentStream);
}
loadGroups();
</script></body></html>""")


# ═════════════════════════════════════════════════════════════════════════════
# COSTS PAGE — AWS Cost Dashboard
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/costs")
def page_costs():
    return render_template_string("""<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Costs — AWS Video Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js" integrity="sha384-vsrfeLOOY6KuIYKDlmVH5UiBmgIdB1oEf7p01YgWHuqmOHfZr374+odEv96n9tNC" crossorigin="anonymous"></script>
""" + SHARED_STYLES + """
<style>
.cost-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px}
@media(max-width:900px){.cost-grid{grid-template-columns:1fr}}
.chart-box{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px;position:relative;height:320px}
.chart-box canvas{width:100%!important;height:100%!important}
.month-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:20px}
.month-card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:14px;text-align:center}
.month-card .month{font-size:.75rem;color:#8b949e;text-transform:uppercase}
.month-card .amount{font-size:1.4rem;font-weight:700;color:#c9d1d9;margin-top:4px}
.month-card .change{font-size:.78rem;margin-top:4px}
.change.up{color:#f85149}.change.down{color:#3fb950}
.budget-bar{background:#21262d;border-radius:4px;height:20px;overflow:hidden;margin-top:6px}
.budget-fill{height:100%;border-radius:4px;transition:width .5s}
</style>
</head><body>""" + nav("costs") + """
<div class="container">
<h1 style="font-size:1.3rem;margin-bottom:14px">AWS Cost Dashboard</h1>
<div class="cards" id="summaryCards"><div class="card"><div class="lb">Loading...</div></div></div>
<div class="cost-grid">
  <div class="chart-box"><canvas id="dailyChart"></canvas></div>
  <div class="chart-box"><canvas id="serviceChart"></canvas></div>
</div>
<div class="section"><h2>Monthly Trend</h2><div class="month-cards" id="monthCards"></div></div>
<div class="section"><h2>Budget Status</h2><div id="budgetSection"></div></div>
<div class="section"><h2>Service Breakdown</h2>
  <table><thead><tr><th>Service</th><th>Cost</th><th>% of Total</th></tr></thead>
  <tbody id="serviceTable"></tbody></table>
</div>
</div>
<script>
let dailyChart,serviceChart;
async function loadCosts(){
  try{
  const [dailyR,monthlyR,servicesR,budgetsR]=await Promise.all([
    fetch('/api/costs/daily?days=30').then(r=>r.json()),
    fetch('/api/costs/monthly?months=6').then(r=>r.json()),
    fetch('/api/costs/services?days=30').then(r=>r.json()),
    fetch('/api/costs/budgets').then(r=>r.json()),
  ]);
  // Summary cards
  const total30=dailyR.total||0;const avgDay=dailyR.days?.length?(total30/dailyR.days.length):0;
  document.getElementById('summaryCards').innerHTML=
    '<div class="card"><div class="lb">30-Day Total</div><div class="vl">$'+total30.toFixed(2)+'</div></div>'+
    '<div class="card"><div class="lb">Daily Average</div><div class="vl">$'+avgDay.toFixed(2)+'</div></div>'+
    '<div class="card"><div class="lb">Top Service</div><div class="vl">'+esc(servicesR.services?.[0]?.name||'N/A')+'</div></div>'+
    '<div class="card"><div class="lb">Services</div><div class="vl">'+(servicesR.services?.length||0)+'</div></div>';
  // Daily chart
  if(dailyR.days?.length){
    const labels=dailyR.days.map(d=>d.date);const data=dailyR.days.map(d=>d.total);
    const ctx=document.getElementById('dailyChart').getContext('2d');
    dailyChart=new Chart(ctx,{type:'line',data:{labels,datasets:[{label:'Daily Spend ($)',data,borderColor:'#58a6ff',backgroundColor:'rgba(88,166,255,.1)',fill:true,tension:.3}]},
      options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'#8b949e'}}},scales:{x:{ticks:{color:'#8b949e',maxTicksLimit:10},grid:{color:'#21262d'}},y:{ticks:{color:'#8b949e',callback:v=>'$'+v},grid:{color:'#21262d'}}}}});
  }
  // Service pie chart
  if(servicesR.services?.length){
    const colors=['#58a6ff','#3fb950','#d29922','#f85149','#bc8cff','#f0883e','#79c0ff','#a5d6ff','#7ee787','#ffd33d'];
    const ctx2=document.getElementById('serviceChart').getContext('2d');
    serviceChart=new Chart(ctx2,{type:'doughnut',data:{labels:servicesR.services.map(s=>s.name),datasets:[{data:servicesR.services.map(s=>s.cost),backgroundColor:colors}]},
      options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'right',labels:{color:'#8b949e',font:{size:11}}}}}});
  }
  // Monthly cards
  if(monthlyR.months?.length){
    document.getElementById('monthCards').innerHTML=monthlyR.months.map(m=>{
      let changeHtml='';if(m.change_pct!==undefined&&m.change_pct!==null){
        const cls=m.change_pct>0?'up':'down';const arrow=m.change_pct>0?'+':'';
        changeHtml='<div class="change '+cls+'">'+arrow+m.change_pct.toFixed(1)+'%</div>';
      }
      return '<div class="month-card"><div class="month">'+esc(m.month)+'</div><div class="amount">$'+m.total.toFixed(2)+'</div>'+changeHtml+'</div>';
    }).join('');
  }
  // Budgets
  const budgets=budgetsR.budgets||[];
  if(budgets.length){
    document.getElementById('budgetSection').innerHTML=budgets.map(b=>{
      const pct=Math.min(b.pct_used||0,100);const color=pct>90?'#f85149':pct>70?'#d29922':'#3fb950';
      return '<div class="panel"><h3>'+esc(b.name)+'</h3><div style="display:flex;justify-content:space-between;font-size:.85rem"><span>$'+b.actual.toFixed(2)+' / $'+b.limit.toFixed(2)+'</span><span style="color:'+color+'">'+pct.toFixed(0)+'%</span></div><div class="budget-bar"><div class="budget-fill" style="width:'+pct+'%;background:'+color+'"></div></div>'+(b.forecasted?'<div style="font-size:.75rem;color:#8b949e;margin-top:4px">Forecasted: $'+b.forecasted.toFixed(2)+'</div>':'')+'</div>';
    }).join('');
  }else{document.getElementById('budgetSection').innerHTML='<div style="color:#8b949e;font-size:.85rem">No AWS Budgets configured</div>';}
  // Service table
  if(servicesR.services?.length){
    document.getElementById('serviceTable').innerHTML=servicesR.services.map(s=>
      '<tr><td>'+esc(s.name)+'</td><td>$'+s.cost.toFixed(2)+'</td><td>'+s.pct.toFixed(1)+'%</td></tr>'
    ).join('');
  }
  }catch(e){
    document.getElementById('cost-daily').innerHTML='<div style="color:#f85149;padding:20px">Failed to load cost data</div>';
    console.error('Cost load error:', e);
  }
}
loadCosts();
</script></body></html>""")


# ═════════════════════════════════════════════════════════════════════════════
# SCHEDULES PAGE — Scheduled Actions
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/schedules")
def page_schedules():
    return render_template_string("""<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Schedules — AWS Video Dashboard</title>""" + SHARED_STYLES + """
<style>
.sched-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:500;display:none;align-items:center;justify-content:center}
.modal-bg.show{display:flex}
.modal{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:24px;width:500px;max-width:90vw;max-height:85vh;overflow-y:auto}
.modal h2{font-size:1rem;margin-bottom:14px;color:#58a6ff}
.cron-presets{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px}
.cron-preset{padding:4px 10px;border:1px solid #30363d;background:#21262d;color:#8b949e;border-radius:4px;cursor:pointer;font-size:.75rem}
.cron-preset:hover{border-color:#58a6ff;color:#c9d1d9}
</style>
</head><body>""" + nav("schedules") + """
<div class="container">
<div class="sched-header">
  <h1 style="font-size:1.3rem">Scheduled Actions</h1>
  <button class="btn p" onclick="showCreate()">+ New Schedule</button>
</div>
<div class="cards" id="statsCards"><div class="card"><div class="lb">Loading...</div></div></div>
<table><thead><tr><th>Name</th><th>Action</th><th>Cron</th><th>Enabled</th><th>Last Run</th><th>Runs</th><th>Actions</th></tr></thead>
<tbody id="schedTable"></tbody></table>
<div id="runHistory" style="margin-top:20px;display:none">
  <h2 style="font-size:1rem;margin-bottom:10px;color:#c9d1d9">Run History — <span id="runSchedName"></span></h2>
  <table><thead><tr><th>Started</th><th>Completed</th><th>Status</th><th>Result</th></tr></thead>
  <tbody id="runTable"></tbody></table>
</div>
</div>
<div class="modal-bg" id="createModal">
<div class="modal">
<h2>Create Schedule</h2>
<div class="field"><label>Name</label><input id="schedName" placeholder="e.g. Nightly backup"></div>
<div class="field"><label>Description</label><input id="schedDesc" placeholder="Optional description"></div>
<div class="field"><label>Action</label><select id="schedAction"></select></div>
<div class="field"><label>Action Parameters (JSON)</label><textarea id="schedParams" rows="3" placeholder='{"key":"value"}'>{}</textarea></div>
<div class="field"><label>Cron Expression</label><input id="schedCron" placeholder="0 8 * * *">
<div class="hint">minute hour day month weekday</div></div>
<div class="cron-presets" id="cronPresets"></div>
<div style="display:flex;gap:8px;justify-content:flex-end;margin-top:16px">
  <button class="btn" onclick="closeCreate()">Cancel</button>
  <button class="btn p" onclick="createSched()">Create</button>
</div>
</div>
</div>
<script>
async function loadSchedules(){
  const [sr,str]=await Promise.all([fetch('/api/schedules').then(r=>r.json()),fetch('/api/schedules/stats').then(r=>r.json())]);
  // Stats
  document.getElementById('statsCards').innerHTML=
    '<div class="card"><div class="lb">Total</div><div class="vl">'+(str.total||0)+'</div></div>'+
    '<div class="card"><div class="lb">Enabled</div><div class="vl green">'+(str.enabled||0)+'</div></div>'+
    '<div class="card"><div class="lb">Disabled</div><div class="vl yellow">'+(str.disabled||0)+'</div></div>'+
    '<div class="card"><div class="lb">Runs Today</div><div class="vl blue">'+(str.runs_today||0)+'</div></div>';
  // Table
  const schedules=sr.schedules||[];
  document.getElementById('schedTable').innerHTML=schedules.length?schedules.map(s=>
    '<tr><td>'+esc(s.name)+'</td><td><span class="badge info">'+esc(s.action_id)+'</span></td><td><code>'+esc(s.cron_expression)+'</code></td>'+
    '<td>'+(s.enabled?'<span class="badge ok">On</span>':'<span class="badge off">Off</span>')+'</td>'+
    '<td style="font-size:.78rem">'+esc(s.last_run||'Never')+'</td><td>'+s.run_count+'</td>'+
    '<td><button class="btn sm" onclick="toggleSched('+s.id+')">'+(s.enabled?'Disable':'Enable')+'</button> '+
    '<button class="btn sm" onclick="showRuns('+s.id+',\''+s.name.replace(/'/g,"\\'")+'\')">Runs</button> '+
    '<button class="btn sm d" onclick="deleteSched('+s.id+')">Del</button></td></tr>'
  ).join(''):'<tr><td colspan="7" style="color:#8b949e;text-align:center;padding:20px">No schedules configured</td></tr>';
}
async function toggleSched(id){await fetch('/api/schedules/'+id+'/toggle',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});loadSchedules();}
async function deleteSched(id){if(!confirm('Delete this schedule?'))return;await fetch('/api/schedules/'+id,{method:'DELETE',headers:{'Content-Type':'application/json'}});loadSchedules();}
async function showRuns(id,name){
  document.getElementById('runHistory').style.display='block';
  document.getElementById('runSchedName').textContent=name;
  const r=await fetch('/api/schedules/'+id+'/runs');const d=await r.json();
  const runs=d.runs||[];
  document.getElementById('runTable').innerHTML=runs.length?runs.map(r=>
    '<tr><td style="font-size:.78rem">'+(r.started_at||'')+'</td><td style="font-size:.78rem">'+(r.completed_at||'')+'</td>'+
    '<td>'+(r.success?'<span class="badge ok">OK</span>':'<span class="badge error">Fail</span>')+'</td>'+
    '<td style="font-size:.78rem;max-width:300px;overflow:hidden;text-overflow:ellipsis">'+esc(typeof r.result==='object'?JSON.stringify(r.result):r.result||'')+'</td></tr>'
  ).join(''):'<tr><td colspan="4" style="color:#8b949e;text-align:center">No runs yet</td></tr>';
}
function showCreate(){document.getElementById('createModal').classList.add('show');}
function closeCreate(){document.getElementById('createModal').classList.remove('show');}
async function loadPresets(){
  const r=await fetch('/api/schedules/presets');const d=await r.json();
  document.getElementById('cronPresets').innerHTML=(d.presets||[]).map(p=>
    '<div class="cron-preset" onclick="document.getElementById(\'schedCron\').value=\''+esc(p.cron).replace(/'/g,"&#39;")+'\'">'+esc(p.name)+'</div>'
  ).join('');
  const ar=await fetch('/api/ai/actions');const ad=await ar.json();
  const sel=document.getElementById('schedAction');
  sel.innerHTML=(ad.actions||[]).map(a=>'<option value="'+esc(a.id)+'">'+esc(a.name)+' ['+esc(a.risk)+']</option>').join('');
}
async function createSched(){
  const name=document.getElementById('schedName').value;
  const cron=document.getElementById('schedCron').value;
  const action_id=document.getElementById('schedAction').value;
  if(!name||!cron||!action_id){alert('Name, action, and cron are required');return}
  let params={};try{params=JSON.parse(document.getElementById('schedParams').value||'{}');}catch(e){alert('Invalid JSON');return}
  await fetch('/api/schedules',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name,description:document.getElementById('schedDesc').value,action_id,action_params:params,cron_expression:cron})});
  closeCreate();loadSchedules();
}
loadSchedules();loadPresets();
</script></body></html>""")


# ═════════════════════════════════════════════════════════════════════════════
# 3. AI ASSISTANT PAGE
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/ai")
def page_ai():
    return render_template_string("""<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Assistant — AWS Video Dashboard</title>""" + SHARED_STYLES + """
<style>
.chat-wrap{display:flex;flex-direction:column;height:calc(100vh - 140px);max-height:800px}
.chat-messages{flex:1;overflow-y:auto;padding:16px;background:#0d1117;border:1px solid #21262d;border-radius:8px 8px 0 0}
.msg{margin-bottom:14px;max-width:85%}
.msg.user{margin-left:auto;text-align:right}
.msg.user .bubble{background:#1f6feb;color:#fff;border-radius:12px 12px 2px 12px;padding:10px 14px;display:inline-block;text-align:left}
.msg.ai .bubble{background:#161b22;border:1px solid #21262d;border-radius:12px 12px 12px 2px;padding:10px 14px;display:inline-block}
.msg .meta{font-size:.7rem;color:#484f58;margin-top:3px}
.msg.ai .bubble pre{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:10px;overflow-x:auto;margin:8px 0;font-size:.82rem}
.msg.ai .bubble code{background:#0d1117;padding:1px 4px;border-radius:3px;font-size:.82rem}
.msg.ai .bubble p{margin-bottom:8px}
.chat-input{display:flex;gap:8px;padding:12px;background:#161b22;border:1px solid #21262d;border-top:none;border-radius:0 0 8px 8px}
.chat-input input,.chat-input textarea{flex:1;padding:10px 14px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#e1e4e8;font-size:.9rem;font-family:inherit;resize:none}
.chat-input input:focus,.chat-input textarea:focus{outline:none;border-color:#58a6ff}
.suggestions{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
.suggestions button{background:#0d1117;border:1px solid #21262d;color:#8b949e;padding:6px 12px;border-radius:16px;cursor:pointer;font-size:.78rem;transition:.15s}
.suggestions button:hover{border-color:#58a6ff;color:#58a6ff}
/* Agent Mode Toggle */
.mode-toggle{display:flex;align-items:center;gap:6px;font-size:.78rem;color:#8b949e}
.mode-toggle .switch{position:relative;width:36px;height:20px;cursor:pointer}
.mode-toggle .switch input{opacity:0;width:0;height:0}
.mode-toggle .slider{position:absolute;inset:0;background:#30363d;border-radius:20px;transition:.2s}
.mode-toggle .slider:before{content:'';position:absolute;height:14px;width:14px;left:3px;bottom:3px;background:#8b949e;border-radius:50%;transition:.2s}
.mode-toggle .switch input:checked+.slider{background:#238636}
.mode-toggle .switch input:checked+.slider:before{transform:translateX(16px);background:#fff}
/* Agent Timeline */
.agent-panel{display:none}
.agent-panel.active{display:flex;flex-direction:column;height:calc(100vh - 140px);max-height:800px}
.agent-timeline{flex:1;overflow-y:auto;padding:16px;background:#0d1117;border:1px solid #21262d;border-radius:8px 8px 0 0}
.agent-input{display:flex;gap:8px;padding:12px;background:#161b22;border:1px solid #21262d;border-top:none;border-radius:0 0 8px 8px}
.agent-input textarea{flex:1;padding:10px 14px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#e1e4e8;font-size:.9rem;font-family:inherit;resize:none;min-height:48px}
.step{margin-bottom:12px;padding:10px 14px;border-radius:8px;border-left:3px solid #30363d;background:#161b22;font-size:.85rem}
.step.thinking{border-left-color:#d29922;color:#d29922}
.step.thinking .spinner{display:inline-block;width:12px;height:12px;border:2px solid #d29922;border-top-color:transparent;border-radius:50%;animation:spin .8s linear infinite;margin-right:6px;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}
.step.plan{border-left-color:#58a6ff;color:#c9d1d9}
.step.plan ol{margin:6px 0 0 18px;color:#8b949e;font-size:.8rem}
.step.ai-text{border-left-color:#8b949e;color:#c9d1d9}
.step.action{border-left-color:#bc8cff}
.step.action .action-header{display:flex;align-items:center;gap:8px;margin-bottom:4px}
.step.action .risk-badge{font-size:.68rem;padding:1px 6px;border-radius:8px;font-weight:600;text-transform:uppercase}
.step.action .risk-badge.low{background:#0d419d;color:#58a6ff}
.step.action .risk-badge.medium{background:#4d2d00;color:#d29922}
.step.action .risk-badge.high{background:#5c1a1a;color:#f85149}
.step.executing{border-left-color:#d29922}
.step.result{border-left-color:#3fb950}
.step.result.fail{border-left-color:#f85149}
.step.approval{border-left-color:#f85149;background:#1c1007}
.step.approval .approval-btns{display:flex;gap:8px;margin-top:8px}
.step.complete{border-left-color:#3fb950;background:#0d1f0d;color:#3fb950}
.step.error{border-left-color:#f85149;background:#1f0d0d;color:#f85149}
.step.stopped{border-left-color:#484f58;color:#8b949e}
.agent-suggestions{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
.agent-suggestions button{background:#0d1117;border:1px solid #21262d;color:#8b949e;padding:6px 12px;border-radius:16px;cursor:pointer;font-size:.78rem;transition:.15s}
.agent-suggestions button:hover{border-color:#bc8cff;color:#bc8cff}
</style>
</head><body>
""" + nav("ai") + """
<div class="container">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
    <h1 style="font-size:1.2rem;color:#c9d1d9">AI Infrastructure Assistant</h1>
    <div style="display:flex;gap:10px;align-items:center">
        <div class="mode-toggle">
            <span>Chat</span>
            <label class="switch"><input type="checkbox" id="agent-toggle" onchange="toggleAgentMode()"><span class="slider"></span></label>
            <span style="color:#bc8cff;font-weight:600">Agent</span>
        </div>
        <select id="ai-model" style="padding:5px 8px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#8b949e;font-size:.78rem"></select>
        <button class="btn sm" onclick="clearChat()">Clear</button>
    </div>
</div>

<!-- Chat Mode (default) -->
<div id="chat-panel">
<div class="suggestions" id="suggestions">
    <button onclick="ask(this.textContent)">Summarise my infrastructure</button>
    <button onclick="ask(this.textContent)">Any issues right now?</button>
    <button onclick="ask(this.textContent)">How can I reduce latency?</button>
    <button onclick="ask(this.textContent)">Review my alert rules</button>
    <button onclick="ask(this.textContent)">Cost optimisation suggestions</button>
    <button onclick="ask(this.textContent)">Best practice for SRT ingest</button>
</div>
<div class="chat-wrap">
    <div class="chat-messages" id="messages">
        <div class="msg ai"><div class="bubble">I'm your infrastructure assistant. I can see your live AWS data and help with video engineering questions. What would you like to know?</div></div>
    </div>
    <div class="chat-input">
        <input type="text" id="input" placeholder="Ask about your infrastructure..." onkeydown="if(event.key==='Enter')send()">
        <button class="btn p" onclick="send()" id="send-btn">Send</button>
    </div>
</div>
</div>

<!-- Agent Mode -->
<div id="agent-panel" class="agent-panel">
<div class="agent-suggestions">
    <button onclick="agentAsk(this.textContent)">Launch a video encoder and build an AMI</button>
    <button onclick="agentAsk(this.textContent)">Check all services and set up alerts for any issues</button>
    <button onclick="agentAsk(this.textContent)">Set up monitoring for all EC2 instances</button>
    <button onclick="agentAsk(this.textContent)">Get cost summary and suggest optimisations</button>
    <button onclick="agentAsk(this.textContent)">Launch a streaming server with NDI support</button>
</div>
<div class="agent-timeline" id="timeline">
    <div class="step ai-text" style="border-left-color:#bc8cff;color:#8b949e">
        Agent Mode — Describe what you want to build or deploy. The AI will plan and execute the steps autonomously. High-risk actions will pause for your approval.
    </div>
</div>
<div class="agent-input">
    <textarea id="agent-input" rows="2" placeholder="Describe what you want to build, deploy, or configure..." onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();startAgent()}"></textarea>
    <button class="btn p" onclick="startAgent()" id="agent-run-btn">Run</button>
    <button class="btn d" onclick="stopAgent()" id="agent-stop-btn" style="display:none">Stop</button>
</div>
</div>
</div>
<div id="toast" class="toast"></div>

<script>
const convId='conv_'+Date.now();
let agentTaskId=null;
let agentSSE=null;

function toast(m,t='info'){const e=document.getElementById('toast');e.textContent=m;e.className='toast '+t+' show';setTimeout(()=>e.classList.remove('show'),3000)}

function renderMd(text){
    return esc(text)
        .replace(/```([\\s\\S]*?)```/g,'<pre>$1</pre>')
        .replace(/`([^`]+)`/g,'<code>$1</code>')
        .replace(/\\*\\*([^*]+)\\*\\*/g,'<strong>$1</strong>')
        .replace(/\\*([^*]+)\\*/g,'<em>$1</em>')
        .replace(/^### (.+)$/gm,'<h4 style="margin:8px 0 4px;color:#58a6ff">$1</h4>')
        .replace(/^## (.+)$/gm,'<h3 style="margin:10px 0 4px;color:#58a6ff">$1</h3>')
        .replace(/^- (.+)$/gm,'<div style="padding-left:12px">&bull; $1</div>')
        .replace(/\\n\\n/g,'<br><br>')
        .replace(/\\n/g,'<br>');
}

// ── Chat Mode Functions ──
function addMsg(role,content,meta=''){
    const el=document.getElementById('messages');
    const div=document.createElement('div');
    div.className='msg '+role;
    div.innerHTML='<div class="bubble">'+(role==='ai'?renderMd(content):esc(content))+'</div>'+(meta?'<div class="meta">'+esc(meta)+'</div>':'');
    el.appendChild(div);
    el.scrollTop=el.scrollHeight;
}

function ask(text){document.getElementById('input').value=text;send()}

async function send(){
    const input=document.getElementById('input');
    const msg=input.value.trim();if(!msg)return;
    input.value='';
    addMsg('user',msg);
    const btn=document.getElementById('send-btn');btn.disabled=true;btn.textContent='...';
    const typing=document.createElement('div');typing.className='msg ai';typing.id='typing';
    typing.innerHTML='<div class="bubble" style="color:#8b949e">Thinking...</div>';
    document.getElementById('messages').appendChild(typing);
    document.getElementById('messages').scrollTop=document.getElementById('messages').scrollHeight;
    try{
        const selModel=document.getElementById('ai-model');
        const res=await fetch('/api/ai/query',{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({message:msg,conversation_id:convId,model:selModel?selModel.value:''})});
        const data=await res.json();
        typing.remove();
        const meta=data.model?data.model+' '+data.tokens+' tokens':'';
        addMsg('ai',data.response,meta);
        if(data.error==='no_api_key')toast('Add your OpenRouter API key in Settings','error');
    }catch(e){typing.remove();addMsg('ai','Error connecting to AI.');toast('AI query failed','error')}
    btn.disabled=false;btn.textContent='Send';
}

async function clearChat(){
    if(document.getElementById('agent-toggle').checked){
        // Clear agent timeline
        if(agentSSE){agentSSE.close();agentSSE=null}
        agentTaskId=null;
        document.getElementById('timeline').innerHTML='<div class="step ai-text" style="border-left-color:#bc8cff;color:#8b949e">Agent Mode — Describe what you want to build or deploy.</div>';
        document.getElementById('agent-run-btn').style.display='';
        document.getElementById('agent-stop-btn').style.display='none';
        document.getElementById('agent-input').disabled=false;
    }else{
        await fetch('/api/ai/clear',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({conversation_id:convId})});
        document.getElementById('messages').innerHTML='<div class="msg ai"><div class="bubble">Chat cleared. How can I help?</div></div>';
    }
}

// ── Mode Toggle ──
function toggleAgentMode(){
    const on=document.getElementById('agent-toggle').checked;
    document.getElementById('chat-panel').style.display=on?'none':'';
    document.getElementById('agent-panel').className='agent-panel'+(on?' active':'');
}

// ── Agent Mode Functions ──
function agentAsk(text){document.getElementById('agent-input').value=text;startAgent()}

function addStep(cls,html){
    const tl=document.getElementById('timeline');
    const div=document.createElement('div');
    div.className='step '+cls;
    div.innerHTML=html;
    tl.appendChild(div);
    tl.scrollTop=tl.scrollHeight;
    return div;
}

async function startAgent(){
    const input=document.getElementById('agent-input');
    const msg=input.value.trim();if(!msg)return;
    input.disabled=true;
    document.getElementById('agent-run-btn').style.display='none';
    document.getElementById('agent-stop-btn').style.display='';

    // Clear previous timeline
    document.getElementById('timeline').innerHTML='';
    addStep('ai-text','<div style="color:#58a6ff;font-weight:600">Task: '+esc(msg)+'</div>');

    try{
        const res=await fetch('/api/ai/agent/start',{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({message:msg})});
        const data=await res.json();
        if(!data.ok){toast(data.error||'Failed to start agent','error');agentDone();return}
        agentTaskId=data.task_id;
        connectAgentSSE(data.task_id);
    }catch(e){
        toast('Failed to start agent','error');
        agentDone();
    }
}

function connectAgentSSE(taskId){
    if(agentSSE)agentSSE.close();
    const es=new EventSource('/api/ai/agent/events/'+taskId);
    agentSSE=es;
    let thinkingEl=null;

    es.addEventListener('thinking',function(){
        thinkingEl=addStep('thinking','<span class="spinner"></span> Thinking...');
    });

    es.addEventListener('ai_response',function(e){
        if(thinkingEl){thinkingEl.remove();thinkingEl=null}
        const d=JSON.parse(e.data);
        if(d.content){
            const meta=d.model?'<span style="font-size:.68rem;color:#484f58;margin-left:8px">'+esc(d.model)+'</span>':'';
            addStep('ai-text',renderMd(d.content)+meta);
        }
    });

    es.addEventListener('plan',function(e){
        const d=JSON.parse(e.data);
        let html='<strong style="color:#58a6ff">Plan:</strong><ol>';
        (d.steps||[]).forEach(function(s){html+='<li>'+esc(s)+'</li>'});
        html+='</ol>';
        addStep('plan',html);
    });

    es.addEventListener('action_proposed',function(e){
        const d=JSON.parse(e.data);
        const riskCls=d.risk||'low';
        addStep('action',
            '<div class="action-header"><span class="risk-badge '+riskCls+'">'+esc(d.risk)+'</span> <strong>'+esc(d.name||d.action_id)+'</strong></div>'+
            '<div style="color:#8b949e;font-size:.8rem">'+esc(d.reason||'')+'</div>'+
            (Object.keys(d.params||{}).length?'<div style="margin-top:4px;font-size:.75rem;color:#484f58"><code>'+esc(JSON.stringify(d.params))+'</code></div>':'')
        );
    });

    es.addEventListener('executing',function(e){
        if(thinkingEl){thinkingEl.remove();thinkingEl=null}
        const d=JSON.parse(e.data);
        thinkingEl=addStep('executing thinking','<span class="spinner"></span> Executing <strong>'+esc(d.name||d.action_id)+'</strong>...');
    });

    es.addEventListener('action_result',function(e){
        if(thinkingEl){thinkingEl.remove();thinkingEl=null}
        const d=JSON.parse(e.data);
        const ok=d.ok;
        const cls=ok?'result':'result fail';
        let html=(ok?'&#10003; ':'&#10007; ')+'<strong>'+esc(d.name||d.action_id)+'</strong>: '+(esc(d.message||d.error||''));
        if(d.data&&typeof d.data==='object'){
            const summary=JSON.stringify(d.data).substring(0,200);
            html+='<div style="margin-top:4px;font-size:.75rem;color:#484f58"><code>'+esc(summary)+(summary.length>=200?'...':'')+'</code></div>';
        }
        addStep(cls,html);
    });

    es.addEventListener('awaiting_approval',function(e){
        if(thinkingEl){thinkingEl.remove();thinkingEl=null}
        const d=JSON.parse(e.data);
        const el=addStep('approval',
            '<div style="font-weight:600;color:#f0883e">Approval Required</div>'+
            '<div style="margin:4px 0"><strong>'+esc(d.name||d.action_id)+'</strong> <span class="risk-badge high">HIGH RISK</span></div>'+
            '<div style="color:#8b949e;font-size:.82rem">'+esc(d.confirm_message||d.reason||'')+'</div>'+
            (Object.keys(d.params||{}).length?'<div style="margin-top:4px;font-size:.75rem;color:#484f58"><code>'+esc(JSON.stringify(d.params))+'</code></div>':'')+
            '<div class="approval-btns">'+
            '<button class="btn p" onclick="approveAction(true,this)">Approve</button>'+
            '<button class="btn d" onclick="approveAction(false,this)">Reject</button>'+
            '</div>'
        );
    });

    es.addEventListener('approved',function(){});
    es.addEventListener('rejected',function(){
        addStep('stopped','Action rejected by user.');
    });

    es.addEventListener('heartbeat',function(){});

    es.addEventListener('complete',function(e){
        if(thinkingEl){thinkingEl.remove();thinkingEl=null}
        const d=JSON.parse(e.data);
        const dur=d.duration_ms?(' in '+(d.duration_ms/1000).toFixed(1)+'s'):'';
        addStep('complete','<strong>Complete</strong>'+dur+(d.summary?' &mdash; '+esc(d.summary):''));
        es.close();agentSSE=null;agentDone();
    });

    es.addEventListener('error',function(e){
        if(thinkingEl){thinkingEl.remove();thinkingEl=null}
        try{const d=JSON.parse(e.data);addStep('error','Error: '+esc(d.message||'Unknown error'))}
        catch(_){addStep('error','Connection lost')}
        es.close();agentSSE=null;agentDone();
    });

    es.addEventListener('stopped',function(){
        if(thinkingEl){thinkingEl.remove();thinkingEl=null}
        addStep('stopped','Agent stopped by user.');
        es.close();agentSSE=null;agentDone();
    });

    es.onerror=function(){
        if(es.readyState===EventSource.CLOSED){
            if(thinkingEl){thinkingEl.remove();thinkingEl=null}
            agentDone();
        }
    };
}

async function approveAction(approved,btn){
    if(!agentTaskId)return;
    // Disable buttons
    const btns=btn.parentElement;
    btns.querySelectorAll('button').forEach(function(b){b.disabled=true});
    btns.innerHTML=approved?'<span style="color:#3fb950">Approved</span>':'<span style="color:#f85149">Rejected</span>';
    try{
        await fetch('/api/ai/agent/'+agentTaskId+'/approve',{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({approved:approved})});
    }catch(e){toast('Failed to send approval','error')}
}

async function stopAgent(){
    if(!agentTaskId)return;
    try{await fetch('/api/ai/agent/'+agentTaskId+'/stop',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})}
    catch(e){}
    if(agentSSE){agentSSE.close();agentSSE=null}
    agentDone();
}

function agentDone(){
    document.getElementById('agent-input').disabled=false;
    document.getElementById('agent-input').value='';
    document.getElementById('agent-run-btn').style.display='';
    document.getElementById('agent-stop-btn').style.display='none';
    agentTaskId=null;
}

async function loadModels(){
    const res=await fetch('/api/ai/models');
    const data=await res.json();
    const sel=document.getElementById('ai-model');
    data.models.forEach(function(m){sel.innerHTML+='<option value="'+esc(m.id)+'">'+esc(m.name)+'</option>'});
}
loadModels();
</script></body></html>""")


# ═════════════════════════════════════════════════════════════════════════════
# 5. CLOUD PAGE — EC2 Media Instances & AMI Builder
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/cloud")
def page_cloud():
    return render_template_string("""<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cloud — AWS Video Dashboard</title>""" + SHARED_STYLES + """
<style>
.tpl-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px;margin-bottom:16px}
.tpl-card{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:14px;transition:.15s}
.tpl-card:hover{border-color:#58a6ff;background:#161b22}
.tpl-card .tname{font-weight:600;font-size:.88rem;margin-bottom:4px;color:#e1e4e8}
.tpl-card .tdesc{font-size:.76rem;color:#8b949e;margin-bottom:8px}
.tpl-card .tmeta{display:flex;gap:6px;flex-wrap:wrap}
.tpl-actions{display:flex;gap:6px;margin-top:10px}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;display:none;align-items:center;justify-content:center}
.modal-bg.show{display:flex}
.modal{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:24px;width:560px;max-width:95vw;max-height:90vh;overflow-y:auto}
.modal h3{margin-bottom:16px;color:#c9d1d9}
.tab-bar{display:flex;gap:2px;margin-bottom:16px;background:#0d1117;border-radius:8px;padding:3px}
.tab-btn{flex:1;padding:8px;text-align:center;border:none;background:transparent;color:#8b949e;cursor:pointer;border-radius:6px;font-size:.82rem;font-weight:600;transition:.15s}
.tab-btn.active{background:#21262d;color:#e1e4e8}
.tab-content{display:none}.tab-content.active{display:block}
.ami-card{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:12px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center}
.ami-card .ami-info{flex:1}
.ami-card .ami-name{font-weight:600;font-size:.88rem}
.ami-card .ami-meta{font-size:.75rem;color:#8b949e;margin-top:2px}
.inst-row{display:grid;grid-template-columns:auto 1fr auto auto auto auto auto;gap:12px;align-items:center;padding:10px 12px;border-bottom:1px solid #21262d}
.inst-row:last-child{border-bottom:none}
.state-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.state-dot.running{background:#3fb950}.state-dot.stopped{background:#f85149}.state-dot.pending{background:#d29922}.state-dot.terminated{background:#484f58}
.state-dot.RUNNING{background:#3fb950}.state-dot.TERMINATED{background:#484f58}.state-dot.STAGING{background:#d29922}.state-dot.STOPPED{background:#f85149}.state-dot.SUSPENDED{background:#d29922}
.provider-bar{display:flex;gap:2px;margin-bottom:18px;background:#0d1117;border-radius:8px;padding:3px;max-width:320px}
.provider-btn{flex:1;padding:10px 16px;text-align:center;border:none;background:transparent;color:#8b949e;cursor:pointer;border-radius:6px;font-size:.88rem;font-weight:600;transition:.15s}
.provider-btn.active{background:#21262d;color:#e1e4e8}
.provider-content{display:none}.provider-content.active{display:block}
.gcp-msg{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:40px;text-align:center;color:#8b949e;font-size:.92rem}
</style>
</head><body>
""" + nav("cloud") + """
<div class="container">
<div class="provider-bar">
    <button class="provider-btn active" onclick="switchProvider('aws')">AWS EC2</button>
    <button class="provider-btn" onclick="switchProvider('gcp')">Google Cloud</button>
</div>

<!-- ═══ AWS Provider Tab ═══ -->
<div id="provider-aws" class="provider-content active">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
    <h1 style="font-size:1.2rem;color:#c9d1d9">AWS EC2 Media Instances</h1>
    <div style="display:flex;gap:8px;align-items:center">
        <select id="ec2-region" style="padding:5px 8px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#8b949e;font-size:.82rem" onchange="loadAll()">
            <option value="">Default Region</option>
            <option value="us-east-1">US East (Virginia)</option>
            <option value="us-east-2">US East (Ohio)</option>
            <option value="us-west-1">US West (California)</option>
            <option value="us-west-2">US West (Oregon)</option>
            <option value="eu-west-1">EU (Ireland)</option>
            <option value="eu-west-2">EU (London)</option>
            <option value="eu-central-1">EU (Frankfurt)</option>
            <option value="ap-southeast-1">AP (Singapore)</option>
            <option value="ap-southeast-2">AP (Sydney)</option>
            <option value="ap-northeast-1">AP (Tokyo)</option>
        </select>
        <button class="btn" onclick="loadAll()">Refresh</button>
    </div>
</div>

<!-- Summary Cards -->
<div class="cards" id="cloud-summary"></div>

<!-- Tabs -->
<div class="tab-bar">
    <button class="tab-btn active" onclick="showTab('templates')">Templates</button>
    <button class="tab-btn" onclick="showTab('instances')">Running Instances</button>
    <button class="tab-btn" onclick="showTab('amis')">AMI Library</button>
</div>

<!-- Templates Tab -->
<div id="tab-templates" class="tab-content active">
<div class="panel">
    <h3>Linux Media Templates</h3>
    <p style="font-size:.78rem;color:#8b949e;margin-bottom:12px">Pre-configured EC2 instances for broadcast and media workloads</p>
    <div class="tpl-grid" id="linux-templates"></div>
</div>
<div class="panel">
    <h3>Windows Media Templates</h3>
    <p style="font-size:.78rem;color:#8b949e;margin-bottom:12px">Windows Server 2022 instances for broadcast software</p>
    <div class="tpl-grid" id="windows-templates"></div>
</div>
</div>

<!-- Instances Tab -->
<div id="tab-instances" class="tab-content">
<div class="panel">
    <h3>Dashboard-Managed EC2 Instances</h3>
    <div id="instances-list"><div style="text-align:center;padding:20px;color:#8b949e">Loading...</div></div>
</div>
</div>

<!-- AMIs Tab -->
<div id="tab-amis" class="tab-content">
<div class="panel">
    <h3>Custom AMI Library</h3>
    <p style="font-size:.78rem;color:#8b949e;margin-bottom:12px">AMIs created from your media instances</p>
    <div id="ami-list"><div style="text-align:center;padding:20px;color:#8b949e">Loading...</div></div>
</div>
</div>

<!-- Launch Modal -->
<div id="launch-modal" class="modal-bg" onclick="if(event.target===this)closeLaunchModal()">
<div class="modal">
    <h3 id="launch-title">Launch EC2 Instance</h3>
    <input type="hidden" id="launch-tpl-id">
    <div class="field"><label>Instance Name</label><input type="text" id="launch-name" placeholder="my-encoder"></div>
    <div class="field"><label>Template</label><input type="text" id="launch-tpl-name" disabled style="opacity:.7"></div>
    <div class="grid2">
        <div class="field"><label>Instance Type</label><input type="text" id="launch-type" placeholder="auto from template"></div>
        <div class="field"><label>Region</label><select id="launch-region">
            <option value="">Default</option>
            <option value="us-east-1">us-east-1</option><option value="us-east-2">us-east-2</option>
            <option value="us-west-1">us-west-1</option><option value="us-west-2">us-west-2</option>
            <option value="eu-west-1">eu-west-1</option><option value="eu-west-2">eu-west-2</option>
            <option value="eu-central-1">eu-central-1</option>
            <option value="ap-southeast-1">ap-southeast-1</option><option value="ap-northeast-1">ap-northeast-1</option>
        </select></div>
    </div>
    <div class="grid2">
        <div class="field"><label>Key Pair</label><select id="launch-key"><option value="">None (no SSH)</option></select></div>
        <div class="field"><label>Security Group</label><select id="launch-sg"><option value="">Default VPC SG</option></select></div>
    </div>
    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px">
        <button class="btn" onclick="closeLaunchModal()">Cancel</button>
        <button class="btn p" onclick="doLaunch(false)">Launch</button>
        <button class="btn" style="background:#1f6feb;border-color:#388bfd;color:#fff" onclick="doLaunch(true)">Launch & Build AMI</button>
    </div>
</div>
</div>

<!-- Create AMI Modal -->
<div id="ami-modal" class="modal-bg" onclick="if(event.target===this)closeAmiModal()">
<div class="modal">
    <h3>Create AMI</h3>
    <input type="hidden" id="ami-inst-id">
    <div class="field"><label>Source Instance</label><input type="text" id="ami-inst-name" disabled style="opacity:.7"></div>
    <div class="field"><label>AMI Name</label><input type="text" id="ami-name" placeholder="my-encoder-ami-v1"></div>
    <div class="field"><label>Description (optional)</label><input type="text" id="ami-desc" placeholder="Pre-configured video encoder"></div>
    <p style="font-size:.78rem;color:#d29922;margin-top:8px">The instance will be stopped during AMI creation.</p>
    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px">
        <button class="btn" onclick="closeAmiModal()">Cancel</button>
        <button class="btn p" onclick="doCreateAmi()">Create AMI</button>
    </div>
</div>
</div>

</div><!-- /provider-aws -->

<!-- ═══ GCP Provider Tab ═══ -->
<div id="provider-gcp" class="provider-content">
<div id="gcp-unavailable" class="gcp-msg" style="display:none">
    <div style="font-size:1.4rem;margin-bottom:8px;filter:grayscale(1)">&#9729;</div>
    <div style="font-weight:600;color:#c9d1d9;margin-bottom:4px">GCP not configured</div>
    <div>Add your service account JSON in <a href="/settings" style="color:#58a6ff">Settings</a>.</div>
</div>
<div id="gcp-content" style="display:none">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
    <h1 style="font-size:1.2rem;color:#c9d1d9">Google Cloud Platform</h1>
    <button class="btn" onclick="loadAllGcp()">Refresh</button>
</div>

<!-- GCP Summary -->
<div class="cards" id="gcp-summary"></div>

<!-- GCP Sub-tabs -->
<div class="tab-bar" id="gcp-tab-bar">
    <button class="tab-btn active" onclick="showGcpTab('gce-tpl')">GCE Templates</button>
    <button class="tab-btn" onclick="showGcpTab('gce-inst')">GCE Instances</button>
    <button class="tab-btn" onclick="showGcpTab('gke')">GKE Clusters</button>
    <button class="tab-btn" onclick="showGcpTab('run')">Cloud Run</button>
    <button class="tab-btn" onclick="showGcpTab('gcs')">GCS Buckets</button>
</div>

<!-- GCE Templates Tab -->
<div id="gtab-gce-tpl" class="tab-content active">
<div class="panel">
    <h3>GCE Media Templates</h3>
    <p style="font-size:.78rem;color:#8b949e;margin-bottom:12px">Pre-configured Compute Engine instances for media workloads</p>
    <div class="tpl-grid" id="gce-templates"></div>
</div>
</div>

<!-- GCE Instances Tab -->
<div id="gtab-gce-inst" class="tab-content">
<div class="panel">
    <h3>Compute Engine Instances</h3>
    <div id="gce-instances-list"><div style="text-align:center;padding:20px;color:#8b949e">Loading...</div></div>
</div>
</div>

<!-- GKE Clusters Tab -->
<div id="gtab-gke" class="tab-content">
<div class="panel">
    <h3>GKE Clusters</h3>
    <div id="gke-clusters-list"><div style="text-align:center;padding:20px;color:#8b949e">Loading...</div></div>
</div>
</div>

<!-- Cloud Run Tab -->
<div id="gtab-run" class="tab-content">
<div class="panel">
    <h3>Cloud Run Services</h3>
    <div id="cloud-run-list"><div style="text-align:center;padding:20px;color:#8b949e">Loading...</div></div>
</div>
</div>

<!-- GCS Buckets Tab -->
<div id="gtab-gcs" class="tab-content">
<div class="panel">
    <h3>Cloud Storage Buckets</h3>
    <div id="gcs-buckets-list"><div style="text-align:center;padding:20px;color:#8b949e">Loading...</div></div>
</div>
</div>

<!-- GCE Launch Modal -->
<div id="gce-launch-modal" class="modal-bg" onclick="if(event.target===this)closeGceLaunchModal()">
<div class="modal">
    <h3>Launch GCE Instance</h3>
    <input type="hidden" id="gce-launch-tpl-id">
    <div class="field"><label>Instance Name</label><input type="text" id="gce-launch-name" placeholder="my-encoder"></div>
    <div class="field"><label>Template</label><input type="text" id="gce-launch-tpl-name" disabled style="opacity:.7"></div>
    <div class="grid2">
        <div class="field"><label>Machine Type</label><input type="text" id="gce-launch-machine" placeholder="n2-standard-8"></div>
        <div class="field"><label>Zone</label><select id="gce-launch-zone">
            <option value="us-central1-a">us-central1-a</option><option value="us-central1-b">us-central1-b</option>
            <option value="us-east1-b">us-east1-b</option><option value="us-east1-c">us-east1-c</option>
            <option value="us-west1-a">us-west1-a</option><option value="us-west1-b">us-west1-b</option>
            <option value="europe-west1-b">europe-west1-b</option><option value="europe-west1-c">europe-west1-c</option>
            <option value="asia-east1-a">asia-east1-a</option><option value="asia-east1-b">asia-east1-b</option>
        </select></div>
    </div>
    <div class="grid2">
        <div class="field"><label>Image Project</label><input type="text" id="gce-launch-img-proj" value="ubuntu-os-cloud"></div>
        <div class="field"><label>Image Family</label><input type="text" id="gce-launch-img-fam" value="ubuntu-2204-lts"></div>
    </div>
    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px">
        <button class="btn" onclick="closeGceLaunchModal()">Cancel</button>
        <button class="btn p" onclick="doGceLaunch()">Launch</button>
    </div>
</div>
</div>

</div><!-- /gcp-content -->
</div><!-- /provider-gcp -->

</div>
<div id="toast" class="toast"></div>

<script>
const _GCP_AVAILABLE=""" + ("true" if _GCP_AVAILABLE else "false") + """;
function toast(m,t='info'){const e=document.getElementById('toast');e.textContent=m;e.className='toast '+t+' show';setTimeout(()=>e.classList.remove('show'),3000)}
function bg(t,c){return `<span class="badge ${esc(c)}">${esc(t)}</span>`}
function getRegion(){return document.getElementById('ec2-region').value||''}

function switchProvider(p){
    document.querySelectorAll('.provider-btn').forEach(b=>b.classList.toggle('active',b.textContent.toLowerCase().includes(p==='aws'?'aws':'google')));
    document.querySelectorAll('.provider-content').forEach(el=>el.classList.remove('active'));
    document.getElementById('provider-'+p).classList.add('active');
    if(p==='gcp'){initGcp()}
}
function showTab(name){
    const bar=document.getElementById('provider-aws');
    bar.querySelectorAll('.tab-btn').forEach((b,i)=>b.classList.toggle('active',b.textContent.toLowerCase().includes(name.substring(0,4))));
    ['tab-templates','tab-instances','tab-amis'].forEach(id=>{document.getElementById(id).classList.remove('active')});
    document.getElementById('tab-'+name).classList.add('active');
}

// ── Templates ──
async function loadTemplates(){
    const r=await fetch('/api/cloud/ec2/templates');
    const d=await r.json();
    document.getElementById('linux-templates').innerHTML=(d.linux||[]).map(t=>`
        <div class="tpl-card">
            <div class="tname">${esc(t.name)}</div>
            <div class="tdesc">${esc(t.description)}</div>
            <div class="tmeta">
                ${bg(t.instance_type,'info')}
                ${bg(t.category,'off')}
            </div>
            <div class="tpl-actions">
                <button class="btn sm p" onclick="showLaunchModal('${esc(t.id)}','${esc(t.name)}','${esc(t.instance_type)}')">Launch</button>
                <button class="btn sm" onclick="showLaunchModal('${esc(t.id)}','${esc(t.name)}','${esc(t.instance_type)}',true)">Build AMI</button>
            </div>
        </div>`).join('');
    document.getElementById('windows-templates').innerHTML=(d.windows||[]).map(t=>`
        <div class="tpl-card">
            <div class="tname">${esc(t.name)}</div>
            <div class="tdesc">${esc(t.description)}</div>
            <div class="tmeta">
                ${bg(t.instance_type,'info')}
                ${bg('Windows','warn')}
                ${bg(t.category,'off')}
            </div>
            <div class="tpl-actions">
                <button class="btn sm p" onclick="showLaunchModal('${esc(t.id)}','${esc(t.name)}','${esc(t.instance_type)}')">Launch</button>
                <button class="btn sm" onclick="showLaunchModal('${esc(t.id)}','${esc(t.name)}','${esc(t.instance_type)}',true)">Build AMI</button>
            </div>
        </div>`).join('');
}

// ── Launch Modal ──
async function showLaunchModal(tplId,tplName,instanceType,buildAmi){
    document.getElementById('launch-tpl-id').value=tplId;
    document.getElementById('launch-tpl-name').value=tplName;
    document.getElementById('launch-type').value=instanceType;
    document.getElementById('launch-name').value='';
    document.getElementById('launch-title').textContent=buildAmi?'Launch & Build AMI':'Launch EC2 Instance';
    // Load VPC info
    try{
        const region=getRegion();
        const r=await fetch('/api/cloud/ec2/vpc-info'+(region?'?region='+region:''));
        const d=await r.json();
        const kSel=document.getElementById('launch-key');
        kSel.innerHTML='<option value="">None (no SSH)</option>';
        (d.key_pairs||[]).forEach(k=>{kSel.innerHTML+=`<option value="${esc(k.name)}">${esc(k.name)}</option>`});
        const sgSel=document.getElementById('launch-sg');
        sgSel.innerHTML='<option value="">Default VPC SG</option>';
        (d.security_groups||[]).forEach(sg=>{sgSel.innerHTML+=`<option value="${esc(sg.id)}">${esc(sg.name)} (${esc(sg.id)})</option>`});
    }catch(e){console.error('VPC info load failed',e)}
    document.getElementById('launch-modal').classList.add('show');
}
function closeLaunchModal(){document.getElementById('launch-modal').classList.remove('show')}

async function doLaunch(buildAmi){
    const body={
        template_id:document.getElementById('launch-tpl-id').value,
        instance_name:document.getElementById('launch-name').value,
        instance_type:document.getElementById('launch-type').value||undefined,
        region:document.getElementById('launch-region').value||undefined,
        key_name:document.getElementById('launch-key').value||undefined,
        security_group_id:document.getElementById('launch-sg').value||undefined,
        build_ami:!!buildAmi,
    };
    toast('Launching instance...','info');
    closeLaunchModal();
    try{
        const url=buildAmi?'/api/cloud/ec2/ami/build':'/api/cloud/ec2/launch';
        const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
        const d=await r.json();
        if(d.ok){toast(d.message||'Instance launched','success');loadInstances()}
        else{toast('Launch failed: '+(d.error||'unknown'),'error')}
    }catch(e){toast('Launch error: '+e.message,'error')}
}

// ── Instances ──
async function loadInstances(){
    const region=getRegion();
    try{
        const r=await fetch('/api/cloud/ec2/instances'+(region?'?region='+region:''));
        const d=await r.json();
        const insts=d.instances||[];
        if(!insts.length){
            document.getElementById('instances-list').innerHTML='<div style="text-align:center;padding:30px;color:#8b949e">No dashboard-managed instances found. Launch one from the Templates tab.</div>';
            updateSummary(0,0,0);
            return;
        }
        const running=insts.filter(i=>i.state==='running').length;
        const stopped=insts.filter(i=>i.state==='stopped').length;
        const builders=insts.filter(i=>i.ami_builder).length;
        updateSummary(insts.length,running,builders);

        document.getElementById('instances-list').innerHTML=`
            <table><thead><tr><th>State</th><th>Name</th><th>ID</th><th>Type</th><th>IP</th><th>Template</th><th>AMI Builder</th><th>Actions</th></tr></thead>
            <tbody>${insts.map(i=>`<tr>
                <td><span class="state-dot ${i.state}" style="display:inline-block;margin-right:6px"></span>${bg(i.state,i.state==='running'?'ok':i.state==='stopped'?'error':'warn')}</td>
                <td><b>${esc(i.name)}</b></td>
                <td style="font-family:monospace;font-size:.78rem">${esc(i.instance_id)}</td>
                <td>${esc(i.instance_type)}</td>
                <td style="font-family:monospace;font-size:.78rem">${esc(i.public_ip||i.private_ip||'—')}</td>
                <td>${bg(i.template_id||'custom','info')}</td>
                <td>${i.ami_builder?bg('AMI BUILD','warn'):'—'}</td>
                <td style="white-space:nowrap">
                    ${i.state==='stopped'?`<button class="btn sm" onclick="instAction('${i.instance_id}','start','${i.region}')">Start</button>`:''}
                    ${i.state==='running'?`<button class="btn sm" onclick="instAction('${i.instance_id}','stop','${i.region}')">Stop</button>`:''}
                    ${i.state==='running'?`<button class="btn sm" onclick="instAction('${i.instance_id}','reboot','${i.region}')">Reboot</button>`:''}
                    ${i.state==='running'||i.state==='stopped'?`<button class="btn sm" onclick="showAmiModal('${i.instance_id}','${esc(i.name)}')">Create AMI</button>`:''}
                    <button class="btn sm d" onclick="instAction('${i.instance_id}','terminate','${i.region}')">Terminate</button>
                </td>
            </tr>`).join('')}</tbody></table>`;
    }catch(e){
        document.getElementById('instances-list').innerHTML='<div style="color:#f85149;padding:20px">Failed to load instances: '+esc(e.message)+'</div>';
    }
}

function updateSummary(total,running,builders){
    document.getElementById('cloud-summary').innerHTML=`
        <div class="card"><div class="lb">EC2 Instances</div><div class="vl blue">${total}</div></div>
        <div class="card"><div class="lb">Running</div><div class="vl green">${running}</div></div>
        <div class="card"><div class="lb">AMI Builders</div><div class="vl yellow">${builders}</div></div>
        <div class="card"><div class="lb">Templates</div><div class="vl" style="color:#8b949e">${document.querySelectorAll('.tpl-card').length}</div></div>`;
}

async function instAction(id,action,region){
    if(action==='terminate'&&!confirm('Terminate instance '+id+'? This cannot be undone.'))return;
    toast(action+'ing '+id+'...','info');
    try{
        const r=await fetch('/api/cloud/ec2/'+id+'/action',{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({action,region})});
        const d=await r.json();
        toast(d.ok?(d.message||'Done'):'Error: '+(d.error||'unknown'),d.ok?'success':'error');
        setTimeout(loadInstances,2000);
    }catch(e){toast('Error: '+e.message,'error')}
}

// ── AMI Modal ──
function showAmiModal(instId,instName){
    document.getElementById('ami-inst-id').value=instId;
    document.getElementById('ami-inst-name').value=instName+' ('+instId+')';
    document.getElementById('ami-name').value='';
    document.getElementById('ami-desc').value='';
    document.getElementById('ami-modal').classList.add('show');
}
function closeAmiModal(){document.getElementById('ami-modal').classList.remove('show')}

async function doCreateAmi(){
    const instId=document.getElementById('ami-inst-id').value;
    const name=document.getElementById('ami-name').value.trim();
    if(!name){toast('AMI name is required','error');return}
    toast('Creating AMI (instance will be stopped)...','info');
    closeAmiModal();
    try{
        const r=await fetch('/api/cloud/ec2/ami/create',{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({instance_id:instId,name,description:document.getElementById('ami-desc').value,region:getRegion()||undefined})});
        const d=await r.json();
        toast(d.ok?(d.message||'AMI created'):'Error: '+(d.error||'unknown'),d.ok?'success':'error');
        loadInstances();loadAmis();
    }catch(e){toast('Error: '+e.message,'error')}
}

// ── AMI Library ──
async function loadAmis(){
    const region=getRegion();
    try{
        const r=await fetch('/api/cloud/ec2/amis'+(region?'?region='+region:''));
        const d=await r.json();
        const amis=d.amis||[];
        if(!amis.length){
            document.getElementById('ami-list').innerHTML='<div style="text-align:center;padding:30px;color:#8b949e">No custom AMIs found. Create one from a running instance.</div>';
            return;
        }
        document.getElementById('ami-list').innerHTML=amis.map(a=>`
            <div class="ami-card">
                <div class="ami-info">
                    <div class="ami-name">${esc(a.name)}</div>
                    <div class="ami-meta">
                        <span style="font-family:monospace">${esc(a.ami_id)}</span>
                        · ${bg(a.state,a.state==='available'?'ok':'warn')}
                        ${a.dashboard_managed?bg('managed','info'):''}
                        ${a.source_template?bg(a.source_template,'off'):''}
                        · Created: ${a.created?new Date(a.created).toLocaleDateString():'—'}
                    </div>
                    ${a.description?`<div style="font-size:.75rem;color:#484f58;margin-top:2px">${esc(a.description)}</div>`:''}
                </div>
                <div style="display:flex;gap:6px">
                    <button class="btn sm p" onclick="showLaunchFromAmi('${a.ami_id}','${esc(a.name)}')">Launch</button>
                    <button class="btn sm d" onclick="deregAmi('${a.ami_id}','${esc(a.name)}')">Deregister</button>
                </div>
            </div>`).join('');
    }catch(e){
        document.getElementById('ami-list').innerHTML='<div style="color:#f85149;padding:20px">Failed to load AMIs: '+esc(e.message)+'</div>';
    }
}

function showLaunchFromAmi(amiId,amiName){
    toast('To launch from a custom AMI, use the AWS console or CLI with AMI ID: '+amiId,'info');
}

async function deregAmi(amiId,name){
    if(!confirm('Deregister AMI '+name+' ('+amiId+')? This will also delete associated snapshots.'))return;
    toast('Deregistering AMI...','info');
    try{
        const r=await fetch('/api/cloud/ec2/ami/'+amiId+'/deregister',{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({region:getRegion()||undefined})});
        const d=await r.json();
        toast(d.ok?(d.message||'AMI deregistered'):'Error: '+(d.error||'unknown'),d.ok?'success':'error');
        loadAmis();
    }catch(e){toast('Error: '+e.message,'error')}
}

// ── GCP Functions ──
let _gcpInited=false;
function initGcp(){
    if(_gcpInited)return;_gcpInited=true;
    if(!_GCP_AVAILABLE){document.getElementById('gcp-unavailable').style.display='block';document.getElementById('gcp-content').style.display='none';return}
    document.getElementById('gcp-unavailable').style.display='none';document.getElementById('gcp-content').style.display='block';
    loadAllGcp();
}
function showGcpTab(name){
    const bar=document.getElementById('gcp-tab-bar');
    bar.querySelectorAll('.tab-btn').forEach(b=>{const n=b.getAttribute('onclick')||'';b.classList.toggle('active',n.includes("'"+name+"'"))});
    ['gtab-gce-tpl','gtab-gce-inst','gtab-gke','gtab-run','gtab-gcs'].forEach(id=>{document.getElementById(id).classList.remove('active')});
    document.getElementById('gtab-'+name).classList.add('active');
}
function updateGcpSummary(gce,gke,run,gcs){
    document.getElementById('gcp-summary').innerHTML=`
        <div class="card"><div class="lb">GCE Instances</div><div class="vl blue">${gce}</div></div>
        <div class="card"><div class="lb">GKE Clusters</div><div class="vl green">${gke}</div></div>
        <div class="card"><div class="lb">Cloud Run</div><div class="vl yellow">${run}</div></div>
        <div class="card"><div class="lb">GCS Buckets</div><div class="vl" style="color:#8b949e">${gcs}</div></div>`;
}
async function loadGceTemplates(){
    try{
        const r=await fetch('/api/cloud/gcp/templates');const d=await r.json();
        document.getElementById('gce-templates').innerHTML=(d.templates||[]).map(t=>`
            <div class="tpl-card">
                <div class="tname">${esc(t.name)}</div>
                <div class="tdesc">${esc(t.description)}</div>
                <div class="tmeta">${bg(t.machine_type,'info')}</div>
                <div class="tpl-actions">
                    <button class="btn sm p" onclick="showGceLaunchModal('${esc(t.id)}','${esc(t.name)}','${esc(t.machine_type)}')">Launch</button>
                </div>
            </div>`).join('')||'<div style="color:#8b949e;padding:12px">No templates available.</div>';
    }catch(e){document.getElementById('gce-templates').innerHTML='<div style="color:#f85149;padding:12px">Failed: '+esc(e.message)+'</div>'}
}
async function loadGceInstances(){
    try{
        const r=await fetch('/api/cloud/gcp/instances');const d=await r.json();
        const items=d.items||[];
        if(!items.length){document.getElementById('gce-instances-list').innerHTML='<div style="text-align:center;padding:30px;color:#8b949e">No GCE instances found.</div>';return items.length}
        document.getElementById('gce-instances-list').innerHTML=`
            <table><thead><tr><th>Status</th><th>Name</th><th>Zone</th><th>Machine Type</th><th>IP</th><th>Actions</th></tr></thead>
            <tbody>${items.map(i=>`<tr>
                <td><span class="state-dot ${i.status}" style="display:inline-block;margin-right:6px"></span>${bg(i.status,i.status==='RUNNING'?'ok':i.status==='TERMINATED'?'error':'warn')}</td>
                <td><b>${esc(i.name)}</b></td>
                <td>${esc(i.zone)}</td>
                <td>${esc(i.machine_type)}</td>
                <td style="font-family:monospace;font-size:.78rem">${esc(i.external_ip||i.internal_ip||'—')}</td>
                <td style="white-space:nowrap">
                    ${i.status==='TERMINATED'||i.status==='STOPPED'?`<button class="btn sm" onclick="gcpInstAction('${esc(i.name)}','start','${esc(i.zone)}')">Start</button>`:''}
                    ${i.status==='RUNNING'?`<button class="btn sm" onclick="gcpInstAction('${esc(i.name)}','stop','${esc(i.zone)}')">Stop</button>`:''}
                    ${i.status==='RUNNING'?`<button class="btn sm" onclick="gcpInstAction('${esc(i.name)}','reset','${esc(i.zone)}')">Reset</button>`:''}
                </td>
            </tr>`).join('')}</tbody></table>`;
        return items.length;
    }catch(e){document.getElementById('gce-instances-list').innerHTML='<div style="color:#f85149;padding:20px">Failed: '+esc(e.message)+'</div>';return 0}
}
async function loadGkeClusters(){
    try{
        const r=await fetch('/api/cloud/gcp/clusters');const d=await r.json();
        const items=d.items||[];
        if(!items.length){document.getElementById('gke-clusters-list').innerHTML='<div style="text-align:center;padding:30px;color:#8b949e">No GKE clusters found.</div>';return items.length}
        document.getElementById('gke-clusters-list').innerHTML=`
            <table><thead><tr><th>Status</th><th>Name</th><th>Location</th><th>Node Count</th><th>Version</th></tr></thead>
            <tbody>${items.map(i=>`<tr>
                <td>${bg(i.status,i.status==='RUNNING'?'ok':'warn')}</td>
                <td><b>${esc(i.name)}</b></td>
                <td>${esc(i.location)}</td>
                <td>${i.node_count}</td>
                <td style="font-family:monospace;font-size:.78rem">${esc(i.current_master_version)}</td>
            </tr>`).join('')}</tbody></table>`;
        return items.length;
    }catch(e){document.getElementById('gke-clusters-list').innerHTML='<div style="color:#f85149;padding:20px">Failed: '+esc(e.message)+'</div>';return 0}
}
async function loadCloudRun(){
    try{
        const r=await fetch('/api/cloud/gcp/cloud-run');const d=await r.json();
        const items=d.items||[];
        if(!items.length){document.getElementById('cloud-run-list').innerHTML='<div style="text-align:center;padding:30px;color:#8b949e">No Cloud Run services found.</div>';return items.length}
        document.getElementById('cloud-run-list').innerHTML=`
            <table><thead><tr><th>Status</th><th>Name</th><th>Region</th><th>URL</th></tr></thead>
            <tbody>${items.map(i=>`<tr>
                <td>${bg(i.condition_status,i.condition_status==='CONDITION_SUCCEEDED'?'ok':'warn')}</td>
                <td><b>${esc(i.name)}</b></td>
                <td>${esc(i.region)}</td>
                <td style="font-size:.78rem">${i.url&&/^https?:\/\//i.test(i.url)?`<a href="${esc(i.url)}" target="_blank" style="color:#58a6ff">${esc(i.url)}</a>`:'—'}</td>
            </tr>`).join('')}</tbody></table>`;
        return items.length;
    }catch(e){document.getElementById('cloud-run-list').innerHTML='<div style="color:#f85149;padding:20px">Failed: '+esc(e.message)+'</div>';return 0}
}
async function loadGcsBuckets(){
    try{
        const r=await fetch('/api/cloud/gcp/buckets');const d=await r.json();
        const items=d.items||[];
        if(!items.length){document.getElementById('gcs-buckets-list').innerHTML='<div style="text-align:center;padding:30px;color:#8b949e">No GCS buckets found.</div>';return items.length}
        document.getElementById('gcs-buckets-list').innerHTML=`
            <table><thead><tr><th>Name</th><th>Location</th><th>Storage Class</th><th>Versioning</th></tr></thead>
            <tbody>${items.map(i=>`<tr>
                <td><b>${esc(i.name)}</b></td>
                <td>${esc(i.location)}</td>
                <td>${bg(i.storage_class,'info')}</td>
                <td>${i.versioning_enabled?bg('ON','ok'):bg('OFF','off')}</td>
            </tr>`).join('')}</tbody></table>`;
        return items.length;
    }catch(e){document.getElementById('gcs-buckets-list').innerHTML='<div style="color:#f85149;padding:20px">Failed: '+esc(e.message)+'</div>';return 0}
}
async function gcpInstAction(name,action,zone){
    if(action==='delete'&&!confirm('Delete instance '+name+'? This cannot be undone.'))return;
    toast(action+'ing '+name+'...','info');
    try{
        const r=await fetch('/api/cloud/gcp/'+encodeURIComponent(name)+'/action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action,zone})});
        const d=await r.json();
        toast(d.ok?(d.message||'Done'):'Error: '+(d.error||'unknown'),d.ok?'success':'error');
        setTimeout(loadGceInstances,2000);
    }catch(e){toast('Error: '+e.message,'error')}
}
function showGceLaunchModal(tplId,tplName,machineType){
    document.getElementById('gce-launch-tpl-id').value=tplId;
    document.getElementById('gce-launch-tpl-name').value=tplName;
    document.getElementById('gce-launch-machine').value=machineType;
    document.getElementById('gce-launch-name').value='';
    document.getElementById('gce-launch-modal').classList.add('show');
}
function closeGceLaunchModal(){document.getElementById('gce-launch-modal').classList.remove('show')}
async function doGceLaunch(){
    const body={
        name:document.getElementById('gce-launch-name').value.trim(),
        zone:document.getElementById('gce-launch-zone').value,
        machine_type:document.getElementById('gce-launch-machine').value.trim(),
        image_project:document.getElementById('gce-launch-img-proj').value.trim(),
        image_family:document.getElementById('gce-launch-img-fam').value.trim(),
    };
    if(!body.name){toast('Instance name is required','error');return}
    toast('Launching GCE instance...','info');
    closeGceLaunchModal();
    try{
        const r=await fetch('/api/cloud/gcp/launch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
        const d=await r.json();
        if(d.ok){toast(d.message||'Instance launched','success');loadGceInstances()}
        else{toast('Launch failed: '+(d.error||'unknown'),'error')}
    }catch(e){toast('Launch error: '+e.message,'error')}
}
async function loadAllGcp(){
    const [gce,gke,run,gcs]=await Promise.all([loadGceInstances(),loadGkeClusters(),loadCloudRun(),loadGcsBuckets()]);
    updateGcpSummary(gce||0,gke||0,run||0,gcs||0);
    loadGceTemplates();
}

// ── Init ──
async function loadAll(){
    await Promise.all([loadTemplates(),loadInstances(),loadAmis()]);
}
loadAll();
</script></body></html>""")


# ═════════════════════════════════════════════════════════════════════════════
# 4. SETTINGS PAGE
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/settings")
def page_settings():
    return render_template_string("""<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Settings — AWS Video Dashboard</title>""" + SHARED_STYLES + """</head><body>
""" + nav("settings") + """
<div class="container">
<h1 style="font-size:1.2rem;color:#c9d1d9;margin-bottom:16px">Settings</h1>
<div class="grid2">

<!-- AWS -->
<div class="panel"><h3>AWS</h3>
    <div class="field"><label>Regions</label><div id="aws-regions" style="display:grid;grid-template-columns:1fr 1fr;gap:2px">
        <label style="font-size:.82rem;padding:3px 0"><input type="checkbox" value="us-east-1"> US East (Virginia)</label>
        <label style="font-size:.82rem;padding:3px 0"><input type="checkbox" value="us-east-2"> US East (Ohio)</label>
        <label style="font-size:.82rem;padding:3px 0"><input type="checkbox" value="us-west-1"> US West (California)</label>
        <label style="font-size:.82rem;padding:3px 0"><input type="checkbox" value="us-west-2"> US West (Oregon)</label>
        <label style="font-size:.82rem;padding:3px 0"><input type="checkbox" value="ca-central-1"> Canada (Central)</label>
        <label style="font-size:.82rem;padding:3px 0"><input type="checkbox" value="eu-west-1"> EU (Ireland)</label>
        <label style="font-size:.82rem;padding:3px 0"><input type="checkbox" value="eu-west-2"> EU (London)</label>
        <label style="font-size:.82rem;padding:3px 0"><input type="checkbox" value="eu-west-3"> EU (Paris)</label>
        <label style="font-size:.82rem;padding:3px 0"><input type="checkbox" value="eu-central-1"> EU (Frankfurt)</label>
        <label style="font-size:.82rem;padding:3px 0"><input type="checkbox" value="eu-north-1"> EU (Stockholm)</label>
        <label style="font-size:.82rem;padding:3px 0"><input type="checkbox" value="ap-south-1"> AP (Mumbai)</label>
        <label style="font-size:.82rem;padding:3px 0"><input type="checkbox" value="ap-southeast-1"> AP (Singapore)</label>
        <label style="font-size:.82rem;padding:3px 0"><input type="checkbox" value="ap-southeast-2"> AP (Sydney)</label>
        <label style="font-size:.82rem;padding:3px 0"><input type="checkbox" value="ap-northeast-1"> AP (Tokyo)</label>
        <label style="font-size:.82rem;padding:3px 0"><input type="checkbox" value="ap-northeast-2"> AP (Seoul)</label>
        <label style="font-size:.82rem;padding:3px 0"><input type="checkbox" value="sa-east-1"> SA (São Paulo)</label>
        <label style="font-size:.82rem;padding:3px 0"><input type="checkbox" value="me-south-1"> ME (Bahrain)</label>
        <label style="font-size:.82rem;padding:3px 0"><input type="checkbox" value="af-south-1"> Africa (Cape Town)</label>
    </div></div>
    <div class="field"><label>Access Key</label><input type="text" id="aws-key" placeholder="AKIA..."><div class="hint">Blank = use instance role / ~/.aws/credentials</div></div>
    <div class="field"><label>Secret Key</label><input type="password" id="aws-secret"></div>
</div>

<!-- Monitoring -->
<div class="panel"><h3>Monitoring</h3>
    <div class="grid2">
        <div class="field"><label>Check Interval</label><select id="m-int">
            <option value="10">10 seconds</option>
            <option value="30">30 seconds</option>
            <option value="60">1 minute</option>
            <option value="120">2 minutes</option>
            <option value="300" selected>5 minutes (default)</option>
            <option value="600">10 minutes</option>
            <option value="900">15 minutes</option>
            <option value="1800">30 minutes</option>
            <option value="3600">60 minutes</option>
        </select></div>
        <div class="field"><label>CPU Threshold (%)</label><input type="number" id="m-cpu" min="1" max="100" value="80"></div>
    </div>
    <div class="field"><label>Deploy Lookback (hrs)</label><input type="number" id="m-dep" min="1" max="168" value="24"></div>
    <div class="field"><label>EC2 Uptime Alert (hrs, 0=off)</label><input type="number" id="m-uptime" min="0" max="720" value="0"><small style="color:#8b949e;font-size:.72rem">Alert if EC2 running longer than this</small></div>
    <div style="margin-top:10px">
        <div style="font-size:.75rem;color:#8b949e;text-transform:uppercase;margin-bottom:8px">Infrastructure</div>
        <div class="toggle-row"><span style="font-size:.85rem">EC2</span><label class="switch"><input type="checkbox" id="m-ec2"><span class="slider"></span></label></div>
        <div class="toggle-row"><span style="font-size:.85rem">CodeDeploy</span><label class="switch"><input type="checkbox" id="m-cd"><span class="slider"></span></label></div>
        <div class="toggle-row"><span style="font-size:.85rem">ECS</span><label class="switch"><input type="checkbox" id="m-ecs"><span class="slider"></span></label></div>
        <div style="font-size:.75rem;color:#8b949e;text-transform:uppercase;margin:12px 0 8px">Video Engineering</div>
        <div class="toggle-row"><span style="font-size:.85rem">MediaLive</span><label class="switch"><input type="checkbox" id="m-ml"><span class="slider"></span></label></div>
        <div class="toggle-row"><span style="font-size:.85rem">MediaConnect</span><label class="switch"><input type="checkbox" id="m-mc"><span class="slider"></span></label></div>
        <div class="toggle-row"><span style="font-size:.85rem">MediaPackage</span><label class="switch"><input type="checkbox" id="m-mp"><span class="slider"></span></label></div>
        <div class="toggle-row"><span style="font-size:.85rem">CloudFront CDN</span><label class="switch"><input type="checkbox" id="m-cf"><span class="slider"></span></label></div>
        <div class="toggle-row"><span style="font-size:.85rem">IVS</span><label class="switch"><input type="checkbox" id="m-ivs"><span class="slider"></span></label></div>
        <div style="font-size:.75rem;color:#8b949e;text-transform:uppercase;margin:12px 0 8px">AWS Services</div>
        <div class="toggle-row"><span style="font-size:.85rem">RDS</span><label class="switch"><input type="checkbox" id="m-rds"><span class="slider"></span></label></div>
        <div class="toggle-row"><span style="font-size:.85rem">Lambda</span><label class="switch"><input type="checkbox" id="m-lam"><span class="slider"></span></label></div>
        <div class="toggle-row"><span style="font-size:.85rem">S3</span><label class="switch"><input type="checkbox" id="m-s3"><span class="slider"></span></label></div>
        <div class="toggle-row"><span style="font-size:.85rem">SQS</span><label class="switch"><input type="checkbox" id="m-sqs"><span class="slider"></span></label></div>
        <div class="toggle-row"><span style="font-size:.85rem">Route53</span><label class="switch"><input type="checkbox" id="m-r53"><span class="slider"></span></label></div>
        <div class="toggle-row"><span style="font-size:.85rem">API Gateway</span><label class="switch"><input type="checkbox" id="m-apigw"><span class="slider"></span></label></div>
        <div style="font-size:.75rem;color:#8b949e;text-transform:uppercase;margin:12px 0 8px">Networking</div>
        <div class="toggle-row"><span style="font-size:.85rem">VPCs</span><label class="switch"><input type="checkbox" id="m-vpc"><span class="slider"></span></label></div>
        <div class="toggle-row"><span style="font-size:.85rem">Load Balancers</span><label class="switch"><input type="checkbox" id="m-elb"><span class="slider"></span></label></div>
        <div class="toggle-row"><span style="font-size:.85rem">Elastic IPs</span><label class="switch"><input type="checkbox" id="m-eip"><span class="slider"></span></label></div>
        <div class="toggle-row"><span style="font-size:.85rem">NAT Gateways</span><label class="switch"><input type="checkbox" id="m-nat"><span class="slider"></span></label></div>
        <div class="toggle-row"><span style="font-size:.85rem">Security Groups</span><label class="switch"><input type="checkbox" id="m-sg"><span class="slider"></span></label></div>
        <div class="toggle-row"><span style="font-size:.85rem">VPN Connections</span><label class="switch"><input type="checkbox" id="m-vpn"><span class="slider"></span></label></div>
    </div>
</div>

<!-- Email -->
<div class="panel"><h3>Email</h3>
    <div class="toggle-row" style="margin-bottom:10px"><span style="font-size:.85rem">Enable Email</span><label class="switch"><input type="checkbox" id="e-on"><span class="slider"></span></label></div>
    <div class="field"><label>Provider</label><select id="e-prov" onchange="toggleSmtp()"><option value="smtp">SMTP</option><option value="ses">AWS SES</option></select></div>
    <div id="smtp-f">
        <div class="grid2"><div class="field"><label>SMTP Host</label><input type="text" id="e-host" placeholder="smtp.gmail.com"></div>
        <div class="field"><label>Port</label><input type="number" id="e-port" value="587"></div></div>
        <div class="field"><label>Username</label><input type="text" id="e-user"></div>
        <div class="field"><label>Password</label><input type="password" id="e-pass"><div class="hint">Gmail: use App Password</div></div>
        <div class="toggle-row"><span style="font-size:.85rem">TLS</span><label class="switch"><input type="checkbox" id="e-tls" checked><span class="slider"></span></label></div>
    </div>
    <div id="ses-f" style="display:none"><div class="field"><label>SES Region</label><input type="text" id="e-ses" placeholder="eu-west-2"></div></div>
    <div class="field"><label>From</label><input type="email" id="e-from"></div>
    <div class="field"><label>To (comma-sep)</label><input type="text" id="e-to"></div>
</div>

<!-- WhatsApp -->
<div class="panel"><h3>WhatsApp</h3>
    <div class="toggle-row" style="margin-bottom:10px"><span style="font-size:.85rem">Enable WhatsApp</span><label class="switch"><input type="checkbox" id="w-on"><span class="slider"></span></label></div>
    <div class="field"><label>Twilio SID</label><input type="text" id="w-sid"></div>
    <div class="field"><label>Auth Token</label><input type="password" id="w-tok"></div>
    <div class="field"><label>From</label><input type="text" id="w-from" placeholder="whatsapp:+14155238886"></div>
    <div class="field"><label>To</label><input type="text" id="w-to" placeholder="whatsapp:+44..."></div>
</div>

<!-- Telegram -->
<div class="panel"><h3>Telegram</h3>
    <div class="toggle-row" style="margin-bottom:10px"><span style="font-size:.85rem">Enable Telegram</span><label class="switch"><input type="checkbox" id="t-on"><span class="slider"></span></label></div>
    <div class="field"><label>Bot Token</label><input type="password" id="t-tok"><div class="hint">From @BotFather → /newbot</div></div>
    <div class="field"><label>Chat ID</label><input type="text" id="t-cid"><div class="hint">DM the bot, then check /getUpdates</div></div>
    <div class="field"><label>Parse Mode</label><select id="t-pm"><option value="HTML">HTML</option><option value="Markdown">Markdown</option></select></div>
</div>

<!-- Slack -->
<div class="panel"><h3>Slack</h3>
    <div class="toggle-row" style="margin-bottom:10px"><span style="font-size:.85rem">Enable Slack</span><label class="switch"><input type="checkbox" id="s-on"><span class="slider"></span></label></div>
    <div class="field"><label>Webhook URL</label><input type="password" id="s-url" placeholder="https://hooks.slack.com/services/..."><div class="hint">Slack App → Incoming Webhooks → Add to channel → Copy URL</div></div>
</div>

<!-- Discord -->
<div class="panel"><h3>Discord</h3>
    <div class="toggle-row" style="margin-bottom:10px"><span style="font-size:.85rem">Enable Discord</span><label class="switch"><input type="checkbox" id="d-on"><span class="slider"></span></label></div>
    <div class="field"><label>Webhook URL</label><input type="password" id="d-url" placeholder="https://discord.com/api/webhooks/..."><div class="hint">Server Settings → Integrations → Webhooks → New Webhook → Copy URL</div></div>
    <div class="field"><label>Bot Username</label><input type="text" id="d-user" value="AWS Dashboard" placeholder="AWS Dashboard"><div class="hint">Display name for webhook messages</div></div>
</div>

<!-- Microsoft Teams -->
<div class="panel"><h3>Microsoft Teams</h3>
    <div class="toggle-row" style="margin-bottom:10px"><span style="font-size:.85rem">Enable Teams</span><label class="switch"><input type="checkbox" id="tm-on"><span class="slider"></span></label></div>
    <div class="field"><label>Webhook URL</label><input type="password" id="tm-url" placeholder="https://outlook.office.com/webhook/... or Workflows URL"><div class="hint">Channel → ••• → Connectors → Incoming Webhook → Copy URL. Also supports Power Automate Workflows webhooks.</div></div>
</div>

<!-- AI Assistant -->
<div class="panel"><h3>AI Assistant (OpenRouter)</h3>
    <div class="field"><label>API Key</label><input type="password" id="ai-key" placeholder="sk-or-...">
    <div class="hint">Get a key at <a href="https://openrouter.ai/keys" target="_blank">openrouter.ai/keys</a> — pay per token, no subscription</div></div>
    <div class="field"><label>Model</label><select id="ai-model"></select></div>
    <div class="grid2">
        <div class="field"><label>Max Tokens</label><input type="number" id="ai-maxt" value="2048"></div>
        <div class="field"><label>Temperature</label><input type="number" id="ai-temp" value="0.3" step="0.1" min="0" max="1"></div>
    </div>
</div>

<!-- Notification Triggers -->
<div class="panel"><h3>Triggers</h3>
    <div class="toggle-row"><div><b style="font-size:.85rem">Master Switch</b><div style="font-size:.72rem;color:#8b949e">All notifications</div></div><label class="switch"><input type="checkbox" id="n-on"><span class="slider"></span></label></div>
    <div class="toggle-row"><span style="font-size:.85rem">EC2 Issues</span><label class="switch"><input type="checkbox" id="n-ec2"><span class="slider"></span></label></div>
    <div class="toggle-row"><span style="font-size:.85rem">Deploy Failures</span><label class="switch"><input type="checkbox" id="n-dep"><span class="slider"></span></label></div>
    <div class="toggle-row"><span style="font-size:.85rem">ECS Issues</span><label class="switch"><input type="checkbox" id="n-ecs"><span class="slider"></span></label></div>
    <div class="toggle-row"><span style="font-size:.85rem">Media Issues</span><label class="switch"><input type="checkbox" id="n-med"><span class="slider"></span></label></div>
    <div class="toggle-row"><span style="font-size:.85rem">Daily Summary</span><label class="switch"><input type="checkbox" id="n-daily"><span class="slider"></span></label></div>
    <div class="field" style="margin-top:8px"><label>Summary Hour (0-23)</label><input type="number" id="n-hr" min="0" max="23" value="9" style="width:70px"></div>
</div>

<!-- Security -->
<div class="panel"><h3>Security</h3>
    <div class="field"><label>Username</label><input type="text" id="auth-user" value="admin"></div>
    <div class="field"><label>New Password</label><input type="password" id="auth-pass" placeholder="Leave blank to keep current"></div>
    <div class="field"><label>Confirm Password</label><input type="password" id="auth-pass2" placeholder="Leave blank to keep current"></div>
    <div class="hint">Set a password to enable login. Leave blank to keep current or disable auth.</div>
</div>

</div>

<!-- User Management (admin only) -->
<div id="user-mgmt-section" style="display:none;margin-bottom:20px">
<div class="panel"><h3>User Management</h3>
    <div id="user-stats" class="cards" style="margin-bottom:16px">
        <div class="card"><div class="lb">Total Users</div><div class="vl blue" id="us-total">-</div></div>
        <div class="card"><div class="lb">Admins</div><div class="vl green" id="us-admin">-</div></div>
        <div class="card"><div class="lb">Operators</div><div class="vl yellow" id="us-operator">-</div></div>
        <div class="card"><div class="lb">Viewers</div><div class="vl" id="us-viewer" style="color:#8b949e">-</div></div>
    </div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <span style="font-size:.85rem;color:#8b949e">Manage dashboard users and roles</span>
        <button class="btn p" onclick="openAddUser()">Add User</button>
    </div>
    <table id="users-table">
        <thead><tr><th>Username</th><th>Role</th><th>Email</th><th>Created</th><th>Last Login</th><th>Actions</th></tr></thead>
        <tbody id="users-tbody"><tr><td colspan="6" style="text-align:center;color:#8b949e">Loading...</td></tr></tbody>
    </table>
</div>
</div>

<!-- Change My Password -->
<div class="panel" id="change-pw-section"><h3>Change My Password</h3>
    <div class="grid2">
        <div>
            <div class="field"><label>Current Password</label><input type="password" id="cp-current" placeholder="Enter current password"></div>
            <div class="field"><label>New Password</label><input type="password" id="cp-new" placeholder="Min 8 chars, letters + numbers"></div>
            <div class="field"><label>Confirm New Password</label><input type="password" id="cp-confirm" placeholder="Re-enter new password"></div>
            <button class="btn p" onclick="changeMyPassword()" id="btn-cp" style="margin-top:4px">Change Password</button>
        </div>
        <div style="padding-top:18px">
            <div style="font-size:.82rem;color:#8b949e;line-height:1.6">
                Password requirements:<br>
                &bull; At least 8 characters<br>
                &bull; Must contain at least one letter<br>
                &bull; Must contain at least one number
            </div>
        </div>
    </div>
</div>

<!-- Add User Modal -->
<div id="modal-add-user" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:999;align-items:center;justify-content:center">
<div style="background:#161b22;border:1px solid #30363d;border-radius:10px;padding:24px;width:420px;max-width:90vw">
    <h3 style="font-size:.95rem;color:#58a6ff;margin-bottom:16px">Add User</h3>
    <div class="field"><label>Username</label><input type="text" id="au-username" placeholder="3-30 alphanumeric/underscore"></div>
    <div class="field"><label>Password</label><input type="password" id="au-password" placeholder="Min 8 chars, letters + numbers"></div>
    <div class="field"><label>Role</label><select id="au-role"><option value="viewer">Viewer</option><option value="operator">Operator</option><option value="admin">Admin</option></select></div>
    <div class="field"><label>Email</label><input type="email" id="au-email" placeholder="Optional"></div>
    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px">
        <button class="btn" onclick="closeModal('modal-add-user')">Cancel</button>
        <button class="btn p" onclick="createUser()" id="btn-au">Create User</button>
    </div>
</div>
</div>

<!-- Edit User Modal -->
<div id="modal-edit-user" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:999;align-items:center;justify-content:center">
<div style="background:#161b22;border:1px solid #30363d;border-radius:10px;padding:24px;width:420px;max-width:90vw">
    <h3 style="font-size:.95rem;color:#58a6ff;margin-bottom:16px">Edit User</h3>
    <input type="hidden" id="eu-id">
    <div class="field"><label>Username</label><input type="text" id="eu-username" disabled style="opacity:.6"></div>
    <div class="field"><label>Role</label><select id="eu-role"><option value="viewer">Viewer</option><option value="operator">Operator</option><option value="admin">Admin</option></select></div>
    <div class="field"><label>Email</label><input type="email" id="eu-email"></div>
    <div class="field"><label>Reset Password</label><input type="password" id="eu-password" placeholder="Leave blank to keep current"></div>
    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px">
        <button class="btn" onclick="closeModal('modal-edit-user')">Cancel</button>
        <button class="btn p" onclick="saveEditUser()" id="btn-eu">Save Changes</button>
    </div>
</div>
</div>

<!-- Action Bar -->
<div style="display:flex;justify-content:space-between;align-items:center;margin-top:20px;padding-top:14px;border-top:1px solid #21262d">
    <div style="display:flex;gap:8px">
        <button class="btn" onclick="testN('email')" id="bt-e">Test Email</button>
        <button class="btn" onclick="testN('whatsapp')" id="bt-w">Test WhatsApp</button>
        <button class="btn" onclick="testN('telegram')" id="bt-t">Test Telegram</button>
        <button class="btn" onclick="testN('slack')" id="bt-s2">Test Slack</button>
        <button class="btn" onclick="testN('discord')" id="bt-d">Test Discord</button>
        <button class="btn" onclick="testN('teams')" id="bt-tm">Test Teams</button>
    </div>
    <button class="btn p" onclick="save()" id="bt-s" style="font-size:.95rem;padding:9px 24px">Save Settings</button>
</div>
</div>
<div id="toast" class="toast"></div>

<script>
function toast(m,t='info'){const e=document.getElementById('toast');e.textContent=m;e.className='toast '+t+' show';setTimeout(()=>e.classList.remove('show'),3000)}
function toggleSmtp(){document.getElementById('smtp-f').style.display=document.getElementById('e-prov').value==='smtp'?'block':'none';document.getElementById('ses-f').style.display=document.getElementById('e-prov').value==='ses'?'block':'none'}

async function loadCfg(){
    const c=await(await fetch('/api/config')).json();
    // AWS
    const regions=c.aws.regions||[c.aws.region];
    document.querySelectorAll('#aws-regions input[type=checkbox]').forEach(cb=>{cb.checked=regions.includes(cb.value)});
    document.getElementById('aws-key').value=c.aws.access_key_id;
    document.getElementById('aws-secret').value=c.aws.secret_access_key;
    // Monitoring
    document.getElementById('m-int').value=c.monitoring.check_interval_seconds;
    document.getElementById('m-cpu').value=c.monitoring.cpu_threshold;
    document.getElementById('m-dep').value=c.monitoring.deployment_lookback_hours;
    document.getElementById('m-uptime').value=c.monitoring.uptime_alert_hours||0;
    document.getElementById('m-ec2').checked=c.monitoring.monitor_ec2;
    document.getElementById('m-cd').checked=c.monitoring.monitor_codedeploy;
    document.getElementById('m-ecs').checked=c.monitoring.monitor_ecs;
    document.getElementById('m-ml').checked=c.monitoring.monitor_medialive;
    document.getElementById('m-mc').checked=c.monitoring.monitor_mediaconnect;
    document.getElementById('m-mp').checked=c.monitoring.monitor_mediapackage;
    document.getElementById('m-cf').checked=c.monitoring.monitor_cloudfront;
    document.getElementById('m-ivs').checked=c.monitoring.monitor_ivs;
    document.getElementById('m-rds').checked=c.monitoring.monitor_rds||false;
    document.getElementById('m-lam').checked=c.monitoring.monitor_lambda||false;
    document.getElementById('m-s3').checked=c.monitoring.monitor_s3||false;
    document.getElementById('m-sqs').checked=c.monitoring.monitor_sqs||false;
    document.getElementById('m-r53').checked=c.monitoring.monitor_route53||false;
    document.getElementById('m-apigw').checked=c.monitoring.monitor_apigateway||false;
    document.getElementById('m-vpc').checked=c.monitoring.monitor_vpc||false;
    document.getElementById('m-elb').checked=c.monitoring.monitor_elb||false;
    document.getElementById('m-eip').checked=c.monitoring.monitor_eip||false;
    document.getElementById('m-nat').checked=c.monitoring.monitor_nat||false;
    document.getElementById('m-sg').checked=c.monitoring.monitor_security_groups||false;
    document.getElementById('m-vpn').checked=c.monitoring.monitor_vpn||false;
    // Email
    const em=c.notifications.channels.email;
    document.getElementById('e-on').checked=em.enabled;
    document.getElementById('e-prov').value=em.provider;toggleSmtp();
    document.getElementById('e-host').value=em.smtp_host;
    document.getElementById('e-port').value=em.smtp_port;
    document.getElementById('e-user').value=em.smtp_username;
    document.getElementById('e-pass').value=em.smtp_password;
    document.getElementById('e-tls').checked=em.smtp_use_tls;
    document.getElementById('e-ses').value=em.ses_region;
    document.getElementById('e-from').value=em.from_address;
    document.getElementById('e-to').value=(em.to_addresses||[]).join(', ');
    // WhatsApp
    const wh=c.notifications.channels.whatsapp;
    document.getElementById('w-on').checked=wh.enabled;
    document.getElementById('w-sid').value=wh.twilio_account_sid;
    document.getElementById('w-tok').value=wh.twilio_auth_token;
    document.getElementById('w-from').value=wh.from_number;
    document.getElementById('w-to').value=wh.to_number;
    // Telegram
    const tg=c.notifications.channels.telegram||{};
    document.getElementById('t-on').checked=tg.enabled||false;
    document.getElementById('t-tok').value=tg.bot_token||'';
    document.getElementById('t-cid').value=tg.chat_id||'';
    document.getElementById('t-pm').value=tg.parse_mode||'HTML';
    // Slack
    const sl=c.notifications.channels.slack||{};
    document.getElementById('s-on').checked=sl.enabled||false;
    document.getElementById('s-url').value=sl.webhook_url||'';
    // Discord
    const dc=c.notifications.channels.discord||{};
    document.getElementById('d-on').checked=dc.enabled||false;
    document.getElementById('d-url').value=dc.webhook_url||'';
    document.getElementById('d-user').value=dc.username||'AWS Dashboard';
    // Teams
    const tm=c.notifications.channels.teams||{};
    document.getElementById('tm-on').checked=tm.enabled||false;
    document.getElementById('tm-url').value=tm.webhook_url||'';
    // AI
    const ai=c.ai||{};
    document.getElementById('ai-key').value=ai.openrouter_api_key||'';
    // Load models dynamically then set saved value
    fetch('/api/ai/models').then(r=>r.json()).then(d=>{
        const sel=document.getElementById('ai-model');
        sel.innerHTML='';
        d.models.forEach(m=>{sel.innerHTML+=`<option value="${esc(m.id)}">${esc(m.name)} (${esc(m.context)})</option>`});
        sel.value=ai.model||'anthropic/claude-sonnet-4.6';
    });
    document.getElementById('ai-maxt').value=ai.max_tokens||2048;
    document.getElementById('ai-temp').value=ai.temperature||0.3;
    // Triggers
    document.getElementById('n-on').checked=c.notifications.enabled;
    document.getElementById('n-ec2').checked=c.notifications.on_ec2_issues;
    document.getElementById('n-dep').checked=c.notifications.on_deploy_failures;
    document.getElementById('n-ecs').checked=c.notifications.on_ecs_issues;
    document.getElementById('n-med').checked=c.notifications.on_media_issues;
    document.getElementById('n-daily').checked=c.notifications.send_daily_summary;
    document.getElementById('n-hr').value=c.notifications.daily_summary_hour;
    // Auth
    const auth=c.auth||{};
    document.getElementById('auth-user').value=auth.username||'admin';
}

function gather(){
    const pass1=document.getElementById('auth-pass').value;
    const pass2=document.getElementById('auth-pass2').value;
    if(pass1&&pass1!==pass2){toast('Passwords do not match','error');return null}
    return{
    aws:{regions:[...document.querySelectorAll('#aws-regions input:checked')].map(cb=>cb.value),access_key_id:document.getElementById('aws-key').value,secret_access_key:document.getElementById('aws-secret').value},
    monitoring:{
        check_interval_seconds:+document.getElementById('m-int').value,cpu_threshold:+document.getElementById('m-cpu').value,
        deployment_lookback_hours:+document.getElementById('m-dep').value,
        uptime_alert_hours:+document.getElementById('m-uptime').value,
        monitor_ec2:document.getElementById('m-ec2').checked,monitor_codedeploy:document.getElementById('m-cd').checked,
        monitor_ecs:document.getElementById('m-ecs').checked,monitor_medialive:document.getElementById('m-ml').checked,
        monitor_mediaconnect:document.getElementById('m-mc').checked,monitor_mediapackage:document.getElementById('m-mp').checked,
        monitor_cloudfront:document.getElementById('m-cf').checked,monitor_ivs:document.getElementById('m-ivs').checked,
        monitor_rds:document.getElementById('m-rds').checked,monitor_lambda:document.getElementById('m-lam').checked,
        monitor_s3:document.getElementById('m-s3').checked,monitor_sqs:document.getElementById('m-sqs').checked,
        monitor_route53:document.getElementById('m-r53').checked,monitor_apigateway:document.getElementById('m-apigw').checked,
        monitor_vpc:document.getElementById('m-vpc').checked,monitor_elb:document.getElementById('m-elb').checked,
        monitor_eip:document.getElementById('m-eip').checked,monitor_nat:document.getElementById('m-nat').checked,
        monitor_security_groups:document.getElementById('m-sg').checked,monitor_vpn:document.getElementById('m-vpn').checked,
    },
    ai:{openrouter_api_key:document.getElementById('ai-key').value,model:document.getElementById('ai-model').value,
        max_tokens:+document.getElementById('ai-maxt').value,temperature:+document.getElementById('ai-temp').value},
    notifications:{
        enabled:document.getElementById('n-on').checked,on_ec2_issues:document.getElementById('n-ec2').checked,
        on_deploy_failures:document.getElementById('n-dep').checked,on_ecs_issues:document.getElementById('n-ecs').checked,
        on_media_issues:document.getElementById('n-med').checked,send_daily_summary:document.getElementById('n-daily').checked,
        daily_summary_hour:+document.getElementById('n-hr').value,
        channels:{
            email:{enabled:document.getElementById('e-on').checked,provider:document.getElementById('e-prov').value,
                smtp_host:document.getElementById('e-host').value,smtp_port:+document.getElementById('e-port').value,
                smtp_username:document.getElementById('e-user').value,smtp_password:document.getElementById('e-pass').value,
                smtp_use_tls:document.getElementById('e-tls').checked,ses_region:document.getElementById('e-ses').value,
                from_address:document.getElementById('e-from').value,to_addresses:document.getElementById('e-to').value},
            whatsapp:{enabled:document.getElementById('w-on').checked,twilio_account_sid:document.getElementById('w-sid').value,
                twilio_auth_token:document.getElementById('w-tok').value,from_number:document.getElementById('w-from').value,
                to_number:document.getElementById('w-to').value},
            telegram:{enabled:document.getElementById('t-on').checked,bot_token:document.getElementById('t-tok').value,
                chat_id:document.getElementById('t-cid').value,parse_mode:document.getElementById('t-pm').value},
            slack:{enabled:document.getElementById('s-on').checked,webhook_url:document.getElementById('s-url').value},
            discord:{enabled:document.getElementById('d-on').checked,webhook_url:document.getElementById('d-url').value,username:document.getElementById('d-user').value},
            teams:{enabled:document.getElementById('tm-on').checked,webhook_url:document.getElementById('tm-url').value},
        }
    },
    auth:{username:document.getElementById('auth-user').value,password:pass1||''}
}}

async function save(){
    const data=gather();if(!data)return;
    const b=document.getElementById('bt-s');b.disabled=true;b.textContent='Saving...';
    try{const r=await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
        const j=await r.json();toast(j.status==='ok'?'Saved!':'Save failed',j.status==='ok'?'success':'error')
    }catch(e){toast('Error: '+e.message,'error')}
    b.disabled=false;b.textContent='Save Settings';
}

async function testN(ch){
    const btn=document.getElementById({email:'bt-e',whatsapp:'bt-w',telegram:'bt-t',slack:'bt-s2',discord:'bt-d',teams:'bt-tm'}[ch]);
    btn.disabled=true;
    try{const r=await fetch('/api/test/'+ch,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});const j=await r.json();
        toast(j.sent?ch+' test sent!':ch+' failed — check settings',j.sent?'success':'error')
    }catch(e){toast('Error','error')}
    btn.disabled=false;
}

// ── User Management ──
function roleBadge(r){const c={admin:'ok',operator:'warn',viewer:'off'};return `<span class="badge ${c[r]||'info'}">${esc(r)}</span>`}
function fmtDate(d){if(!d)return'<span style="color:#484f58">Never</span>';try{const dt=new Date(d);return dt.toLocaleDateString()+' '+dt.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}catch(e){return esc(d)}}

async function loadUserMgmt(){
    try{
        const [statsR,usersR]=await Promise.all([fetch('/api/users/stats'),fetch('/api/users')]);
        const stats=await statsR.json();
        const users=await usersR.json();
        if(stats.ok){
            document.getElementById('us-total').textContent=stats.total;
            document.getElementById('us-admin').textContent=(stats.by_role||{}).admin||0;
            document.getElementById('us-operator').textContent=(stats.by_role||{}).operator||0;
            document.getElementById('us-viewer').textContent=(stats.by_role||{}).viewer||0;
        }
        if(users.ok){
            const tb=document.getElementById('users-tbody');
            if(!users.users||users.users.length===0){tb.innerHTML='<tr><td colspan="6" style="text-align:center;color:#8b949e">No users found</td></tr>';return}
            tb.innerHTML=users.users.map(u=>`<tr>
                <td style="font-weight:600">${esc(u.username)}</td>
                <td>${roleBadge(u.role)}</td>
                <td>${u.email?esc(u.email):'<span style="color:#484f58">-</span>'}</td>
                <td style="font-size:.78rem">${fmtDate(u.created_at)}</td>
                <td style="font-size:.78rem">${fmtDate(u.last_login)}</td>
                <td><button class="btn sm" onclick="openEditUser(${u.id},'${esc(u.username).replace(/'/g,"&#39;")}','${esc(u.role).replace(/'/g,"&#39;")}','${esc(u.email||'').replace(/'/g,"&#39;")}')">Edit</button> <button class="btn sm d" onclick="deleteUser(${u.id},'${esc(u.username).replace(/'/g,"&#39;")}')">Delete</button></td>
            </tr>`).join('');
        }
    }catch(e){console.error('Failed to load user management',e)}
}

function openModal(id){document.getElementById(id).style.display='flex'}
function closeModal(id){document.getElementById(id).style.display='none'}

function openAddUser(){
    document.getElementById('au-username').value='';
    document.getElementById('au-password').value='';
    document.getElementById('au-role').value='viewer';
    document.getElementById('au-email').value='';
    openModal('modal-add-user');
}

async function createUser(){
    const btn=document.getElementById('btn-au');btn.disabled=true;btn.textContent='Creating...';
    const body={username:document.getElementById('au-username').value,password:document.getElementById('au-password').value,
        role:document.getElementById('au-role').value,email:document.getElementById('au-email').value};
    try{
        const r=await fetch('/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
        const j=await r.json();
        if(j.ok){toast('User created','success');closeModal('modal-add-user');loadUserMgmt()}
        else{toast(j.error||'Failed to create user','error')}
    }catch(e){toast('Error: '+e.message,'error')}
    btn.disabled=false;btn.textContent='Create User';
}

function openEditUser(id,username,role,email){
    document.getElementById('eu-id').value=id;
    document.getElementById('eu-username').value=username;
    document.getElementById('eu-role').value=role;
    document.getElementById('eu-email').value=email;
    document.getElementById('eu-password').value='';
    openModal('modal-edit-user');
}

async function saveEditUser(){
    const btn=document.getElementById('btn-eu');btn.disabled=true;btn.textContent='Saving...';
    const id=document.getElementById('eu-id').value;
    const body={role:document.getElementById('eu-role').value,email:document.getElementById('eu-email').value};
    const pw=document.getElementById('eu-password').value;
    if(pw)body.password=pw;
    try{
        const r=await fetch('/api/users/'+id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
        const j=await r.json();
        if(j.ok){toast('User updated','success');closeModal('modal-edit-user');loadUserMgmt()}
        else{toast(j.error||'Failed to update user','error')}
    }catch(e){toast('Error: '+e.message,'error')}
    btn.disabled=false;btn.textContent='Save Changes';
}

async function deleteUser(id,username){
    if(!confirm('Delete user "'+username+'"? This cannot be undone.'))return;
    try{
        const r=await fetch('/api/users/'+id,{method:'DELETE',headers:{'Content-Type':'application/json'},body:'{}'});
        const j=await r.json();
        if(j.ok){toast('User deleted','success');loadUserMgmt()}
        else{toast(j.error||'Cannot delete user','error')}
    }catch(e){toast('Error: '+e.message,'error')}
}

async function changeMyPassword(){
    const cur=document.getElementById('cp-current').value;
    const np=document.getElementById('cp-new').value;
    const conf=document.getElementById('cp-confirm').value;
    if(!cur||!np){toast('Fill in all password fields','error');return}
    if(np!==conf){toast('New passwords do not match','error');return}
    if(np.length<8||!/[A-Za-z]/.test(np)||!/[0-9]/.test(np)){toast('Password must be 8+ chars with letters and numbers','error');return}
    const btn=document.getElementById('btn-cp');btn.disabled=true;btn.textContent='Changing...';
    try{
        const r=await fetch('/api/users/me/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_password:np})});
        const j=await r.json();
        if(j.ok){toast('Password changed successfully','success');document.getElementById('cp-current').value='';document.getElementById('cp-new').value='';document.getElementById('cp-confirm').value=''}
        else{toast(j.error||'Failed to change password','error')}
    }catch(e){toast('Error: '+e.message,'error')}
    btn.disabled=false;btn.textContent='Change Password';
}

// Show user management section if admin (GET /api/users requires admin role)
async function initUserSection(){
    try{
        const r=await fetch('/api/users');
        if(r.ok){
            const j=await r.json();
            if(j.ok){document.getElementById('user-mgmt-section').style.display='block';loadUserMgmt()}
        }
    }catch(e){}
}
initUserSection();

loadCfg();
</script></body></html>""")


# ─── Schedule Execution ──────────────────────────────────────────────────────

def _execute_scheduled_action(schedule_id):
    """Execute a scheduled action and log the result."""
    if not _SCHEDULES_AVAILABLE:
        return
    schedule = get_schedule(schedule_id)
    if not schedule or not schedule.get("enabled"):
        return
    action_id = schedule.get("action_id", "")
    action = next((a for a in ACTION_REGISTRY if a["id"] == action_id), None)
    if action and action.get("risk") == "high":
        log_run(schedule_id, False, {"error": "High-risk actions cannot be scheduled"})
        return
    try:
        params = schedule.get("action_params")
        if isinstance(params, str):
            params = json.loads(params) if params else {}
        elif not params:
            params = {}
        config = load_config()
        result = _execute_action(action_id, params, config)
        success = result.get("ok", False) if isinstance(result, dict) else False
        log_run(schedule_id, success, result)
        _audit_logger.info(
            "[SCHEDULE] schedule=%s action=%s success=%s", schedule_id, action_id, success
        )
    except Exception as e:
        _logging.getLogger(__name__).error("Scheduled action %s failed: %s", schedule_id, e)
        log_run(schedule_id, False, {"error": str(e)})


def _sync_schedule_jobs():
    """Register/update APScheduler CronTrigger jobs for all enabled schedules."""
    global _scheduler
    if not _scheduler or not _SCHEDULES_AVAILABLE:
        return
    for job in _scheduler.get_jobs():
        if job.id.startswith("schedule_"):
            _scheduler.remove_job(job.id)
    for s in get_schedules(enabled_only=True):
        try:
            parts = s["cron_expression"].strip().split()
            if len(parts) != 5:
                continue
            trigger = CronTrigger(
                minute=parts[0], hour=parts[1], day=parts[2],
                month=parts[3], day_of_week=parts[4]
            )
            _scheduler.add_job(
                _execute_scheduled_action, trigger,
                args=[s["id"]], id=f"schedule_{s['id']}", replace_existing=True,
            )
        except Exception as e:
            _logging.getLogger(__name__).warning("Failed to register schedule %s: %s", s["id"], e)


# ─── Scheduler ───────────────────────────────────────────────────────────────

_scheduler = None

def start_scheduler():
    global _scheduler
    config = load_config()
    _scheduler = BackgroundScheduler()
    interval = max(10, config.get("monitoring", {}).get("check_interval_seconds", 300))
    _scheduler.add_job(scheduled_check, "interval", seconds=interval, id="main_check", replace_existing=True)
    summary_hour = config.get("notifications", {}).get("daily_summary_hour", 9)
    _scheduler.add_job(send_daily_summary, "cron", hour=summary_hour, minute=0, id="daily_summary", replace_existing=True)
    _scheduler.start()
    _sync_schedule_jobs()
    try:
        scheduled_check()
    except Exception as e:
        print(f"Initial check failed (will retry later): {e}")

import atexit

# Start scheduler once (works with both gunicorn and direct run)
start_scheduler()
atexit.register(lambda: _scheduler.shutdown(wait=False) if _scheduler else None)

if __name__ == "__main__":
    print("AWS Video Dashboard at http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
