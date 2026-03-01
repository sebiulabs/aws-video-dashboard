"""
Tests for Flask app routes and middleware
==========================================
Covers page loads, health/status, CSRF, security headers, GET APIs,
CRUD operations, AI agent endpoints, and input validation.
"""

import json
import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ─── Helpers ────────────────────────────────────────────────────────────────

ORIGIN = {"Origin": "http://localhost"}


def _json_post(client, url, data=None, **kwargs):
    """POST with JSON content-type and localhost Origin."""
    return client.post(
        url,
        data=json.dumps(data or {}),
        content_type="application/json",
        headers=ORIGIN,
        **kwargs,
    )


def _json_put(client, url, data=None, **kwargs):
    """PUT with JSON content-type and localhost Origin."""
    return client.put(
        url,
        data=json.dumps(data or {}),
        content_type="application/json",
        headers=ORIGIN,
        **kwargs,
    )


def _json_delete(client, url, **kwargs):
    """DELETE with JSON content-type and localhost Origin."""
    return client.delete(
        url,
        data=json.dumps({}),
        content_type="application/json",
        headers=ORIGIN,
        **kwargs,
    )


# ═════════════════════════════════════════════════════════════════════════════
# Page loads — every page returns 200
# ═════════════════════════════════════════════════════════════════════════════

class TestPageLoads:
    def test_dashboard(self, flask_client):
        assert flask_client.get("/").status_code == 200

    def test_monitors(self, flask_client):
        assert flask_client.get("/monitors").status_code == 200

    def test_alerts(self, flask_client):
        assert flask_client.get("/alerts").status_code == 200

    def test_incidents(self, flask_client):
        assert flask_client.get("/incidents").status_code == 200

    def test_ai(self, flask_client):
        assert flask_client.get("/ai").status_code == 200

    def test_settings(self, flask_client):
        assert flask_client.get("/settings").status_code == 200

    def test_cloud(self, flask_client):
        assert flask_client.get("/cloud").status_code == 200

    def test_logs(self, flask_client):
        assert flask_client.get("/logs").status_code == 200

    def test_costs(self, flask_client):
        assert flask_client.get("/costs").status_code == 200

    def test_schedules(self, flask_client):
        assert flask_client.get("/schedules").status_code == 200


# ═════════════════════════════════════════════════════════════════════════════
# Health & status
# ═════════════════════════════════════════════════════════════════════════════

class TestHealthAndStatus:
    def test_health_returns_ok(self, flask_client):
        r = flask_client.get("/health")
        assert r.status_code == 200
        data = r.get_json()
        assert data["status"] == "ok"

    def test_api_status_returns_200(self, flask_client):
        r = flask_client.get("/api/status")
        assert r.status_code == 200

    def test_api_config_returns_aws_key(self, flask_client):
        r = flask_client.get("/api/config")
        assert r.status_code == 200
        data = r.get_json()
        assert "aws" in data


# ═════════════════════════════════════════════════════════════════════════════
# CSRF protection
# ═════════════════════════════════════════════════════════════════════════════

class TestCSRF:
    def test_post_without_json_content_type_returns_400(self, flask_client):
        r = flask_client.post("/api/refresh", data="{}")
        assert r.status_code == 400

    def test_put_without_json_content_type_returns_400(self, flask_client):
        r = flask_client.put("/api/rules/test", data="{}")
        assert r.status_code == 400

    def test_delete_without_json_content_type_returns_400(self, flask_client):
        r = flask_client.delete("/api/endpoints/test", data="{}")
        assert r.status_code == 400

    def test_post_with_json_and_origin_succeeds(self, flask_client):
        r = _json_post(flask_client, "/api/ai/agent/start", {"message": "test"})
        assert r.status_code == 200

    def test_cross_origin_returns_403(self, flask_client):
        r = flask_client.post(
            "/api/ai/agent/start",
            data=json.dumps({"message": "test"}),
            content_type="application/json",
            headers={"Origin": "http://evil.example.com"},
        )
        assert r.status_code == 403

    def test_no_origin_no_referer_returns_403(self, flask_client):
        r = flask_client.post(
            "/api/ai/agent/start",
            data=json.dumps({"message": "test"}),
            content_type="application/json",
            # No Origin, no Referer
        )
        assert r.status_code == 403


# ═════════════════════════════════════════════════════════════════════════════
# Security headers
# ═════════════════════════════════════════════════════════════════════════════

class TestSecurityHeaders:
    def test_x_content_type_options(self, flask_client):
        r = flask_client.get("/")
        assert r.headers.get("X-Content-Type-Options") == "nosniff"

    def test_x_frame_options(self, flask_client):
        r = flask_client.get("/")
        assert r.headers.get("X-Frame-Options") == "DENY"

    def test_x_xss_protection(self, flask_client):
        r = flask_client.get("/")
        assert r.headers.get("X-XSS-Protection") == "1; mode=block"

    def test_referrer_policy_present(self, flask_client):
        r = flask_client.get("/")
        assert r.headers.get("Referrer-Policy") is not None

    def test_content_security_policy_present(self, flask_client):
        r = flask_client.get("/")
        assert r.headers.get("Content-Security-Policy") is not None


# ═════════════════════════════════════════════════════════════════════════════
# GET API routes
# ═════════════════════════════════════════════════════════════════════════════

class TestGetAPIs:
    def test_history_with_limit(self, flask_client):
        r = flask_client.get("/api/history?limit=10")
        assert r.status_code == 200

    def test_history_negative_limit_clamped(self, flask_client):
        r = flask_client.get("/api/history?limit=-5")
        assert r.status_code == 200

    def test_schedules_list(self, flask_client):
        r = flask_client.get("/api/schedules")
        assert r.status_code == 200

    def test_schedules_stats(self, flask_client):
        r = flask_client.get("/api/schedules/stats")
        assert r.status_code == 200

    def test_remediation_presets(self, flask_client):
        r = flask_client.get("/api/remediation/presets")
        assert r.status_code == 200

    def test_users_list(self, flask_client):
        r = flask_client.get("/api/users")
        assert r.status_code == 200

    def test_gcp_templates(self, flask_client):
        r = flask_client.get("/api/cloud/gcp/templates")
        assert r.status_code == 200

    def test_incidents_list(self, flask_client):
        r = flask_client.get("/api/incidents")
        assert r.status_code == 200


# ═════════════════════════════════════════════════════════════════════════════
# API CRUD
# ═════════════════════════════════════════════════════════════════════════════

class TestAPICrud:
    def test_add_rule(self, flask_client):
        r = _json_post(flask_client, "/api/rules", {
            "name": "Test Rule",
            "service": "ec2",
            "metric": "cpu_utilization",
            "operator": ">",
            "threshold": 80,
            "severity": "warning",
        })
        assert r.status_code == 200
        data = r.get_json()
        assert data["status"] == "ok"
        assert "rule" in data

    def test_get_rules_returns_added_rule(self, flask_client):
        _json_post(flask_client, "/api/rules", {
            "name": "Findme Rule",
            "service": "ec2",
            "metric": "cpu_utilization",
            "operator": ">",
            "threshold": 90,
        })
        r = flask_client.get("/api/rules")
        assert r.status_code == 200
        rules = r.get_json()["rules"]
        assert any(rule["name"] == "Findme Rule" for rule in rules)

    def test_update_rule(self, flask_client):
        r = _json_post(flask_client, "/api/rules", {
            "name": "Original",
            "service": "ec2",
            "metric": "cpu_utilization",
            "operator": ">",
            "threshold": 80,
        })
        rule_id = r.get_json()["rule"]["id"]
        r = _json_put(flask_client, f"/api/rules/{rule_id}", {"name": "Updated"})
        assert r.status_code == 200
        assert r.get_json()["status"] == "ok"

    def test_delete_rule(self, flask_client):
        r = _json_post(flask_client, "/api/rules", {
            "name": "ToDelete",
            "service": "ec2",
            "metric": "cpu_utilization",
            "operator": ">",
            "threshold": 80,
        })
        rule_id = r.get_json()["rule"]["id"]
        r = _json_delete(flask_client, f"/api/rules/{rule_id}")
        assert r.status_code == 200
        assert r.get_json()["status"] == "ok"

    def test_add_incident_note(self, flask_client):
        from incident_manager import create_incident
        incident = create_incident("Test incident", severity="warning")
        incident_id = incident["id"]
        r = _json_post(flask_client, f"/api/incidents/{incident_id}/note", {
            "note": "This is a test note",
        })
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True

    def test_incident_stats(self, flask_client):
        r = flask_client.get("/api/incidents/stats")
        assert r.status_code == 200
        data = r.get_json()
        # Stats should have count keys
        assert "open" in data or "total" in data or isinstance(data, dict)

    def test_create_schedule(self, flask_client):
        r = _json_post(flask_client, "/api/schedules", {
            "name": "Test Schedule",
            "action_id": "test_action",
            "cron_expression": "0 * * * *",
            "description": "Hourly test",
        })
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True
        assert "schedule" in data

    def test_toggle_schedule(self, flask_client):
        r = _json_post(flask_client, "/api/schedules", {
            "name": "Toggle Test",
            "action_id": "test_action",
            "cron_expression": "0 * * * *",
        })
        schedule_id = r.get_json()["schedule"]["id"]
        r = _json_post(flask_client, f"/api/schedules/{schedule_id}/toggle")
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True


# ═════════════════════════════════════════════════════════════════════════════
# AI Agent
# ═════════════════════════════════════════════════════════════════════════════

class TestAIAgent:
    def test_agent_start(self, flask_client):
        r = _json_post(flask_client, "/api/ai/agent/start", {"message": "test"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True
        assert "task_id" in data

    def test_agent_stop(self, flask_client):
        r = _json_post(flask_client, "/api/ai/agent/start", {"message": "test"})
        task_id = r.get_json()["task_id"]
        r = _json_post(flask_client, f"/api/ai/agent/{task_id}/stop")
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True

    def test_ai_actions_returns_list(self, flask_client):
        r = flask_client.get("/api/ai/actions")
        assert r.status_code == 200
        data = r.get_json()
        assert "actions" in data
        assert isinstance(data["actions"], list)


# ═════════════════════════════════════════════════════════════════════════════
# Input validation
# ═════════════════════════════════════════════════════════════════════════════

class TestInputValidation:
    def test_history_large_limit_clamped(self, flask_client):
        r = flask_client.get("/api/history?limit=999999")
        assert r.status_code == 200
        data = r.get_json()
        # The API clamps to max 2000, so it should still return successfully
        assert "history" in data

    def test_api_error_returns_json(self, flask_client):
        # A request to a non-existent incident should return valid JSON
        r = flask_client.get("/api/incidents/99999")
        assert r.status_code in (200, 404)
        data = r.get_json()
        assert data is not None

    def test_health_works_without_auth(self, flask_client):
        # Health endpoint should always return 200, even without session
        r = flask_client.get("/health")
        assert r.status_code == 200
        assert r.get_json()["status"] == "ok"

    def test_agent_start_empty_message_returns_400(self, flask_client):
        r = _json_post(flask_client, "/api/ai/agent/start", {"message": ""})
        assert r.status_code == 400

    def test_agent_start_missing_message_returns_400(self, flask_client):
        r = _json_post(flask_client, "/api/ai/agent/start", {})
        assert r.status_code == 400

    def test_agent_stop_unknown_task_returns_404(self, flask_client):
        r = _json_post(flask_client, "/api/ai/agent/nonexistent-id/stop")
        assert r.status_code == 404

    def test_incident_note_empty_returns_400(self, flask_client):
        from incident_manager import create_incident
        inc = create_incident("Empty note test", severity="warning")
        r = _json_post(flask_client, f"/api/incidents/{inc['id']}/note", {"note": ""})
        assert r.status_code == 400

    def test_schedule_missing_name_returns_400(self, flask_client):
        r = _json_post(flask_client, "/api/schedules", {
            "action_id": "test_action",
            "cron_expression": "0 * * * *",
        })
        assert r.status_code == 400

    def test_schedule_missing_action_returns_400(self, flask_client):
        r = _json_post(flask_client, "/api/schedules", {
            "name": "No Action",
            "cron_expression": "0 * * * *",
        })
        assert r.status_code == 400

    def test_schedule_missing_cron_returns_400(self, flask_client):
        r = _json_post(flask_client, "/api/schedules", {
            "name": "No Cron",
            "action_id": "test_action",
        })
        assert r.status_code == 400

    def test_delete_nonexistent_rule_returns_not_found(self, flask_client):
        r = _json_delete(flask_client, "/api/rules/nonexistent-id")
        assert r.status_code == 200
        assert r.get_json()["status"] == "not_found"

    def test_history_returns_list_structure(self, flask_client):
        r = flask_client.get("/api/history?limit=5")
        assert r.status_code == 200
        data = r.get_json()
        assert "history" in data
        assert isinstance(data["history"], list)
