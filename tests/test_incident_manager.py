"""Tests for incident_manager module."""

import pytest

from incident_manager import (
    create_incident,
    get_incidents,
    get_incident,
    acknowledge_incident,
    resolve_incident,
    add_note,
    find_open_incident,
    get_incident_stats,
)


# ── create_incident ─────────────────────────────────────────────────────────

class TestCreateIncident:
    def test_returns_dict_with_expected_keys(self, tmp_incidents_db):
        inc = create_incident("Server down", severity="critical")
        assert isinstance(inc, dict)
        assert "id" in inc
        assert "title" in inc
        assert "status" in inc
        assert "severity" in inc
        assert "created_at" in inc

    def test_defaults_status_to_open(self, tmp_incidents_db):
        inc = create_incident("Disk full")
        assert inc["status"] == "open"

    def test_stores_alert_rule_id_and_resource_id(self, tmp_incidents_db):
        inc = create_incident(
            "High CPU",
            alert_rule_id="rule_cpu_90",
            resource_id="i-abc123",
        )
        assert inc["alert_rule_id"] == "rule_cpu_90"
        assert inc["resource_id"] == "i-abc123"

    def test_stores_severity(self, tmp_incidents_db):
        inc = create_incident("Memory leak", severity="critical")
        assert inc["severity"] == "critical"

    def test_stores_trigger_message(self, tmp_incidents_db):
        inc = create_incident("Test", trigger_message="CPU at 95%")
        assert inc["trigger_message"] == "CPU at 95%"


# ── get_incidents ────────────────────────────────────────────────────────────

class TestGetIncidents:
    def test_returns_empty_list_initially(self, tmp_incidents_db):
        result = get_incidents()
        assert result == []

    def test_returns_created_incidents(self, tmp_incidents_db):
        create_incident("Inc 1")
        create_incident("Inc 2")
        result = get_incidents()
        assert len(result) == 2

    def test_filter_by_status_open(self, tmp_incidents_db):
        inc = create_incident("Open one")
        create_incident("To resolve")
        resolve_incident(2)
        result = get_incidents(status="open")
        assert len(result) == 1
        assert result[0]["title"] == "Open one"

    def test_filter_by_status_acknowledged(self, tmp_incidents_db):
        create_incident("A")
        create_incident("B")
        acknowledge_incident(1)
        result = get_incidents(status="acknowledged")
        assert len(result) == 1
        assert result[0]["id"] == 1

    def test_filter_by_status_resolved(self, tmp_incidents_db):
        create_incident("A")
        resolve_incident(1, resolution_note="fixed")
        result = get_incidents(status="resolved")
        assert len(result) == 1

    def test_filter_by_severity(self, tmp_incidents_db):
        create_incident("Warning", severity="warning")
        create_incident("Critical", severity="critical")
        result = get_incidents(severity="critical")
        assert len(result) == 1
        assert result[0]["severity"] == "critical"

    def test_limit_parameter(self, tmp_incidents_db):
        for i in range(5):
            create_incident(f"Inc {i}")
        result = get_incidents(limit=3)
        assert len(result) == 3


# ── get_incident ─────────────────────────────────────────────────────────────

class TestGetIncident:
    def test_returns_full_details(self, tmp_incidents_db):
        created = create_incident("Detailed", severity="critical")
        inc = get_incident(created["id"])
        assert inc["title"] == "Detailed"
        assert inc["severity"] == "critical"

    def test_includes_notes_list(self, tmp_incidents_db):
        created = create_incident("With notes")
        inc = get_incident(created["id"])
        assert "notes" in inc
        assert isinstance(inc["notes"], list)

    def test_nonexistent_returns_none(self, tmp_incidents_db):
        result = get_incident(9999)
        assert result is None


# ── acknowledge_incident ─────────────────────────────────────────────────────

class TestAcknowledgeIncident:
    def test_changes_status_to_acknowledged(self, tmp_incidents_db):
        inc = create_incident("Ack me")
        result = acknowledge_incident(inc["id"])
        assert result["status"] == "acknowledged"

    def test_sets_acknowledged_at_timestamp(self, tmp_incidents_db):
        inc = create_incident("Ack me")
        result = acknowledge_incident(inc["id"])
        assert result["acknowledged_at"] is not None

    def test_sets_assigned_to(self, tmp_incidents_db):
        inc = create_incident("Ack me")
        result = acknowledge_incident(inc["id"], assigned_to="alice")
        assert result["assigned_to"] == "alice"

    def test_already_acknowledged_returns_none(self, tmp_incidents_db):
        inc = create_incident("Ack me")
        acknowledge_incident(inc["id"])
        result = acknowledge_incident(inc["id"])
        assert result is None

    def test_resolved_incident_returns_none(self, tmp_incidents_db):
        inc = create_incident("Resolve me")
        resolve_incident(inc["id"])
        result = acknowledge_incident(inc["id"])
        assert result is None

    def test_creates_system_note(self, tmp_incidents_db):
        inc = create_incident("Note test")
        acknowledge_incident(inc["id"], assigned_to="bob")
        detail = get_incident(inc["id"])
        notes = detail["notes"]
        assert len(notes) >= 1
        assert "acknowledged" in notes[0]["note"].lower()


# ── resolve_incident ─────────────────────────────────────────────────────────

class TestResolveIncident:
    def test_from_open_works(self, tmp_incidents_db):
        inc = create_incident("Resolve me")
        result = resolve_incident(inc["id"])
        assert result["status"] == "resolved"

    def test_from_acknowledged_works(self, tmp_incidents_db):
        inc = create_incident("Ack then resolve")
        acknowledge_incident(inc["id"])
        result = resolve_incident(inc["id"])
        assert result["status"] == "resolved"

    def test_sets_resolved_at_timestamp(self, tmp_incidents_db):
        inc = create_incident("Resolve me")
        result = resolve_incident(inc["id"])
        assert result["resolved_at"] is not None

    def test_with_resolution_note(self, tmp_incidents_db):
        inc = create_incident("Resolve me")
        result = resolve_incident(inc["id"], resolution_note="root cause found")
        assert result["resolution_note"] == "root cause found"

    def test_already_resolved_returns_none(self, tmp_incidents_db):
        inc = create_incident("Resolve me")
        resolve_incident(inc["id"])
        result = resolve_incident(inc["id"])
        assert result is None

    def test_creates_system_note(self, tmp_incidents_db):
        inc = create_incident("Resolve note test")
        resolve_incident(inc["id"], resolution_note="fixed it")
        detail = get_incident(inc["id"])
        notes = detail["notes"]
        assert len(notes) >= 1
        assert "resolved" in notes[0]["note"].lower()


# ── add_note ─────────────────────────────────────────────────────────────────

class TestAddNote:
    def test_success_returns_dict(self, tmp_incidents_db):
        inc = create_incident("Note target")
        note = add_note(inc["id"], "investigation started")
        assert isinstance(note, dict)
        assert note["note"] == "investigation started"

    def test_with_custom_author(self, tmp_incidents_db):
        inc = create_incident("Note target")
        note = add_note(inc["id"], "checking logs", author="alice")
        assert note["author"] == "alice"


# ── find_open_incident ───────────────────────────────────────────────────────

class TestFindOpenIncident:
    def test_matches_by_alert_rule_and_resource(self, tmp_incidents_db):
        create_incident(
            "Match me",
            alert_rule_id="rule_1",
            resource_id="res_1",
        )
        result = find_open_incident("rule_1", "res_1")
        assert result is not None
        assert result["title"] == "Match me"

    def test_returns_none_when_no_match(self, tmp_incidents_db):
        result = find_open_incident("no_rule", "no_res")
        assert result is None

    def test_ignores_resolved_incidents(self, tmp_incidents_db):
        inc = create_incident(
            "Resolved one",
            alert_rule_id="rule_2",
            resource_id="res_2",
        )
        resolve_incident(inc["id"])
        result = find_open_incident("rule_2", "res_2")
        assert result is None


# ── get_incident_stats ───────────────────────────────────────────────────────

class TestGetIncidentStats:
    def test_returns_counts_by_status(self, tmp_incidents_db):
        create_incident("Open 1")
        create_incident("Open 2")
        inc3 = create_incident("Ack 1")
        acknowledge_incident(inc3["id"])
        inc4 = create_incident("Resolved 1")
        resolve_incident(inc4["id"])

        stats = get_incident_stats()
        assert stats["open"] == 2
        assert stats["acknowledged"] == 1
        assert stats["resolved"] == 1

    def test_empty_db_returns_zeros(self, tmp_incidents_db):
        stats = get_incident_stats()
        assert stats == {"open": 0, "acknowledged": 0, "resolved": 0}


# ── Full lifecycle ───────────────────────────────────────────────────────────

class TestFullLifecycle:
    def test_create_acknowledge_resolve(self, tmp_incidents_db):
        # Create
        inc = create_incident("Lifecycle test", severity="critical")
        assert inc["status"] == "open"

        # Acknowledge
        acked = acknowledge_incident(inc["id"], assigned_to="ops-team")
        assert acked["status"] == "acknowledged"
        assert acked["assigned_to"] == "ops-team"

        # Resolve
        resolved = resolve_incident(inc["id"], resolution_note="patched")
        assert resolved["status"] == "resolved"
        assert resolved["resolved_at"] is not None
        assert resolved["resolution_note"] == "patched"

        # Verify notes timeline
        detail = get_incident(inc["id"])
        assert len(detail["notes"]) == 2  # ack note + resolve note
