"""Tests for remediation module."""

from datetime import datetime, timezone, timedelta

import pytest

from remediation import (
    should_remediate,
    log_remediation,
    get_remediation_log,
    get_remediation_stats,
    REMEDIATION_PRESETS,
)


# ── should_remediate pure logic (no fixture needed) ──────────────────────────

class TestShouldRemediate:
    def test_returns_true_when_enabled_under_limits_no_recent(self):
        rule = {
            "id": "rule_1",
            "remediation": {
                "enabled": True,
                "max_executions": 5,
                "cooldown_minutes": 10,
            },
        }
        assert should_remediate(rule, []) is True

    def test_returns_false_when_not_enabled(self):
        rule = {
            "id": "rule_1",
            "remediation": {"enabled": False},
        }
        assert should_remediate(rule, []) is False

    def test_returns_false_when_no_remediation_key(self):
        rule = {"id": "rule_1"}
        assert should_remediate(rule, []) is False

    def test_returns_false_when_remediation_is_none(self):
        rule = {"id": "rule_1", "remediation": None}
        assert should_remediate(rule, []) is False

    def test_returns_false_when_max_executions_reached(self):
        rule = {
            "id": "rule_1",
            "remediation": {
                "enabled": True,
                "max_executions": 2,
            },
        }
        log_entries = [
            {"timestamp": datetime.now(timezone.utc).isoformat()},
            {"timestamp": datetime.now(timezone.utc).isoformat()},
        ]
        assert should_remediate(rule, log_entries) is False

    def test_returns_true_when_under_max_executions(self):
        rule = {
            "id": "rule_1",
            "remediation": {
                "enabled": True,
                "max_executions": 5,
            },
        }
        log_entries = [
            {"timestamp": datetime.now(timezone.utc).isoformat()},
        ]
        assert should_remediate(rule, log_entries) is True

    def test_returns_false_when_cooldown_not_expired(self):
        rule = {
            "id": "rule_1",
            "remediation": {
                "enabled": True,
                "cooldown_minutes": 30,
            },
        }
        recent_ts = datetime.now(timezone.utc).isoformat()
        log_entries = [{"timestamp": recent_ts}]
        assert should_remediate(rule, log_entries) is False

    def test_returns_true_when_cooldown_expired(self):
        rule = {
            "id": "rule_1",
            "remediation": {
                "enabled": True,
                "cooldown_minutes": 10,
            },
        }
        old_ts = (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat()
        log_entries = [{"timestamp": old_ts}]
        assert should_remediate(rule, log_entries) is True

    def test_returns_true_with_no_previous_entries(self):
        rule = {
            "id": "rule_1",
            "remediation": {
                "enabled": True,
                "cooldown_minutes": 10,
                "max_executions": 5,
            },
        }
        assert should_remediate(rule, []) is True


# ── Database operations ──────────────────────────────────────────────────────

class TestLogRemediation:
    def test_creates_entry_with_all_fields(self, tmp_remediation_db):
        entry = log_remediation(
            rule_id="rule_cpu",
            action_id="reboot_ec2",
            params={"instance_id": "i-abc"},
            result={"status": "rebooting"},
            success=True,
            incident_id=42,
        )
        assert entry is not None
        assert entry["rule_id"] == "rule_cpu"
        assert entry["action_id"] == "reboot_ec2"
        assert entry["incident_id"] == 42
        assert entry["success"] is True
        assert entry["timestamp"] is not None

    def test_returns_dict(self, tmp_remediation_db):
        entry = log_remediation("r1", "a1", {}, {}, True)
        assert isinstance(entry, dict)

    def test_params_and_result_deserialized(self, tmp_remediation_db):
        entry = log_remediation(
            "r1", "a1",
            params={"key": "value"},
            result={"output": "done"},
            success=True,
        )
        assert isinstance(entry["params"], dict)
        assert entry["params"]["key"] == "value"
        assert isinstance(entry["result"], dict)
        assert entry["result"]["output"] == "done"


class TestGetRemediationLog:
    def test_empty_initially(self, tmp_remediation_db):
        result = get_remediation_log()
        assert result == []

    def test_filtered_by_rule_id(self, tmp_remediation_db):
        log_remediation("rule_a", "act1", {}, {}, True)
        log_remediation("rule_b", "act2", {}, {}, True)
        log_remediation("rule_a", "act3", {}, {}, False)

        result = get_remediation_log(rule_id="rule_a")
        assert len(result) == 2
        assert all(e["rule_id"] == "rule_a" for e in result)

    def test_with_limit(self, tmp_remediation_db):
        for i in range(10):
            log_remediation(f"rule_{i}", "act", {}, {}, True)
        result = get_remediation_log(limit=5)
        assert len(result) == 5

    def test_returns_all_without_filter(self, tmp_remediation_db):
        log_remediation("rule_a", "act1", {}, {}, True)
        log_remediation("rule_b", "act2", {}, {}, False)
        result = get_remediation_log()
        assert len(result) == 2


class TestGetRemediationStats:
    def test_empty_stats(self, tmp_remediation_db):
        stats = get_remediation_stats()
        assert stats["total"] == 0
        assert stats["successful"] == 0
        assert stats["failed"] == 0

    def test_with_entries(self, tmp_remediation_db):
        log_remediation("r1", "a1", {}, {}, True)
        log_remediation("r2", "a2", {}, {}, True)
        log_remediation("r3", "a3", {}, {}, False)

        stats = get_remediation_stats()
        assert stats["total"] == 3
        assert stats["successful"] == 2
        assert stats["failed"] == 1


# ── Constants ────────────────────────────────────────────────────────────────

class TestRemediationPresets:
    def test_presets_not_empty(self):
        assert len(REMEDIATION_PRESETS) > 0

    def test_each_preset_has_required_keys(self):
        required_keys = {"name", "description", "action", "params"}
        for preset in REMEDIATION_PRESETS:
            assert required_keys.issubset(preset.keys()), (
                f"Preset {preset.get('id', '?')} missing keys: "
                f"{required_keys - set(preset.keys())}"
            )
