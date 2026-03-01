"""
Tests for alert_rules.py
=========================
Covers operators, metric extraction, rule evaluation, CRUD, and constants.
"""

import json
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

import pytest

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from alert_rules import (
    OPERATORS,
    SERVICE_METRICS,
    RULE_TEMPLATES,
    _extract_metric_value,
    evaluate_rules,
    get_rules,
    save_rules,
    add_rule,
    update_rule,
    delete_rule,
    add_template,
)


# ─── OPERATORS ───────────────────────────────────────────────────────────────

class TestOperators:
    def test_gt_true(self):
        assert OPERATORS[">"](10, 5) is True

    def test_gt_false(self):
        assert OPERATORS[">"](3, 5) is False

    def test_lt_true(self):
        assert OPERATORS["<"](3, 5) is True

    def test_lt_false(self):
        assert OPERATORS["<"](10, 5) is False

    def test_gte_true_equal(self):
        assert OPERATORS[">="](5, 5) is True

    def test_gte_true_greater(self):
        assert OPERATORS[">="](6, 5) is True

    def test_gte_false(self):
        assert OPERATORS[">="](4, 5) is False

    def test_lte_true_equal(self):
        assert OPERATORS["<="](5, 5) is True

    def test_lte_true_less(self):
        assert OPERATORS["<="](4, 5) is True

    def test_lte_false(self):
        assert OPERATORS["<="](6, 5) is False

    def test_eq_true(self):
        assert OPERATORS["=="](5, 5) is True

    def test_eq_false(self):
        assert OPERATORS["=="](5, 6) is False

    def test_ne_true(self):
        assert OPERATORS["!="](5, 6) is True

    def test_ne_false(self):
        assert OPERATORS["!="](5, 5) is False

    def test_contains_true(self):
        assert OPERATORS["contains"]("hello world", "world") is True

    def test_contains_case_insensitive(self):
        assert OPERATORS["contains"]("Hello World", "hello") is True

    def test_contains_false(self):
        assert OPERATORS["contains"]("hello world", "xyz") is False

    def test_not_contains_true(self):
        assert OPERATORS["not_contains"]("hello", "xyz") is True

    def test_not_contains_false(self):
        assert OPERATORS["not_contains"]("hello world", "world") is False

    def test_gt_with_floats(self):
        assert OPERATORS[">"](3.14, 2.71) is True

    def test_lt_with_int_and_float(self):
        assert OPERATORS["<"](2, 3.5) is True


# ─── _extract_metric_value ───────────────────────────────────────────────────

class TestExtractMetricValue:
    def test_direct_key(self):
        resource = {"cpu_utilization": 75.2, "state": "running"}
        assert _extract_metric_value(resource, "cpu_utilization", "ec2") == 75.2

    def test_direct_key_string(self):
        resource = {"state": "running"}
        assert _extract_metric_value(resource, "state", "ec2") == "running"

    def test_ecs_running_vs_desired(self):
        resource = {"running": 3, "desired": 5}
        assert _extract_metric_value(resource, "running_vs_desired", "ecs") == -2

    def test_ecs_running_vs_desired_equal(self):
        resource = {"running": 5, "desired": 5}
        assert _extract_metric_value(resource, "running_vs_desired", "ecs") == 0

    def test_missing_key_returns_none(self):
        resource = {"state": "running"}
        assert _extract_metric_value(resource, "nonexistent", "ec2") is None

    def test_missing_key_non_ecs(self):
        resource = {"status": "ACTIVE"}
        assert _extract_metric_value(resource, "running_vs_desired", "mediaconnect") is None

    def test_ecs_defaults_when_keys_missing(self):
        resource = {}
        # running defaults to 0, desired defaults to 1
        assert _extract_metric_value(resource, "running_vs_desired", "ecs") == -1


# ─── evaluate_rules ──────────────────────────────────────────────────────────

class TestEvaluateRules:
    def test_empty_rules_returns_empty(self, tmp_config):
        result = evaluate_rules({})
        assert result == []

    def test_disabled_rule_skipped(self, tmp_config):
        add_rule({
            "name": "Disabled rule",
            "enabled": False,
            "service": "ec2",
            "metric": "cpu_utilization",
            "operator": ">",
            "threshold": 80,
        })
        infra = {"ec2": {"instances": [{"instance_id": "i-123", "cpu_utilization": 95}]}}
        result = evaluate_rules(infra)
        assert len(result) == 0

    def test_rule_triggers_gt_threshold(self, tmp_config):
        add_rule({
            "name": "High CPU",
            "service": "ec2",
            "metric": "cpu_utilization",
            "operator": ">",
            "threshold": 80,
            "resource_filter": "*",
        })
        infra = {"ec2": {"instances": [{"instance_id": "i-123", "cpu_utilization": 95}]}}
        result = evaluate_rules(infra)
        assert len(result) == 1
        assert result[0]["value"] == 95.0

    def test_rule_does_not_trigger_below_threshold(self, tmp_config):
        add_rule({
            "name": "High CPU",
            "service": "ec2",
            "metric": "cpu_utilization",
            "operator": ">",
            "threshold": 80,
            "resource_filter": "*",
        })
        infra = {"ec2": {"instances": [{"instance_id": "i-123", "cpu_utilization": 50}]}}
        result = evaluate_rules(infra)
        assert len(result) == 0

    def test_rule_triggers_lt_operator(self, tmp_config):
        add_rule({
            "name": "Low viewers",
            "service": "ivs",
            "metric": "viewer_count",
            "operator": "<",
            "threshold": 10,
            "resource_filter": "*",
        })
        infra = {"ivs": {"channels": [{"channel_id": "ch-1", "viewer_count": 3}]}}
        result = evaluate_rules(infra)
        assert len(result) == 1

    def test_rule_triggers_string_eq(self, tmp_config):
        add_rule({
            "name": "Stopped instance",
            "service": "ec2",
            "metric": "state",
            "operator": "==",
            "threshold": "stopped",
            "resource_filter": "*",
        })
        infra = {"ec2": {"instances": [{"instance_id": "i-abc", "state": "stopped"}]}}
        result = evaluate_rules(infra)
        assert len(result) == 1

    def test_cooldown_prevents_retrigger(self, tmp_config):
        rule = add_rule({
            "name": "Test cooldown",
            "service": "ec2",
            "metric": "cpu_utilization",
            "operator": ">",
            "threshold": 80,
            "resource_filter": "*",
            "cooldown_minutes": 15,
        })
        # Manually set last_triggered to recent
        rules = get_rules()
        rules[0]["last_triggered"] = datetime.now(timezone.utc).isoformat()
        save_rules(rules)

        infra = {"ec2": {"instances": [{"instance_id": "i-123", "cpu_utilization": 95}]}}
        result = evaluate_rules(infra)
        assert len(result) == 0

    def test_cooldown_expired_allows_retrigger(self, tmp_config):
        rule = add_rule({
            "name": "Test cooldown expired",
            "service": "ec2",
            "metric": "cpu_utilization",
            "operator": ">",
            "threshold": 80,
            "resource_filter": "*",
            "cooldown_minutes": 15,
        })
        # Set last_triggered to 20 minutes ago
        rules = get_rules()
        past = (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat()
        rules[0]["last_triggered"] = past
        save_rules(rules)

        infra = {"ec2": {"instances": [{"instance_id": "i-123", "cpu_utilization": 95}]}}
        result = evaluate_rules(infra)
        assert len(result) == 1

    def test_resource_filter_specific_id(self, tmp_config):
        add_rule({
            "name": "Specific instance",
            "service": "ec2",
            "metric": "cpu_utilization",
            "operator": ">",
            "threshold": 80,
            "resource_filter": "i-specific",
        })
        infra = {"ec2": {"instances": [
            {"instance_id": "i-specific", "cpu_utilization": 95},
            {"instance_id": "i-other", "cpu_utilization": 95},
        ]}}
        result = evaluate_rules(infra)
        assert len(result) == 1
        assert result[0]["resource_id"] == "i-specific"

    def test_resource_filter_wildcard_matches_all(self, tmp_config):
        add_rule({
            "name": "All instances",
            "service": "ec2",
            "metric": "cpu_utilization",
            "operator": ">",
            "threshold": 80,
            "resource_filter": "*",
        })
        infra = {"ec2": {"instances": [
            {"instance_id": "i-aaa", "cpu_utilization": 95},
            {"instance_id": "i-bbb", "cpu_utilization": 90},
        ]}}
        result = evaluate_rules(infra)
        assert len(result) == 2

    def test_boolean_normalization(self, tmp_config):
        add_rule({
            "name": "Input loss",
            "service": "medialive",
            "metric": "input_loss",
            "operator": "==",
            "threshold": "true",
            "resource_filter": "*",
        })
        infra = {"medialive": {"channels": [{"channel_id": "ch-1", "input_loss": True}]}}
        result = evaluate_rules(infra)
        assert len(result) == 1

    def test_type_coercion_numeric(self, tmp_config):
        add_rule({
            "name": "High CPU int",
            "service": "ec2",
            "metric": "cpu_utilization",
            "operator": ">",
            "threshold": 80,
            "resource_filter": "*",
        })
        # cpu_utilization as int rather than float
        infra = {"ec2": {"instances": [{"instance_id": "i-123", "cpu_utilization": 95}]}}
        result = evaluate_rules(infra)
        assert len(result) == 1

    def test_trigger_count_incremented(self, tmp_config):
        add_rule({
            "name": "Trigger count test",
            "service": "ec2",
            "metric": "cpu_utilization",
            "operator": ">",
            "threshold": 80,
            "resource_filter": "*",
        })
        infra = {"ec2": {"instances": [{"instance_id": "i-123", "cpu_utilization": 95}]}}
        evaluate_rules(infra)
        rules = get_rules()
        assert rules[0]["trigger_count"] == 1

    def test_last_triggered_set(self, tmp_config):
        add_rule({
            "name": "Timestamp test",
            "service": "ec2",
            "metric": "cpu_utilization",
            "operator": ">",
            "threshold": 80,
            "resource_filter": "*",
        })
        infra = {"ec2": {"instances": [{"instance_id": "i-123", "cpu_utilization": 95}]}}
        evaluate_rules(infra)
        rules = get_rules()
        assert rules[0]["last_triggered"] is not None

    def test_contains_operator_string_field(self, tmp_config):
        add_rule({
            "name": "Contains test",
            "service": "ec2",
            "metric": "status_checks",
            "operator": "contains",
            "threshold": "impair",
            "resource_filter": "*",
        })
        infra = {"ec2": {"instances": [{"instance_id": "i-123", "status_checks": "impaired"}]}}
        result = evaluate_rules(infra)
        assert len(result) == 1

    def test_multiple_resources_only_matching_trigger(self, tmp_config):
        add_rule({
            "name": "High CPU",
            "service": "ec2",
            "metric": "cpu_utilization",
            "operator": ">",
            "threshold": 80,
            "resource_filter": "*",
        })
        infra = {"ec2": {"instances": [
            {"instance_id": "i-high", "cpu_utilization": 95},
            {"instance_id": "i-low", "cpu_utilization": 30},
            {"instance_id": "i-mid", "cpu_utilization": 85},
        ]}}
        result = evaluate_rules(infra)
        assert len(result) == 2
        ids = {r["resource_id"] for r in result}
        assert ids == {"i-high", "i-mid"}


# ─── CRUD ────────────────────────────────────────────────────────────────────

class TestCRUD:
    def test_add_rule_returns_dict_with_id(self, tmp_config):
        rule = add_rule({"name": "Test Rule", "service": "ec2"})
        assert isinstance(rule, dict)
        assert "id" in rule
        assert len(rule["id"]) == 8

    def test_get_rules_empty_initially(self, tmp_config):
        rules = get_rules()
        assert rules == []

    def test_get_rules_returns_added(self, tmp_config):
        add_rule({"name": "Rule A"})
        add_rule({"name": "Rule B"})
        rules = get_rules()
        assert len(rules) == 2
        assert rules[0]["name"] == "Rule A"
        assert rules[1]["name"] == "Rule B"

    def test_update_rule_changes_allowed_fields(self, tmp_config):
        rule = add_rule({"name": "Original"})
        updated = update_rule(rule["id"], {"name": "Updated", "enabled": False})
        assert updated is not None
        assert updated["name"] == "Updated"
        assert updated["enabled"] is False

    def test_update_rule_blocks_disallowed_fields(self, tmp_config):
        rule = add_rule({"name": "Untouched"})
        updated = update_rule(rule["id"], {"last_triggered": "2025-01-01", "trigger_count": 999})
        assert updated is not None
        assert updated["last_triggered"] is None
        assert updated["trigger_count"] == 0

    def test_update_rule_nonexistent_returns_none(self, tmp_config):
        result = update_rule("nonexistent-id", {"name": "Doesn't matter"})
        assert result is None

    def test_delete_rule_removes(self, tmp_config):
        rule = add_rule({"name": "To Delete"})
        assert delete_rule(rule["id"]) is True
        assert len(get_rules()) == 0

    def test_delete_rule_nonexistent_returns_false(self, tmp_config):
        assert delete_rule("nonexistent-id") is False

    def test_add_template_valid_index(self, tmp_config):
        rule = add_template(0)
        assert rule is not None
        assert isinstance(rule, dict)
        assert "id" in rule
        assert rule["name"] == RULE_TEMPLATES[0]["name"]

    def test_add_template_invalid_index_returns_none(self, tmp_config):
        assert add_template(-1) is None
        assert add_template(9999) is None


# ─── Constants ───────────────────────────────────────────────────────────────

class TestConstants:
    def test_rule_templates_not_empty(self):
        assert len(RULE_TEMPLATES) > 0

    def test_service_metrics_not_empty(self):
        assert len(SERVICE_METRICS) > 0

    def test_every_template_service_in_service_metrics(self):
        for tpl in RULE_TEMPLATES:
            assert tpl["service"] in SERVICE_METRICS, (
                f"Template '{tpl['name']}' references service '{tpl['service']}' "
                f"not found in SERVICE_METRICS"
            )
