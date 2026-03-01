"""Tests for schedule_manager module."""

import pytest

from schedule_manager import (
    _validate_cron,
    create_schedule,
    get_schedules,
    get_schedule,
    update_schedule,
    delete_schedule,
    toggle_schedule,
    log_run,
    get_runs,
    get_schedule_stats,
)


# ── _validate_cron pure logic ────────────────────────────────────────────────

class TestValidateCron:
    def test_valid_daily_at_8am(self):
        assert _validate_cron("0 8 * * *") is True

    def test_valid_weekdays(self):
        assert _validate_cron("0 8 * * 1-5") is True

    def test_valid_every_15_min(self):
        assert _validate_cron("*/15 * * * *") is True

    def test_valid_list_values(self):
        assert _validate_cron("0,15,30,45 * * * *") is True

    def test_valid_step_and_range(self):
        assert _validate_cron("0 */6 * * *") is True

    def test_invalid_too_few_fields(self):
        assert _validate_cron("0 8 *") is False

    def test_invalid_too_many_fields(self):
        assert _validate_cron("0 8 * * * *") is False

    def test_invalid_bad_characters(self):
        assert _validate_cron("0 8 * * abc") is False

    def test_invalid_empty_string(self):
        assert _validate_cron("") is False

    def test_invalid_none(self):
        assert _validate_cron(None) is False


# ── CRUD operations ──────────────────────────────────────────────────────────

class TestCreateSchedule:
    def test_returns_dict_with_id(self, tmp_schedules_db):
        sched = create_schedule(
            name="Daily backup",
            action_id="backup_action",
            action_params={"bucket": "my-bucket"},
            cron_expression="0 2 * * *",
        )
        assert isinstance(sched, dict)
        assert "id" in sched

    def test_invalid_cron_returns_none(self, tmp_schedules_db):
        result = create_schedule(
            name="Bad schedule",
            action_id="action",
            action_params={},
            cron_expression="invalid",
        )
        assert result is None

    def test_sets_defaults(self, tmp_schedules_db):
        sched = create_schedule(
            name="Defaults",
            action_id="act",
            action_params={},
            cron_expression="0 * * * *",
        )
        assert sched["enabled"] == 1
        assert sched["run_count"] == 0


class TestGetSchedules:
    def test_returns_empty_initially(self, tmp_schedules_db):
        result = get_schedules()
        assert result == []

    def test_enabled_only_filter(self, tmp_schedules_db):
        s1 = create_schedule("S1", "a", {}, "0 * * * *")
        s2 = create_schedule("S2", "a", {}, "0 * * * *")
        toggle_schedule(s2["id"])  # disable s2

        enabled = get_schedules(enabled_only=True)
        assert len(enabled) == 1
        assert enabled[0]["id"] == s1["id"]

    def test_returns_all_when_not_filtered(self, tmp_schedules_db):
        create_schedule("S1", "a", {}, "0 * * * *")
        create_schedule("S2", "a", {}, "0 * * * *")
        all_scheds = get_schedules()
        assert len(all_scheds) == 2


class TestGetSchedule:
    def test_get_by_id(self, tmp_schedules_db):
        created = create_schedule("Find me", "act", {}, "0 8 * * *")
        fetched = get_schedule(created["id"])
        assert fetched["name"] == "Find me"

    def test_nonexistent_returns_none(self, tmp_schedules_db):
        result = get_schedule(9999)
        assert result is None


class TestUpdateSchedule:
    def test_changes_allowed_fields(self, tmp_schedules_db):
        sched = create_schedule("Original", "act", {}, "0 8 * * *")
        updated = update_schedule(sched["id"], {"name": "Updated"})
        assert updated["name"] == "Updated"

    def test_invalid_cron_rejected(self, tmp_schedules_db):
        sched = create_schedule("Cron test", "act", {}, "0 8 * * *")
        result = update_schedule(sched["id"], {"cron_expression": "bad"})
        assert result is None

    def test_ignores_unknown_fields(self, tmp_schedules_db):
        sched = create_schedule("Ignore test", "act", {}, "0 8 * * *")
        updated = update_schedule(sched["id"], {"unknown_field": "value"})
        # Should still return the schedule, just without applying unknown fields
        assert updated is not None
        assert updated["name"] == "Ignore test"


class TestDeleteSchedule:
    def test_removes_schedule(self, tmp_schedules_db):
        sched = create_schedule("Delete me", "act", {}, "0 8 * * *")
        result = delete_schedule(sched["id"])
        assert result is True
        assert get_schedule(sched["id"]) is None

    def test_nonexistent_returns_true(self, tmp_schedules_db):
        # delete_schedule always returns True (even for nonexistent ids)
        result = delete_schedule(9999)
        assert result is True


class TestToggleSchedule:
    def test_disables_enabled_schedule(self, tmp_schedules_db):
        sched = create_schedule("Toggle me", "act", {}, "0 8 * * *")
        assert sched["enabled"] == 1
        toggled = toggle_schedule(sched["id"])
        assert toggled["enabled"] == 0

    def test_enables_disabled_schedule(self, tmp_schedules_db):
        sched = create_schedule("Toggle me", "act", {}, "0 8 * * *")
        toggle_schedule(sched["id"])  # disable
        toggled = toggle_schedule(sched["id"])  # re-enable
        assert toggled["enabled"] == 1

    def test_nonexistent_returns_none(self, tmp_schedules_db):
        result = toggle_schedule(9999)
        assert result is None


# ── Run logging ──────────────────────────────────────────────────────────────

class TestLogRun:
    def test_records_success(self, tmp_schedules_db):
        sched = create_schedule("Run test", "act", {}, "0 * * * *")
        run = log_run(sched["id"], success=True, result="ok")
        assert run is not None
        assert run["success"] == 1

    def test_records_failure(self, tmp_schedules_db):
        sched = create_schedule("Run test", "act", {}, "0 * * * *")
        run = log_run(sched["id"], success=False, result="error: timeout")
        assert run is not None
        assert run["success"] == 0

    def test_increments_run_count(self, tmp_schedules_db):
        sched = create_schedule("Count test", "act", {}, "0 * * * *")
        log_run(sched["id"], success=True, result="ok")
        log_run(sched["id"], success=True, result="ok")
        updated = get_schedule(sched["id"])
        assert updated["run_count"] == 2


class TestGetRuns:
    def test_returns_run_history(self, tmp_schedules_db):
        sched = create_schedule("History test", "act", {}, "0 * * * *")
        log_run(sched["id"], success=True, result="run 1")
        log_run(sched["id"], success=False, result="run 2")
        runs = get_runs(sched["id"])
        assert len(runs) == 2

    def test_with_limit(self, tmp_schedules_db):
        sched = create_schedule("Limit test", "act", {}, "0 * * * *")
        for i in range(5):
            log_run(sched["id"], success=True, result=f"run {i}")
        runs = get_runs(sched["id"], limit=3)
        assert len(runs) == 3


# ── Stats ────────────────────────────────────────────────────────────────────

class TestGetScheduleStats:
    def test_empty_stats(self, tmp_schedules_db):
        stats = get_schedule_stats()
        assert stats["total"] == 0
        assert stats["enabled"] == 0
        assert stats["disabled"] == 0
        assert stats["runs_today"] == 0

    def test_with_schedules(self, tmp_schedules_db):
        s1 = create_schedule("Enabled", "act", {}, "0 * * * *")
        s2 = create_schedule("Disabled", "act", {}, "0 * * * *")
        toggle_schedule(s2["id"])  # disable
        log_run(s1["id"], success=True, result="ok")

        stats = get_schedule_stats()
        assert stats["total"] == 2
        assert stats["enabled"] == 1
        assert stats["disabled"] == 1
        assert stats["runs_today"] >= 1
