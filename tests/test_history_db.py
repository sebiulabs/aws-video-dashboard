"""Tests for history_db module."""

import json

import pytest

from history_db import save_snapshot, get_history, _avg_cpu


class TestGetHistoryEmpty:
    def test_get_history_returns_empty_list_initially(self, tmp_history_db):
        result = get_history()
        assert result == []


class TestSaveAndRetrieve:
    def test_save_snapshot_and_retrieve_returns_one_entry(self, tmp_history_db):
        summary = {
            "timestamp": "2025-01-01T00:00:00Z",
            "ec2": {"total": 3, "running": 2, "healthy": 2, "alerts": 0},
        }
        save_snapshot(summary)
        history = get_history()
        assert len(history) == 1
        assert history[0]["timestamp"] == "2025-01-01T00:00:00Z"

    def test_multiple_snapshots_maintain_correct_count(self, tmp_history_db):
        for i in range(5):
            save_snapshot({
                "timestamp": f"2025-01-01T0{i}:00:00Z",
                "ec2": {"total": i, "running": i, "healthy": i, "alerts": 0},
            })
        history = get_history()
        assert len(history) == 5

    def test_get_history_with_limit_parameter(self, tmp_history_db):
        for i in range(10):
            save_snapshot({
                "timestamp": f"2025-01-01T{i:02d}:00:00Z",
                "ec2": {"total": i, "running": i, "healthy": i, "alerts": 0},
            })
        history = get_history(limit=3)
        assert len(history) == 3

    def test_default_limit_is_500(self, tmp_history_db):
        # Save a small number and confirm we get all of them back (default limit=500)
        for i in range(10):
            save_snapshot({
                "timestamp": f"2025-01-01T{i:02d}:00:00Z",
                "ec2": {"total": 0, "running": 0, "healthy": 0, "alerts": 0},
            })
        # Default call should return all 10 (well under 500)
        history = get_history()
        assert len(history) == 10


class TestFieldExtraction:
    def test_ec2_fields_extracted_correctly(self, tmp_history_db):
        summary = {
            "timestamp": "2025-01-01T00:00:00Z",
            "ec2": {"total": 5, "running": 3, "healthy": 2, "alerts": 1},
        }
        save_snapshot(summary)
        entry = get_history()[0]
        assert entry["ec2_total"] == 5
        assert entry["ec2_running"] == 3
        assert entry["ec2_healthy"] == 2

    def test_avg_cpu_calculated_from_instances(self, tmp_history_db):
        summary = {
            "timestamp": "2025-01-01T00:00:00Z",
            "ec2": {
                "total": 2, "running": 2, "healthy": 2, "alerts": 0,
                "instances": [
                    {"cpu_utilization": 40.0},
                    {"cpu_utilization": 60.0},
                ],
            },
        }
        save_snapshot(summary)
        entry = get_history()[0]
        assert entry["avg_cpu"] == 50.0

    def test_avg_cpu_with_no_instances_returns_none(self, tmp_history_db):
        summary = {
            "timestamp": "2025-01-01T00:00:00Z",
            "ec2": {"total": 0, "running": 0, "healthy": 0, "alerts": 0, "instances": []},
        }
        save_snapshot(summary)
        entry = get_history()[0]
        assert entry["avg_cpu"] is None

    def test_ecs_fields_extracted_if_present(self, tmp_history_db):
        summary = {
            "timestamp": "2025-01-01T00:00:00Z",
            "ec2": {"total": 0, "running": 0, "healthy": 0, "alerts": 0},
            "ecs_services": [
                {"name": "svc1", "healthy": True},
                {"name": "svc2", "healthy": False},
                {"name": "svc3", "healthy": True},
            ],
        }
        save_snapshot(summary)
        entry = get_history()[0]
        assert entry["ecs_total"] == 3
        assert entry["ecs_healthy"] == 2

    def test_endpoint_fields_extracted_if_present(self, tmp_history_db):
        summary = {
            "timestamp": "2025-01-01T00:00:00Z",
            "ec2": {"total": 0, "running": 0, "healthy": 0, "alerts": 0},
            "easy_monitor": {"total": 5, "up": 4},
        }
        save_snapshot(summary)
        entry = get_history()[0]
        assert entry["endpoints_total"] == 5
        assert entry["endpoints_up"] == 4

    def test_deploy_fields_extracted_if_present(self, tmp_history_db):
        summary = {
            "timestamp": "2025-01-01T00:00:00Z",
            "ec2": {"total": 0, "running": 0, "healthy": 0, "alerts": 0},
            "deployments": {"failed": 2},
        }
        save_snapshot(summary)
        entry = get_history()[0]
        assert entry["deploy_failed"] == 2

    def test_empty_minimal_data_doesnt_crash(self, tmp_history_db):
        save_snapshot({})
        history = get_history()
        assert len(history) == 1
        entry = history[0]
        assert entry["ec2_total"] == 0
        assert entry["avg_cpu"] is None


class TestAvgCpuHelper:
    def test_avg_cpu_with_values(self):
        summary = {"ec2": {"instances": [
            {"cpu_utilization": 20.0},
            {"cpu_utilization": 80.0},
        ]}}
        assert _avg_cpu(summary) == 50.0

    def test_avg_cpu_no_instances(self):
        assert _avg_cpu({"ec2": {"instances": []}}) is None

    def test_avg_cpu_missing_ec2(self):
        assert _avg_cpu({}) is None
