"""Tests for log_viewer.py — pure logic and mocked CloudWatch Logs calls."""

from unittest.mock import MagicMock, patch, call

import pytest
from botocore.exceptions import ClientError

import log_viewer


# ═════════════════════════════════════════════════════════════════════════════
# PURE LOGIC
# ═════════════════════════════════════════════════════════════════════════════


class TestGetBotoKwargs:
    def test_with_credentials(self, sample_config):
        kwargs = log_viewer._get_boto_kwargs(sample_config)
        assert kwargs["aws_access_key_id"] == "AKIAIOSFODNN7EXAMPLE"
        assert kwargs["aws_secret_access_key"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert kwargs["region_name"] == "eu-west-2"

    def test_without_credentials(self):
        config = {"aws": {"region": "us-east-1"}}
        kwargs = log_viewer._get_boto_kwargs(config)
        assert "aws_access_key_id" not in kwargs
        assert kwargs["region_name"] == "us-east-1"


# ═════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═════════════════════════════════════════════════════════════════════════════


def _make_client_error(code="AccessDenied", message="Access Denied"):
    return ClientError(
        {"Error": {"Code": code, "Message": message}},
        "TestOperation",
    )


# ═════════════════════════════════════════════════════════════════════════════
# LIST LOG GROUPS
# ═════════════════════════════════════════════════════════════════════════════


class TestListLogGroups:
    @patch("log_viewer.boto3.client")
    def test_success(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.describe_log_groups.return_value = {
            "logGroups": [
                {
                    "logGroupName": "/aws/lambda/my-func",
                    "storedBytes": 1024000,
                    "retentionInDays": 30,
                    "creationTime": 1705000000000,
                },
                {
                    "logGroupName": "/aws/ecs/my-service",
                    "storedBytes": 512000,
                    "retentionInDays": 14,
                    "creationTime": 1704000000000,
                },
            ]
        }

        result = log_viewer.list_log_groups(sample_config)
        assert len(result) == 2
        assert result[0]["name"] == "/aws/lambda/my-func"
        assert result[0]["stored_bytes"] == 1024000
        assert result[0]["retention_days"] == 30

    @patch("log_viewer.boto3.client")
    def test_with_prefix_filter(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.describe_log_groups.return_value = {
            "logGroups": [
                {
                    "logGroupName": "/aws/lambda/my-func",
                    "storedBytes": 1024000,
                    "retentionInDays": 30,
                    "creationTime": 1705000000000,
                }
            ]
        }

        result = log_viewer.list_log_groups(sample_config, prefix="/aws/lambda")
        assert len(result) == 1
        # Verify the prefix was passed to the API
        call_kwargs = mock_client.describe_log_groups.call_args[1]
        assert call_kwargs["logGroupNamePrefix"] == "/aws/lambda"

    @patch("log_viewer.boto3.client")
    def test_client_error(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.describe_log_groups.side_effect = _make_client_error()

        result = log_viewer.list_log_groups(sample_config)
        assert result == []


# ═════════════════════════════════════════════════════════════════════════════
# LIST LOG STREAMS
# ═════════════════════════════════════════════════════════════════════════════


class TestListLogStreams:
    @patch("log_viewer.boto3.client")
    def test_success(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.describe_log_streams.return_value = {
            "logStreams": [
                {
                    "logStreamName": "2024/01/15/[$LATEST]abc123",
                    "firstEventTimestamp": 1705000000000,
                    "lastEventTimestamp": 1705003600000,
                    "storedBytes": 4096,
                },
            ]
        }

        result = log_viewer.list_log_streams(
            sample_config, group="/aws/lambda/my-func"
        )
        assert len(result) == 1
        assert result[0]["name"] == "2024/01/15/[$LATEST]abc123"
        assert result[0]["stored_bytes"] == 4096

    @patch("log_viewer.boto3.client")
    def test_empty(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.describe_log_streams.return_value = {"logStreams": []}

        result = log_viewer.list_log_streams(
            sample_config, group="/aws/lambda/my-func"
        )
        assert result == []


# ═════════════════════════════════════════════════════════════════════════════
# GET LOG EVENTS
# ═════════════════════════════════════════════════════════════════════════════


class TestGetLogEvents:
    @patch("log_viewer.boto3.client")
    def test_success_with_events(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.get_log_events.return_value = {
            "events": [
                {
                    "timestamp": 1705000000000,
                    "message": "START RequestId: abc-123",
                    "ingestionTime": 1705000001000,
                },
                {
                    "timestamp": 1705000001000,
                    "message": "END RequestId: abc-123",
                    "ingestionTime": 1705000002000,
                },
            ]
        }

        result = log_viewer.get_log_events(
            sample_config,
            group="/aws/lambda/my-func",
            stream="2024/01/15/[$LATEST]abc123",
        )
        assert len(result) == 2
        assert result[0]["message"] == "START RequestId: abc-123"
        assert result[0]["timestamp"] == 1705000000000

    @patch("log_viewer.boto3.client")
    def test_with_time_range(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.get_log_events.return_value = {"events": []}

        log_viewer.get_log_events(
            sample_config,
            group="/aws/lambda/my-func",
            stream="stream-1",
            start_time=1705000000000,
            end_time=1705003600000,
        )

        call_kwargs = mock_client.get_log_events.call_args[1]
        assert call_kwargs["startTime"] == 1705000000000
        assert call_kwargs["endTime"] == 1705003600000

    @patch("log_viewer.boto3.client")
    def test_client_error(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.get_log_events.side_effect = _make_client_error()

        result = log_viewer.get_log_events(
            sample_config,
            group="/aws/lambda/my-func",
            stream="stream-1",
        )
        assert result == []


# ═════════════════════════════════════════════════════════════════════════════
# SEARCH LOGS
# ═════════════════════════════════════════════════════════════════════════════


class TestSearchLogs:
    @patch("log_viewer.time.sleep")
    @patch("log_viewer.time.monotonic")
    @patch("log_viewer.boto3.client")
    def test_success(self, mock_boto_client, mock_monotonic, mock_sleep, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        mock_client.start_query.return_value = {"queryId": "query-abc"}
        mock_client.get_query_results.return_value = {
            "status": "Complete",
            "results": [
                [
                    {"field": "@timestamp", "value": "2024-01-15 10:00:00"},
                    {"field": "@message", "value": "Test log message"},
                ]
            ],
        }
        # monotonic: first call sets deadline (0+30=30), second call checks loop (< 30)
        mock_monotonic.side_effect = [0, 1]

        result = log_viewer.search_logs(
            sample_config,
            group="/aws/lambda/my-func",
            query="fields @timestamp, @message | sort @timestamp desc | limit 10",
        )
        assert len(result) == 1
        assert result[0]["@timestamp"] == "2024-01-15 10:00:00"
        assert result[0]["@message"] == "Test log message"

    @patch("log_viewer.time.sleep")
    @patch("log_viewer.time.monotonic")
    @patch("log_viewer.boto3.client")
    def test_timeout_incomplete(self, mock_boto_client, mock_monotonic, mock_sleep, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        mock_client.start_query.return_value = {"queryId": "query-timeout"}
        mock_client.get_query_results.return_value = {
            "status": "Running",
            "results": [],
        }
        # Simulate time passing beyond deadline
        mock_monotonic.side_effect = [0, 31]

        result = log_viewer.search_logs(
            sample_config,
            group="/aws/lambda/my-func",
        )
        assert result == []

    @patch("log_viewer.time.sleep")
    @patch("log_viewer.time.monotonic")
    @patch("log_viewer.boto3.client")
    def test_no_results(self, mock_boto_client, mock_monotonic, mock_sleep, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        mock_client.start_query.return_value = {"queryId": "query-empty"}
        mock_client.get_query_results.return_value = {
            "status": "Complete",
            "results": [],
        }
        mock_monotonic.side_effect = [0, 1]

        result = log_viewer.search_logs(
            sample_config,
            group="/aws/lambda/my-func",
        )
        assert result == []
