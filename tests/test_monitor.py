"""
Tests for monitor.py
=====================
Covers uptime calculation, error sanitization, boto kwargs, mocked AWS checks,
and alert formatting / summary generation.
"""

import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

import pytest

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from monitor import (
    _calc_uptime,
    _sanitize_error,
    _get_boto_kwargs,
    check_ec2_instances,
    check_ecs_services,
    get_cpu_utilization,
    format_alert_message,
    generate_summary,
    InstanceStatus,
    DeploymentStatus,
)


# ─── _calc_uptime ───────────────────────────────────────────────────────────

class TestCalcUptime:
    def test_none_returns_none(self):
        hours, display = _calc_uptime(None)
        assert hours is None
        assert display == ""

    def test_with_datetime_returns_tuple(self):
        lt = datetime.now(timezone.utc) - timedelta(hours=5, minutes=30)
        hours, display = _calc_uptime(lt)
        assert isinstance(hours, float)
        assert hours >= 5.0
        assert isinstance(display, str)

    def test_display_format_with_days(self):
        lt = datetime.now(timezone.utc) - timedelta(days=3, hours=2, minutes=15)
        hours, display = _calc_uptime(lt)
        assert "3d" in display
        assert "h" in display

    def test_display_format_hours_only(self):
        lt = datetime.now(timezone.utc) - timedelta(hours=7, minutes=45)
        hours, display = _calc_uptime(lt)
        assert "d" not in display
        assert "h" in display
        assert "m" in display

    def test_display_format_minutes_only(self):
        lt = datetime.now(timezone.utc) - timedelta(minutes=15)
        hours, display = _calc_uptime(lt)
        assert "d" not in display
        assert "h" not in display
        assert "m" in display

    def test_with_iso_string(self):
        lt = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        hours, display = _calc_uptime(lt)
        assert isinstance(hours, float)
        assert hours >= 1.9


# ─── _sanitize_error ────────────────────────────────────────────────────────

class TestSanitizeError:
    def test_strips_akia_access_key(self):
        msg = "Error with key AKIAIOSFODNN7EXAMPLE"
        result = _sanitize_error(msg)
        assert "AKIAIOSFODNN" not in result
        assert "****" in result

    def test_strips_asia_temp_credentials(self):
        msg = "Creds: ASIAIOSFODNN7EXAMPLE"
        result = _sanitize_error(msg)
        assert "ASIAIOSFODNN" not in result
        assert "****" in result

    def test_strips_12_digit_account_id(self):
        msg = "Account 123456789012 not authorized"
        result = _sanitize_error(msg)
        assert "123456789012" not in result
        assert "****" in result

    def test_strips_arn(self):
        # The 12-digit account ID regex runs first, partially sanitizing the ARN.
        # Verify the account number is removed from the ARN string.
        msg = "arn:aws:iam:us-east-1:123456789012:role/MyRole not found"
        result = _sanitize_error(msg)
        assert "123456789012" not in result
        assert "****" in result

    def test_preserves_normal_text(self):
        msg = "Connection timed out after 30 seconds"
        result = _sanitize_error(msg)
        assert result == msg


# ─── _get_boto_kwargs ────────────────────────────────────────────────────────

class TestGetBotoKwargs:
    def test_with_access_keys(self, sample_config):
        kwargs = _get_boto_kwargs(sample_config)
        assert "aws_access_key_id" in kwargs
        assert "aws_secret_access_key" in kwargs
        assert kwargs["region_name"] == "eu-west-2"

    def test_without_keys_returns_region_only(self):
        config = {
            "aws": {
                "region": "us-east-1",
                "access_key_id": "",
                "secret_access_key": "",
            }
        }
        kwargs = _get_boto_kwargs(config)
        assert "aws_access_key_id" not in kwargs
        assert "aws_secret_access_key" not in kwargs
        assert kwargs["region_name"] == "us-east-1"

    def test_with_masked_keys_excluded(self):
        config = {
            "aws": {
                "region": "eu-west-2",
                "access_key_id": "",
                "secret_access_key": "",
            }
        }
        kwargs = _get_boto_kwargs(config)
        assert "aws_access_key_id" not in kwargs

    def test_custom_region_override(self, sample_config):
        kwargs = _get_boto_kwargs(sample_config, region="ap-southeast-1")
        assert kwargs["region_name"] == "ap-southeast-1"


# ─── Mocked AWS Checks ──────────────────────────────────────────────────────

class TestCheckEc2Instances:
    @patch("monitor.get_cpu_utilization", return_value=45.0)
    @patch("monitor.boto3.client")
    def test_success_running_instances(self, mock_boto_client, mock_cpu, sample_config):
        mock_ec2 = MagicMock()
        mock_boto_client.return_value = mock_ec2

        mock_paginator = MagicMock()
        mock_ec2.get_paginator.return_value = mock_paginator

        # describe_instances paginator
        mock_paginator.paginate.side_effect = [
            # First call: describe_instances
            [{"Reservations": [{"Instances": [{
                "InstanceId": "i-abc123",
                "State": {"Name": "running"},
                "InstanceType": "t3.micro",
                "PublicIpAddress": "1.2.3.4",
                "PrivateIpAddress": "10.0.0.5",
                "Placement": {"AvailabilityZone": "eu-west-2a"},
                "LaunchTime": datetime.now(timezone.utc) - timedelta(hours=2),
                "Tags": [{"Key": "Name", "Value": "web-server"}],
            }]}]}],
            # Second call: describe_instance_status
            [{"InstanceStatuses": [{
                "InstanceId": "i-abc123",
                "SystemStatus": {"Status": "ok"},
                "InstanceStatus": {"Status": "ok"},
            }]}],
        ]

        instances = check_ec2_instances(sample_config)
        assert len(instances) == 1
        assert instances[0].instance_id == "i-abc123"
        assert instances[0].state == "running"
        assert instances[0].name == "web-server"

    @patch("monitor.boto3.client")
    def test_no_instances(self, mock_boto_client, sample_config):
        mock_ec2 = MagicMock()
        mock_boto_client.return_value = mock_ec2

        mock_paginator = MagicMock()
        mock_ec2.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{"Reservations": []}]

        instances = check_ec2_instances(sample_config)
        assert instances == []

    @patch("monitor.boto3.client")
    def test_handles_client_error(self, mock_boto_client, sample_config):
        from botocore.exceptions import ClientError
        mock_ec2 = MagicMock()
        mock_boto_client.return_value = mock_ec2

        mock_paginator = MagicMock()
        mock_ec2.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedAccess", "Message": "Not allowed"}},
            "DescribeInstances"
        )

        instances = check_ec2_instances(sample_config)
        assert instances == []


class TestCheckEcsServices:
    @patch("monitor.boto3.client")
    def test_success(self, mock_boto_client, sample_config):
        mock_ecs = MagicMock()
        mock_boto_client.return_value = mock_ecs

        # list_clusters paginator
        mock_cluster_pag = MagicMock()
        mock_svc_pag = MagicMock()

        def get_paginator_side_effect(api_name):
            if api_name == "list_clusters":
                return mock_cluster_pag
            elif api_name == "list_services":
                return mock_svc_pag
            return MagicMock()

        mock_ecs.get_paginator.side_effect = get_paginator_side_effect
        mock_cluster_pag.paginate.return_value = [{"clusterArns": ["arn:aws:ecs:eu-west-2:123:cluster/my-cluster"]}]
        mock_svc_pag.paginate.return_value = [{"serviceArns": ["arn:aws:ecs:eu-west-2:123:service/my-svc"]}]
        mock_ecs.describe_services.return_value = {
            "services": [{
                "serviceName": "my-svc",
                "desiredCount": 2,
                "runningCount": 2,
                "pendingCount": 0,
                "status": "ACTIVE",
            }]
        }

        services = check_ecs_services(sample_config)
        assert len(services) == 1
        assert services[0]["service"] == "my-svc"
        assert services[0]["healthy"] is True

    @patch("monitor.boto3.client")
    def test_empty_clusters(self, mock_boto_client, sample_config):
        mock_ecs = MagicMock()
        mock_boto_client.return_value = mock_ecs
        mock_paginator = MagicMock()
        mock_ecs.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{"clusterArns": []}]

        services = check_ecs_services(sample_config)
        assert services == []


class TestGetCpuUtilization:
    @patch("monitor.boto3.client")
    def test_success(self, mock_boto_client, sample_config):
        mock_cw = MagicMock()
        mock_boto_client.return_value = mock_cw
        mock_cw.get_metric_statistics.return_value = {
            "Datapoints": [
                {"Timestamp": datetime.now(timezone.utc), "Average": 42.5},
            ]
        }
        result = get_cpu_utilization(sample_config, "i-abc123")
        assert result == 42.5

    @patch("monitor.boto3.client")
    def test_no_datapoints(self, mock_boto_client, sample_config):
        mock_cw = MagicMock()
        mock_boto_client.return_value = mock_cw
        mock_cw.get_metric_statistics.return_value = {"Datapoints": []}
        result = get_cpu_utilization(sample_config, "i-abc123")
        assert result is None


# ─── Format Functions ────────────────────────────────────────────────────────

class TestFormatAlertMessage:
    def test_no_issues_returns_none(self):
        instances = [InstanceStatus(
            instance_id="i-ok", name="healthy", state="running",
            instance_type="t3.micro", public_ip="1.2.3.4",
            private_ip="10.0.0.1", az="eu-west-2a",
            launch_time="", status_checks="ok",
        )]
        result = format_alert_message(instances, [])
        assert result is None

    def test_with_ec2_issues(self):
        inst = InstanceStatus(
            instance_id="i-bad", name="bad-server", state="running",
            instance_type="t3.micro", public_ip="1.2.3.4",
            private_ip="10.0.0.1", az="eu-west-2a",
            launch_time="", status_checks="impaired",
            alerts=["Status check FAILED"],
        )
        result = format_alert_message([inst], [])
        assert result is not None
        assert "EC2 Issues" in result
        assert "bad-server" in result

    def test_with_deployment_failures(self):
        dep = DeploymentStatus(
            deployment_id="d-123", application="my-app",
            group="my-group", status="Failed",
            create_time="2025-01-01T00:00:00",
            error_info="Rollback triggered",
        )
        result = format_alert_message([], [dep])
        assert result is not None
        assert "Deployment Failures" in result
        assert "my-app" in result


class TestGenerateSummary:
    def test_structure(self):
        inst = InstanceStatus(
            instance_id="i-001", name="test", state="running",
            instance_type="t3.micro", public_ip=None,
            private_ip="10.0.0.1", az="eu-west-2a",
            launch_time="", status_checks="ok",
        )
        dep = DeploymentStatus(
            deployment_id="d-001", application="app",
            group="grp", status="Succeeded",
            create_time="2025-01-01T00:00:00",
        )
        ecs = [{"service": "svc1", "healthy": True}]

        summary = generate_summary([inst], [dep], ecs)
        assert "timestamp" in summary
        assert summary["ec2"]["total"] == 1
        assert summary["ec2"]["running"] == 1
        assert summary["deployments"]["total"] == 1
        assert summary["deployments"]["succeeded"] == 1
        assert summary["ecs_services"] == ecs

    def test_empty_inputs(self):
        summary = generate_summary([], [], [])
        assert summary["ec2"]["total"] == 0
        assert summary["deployments"]["total"] == 0
        assert summary["ecs_services"] == []
