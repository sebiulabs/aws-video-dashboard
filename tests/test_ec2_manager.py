"""Tests for ec2_manager.py — pure logic, template constants, and mocked EC2 calls."""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

import ec2_manager


# ═════════════════════════════════════════════════════════════════════════════
# PURE LOGIC
# ═════════════════════════════════════════════════════════════════════════════


class TestSanitizeError:
    def test_strips_access_keys(self):
        msg = "Unauthorized access with AKIAIOSFODNN7EXAMPLE"
        result = ec2_manager._sanitize_error(msg)
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "****" in result

    def test_strips_arns(self):
        msg = "Not authorized for arn:aws:ec2:us-east-1:123456789012:instance/i-abc"
        result = ec2_manager._sanitize_error(msg)
        assert "123456789012" not in result
        assert "****" in result


class TestTemplateConstants:
    def test_ec2_media_templates_not_empty(self):
        assert len(ec2_manager.EC2_MEDIA_TEMPLATES) > 0

    def test_windows_templates_not_empty(self):
        assert len(ec2_manager.WINDOWS_EC2_TEMPLATES) > 0


# ═════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═════════════════════════════════════════════════════════════════════════════


def _make_client_error(code="AccessDenied", message="Access Denied"):
    return ClientError(
        {"Error": {"Code": code, "Message": message}},
        "TestOperation",
    )


# ═════════════════════════════════════════════════════════════════════════════
# LIST EC2 INSTANCES
# ═════════════════════════════════════════════════════════════════════════════


class TestCheckEC2Instances:
    @patch("ec2_manager._get_boto_client")
    def test_success(self, mock_get_client, sample_config):
        mock_ec2 = MagicMock()
        mock_get_client.return_value = mock_ec2

        launch_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        mock_ec2.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-abc12345678901234",
                            "State": {"Name": "running"},
                            "InstanceType": "c5.2xlarge",
                            "PublicIpAddress": "1.2.3.4",
                            "PrivateIpAddress": "10.0.1.5",
                            "LaunchTime": launch_time,
                            "Tags": [
                                {"Key": "Name", "Value": "media-encoder"},
                                {"Key": "dashboard-managed", "Value": "true"},
                                {"Key": "template-id", "Value": "ec2_encoding"},
                                {"Key": "os-type", "Value": "linux"},
                            ],
                        }
                    ]
                }
            ]
        }

        result = ec2_manager.check_ec2_instances(sample_config, region="eu-west-2")
        assert result["ok"] is True
        assert result["count"] == 1
        assert result["instances"][0]["instance_id"] == "i-abc12345678901234"
        assert result["instances"][0]["name"] == "media-encoder"
        assert result["instances"][0]["state"] == "running"

    @patch("ec2_manager._get_boto_client")
    def test_empty(self, mock_get_client, sample_config):
        mock_ec2 = MagicMock()
        mock_get_client.return_value = mock_ec2
        mock_ec2.describe_instances.return_value = {"Reservations": []}

        result = ec2_manager.check_ec2_instances(sample_config, region="eu-west-2")
        assert result["ok"] is True
        assert result["count"] == 0
        assert result["instances"] == []


# ═════════════════════════════════════════════════════════════════════════════
# LAUNCH EC2 INSTANCE
# ═════════════════════════════════════════════════════════════════════════════


class TestLaunchEC2Instance:
    @patch("ec2_manager._get_latest_ami", return_value="ami-0test123")
    @patch("ec2_manager._get_boto_client")
    def test_success(self, mock_get_client, mock_ami, sample_config):
        mock_ec2 = MagicMock()
        mock_get_client.return_value = mock_ec2
        mock_ec2.run_instances.return_value = {
            "Instances": [
                {
                    "InstanceId": "i-new12345678901234",
                    "PublicIpAddress": "5.6.7.8",
                }
            ]
        }

        result = ec2_manager.launch_ec2_instance(
            sample_config,
            {
                "template_id": "ec2_encoding",
                "region": "eu-west-2",
            },
        )
        assert result["ok"] is True
        assert result["instance_id"] == "i-new12345678901234"
        assert result["template_id"] == "ec2_encoding"

    @patch("ec2_manager._get_boto_client")
    def test_invalid_template(self, mock_get_client, sample_config):
        result = ec2_manager.launch_ec2_instance(
            sample_config,
            {"template_id": "nonexistent_template", "region": "eu-west-2"},
        )
        assert result["ok"] is False
        assert "not found" in result["error"]


# ═════════════════════════════════════════════════════════════════════════════
# EC2 INSTANCE ACTIONS
# ═════════════════════════════════════════════════════════════════════════════


class TestEC2InstanceAction:
    @patch("ec2_manager._get_boto_client")
    def test_reboot_managed_instance(self, mock_get_client, sample_config):
        mock_ec2 = MagicMock()
        mock_get_client.return_value = mock_ec2

        # _verify_dashboard_managed returns True
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{"InstanceId": "i-abc12345678901234"}]}]
        }

        result = ec2_manager.ec2_instance_action(
            sample_config, "i-abc12345678901234", "reboot", region="eu-west-2"
        )
        assert result["ok"] is True
        assert result["action"] == "reboot"
        mock_ec2.reboot_instances.assert_called_once_with(
            InstanceIds=["i-abc12345678901234"]
        )

    @patch("ec2_manager._get_boto_client")
    def test_not_managed_returns_error(self, mock_get_client, sample_config):
        mock_ec2 = MagicMock()
        mock_get_client.return_value = mock_ec2

        # _verify_dashboard_managed returns False
        mock_ec2.describe_instances.return_value = {"Reservations": []}

        result = ec2_manager.ec2_instance_action(
            sample_config, "i-abc12345678901234", "reboot", region="eu-west-2"
        )
        assert result["ok"] is False
        assert "not managed" in result["error"]


# ═════════════════════════════════════════════════════════════════════════════
# TERMINATE EC2 INSTANCE
# ═════════════════════════════════════════════════════════════════════════════


class TestTerminateEC2Instance:
    @patch("ec2_manager._get_boto_client")
    def test_success_managed(self, mock_get_client, sample_config):
        mock_ec2 = MagicMock()
        mock_get_client.return_value = mock_ec2

        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{"InstanceId": "i-abc12345678901234"}]}]
        }

        result = ec2_manager.terminate_ec2_instance(
            sample_config, "i-abc12345678901234", region="eu-west-2"
        )
        assert result["ok"] is True
        mock_ec2.terminate_instances.assert_called_once_with(
            InstanceIds=["i-abc12345678901234"]
        )

    @patch("ec2_manager._get_boto_client")
    def test_not_managed_returns_error(self, mock_get_client, sample_config):
        mock_ec2 = MagicMock()
        mock_get_client.return_value = mock_ec2
        mock_ec2.describe_instances.return_value = {"Reservations": []}

        result = ec2_manager.terminate_ec2_instance(
            sample_config, "i-abc12345678901234", region="eu-west-2"
        )
        assert result["ok"] is False
        assert "not managed" in result["error"]


# ═════════════════════════════════════════════════════════════════════════════
# CREATE AMI
# ═════════════════════════════════════════════════════════════════════════════


class TestCreateAMI:
    @patch("ec2_manager._get_boto_client")
    def test_success(self, mock_get_client, sample_config):
        mock_ec2 = MagicMock()
        mock_get_client.return_value = mock_ec2

        # _verify_dashboard_managed check
        mock_ec2.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-abc12345678901234",
                            "State": {"Name": "stopped"},
                            "Tags": [
                                {"Key": "Name", "Value": "encoder"},
                                {"Key": "dashboard-managed", "Value": "true"},
                                {"Key": "template-id", "Value": "ec2_encoding"},
                            ],
                        }
                    ]
                }
            ]
        }
        mock_ec2.create_image.return_value = {"ImageId": "ami-newimage123"}

        result = ec2_manager.create_ami_from_instance(
            sample_config, "i-abc12345678901234", "my-custom-ami", region="eu-west-2"
        )
        assert result["ok"] is True
        assert result["ami_id"] == "ami-newimage123"
        assert result["name"] == "my-custom-ami"


# ═════════════════════════════════════════════════════════════════════════════
# LIST CUSTOM AMIS
# ═════════════════════════════════════════════════════════════════════════════


class TestListCustomAMIs:
    @patch("ec2_manager._get_boto_client")
    def test_success(self, mock_get_client, sample_config):
        mock_ec2 = MagicMock()
        mock_get_client.return_value = mock_ec2
        mock_ec2.describe_images.return_value = {
            "Images": [
                {
                    "ImageId": "ami-custom001",
                    "Name": "my-encoder-ami",
                    "Description": "Custom encoder AMI",
                    "State": "available",
                    "CreationDate": "2024-01-15T10:00:00.000Z",
                    "Tags": [
                        {"Key": "dashboard-managed", "Value": "true"},
                        {"Key": "source-template", "Value": "ec2_encoding"},
                        {"Key": "source-instance", "Value": "i-abc123"},
                    ],
                }
            ]
        }

        result = ec2_manager.list_custom_amis(sample_config, region="eu-west-2")
        assert result["ok"] is True
        assert result["count"] == 1
        assert result["amis"][0]["ami_id"] == "ami-custom001"
        assert result["amis"][0]["dashboard_managed"] is True


# ═════════════════════════════════════════════════════════════════════════════
# DEREGISTER AMI
# ═════════════════════════════════════════════════════════════════════════════


class TestDeregisterAMI:
    @patch("ec2_manager._get_boto_client")
    def test_success(self, mock_get_client, sample_config):
        mock_ec2 = MagicMock()
        mock_get_client.return_value = mock_ec2

        mock_ec2.describe_images.side_effect = [
            # First call: get snapshots before deregister
            {
                "Images": [
                    {
                        "ImageId": "ami-todelete",
                        "BlockDeviceMappings": [
                            {"Ebs": {"SnapshotId": "snap-abc123"}}
                        ],
                    }
                ]
            },
            # Second call: check if snapshot is used by other AMIs
            {"Images": []},
        ]

        result = ec2_manager.deregister_ami(sample_config, "ami-todelete", region="eu-west-2")
        assert result["ok"] is True
        assert result["ami_id"] == "ami-todelete"
        mock_ec2.deregister_image.assert_called_once_with(ImageId="ami-todelete")
        mock_ec2.delete_snapshot.assert_called_once_with(SnapshotId="snap-abc123")


# ═════════════════════════════════════════════════════════════════════════════
# LIST SECURITY GROUPS
# ═════════════════════════════════════════════════════════════════════════════


class TestListSecurityGroups:
    @patch("ec2_manager._get_boto_client")
    def test_success(self, mock_get_client, sample_config):
        mock_ec2 = MagicMock()
        mock_get_client.return_value = mock_ec2
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-abc123",
                    "GroupName": "default",
                    "Description": "Default SG",
                    "VpcId": "vpc-1",
                },
                {
                    "GroupId": "sg-def456",
                    "GroupName": "media-sg",
                    "Description": "Media security group",
                    "VpcId": "vpc-1",
                },
            ]
        }

        result = ec2_manager.list_security_groups(sample_config, region="eu-west-2")
        assert result["ok"] is True
        assert len(result["security_groups"]) == 2
        assert result["security_groups"][0]["id"] == "sg-abc123"


# ═════════════════════════════════════════════════════════════════════════════
# LIST KEY PAIRS
# ═════════════════════════════════════════════════════════════════════════════


class TestListKeyPairs:
    @patch("ec2_manager._get_boto_client")
    def test_success(self, mock_get_client, sample_config):
        mock_ec2 = MagicMock()
        mock_get_client.return_value = mock_ec2
        mock_ec2.describe_key_pairs.return_value = {
            "KeyPairs": [
                {
                    "KeyName": "my-key",
                    "KeyFingerprint": "ab:cd:ef:12:34:56",
                    "KeyType": "rsa",
                },
            ]
        }

        result = ec2_manager.list_key_pairs(sample_config, region="eu-west-2")
        assert result["ok"] is True
        assert len(result["key_pairs"]) == 1
        assert result["key_pairs"][0]["name"] == "my-key"
        assert result["key_pairs"][0]["type"] == "rsa"
