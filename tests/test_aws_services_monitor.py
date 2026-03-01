"""Tests for aws_services_monitor.py — pure logic helpers and mocked service checks."""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

import aws_services_monitor as asm


# ═════════════════════════════════════════════════════════════════════════════
# PURE LOGIC HELPERS
# ═════════════════════════════════════════════════════════════════════════════


class TestSanitizeError:
    def test_strips_akia_access_key(self):
        msg = "Error with key AKIAIOSFODNN7EXAMPLE in request"
        assert "AKIAIOSFODNN7EXAMPLE" not in asm._sanitize_error(msg)
        assert "****" in asm._sanitize_error(msg)

    def test_strips_asia_temporary_credentials(self):
        msg = "Credential ASIAIOSFODNN7EXAMPLE is expired"
        assert "ASIAIOSFODNN7EXAMPLE" not in asm._sanitize_error(msg)
        assert "****" in asm._sanitize_error(msg)

    def test_strips_12_digit_account_id(self):
        msg = "Account 123456789012 not authorized"
        assert "123456789012" not in asm._sanitize_error(msg)
        assert "****" in asm._sanitize_error(msg)

    def test_strips_arn_pattern(self):
        msg = "Access denied for arn:aws:iam:us-east-1:123456789012:role/MyRole"
        result = asm._sanitize_error(msg)
        assert "123456789012" not in result
        assert "****" in result

    def test_preserves_normal_text(self):
        msg = "Something went wrong with the service"
        assert asm._sanitize_error(msg) == msg


class TestGetBotoKwargs:
    def test_with_credentials(self, sample_config):
        kwargs = asm._get_boto_kwargs(sample_config)
        assert kwargs["aws_access_key_id"] == "AKIAIOSFODNN7EXAMPLE"
        assert kwargs["aws_secret_access_key"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert kwargs["region_name"] == "eu-west-2"

    def test_without_credentials(self):
        config = {"aws": {"region": "us-east-1"}}
        kwargs = asm._get_boto_kwargs(config)
        assert "aws_access_key_id" not in kwargs
        assert "aws_secret_access_key" not in kwargs
        assert kwargs["region_name"] == "us-east-1"

    def test_masked_keys_excluded(self):
        config = {
            "aws": {
                "access_key_id": "AKIA••••••EXAMPLE",
                "secret_access_key": "wJalrX••••EXAMPLEKEY",
                "region": "eu-west-2",
            }
        }
        kwargs = asm._get_boto_kwargs(config)
        assert "aws_access_key_id" not in kwargs
        assert "aws_secret_access_key" not in kwargs


class TestSafeIsoformat:
    def test_with_datetime_object(self):
        dt = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        result = asm._safe_isoformat(dt)
        assert "2024-01-15" in result
        assert "10:30" in result

    def test_with_none(self):
        assert asm._safe_isoformat(None) == ""

    def test_with_string(self):
        assert asm._safe_isoformat("2024-01-15") == "2024-01-15"


class TestGetNameTag:
    def test_with_matching_tag(self):
        tags = [
            {"Key": "Environment", "Value": "prod"},
            {"Key": "Name", "Value": "my-resource"},
        ]
        assert asm._get_name_tag(tags) == "my-resource"

    def test_no_name_tag(self):
        tags = [{"Key": "Environment", "Value": "prod"}]
        assert asm._get_name_tag(tags) == ""

    def test_empty_tags(self):
        assert asm._get_name_tag([]) == ""

    def test_none_tags(self):
        assert asm._get_name_tag(None) == ""


# ═════════════════════════════════════════════════════════════════════════════
# MOCKED SERVICE CHECKS
# ═════════════════════════════════════════════════════════════════════════════


def _make_client_error(code="AccessDenied", message="Access Denied"):
    return ClientError(
        {"Error": {"Code": code, "Message": message}},
        "TestOperation",
    )


class TestCheckRDS:
    @patch("aws_services_monitor.boto3.client")
    def test_success_with_instances(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": "mydb",
                        "Engine": "postgres",
                        "EngineVersion": "14.5",
                        "DBInstanceStatus": "available",
                        "MultiAZ": True,
                        "DBInstanceClass": "db.r5.large",
                        "AllocatedStorage": 100,
                        "Endpoint": {"Address": "mydb.abc.rds.amazonaws.com", "Port": 5432},
                    }
                ]
            }
        ]

        result = asm.check_rds(sample_config)
        assert result["total"] == 1
        assert result["healthy"] == 1
        assert result["items"][0]["identifier"] == "mydb"
        assert result["items"][0]["engine"] == "postgres"
        assert result["items"][0]["healthy"] is True

    @patch("aws_services_monitor.boto3.client")
    def test_empty(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{"DBInstances": []}]

        result = asm.check_rds(sample_config)
        assert result["total"] == 0
        assert result["items"] == []

    @patch("aws_services_monitor.boto3.client")
    def test_client_error(self, mock_boto_client, sample_config):
        mock_boto_client.side_effect = _make_client_error()
        result = asm.check_rds(sample_config)
        assert result["total"] == 0
        assert "error" in result


class TestCheckLambda:
    @patch("aws_services_monitor.boto3.client")
    def test_success(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "Functions": [
                    {
                        "FunctionName": "my-func",
                        "Runtime": "python3.12",
                        "MemorySize": 256,
                        "CodeSize": 1048576,
                        "Handler": "handler.main",
                        "LastModified": "2024-01-15T10:00:00",
                        "State": "Active",
                        "Description": "Test function",
                        "Timeout": 30,
                    }
                ]
            }
        ]

        result = asm.check_lambda(sample_config)
        assert result["total"] == 1
        assert result["healthy"] == 1
        assert result["items"][0]["name"] == "my-func"
        assert result["items"][0]["runtime"] == "python3.12"

    @patch("aws_services_monitor.boto3.client")
    def test_empty(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{"Functions": []}]

        result = asm.check_lambda(sample_config)
        assert result["total"] == 0


class TestCheckS3:
    @patch("aws_services_monitor.boto3.client")
    def test_success(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.list_buckets.return_value = {
            "Buckets": [
                {"Name": "my-bucket", "CreationDate": datetime(2024, 1, 1, tzinfo=timezone.utc)},
                {"Name": "other-bucket", "CreationDate": datetime(2024, 2, 1, tzinfo=timezone.utc)},
            ]
        }

        result = asm.check_s3(sample_config)
        assert result["total"] == 2
        assert result["healthy"] == 2
        assert result["items"][0]["name"] == "my-bucket"


class TestCheckSQS:
    @patch("aws_services_monitor.boto3.client")
    def test_success_with_messages(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.list_queues.return_value = {
            "QueueUrls": ["https://sqs.eu-west-2.amazonaws.com/123456789012/my-queue"]
        }
        mock_client.get_queue_attributes.return_value = {
            "Attributes": {
                "ApproximateNumberOfMessages": "5",
                "ApproximateNumberOfMessagesNotVisible": "2",
                "CreatedTimestamp": "1705000000",
            }
        }

        result = asm.check_sqs(sample_config)
        assert result["total"] == 1
        assert result["healthy"] == 1
        assert result["items"][0]["name"] == "my-queue"
        assert result["items"][0]["approximate_message_count"] == 5


class TestCheckVPCs:
    @patch("aws_services_monitor.boto3.client")
    def test_success(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.describe_vpcs.return_value = {
            "Vpcs": [
                {
                    "VpcId": "vpc-abc123",
                    "CidrBlock": "10.0.0.0/16",
                    "State": "available",
                    "IsDefault": True,
                    "Tags": [{"Key": "Name", "Value": "main-vpc"}],
                }
            ]
        }
        mock_client.describe_subnets.return_value = {
            "Subnets": [
                {"VpcId": "vpc-abc123", "SubnetId": "subnet-1"},
                {"VpcId": "vpc-abc123", "SubnetId": "subnet-2"},
            ]
        }

        result = asm.check_vpcs(sample_config)
        assert result["total"] == 1
        assert result["healthy"] == 1
        assert result["items"][0]["vpc_id"] == "vpc-abc123"
        assert result["items"][0]["subnet_count"] == 2
        assert result["items"][0]["name"] == "main-vpc"


class TestCheckLoadBalancers:
    @patch("aws_services_monitor.boto3.client")
    def test_success(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "LoadBalancers": [
                    {
                        "LoadBalancerArn": "arn:aws:elasticloadbalancing:eu-west-2:123456789012:loadbalancer/app/my-alb/abc",
                        "LoadBalancerName": "my-alb",
                        "Type": "application",
                        "State": {"Code": "active"},
                        "DNSName": "my-alb.eu-west-2.elb.amazonaws.com",
                        "Scheme": "internet-facing",
                        "VpcId": "vpc-abc123",
                        "AvailabilityZones": [
                            {"ZoneName": "eu-west-2a"},
                            {"ZoneName": "eu-west-2b"},
                        ],
                    }
                ]
            }
        ]
        mock_client.describe_target_groups.return_value = {
            "TargetGroups": [{"TargetGroupArn": "tg-1"}, {"TargetGroupArn": "tg-2"}]
        }

        result = asm.check_load_balancers(sample_config)
        assert result["total"] == 1
        assert result["healthy"] == 1
        assert result["items"][0]["name"] == "my-alb"
        assert result["items"][0]["target_group_count"] == 2


class TestCheckElasticIPs:
    @patch("aws_services_monitor.boto3.client")
    def test_associated_and_unassociated(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.describe_addresses.return_value = {
            "Addresses": [
                {
                    "AllocationId": "eipalloc-1",
                    "PublicIp": "1.2.3.4",
                    "InstanceId": "i-abc123",
                    "NetworkInterfaceId": "eni-1",
                    "AssociationId": "eipassoc-1",
                    "Domain": "vpc",
                },
                {
                    "AllocationId": "eipalloc-2",
                    "PublicIp": "5.6.7.8",
                    "InstanceId": "",
                    "NetworkInterfaceId": "",
                    "AssociationId": "",
                    "Domain": "vpc",
                },
            ]
        }

        result = asm.check_elastic_ips(sample_config)
        assert result["total"] == 2
        assert result["healthy"] == 1
        assert result["items"][0]["is_associated"] is True
        assert result["items"][1]["is_associated"] is False
        assert result["items"][1]["healthy"] is False


class TestCheckSecurityGroups:
    @patch("aws_services_monitor.boto3.client")
    def test_open_to_world_warning(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-open",
                        "GroupName": "open-sg",
                        "Description": "Open SG",
                        "VpcId": "vpc-1",
                        "IpPermissions": [
                            {
                                "IpProtocol": "-1",
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                "Ipv6Ranges": [],
                            }
                        ],
                        "IpPermissionsEgress": [],
                    }
                ]
            }
        ]

        result = asm.check_security_groups(sample_config)
        assert result["total"] == 1
        assert result["healthy"] == 0
        assert result["open_to_world_count"] == 1
        assert result["items"][0]["open_to_world"] is True

    @patch("aws_services_monitor.boto3.client")
    def test_normal_sg(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-safe",
                        "GroupName": "safe-sg",
                        "Description": "Safe SG",
                        "VpcId": "vpc-1",
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 443,
                                "ToPort": 443,
                                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                                "Ipv6Ranges": [],
                            }
                        ],
                        "IpPermissionsEgress": [],
                    }
                ]
            }
        ]

        result = asm.check_security_groups(sample_config)
        assert result["total"] == 1
        assert result["healthy"] == 1
        assert result["items"][0]["open_to_world"] is False


class TestCheckNATGateways:
    @patch("aws_services_monitor.boto3.client")
    def test_success(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "NatGateways": [
                    {
                        "NatGatewayId": "nat-abc123",
                        "State": "available",
                        "SubnetId": "subnet-1",
                        "VpcId": "vpc-1",
                        "ConnectivityType": "public",
                        "Tags": [{"Key": "Name", "Value": "my-nat"}],
                        "NatGatewayAddresses": [{"PublicIp": "1.2.3.4"}],
                    }
                ]
            }
        ]

        result = asm.check_nat_gateways(sample_config)
        assert result["total"] == 1
        assert result["healthy"] == 1
        assert result["items"][0]["nat_gateway_id"] == "nat-abc123"
        assert result["items"][0]["public_ip"] == "1.2.3.4"


class TestCheckRoute53:
    @patch("aws_services_monitor.boto3.client")
    def test_success(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        # Hosted zones paginator
        hz_paginator = MagicMock()
        hz_paginator.paginate.return_value = [
            {
                "HostedZones": [
                    {
                        "Id": "/hostedzone/Z1234",
                        "Name": "example.com.",
                        "ResourceRecordSetCount": 10,
                        "Config": {"PrivateZone": False, "Comment": "Main zone"},
                    }
                ]
            }
        ]

        # Health checks paginator
        hc_paginator = MagicMock()
        hc_paginator.paginate.return_value = [{"HealthChecks": []}]

        def get_paginator_side_effect(name):
            if name == "list_hosted_zones":
                return hz_paginator
            elif name == "list_health_checks":
                return hc_paginator
            return MagicMock()

        mock_client.get_paginator.side_effect = get_paginator_side_effect

        result = asm.check_route53(sample_config)
        assert result["total"] == 1
        assert result["healthy"] == 1
        assert result["hosted_zones"][0]["name"] == "example.com."


class TestCheckAPIGateway:
    @patch("aws_services_monitor.boto3.client")
    def test_success(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "items": [
                    {
                        "id": "api123",
                        "name": "my-api",
                        "description": "My REST API",
                        "createdDate": datetime(2024, 1, 1, tzinfo=timezone.utc),
                        "endpointConfiguration": {"types": ["REGIONAL"]},
                    }
                ]
            }
        ]

        result = asm.check_apigateway(sample_config)
        assert result["total"] == 1
        assert result["healthy"] == 1
        assert result["items"][0]["name"] == "my-api"
        assert result["items"][0]["endpoint_type"] == "REGIONAL"


class TestCheckVPNConnections:
    @patch("aws_services_monitor.boto3.client")
    def test_success(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.describe_vpn_connections.return_value = {
            "VpnConnections": [
                {
                    "VpnConnectionId": "vpn-abc123",
                    "State": "available",
                    "Type": "ipsec.1",
                    "Tags": [{"Key": "Name", "Value": "office-vpn"}],
                    "VgwTelemetry": [
                        {
                            "OutsideIpAddress": "1.2.3.4",
                            "Status": "UP",
                            "StatusMessage": "",
                            "LastStatusChange": datetime(2024, 1, 15, tzinfo=timezone.utc),
                            "AcceptedRouteCount": 5,
                        }
                    ],
                    "VpnGatewayId": "vgw-1",
                    "CustomerGatewayId": "cgw-1",
                    "TransitGatewayId": "",
                }
            ]
        }
        mock_client.describe_transit_gateways.return_value = {"TransitGateways": []}

        result = asm.check_vpn_connections(sample_config)
        assert result["total"] == 1
        assert result["healthy"] == 1
        assert result["items"][0]["vpn_connection_id"] == "vpn-abc123"
        assert result["items"][0]["tunnels_up"] == 1
