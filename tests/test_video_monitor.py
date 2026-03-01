"""Tests for video_monitor.py — pure logic helpers and mocked service checks."""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

import video_monitor


# ═════════════════════════════════════════════════════════════════════════════
# PURE LOGIC HELPERS
# ═════════════════════════════════════════════════════════════════════════════


class TestSanitizeError:
    def test_strips_aws_keys(self):
        msg = "Invalid key AKIAIOSFODNN7EXAMPLE used"
        result = video_monitor._sanitize_error(msg)
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "****" in result

    def test_strips_temporary_credentials(self):
        msg = "Credential ASIAIOSFODNN7EXAMPLE expired"
        result = video_monitor._sanitize_error(msg)
        assert "ASIAIOSFODNN7EXAMPLE" not in result


class TestGetBotoKwargs:
    def test_with_credentials(self, sample_config):
        kwargs = video_monitor._get_boto_kwargs(sample_config)
        assert kwargs["aws_access_key_id"] == "AKIAIOSFODNN7EXAMPLE"
        assert kwargs["aws_secret_access_key"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert kwargs["region_name"] == "eu-west-2"

    def test_without_credentials(self):
        config = {"aws": {"access_key_id": "", "secret_access_key": "", "region": "us-east-1"}}
        kwargs = video_monitor._get_boto_kwargs(config)
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
# MEDIALIVE
# ═════════════════════════════════════════════════════════════════════════════


class TestCheckMediaLive:
    @patch("video_monitor.boto3.client")
    def test_success_with_channels(self, mock_boto_client, sample_config):
        mock_ml = MagicMock()
        mock_cw = MagicMock()

        def client_factory(service, **kwargs):
            if service == "medialive":
                return mock_ml
            return mock_cw

        mock_boto_client.side_effect = client_factory

        mock_paginator = MagicMock()
        mock_ml.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "Channels": [
                    {"Id": "ch-1", "Name": "live-channel", "State": "RUNNING"}
                ]
            }
        ]
        mock_ml.describe_channel.return_value = {
            "PipelineDetails": [
                {"PipelineId": "0", "ActiveInputAttachmentName": "input-1"}
            ],
            "InputAttachments": [
                {"InputAttachmentName": "input-1", "InputId": "inp-1"}
            ],
        }
        mock_cw.get_metric_statistics.return_value = {
            "Datapoints": [
                {"Timestamp": datetime(2024, 1, 15, tzinfo=timezone.utc), "Average": 30.0}
            ]
        }

        result = video_monitor.check_medialive(sample_config)
        assert result["total"] == 1
        assert result["running"] == 1
        assert result["channels"][0]["name"] == "live-channel"
        assert result["channels"][0]["state"] == "RUNNING"

    @patch("video_monitor.boto3.client")
    def test_empty(self, mock_boto_client, sample_config):
        mock_ml = MagicMock()
        mock_cw = MagicMock()

        def client_factory(service, **kwargs):
            if service == "medialive":
                return mock_ml
            return mock_cw

        mock_boto_client.side_effect = client_factory

        mock_paginator = MagicMock()
        mock_ml.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{"Channels": []}]

        result = video_monitor.check_medialive(sample_config)
        assert result["total"] == 0
        assert result["channels"] == []

    @patch("video_monitor.boto3.client")
    def test_client_error(self, mock_boto_client, sample_config):
        mock_ml = MagicMock()
        mock_cw = MagicMock()

        def client_factory(service, **kwargs):
            if service == "medialive":
                return mock_ml
            return mock_cw

        mock_boto_client.side_effect = client_factory

        mock_paginator = MagicMock()
        mock_ml.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.side_effect = _make_client_error()

        result = video_monitor.check_medialive(sample_config)
        assert result["total"] == 0
        assert result["channels"] == []


# ═════════════════════════════════════════════════════════════════════════════
# MEDIACONNECT
# ═════════════════════════════════════════════════════════════════════════════


class TestCheckMediaConnect:
    @patch("video_monitor.boto3.client")
    def test_success_with_flows(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "Flows": [
                    {
                        "FlowArn": "arn:aws:mediaconnect:eu-west-2:123456789012:flow:1-abc/my-flow",
                        "Name": "my-flow",
                        "Status": "ACTIVE",
                    }
                ]
            }
        ]
        mock_client.describe_flow.return_value = {
            "Flow": {
                "Source": {
                    "Name": "src-1",
                    "Transport": {"Protocol": "srt"},
                    "IngestIp": "1.2.3.4",
                    "IngestPort": 5000,
                    "WhitelistCidr": "0.0.0.0/0",
                },
                "Outputs": [
                    {
                        "Name": "out-1",
                        "Transport": {"Protocol": "srt"},
                        "Destination": "5.6.7.8",
                        "Port": 6000,
                    }
                ],
            }
        }

        result = video_monitor.check_mediaconnect(sample_config)
        assert result["total"] == 1
        assert result["active"] == 1
        assert result["healthy"] == 1
        assert result["flows"][0]["name"] == "my-flow"

    @patch("video_monitor.boto3.client")
    def test_empty(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{"Flows": []}]

        result = video_monitor.check_mediaconnect(sample_config)
        assert result["total"] == 0
        assert result["flows"] == []


# ═════════════════════════════════════════════════════════════════════════════
# MEDIAPACKAGE
# ═════════════════════════════════════════════════════════════════════════════


class TestCheckMediaPackage:
    @patch("video_monitor.boto3.client")
    def test_success(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.list_channels.return_value = {
            "Channels": [
                {
                    "Id": "ch-pkg-1",
                    "Description": "Package Channel 1",
                    "HlsIngest": {
                        "IngestEndpoints": [
                            {"Url": "https://ingest.example.com/v1", "Username": "user1"}
                        ]
                    },
                }
            ]
        }
        mock_client.list_origin_endpoints.return_value = {
            "OriginEndpoints": [
                {
                    "Id": "ep-1",
                    "Url": "https://origin.example.com/v1/index.m3u8",
                    "ManifestName": "index",
                    "HlsPackage": {},
                    "StartoverWindowSeconds": 0,
                    "TimeDelaySeconds": 0,
                }
            ]
        }

        result = video_monitor.check_mediapackage(sample_config)
        assert result["total"] == 1
        assert result["with_endpoints"] == 1
        assert result["channels"][0]["channel_id"] == "ch-pkg-1"
        assert result["channels"][0]["endpoint_count"] == 1

    @patch("video_monitor.boto3.client")
    def test_empty(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.list_channels.return_value = {"Channels": []}

        result = video_monitor.check_mediapackage(sample_config)
        assert result["total"] == 0
        assert result["channels"] == []


# ═════════════════════════════════════════════════════════════════════════════
# CLOUDFRONT
# ═════════════════════════════════════════════════════════════════════════════


class TestCheckCloudFront:
    @patch("video_monitor.boto3.client")
    def test_success_with_distributions(self, mock_boto_client, sample_config):
        mock_cf = MagicMock()
        mock_cw = MagicMock()

        def client_factory(service, **kwargs):
            if service == "cloudfront":
                return mock_cf
            return mock_cw

        mock_boto_client.side_effect = client_factory

        mock_paginator = MagicMock()
        mock_cf.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "DistributionList": {
                    "Items": [
                        {
                            "Id": "EDISTRIB1",
                            "DomainName": "d1234.cloudfront.net",
                            "Status": "Deployed",
                            "Enabled": True,
                            "Comment": "My CDN",
                            "Origins": {"Items": [{"Id": "origin-1", "DomainName": "origin.example.com", "OriginPath": ""}]},
                        }
                    ]
                }
            }
        ]
        mock_cw.get_metric_statistics.return_value = {"Datapoints": []}

        result = video_monitor.check_cloudfront(sample_config)
        assert result["total"] == 1
        assert result["deployed"] == 1
        assert result["distributions"][0]["distribution_id"] == "EDISTRIB1"

    @patch("video_monitor.boto3.client")
    def test_empty(self, mock_boto_client, sample_config):
        mock_cf = MagicMock()
        mock_cw = MagicMock()

        def client_factory(service, **kwargs):
            if service == "cloudfront":
                return mock_cf
            return mock_cw

        mock_boto_client.side_effect = client_factory

        mock_paginator = MagicMock()
        mock_cf.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{"DistributionList": {}}]

        result = video_monitor.check_cloudfront(sample_config)
        assert result["total"] == 0
        assert result["distributions"] == []

    @patch("video_monitor.boto3.client")
    def test_high_error_rate(self, mock_boto_client, sample_config):
        mock_cf = MagicMock()
        mock_cw = MagicMock()

        def client_factory(service, **kwargs):
            if service == "cloudfront":
                return mock_cf
            return mock_cw

        mock_boto_client.side_effect = client_factory

        mock_paginator = MagicMock()
        mock_cf.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "DistributionList": {
                    "Items": [
                        {
                            "Id": "EDISTRIB2",
                            "DomainName": "d5678.cloudfront.net",
                            "Status": "Deployed",
                            "Enabled": True,
                            "Comment": "High error CDN",
                            "Origins": {"Items": []},
                        }
                    ]
                }
            }
        ]

        # Return high 5xx error rate
        def metric_side_effect(**kwargs):
            if kwargs.get("MetricName") == "5xxErrorRate":
                return {
                    "Datapoints": [
                        {"Timestamp": datetime(2024, 1, 15, tzinfo=timezone.utc), "Average": 15.0}
                    ]
                }
            return {"Datapoints": []}

        mock_cw.get_metric_statistics.side_effect = metric_side_effect

        result = video_monitor.check_cloudfront(sample_config)
        assert result["total"] == 1
        assert result["healthy"] == 0
        assert result["distributions"][0]["error_rate_5xx"] == 15.0


# ═════════════════════════════════════════════════════════════════════════════
# IVS
# ═════════════════════════════════════════════════════════════════════════════


class TestCheckIVS:
    @patch("video_monitor.boto3.client")
    def test_success_with_channels(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        mock_client.list_channels.return_value = {
            "channels": [
                {"arn": "arn:aws:ivs:eu-west-2:123456789012:channel/abc123", "name": "test-ivs"}
            ]
        }
        mock_client.get_channel.return_value = {
            "channel": {
                "latencyMode": "LOW",
                "type": "STANDARD",
                "ingestEndpoint": "ingest.ivs.example.com",
                "playbackUrl": "https://playback.ivs.example.com/abc123",
            }
        }
        # No active stream — ChannelNotBroadcasting
        mock_client.get_stream.side_effect = ClientError(
            {"Error": {"Code": "ChannelNotBroadcasting", "Message": "Not broadcasting"}},
            "GetStream",
        )
        # Set up exceptions attribute for ChannelNotBroadcasting
        mock_client.exceptions.ChannelNotBroadcasting = type(
            "ChannelNotBroadcasting", (ClientError,), {}
        )
        # Adjust side_effect to raise the custom exception type
        mock_client.get_stream.side_effect = mock_client.exceptions.ChannelNotBroadcasting(
            {"Error": {"Code": "ChannelNotBroadcasting", "Message": "Not broadcasting"}},
            "GetStream",
        )

        result = video_monitor.check_ivs(sample_config)
        assert result["total"] == 1
        assert result["live"] == 0
        assert result["healthy"] == 1
        assert result["channels"][0]["name"] == "test-ivs"
        assert result["channels"][0]["stream_health"] == "OFFLINE"

    @patch("video_monitor.boto3.client")
    def test_empty(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.list_channels.return_value = {"channels": []}

        result = video_monitor.check_ivs(sample_config)
        assert result["total"] == 0
        assert result["channels"] == []

    @patch("video_monitor.boto3.client")
    def test_with_active_stream(self, mock_boto_client, sample_config):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        mock_client.list_channels.return_value = {
            "channels": [
                {"arn": "arn:aws:ivs:eu-west-2:123456789012:channel/live1", "name": "live-channel"}
            ]
        }
        mock_client.get_channel.return_value = {
            "channel": {
                "latencyMode": "LOW",
                "type": "STANDARD",
                "ingestEndpoint": "ingest.ivs.example.com",
                "playbackUrl": "https://playback.ivs.example.com/live1",
            }
        }
        mock_start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        mock_client.get_stream.return_value = {
            "stream": {
                "state": "LIVE",
                "health": "HEALTHY",
                "viewerCount": 150,
                "startTime": mock_start,
            }
        }

        result = video_monitor.check_ivs(sample_config)
        assert result["total"] == 1
        assert result["live"] == 1
        assert result["healthy"] == 1
        assert result["total_viewers"] == 150
        assert result["channels"][0]["state"] == "LIVE"
        assert result["channels"][0]["stream_health"] == "HEALTHY"
