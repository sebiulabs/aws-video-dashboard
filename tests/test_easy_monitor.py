"""
Tests for easy_monitor.py
==========================
Covers SSRF protection, JSON path resolution, endpoint CRUD, and mocked HTTP checks.
"""

import json
import socket
from unittest.mock import patch, MagicMock

import pytest
import requests

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from easy_monitor import (
    _is_blocked_host,
    _resolve_json_path,
    _check_http,
    get_endpoints,
    save_endpoints,
    add_endpoint,
    update_endpoint,
    delete_endpoint,
)


# ─── _is_blocked_host ───────────────────────────────────────────────────────

class TestIsBlockedHost:
    def test_blocks_localhost(self):
        assert _is_blocked_host("127.0.0.1") is True

    def test_blocks_rfc1918_10(self):
        assert _is_blocked_host("10.0.0.1") is True

    def test_blocks_rfc1918_172(self):
        assert _is_blocked_host("172.16.0.1") is True

    def test_blocks_rfc1918_192(self):
        assert _is_blocked_host("192.168.1.1") is True

    def test_blocks_aws_imds(self):
        assert _is_blocked_host("169.254.169.254") is True

    def test_blocks_empty_string(self):
        assert _is_blocked_host("") is True

    def test_blocks_unresolvable_hostname(self):
        assert _is_blocked_host("this-host-does-not-exist-xyz.invalid") is True

    def test_allows_google(self):
        assert _is_blocked_host("google.com") is False

    def test_allows_public_ip(self):
        assert _is_blocked_host("8.8.8.8") is False


# ─── _resolve_json_path ─────────────────────────────────────────────────────

class TestResolveJsonPath:
    def test_simple_key(self):
        assert _resolve_json_path({"name": "test"}, "name") == "test"

    def test_nested_path(self):
        assert _resolve_json_path({"a": {"b": "val"}}, "a.b") == "val"

    def test_list_index(self):
        data = {"items": [{"id": 1}, {"id": 2}]}
        assert _resolve_json_path(data, "items.0.id") == 1

    def test_missing_key_returns_none(self):
        assert _resolve_json_path({"a": 1}, "b") is None

    def test_invalid_list_index_returns_none(self):
        data = {"items": [{"id": 1}]}
        assert _resolve_json_path(data, "items.99.id") is None

    def test_empty_path_returns_root(self):
        # Empty path means keys=[""], which is not in the dict, so returns None
        assert _resolve_json_path({"a": 1}, "") is None


# ─── Endpoint CRUD ───────────────────────────────────────────────────────────

class TestEndpointCRUD:
    def test_add_endpoint_returns_dict_with_id(self, tmp_config):
        ep = add_endpoint({"name": "My Endpoint", "url": "https://example.com"})
        assert isinstance(ep, dict)
        assert "id" in ep
        assert ep["id"].startswith("ep_")

    def test_get_endpoints_empty_initially(self, tmp_config):
        eps = get_endpoints()
        assert eps == []

    def test_get_endpoints_returns_added(self, tmp_config):
        add_endpoint({"name": "EP1"})
        add_endpoint({"name": "EP2"})
        eps = get_endpoints()
        assert len(eps) == 2

    def test_update_endpoint_changes_fields(self, tmp_config):
        ep = add_endpoint({"name": "Original"})
        updated = update_endpoint(ep["id"], {"name": "Updated"})
        assert updated is not None
        assert updated["name"] == "Updated"
        assert updated["id"] == ep["id"]

    def test_delete_endpoint_removes(self, tmp_config):
        ep = add_endpoint({"name": "To Delete"})
        assert delete_endpoint(ep["id"]) is True
        assert len(get_endpoints()) == 0

    def test_delete_nonexistent_returns_false(self, tmp_config):
        assert delete_endpoint("ep_nonexistent") is False

    def test_update_nonexistent_returns_none(self, tmp_config):
        result = update_endpoint("ep_nonexistent", {"name": "X"})
        assert result is None


# ─── Mocked HTTP checks ─────────────────────────────────────────────────────

class TestCheckHttp:
    @patch("easy_monitor._is_blocked_host", return_value=False)
    @patch("easy_monitor.requests.request")
    def test_success_200(self, mock_req, mock_blocked):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "OK"
        mock_req.return_value = mock_resp

        ep = {
            "url": "https://example.com/health",
            "method": "GET",
            "expected_status": 200,
            "body_contains": "",
            "timeout_seconds": 10,
        }
        result = _check_http(ep)
        assert result["status"] == "up"
        assert result["status_code"] == 200
        assert result["error"] is None

    @patch("easy_monitor._is_blocked_host", return_value=False)
    @patch("easy_monitor.requests.request")
    def test_wrong_status_code(self, mock_req, mock_blocked):
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_resp.text = "Service Unavailable"
        mock_req.return_value = mock_resp

        ep = {
            "url": "https://example.com/health",
            "method": "GET",
            "expected_status": 200,
            "body_contains": "",
            "timeout_seconds": 10,
        }
        result = _check_http(ep)
        assert result["status"] == "degraded"
        assert result["status_code"] == 503
        assert "Expected 200" in result["error"]

    @patch("easy_monitor._is_blocked_host", return_value=False)
    @patch("easy_monitor.requests.request", side_effect=requests.Timeout("timed out"))
    def test_timeout(self, mock_req, mock_blocked):
        ep = {
            "url": "https://example.com/health",
            "method": "GET",
            "expected_status": 200,
            "body_contains": "",
            "timeout_seconds": 5,
        }
        result = _check_http(ep)
        assert result["status"] == "down"
        assert "Timeout" in result["error"]

    def test_ssrf_blocked(self):
        """SSRF protection blocks private IP addresses."""
        ep = {
            "url": "http://10.0.0.1/admin",
            "method": "GET",
            "expected_status": 200,
            "body_contains": "",
            "timeout_seconds": 5,
        }
        result = _check_http(ep)
        assert result["status"] == "down"
        assert "Blocked" in result["error"]

    @patch("easy_monitor._is_blocked_host", return_value=False)
    @patch("easy_monitor.requests.request")
    def test_body_match_failure(self, mock_req, mock_blocked):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "some random content"
        mock_req.return_value = mock_resp

        ep = {
            "url": "https://example.com/manifest.m3u8",
            "method": "GET",
            "expected_status": 200,
            "body_contains": "#EXTM3U",
            "timeout_seconds": 10,
        }
        result = _check_http(ep)
        assert result["status"] == "degraded"
        assert result["body_match"] is False
        assert "Body missing" in result["error"]

    def test_non_http_scheme_blocked(self):
        ep = {
            "url": "ftp://example.com/file.txt",
            "method": "GET",
            "expected_status": 200,
            "body_contains": "",
            "timeout_seconds": 5,
        }
        result = _check_http(ep)
        assert result["status"] == "error"
        assert "Only http/https allowed" in result["error"]

    @patch("easy_monitor._is_blocked_host", return_value=False)
    @patch("easy_monitor.requests.request")
    def test_body_match_success(self, mock_req, mock_blocked):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "#EXTM3U\n#EXT-X-VERSION:3"
        mock_req.return_value = mock_resp

        ep = {
            "url": "https://example.com/manifest.m3u8",
            "method": "GET",
            "expected_status": 200,
            "body_contains": "#EXTM3U",
            "timeout_seconds": 10,
        }
        result = _check_http(ep)
        assert result["status"] == "up"
        assert result["body_match"] is True

    @patch("easy_monitor._is_blocked_host", return_value=False)
    @patch("easy_monitor.requests.request", side_effect=requests.ConnectionError("refused"))
    def test_connection_error(self, mock_req, mock_blocked):
        ep = {
            "url": "https://example.com/health",
            "method": "GET",
            "expected_status": 200,
            "body_contains": "",
            "timeout_seconds": 5,
        }
        result = _check_http(ep)
        assert result["status"] == "down"
        assert "Connection failed" in result["error"]
