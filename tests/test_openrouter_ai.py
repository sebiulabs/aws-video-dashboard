"""
Tests for openrouter_ai.py
============================
Covers _sanitize_infra_for_ai, build_system_prompt, and query_openrouter.
"""

import copy
import json
import os
import sys
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from openrouter_ai import (
    _sanitize_infra_for_ai,
    build_system_prompt,
    query_openrouter,
    AGENT_PROMPT_ADDENDUM,
)


# ═══════════════════════════════════════════════════════════════════════════════
# _sanitize_infra_for_ai  (pure logic)
# ═══════════════════════════════════════════════════════════════════════════════

class TestSanitizeInfraForAi:

    def test_strips_private_ip(self):
        data = {"ec2": {"private_ip": "10.0.0.1", "name": "web-1"}}
        result = _sanitize_infra_for_ai(data)
        assert result["ec2"]["private_ip"] == "***.***.***.***"
        assert result["ec2"]["name"] == "web-1"

    def test_strips_public_ip(self):
        data = {"ec2": {"public_ip": "54.1.2.3"}}
        result = _sanitize_infra_for_ai(data)
        assert result["ec2"]["public_ip"] == "***.***.***.***"

    def test_strips_endpoint(self):
        data = {"rds": {"endpoint": "mydb.abc.eu-west-2.rds.amazonaws.com"}}
        result = _sanitize_infra_for_ai(data)
        assert result["rds"]["endpoint"] == "***.***.***.***"

    def test_strips_arn(self):
        data = {"lambda": {"arn": "arn:aws:lambda:eu-west-2:123456:function:myfn"}}
        result = _sanitize_infra_for_ai(data)
        assert result["lambda"]["arn"] == "***.***.***.***"

    def test_strips_vpc_subnet_sg(self):
        data = {"net": {
            "vpc_id": "vpc-123abc",
            "subnet_id": "subnet-456def",
            "security_group_id": "sg-789ghi",
        }}
        result = _sanitize_infra_for_ai(data)
        assert result["net"]["vpc_id"] == "***.***.***.***"
        assert result["net"]["subnet_id"] == "***.***.***.***"
        assert result["net"]["security_group_id"] == "***.***.***.***"

    def test_preserves_non_sensitive_keys(self):
        data = {"ec2": {"name": "web-1", "status": "running", "state": "active",
                        "instance_type": "t3.micro"}}
        result = _sanitize_infra_for_ai(data)
        assert result["ec2"]["name"] == "web-1"
        assert result["ec2"]["status"] == "running"
        assert result["ec2"]["state"] == "active"
        assert result["ec2"]["instance_type"] == "t3.micro"

    def test_handles_nested_dicts(self):
        data = {"outer": {"inner": {"private_ip": "10.0.0.1", "name": "ok"}}}
        result = _sanitize_infra_for_ai(data)
        assert result["outer"]["inner"]["private_ip"] == "***.***.***.***"
        assert result["outer"]["inner"]["name"] == "ok"

    def test_handles_lists_of_dicts(self):
        data = {"instances": [
            {"public_ip": "1.2.3.4", "name": "a"},
            {"public_ip": "5.6.7.8", "name": "b"},
        ]}
        result = _sanitize_infra_for_ai(data)
        assert result["instances"][0]["public_ip"] == "***.***.***.***"
        assert result["instances"][0]["name"] == "a"
        assert result["instances"][1]["public_ip"] == "***.***.***.***"
        assert result["instances"][1]["name"] == "b"

    def test_empty_input_returns_empty(self):
        assert _sanitize_infra_for_ai({}) == {}
        assert _sanitize_infra_for_ai(None) == {}

    def test_does_not_mutate_original(self):
        original = {"ec2": {"private_ip": "10.0.0.1", "name": "web-1"}}
        saved = copy.deepcopy(original)
        _sanitize_infra_for_ai(original)
        assert original == saved


# ═══════════════════════════════════════════════════════════════════════════════
# build_system_prompt  (pure logic)
# ═══════════════════════════════════════════════════════════════════════════════

def _base_config(**monitoring_overrides):
    cfg = {
        "aws": {"region": "us-east-1"},
        "monitoring": {},
        "alert_rules": [],
    }
    cfg["monitoring"].update(monitoring_overrides)
    return cfg


class TestBuildSystemPrompt:

    @patch("ai_actions.get_action_summary", return_value="")
    def test_includes_region(self, _mock):
        prompt = build_system_prompt({}, _base_config())
        assert "us-east-1" in prompt

    @patch("ai_actions.get_action_summary", return_value="")
    def test_includes_enabled_services(self, _mock):
        cfg = _base_config(monitor_ec2=True, monitor_rds=True)
        prompt = build_system_prompt({}, cfg)
        assert "EC2" in prompt
        assert "RDS" in prompt

    @patch("ai_actions.get_action_summary", return_value="")
    def test_includes_infra_data_as_json(self, _mock):
        infra = {"ec2": [{"name": "web-1", "state": "running"}]}
        prompt = build_system_prompt(infra, _base_config())
        assert '"name": "web-1"' in prompt
        assert '"state": "running"' in prompt

    @patch("ai_actions.get_action_summary", return_value="")
    def test_truncates_very_large_data(self, _mock):
        # Build infra data large enough to exceed 30000 chars when JSON-dumped
        big_infra = {"items": [{"data": "x" * 500} for _ in range(100)]}
        prompt = build_system_prompt(big_infra, _base_config())
        assert "truncated" in prompt

    @patch("ai_actions.get_action_summary", return_value="")
    def test_works_with_empty_infra_data(self, _mock):
        prompt = build_system_prompt({}, _base_config())
        assert "CURRENT INFRASTRUCTURE STATE" in prompt
        assert "{}" in prompt


# ═══════════════════════════════════════════════════════════════════════════════
# query_openrouter  (mocked)
# ═══════════════════════════════════════════════════════════════════════════════

def _ai_config(api_key="sk-or-test-key", model="anthropic/claude-sonnet-4.6",
               max_tokens=512, temperature=0.3):
    return {
        "aws": {"region": "eu-west-2"},
        "monitoring": {},
        "alert_rules": [],
        "ai": {
            "openrouter_api_key": api_key,
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
        },
    }


class TestQueryOpenrouter:

    @patch("openrouter_ai.requests.post")
    def test_success_response(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "All good!"}}],
            "model": "anthropic/claude-sonnet-4.6",
            "usage": {"total_tokens": 150},
        }
        mock_post.return_value = mock_resp

        result = query_openrouter("How is my infra?", {}, config=_ai_config())

        assert result["response"] == "All good!"
        assert result["model"] == "anthropic/claude-sonnet-4.6"
        assert result["tokens"] == 150
        assert result["error"] is None

    def test_no_api_key_returns_error(self):
        result = query_openrouter("Hello", {}, config=_ai_config(api_key=""))
        assert result["error"] == "no_api_key"
        assert "not configured" in result["response"]

    @patch("openrouter_ai.requests.post")
    def test_api_error_status_code(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.json.return_value = {
            "error": {"message": "Rate limit exceeded"},
        }
        mock_post.return_value = mock_resp

        result = query_openrouter("Hello", {}, config=_ai_config())
        assert result["error"] == "Rate limit exceeded"
        assert "Rate limit" in result["response"]

    @patch("openrouter_ai.requests.post")
    def test_network_timeout(self, mock_post):
        import requests as req
        mock_post.side_effect = req.Timeout("Read timed out")

        result = query_openrouter("Hello", {}, config=_ai_config())
        assert result["error"] == "timeout"
        assert "timed out" in result["response"]

    @patch("openrouter_ai.requests.post")
    def test_connection_error(self, mock_post):
        import requests as req
        mock_post.side_effect = req.ConnectionError("DNS failure")

        result = query_openrouter("Hello", {}, config=_ai_config())
        assert result["error"] is not None
        assert "Connection error" in result["response"]

    @patch("openrouter_ai.requests.post")
    def test_conversation_history_passed(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "Got it"}}],
            "usage": {"total_tokens": 50},
        }
        mock_post.return_value = mock_resp

        history = [
            {"role": "user", "content": "What is EC2?"},
            {"role": "assistant", "content": "EC2 is a compute service."},
        ]
        query_openrouter("Tell me more", {}, config=_ai_config(),
                         conversation_history=history)

        # Verify the messages payload includes history + new message
        call_kwargs = mock_post.call_args[1]
        messages = call_kwargs["json"]["messages"]
        roles = [m["role"] for m in messages]
        # system, user (history), assistant (history), user (new)
        assert roles[0] == "system"
        assert roles[1] == "user"
        assert roles[2] == "assistant"
        assert roles[3] == "user"
        assert messages[3]["content"] == "Tell me more"

    @patch("openrouter_ai.requests.post")
    def test_agent_mode_includes_action_protocol(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "AGENT_PLAN: ..."}}],
            "usage": {"total_tokens": 100},
        }
        mock_post.return_value = mock_resp

        query_openrouter("Launch an instance", {}, config=_ai_config(),
                         agent_mode=True)

        call_kwargs = mock_post.call_args[1]
        system_msg = call_kwargs["json"]["messages"][0]["content"]
        assert "AGENT MODE PROTOCOL" in system_msg
        assert "AGENT_PLAN" in system_msg
