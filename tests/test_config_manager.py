"""Tests for config_manager module."""

import copy
import json
import os
import stat

import pytest

from config_manager import (
    DEFAULT_CONFIG,
    _deep_merge,
    load_config,
    save_config,
    update_config,
    get_masked_config,
)


# ── _deep_merge pure-logic tests ─────────────────────────────────────────────

class TestDeepMerge:
    def test_merges_flat_keys(self):
        base = {"a": 1, "b": 2}
        override = {"b": 99, "c": 3}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 99, "c": 3}

    def test_deep_merge_nested_dicts(self):
        base = {"outer": {"inner": 1, "keep": True}}
        override = {"outer": {"inner": 2}}
        result = _deep_merge(base, override)
        assert result["outer"]["inner"] == 2
        assert result["outer"]["keep"] is True

    def test_override_replaces_non_dict_with_scalar(self):
        base = {"key": {"nested": 1}}
        override = {"key": "scalar"}
        result = _deep_merge(base, override)
        assert result["key"] == "scalar"

    def test_empty_override_returns_base_unchanged(self):
        base = {"a": 1, "b": {"c": 2}}
        result = _deep_merge(base, {})
        assert result == base

    def test_new_keys_added_from_override(self):
        base = {"existing": 1}
        override = {"brand_new": 42}
        result = _deep_merge(base, override)
        assert result["brand_new"] == 42
        assert result["existing"] == 1

    def test_base_is_not_mutated(self):
        base = {"a": {"b": 1}}
        original_base = copy.deepcopy(base)
        _deep_merge(base, {"a": {"b": 999}})
        assert base == original_base


# ── Config round-trip tests ───────────────────────────────────────────────────

class TestConfigRoundTrip:
    def test_load_defaults_when_no_file_exists(self, tmp_config):
        cfg = load_config()
        assert cfg["aws"]["region"] == DEFAULT_CONFIG["aws"]["region"]
        assert cfg["monitoring"]["check_interval_seconds"] == DEFAULT_CONFIG["monitoring"]["check_interval_seconds"]

    def test_save_and_load_round_trip_preserves_data(self, tmp_config, sample_config):
        save_config(sample_config)
        loaded = load_config()
        assert loaded["aws"]["access_key_id"] == "AKIAIOSFODNN7EXAMPLE"
        assert loaded["aws"]["secret_access_key"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert loaded["aws"]["region"] == "eu-west-2"

    def test_file_permissions_are_0600_after_save(self, tmp_config, sample_config):
        save_config(sample_config)
        mode = os.stat(tmp_config).st_mode
        assert stat.S_IMODE(mode) == 0o600

    def test_corrupt_json_falls_back_to_defaults(self, tmp_config):
        with open(tmp_config, "w") as f:
            f.write("{{{INVALID JSON")
        cfg = load_config()
        assert cfg["aws"]["region"] == DEFAULT_CONFIG["aws"]["region"]
        assert cfg["aws"]["secret_access_key"] == ""

    def test_update_config_merges_partial_updates(self, tmp_config):
        update_config({"aws": {"access_key_id": "NEWKEY"}})
        cfg = load_config()
        assert cfg["aws"]["access_key_id"] == "NEWKEY"

    def test_update_preserves_existing_untouched_keys(self, tmp_config, sample_config):
        save_config(sample_config)
        update_config({"monitoring": {"cpu_threshold": 95.0}})
        cfg = load_config()
        # Original AWS keys should still be there
        assert cfg["aws"]["access_key_id"] == "AKIAIOSFODNN7EXAMPLE"
        # Updated value should be present
        assert cfg["monitoring"]["cpu_threshold"] == 95.0

    def test_single_region_migrated_to_regions_list(self, tmp_config, monkeypatch):
        # Simulate old DEFAULT_CONFIG that has no "regions" key in aws,
        # and a saved config with only "region".  The migration code should
        # create the regions list from the single region value.
        old_defaults = copy.deepcopy(DEFAULT_CONFIG)
        del old_defaults["aws"]["regions"]
        monkeypatch.setattr("config_manager.DEFAULT_CONFIG", old_defaults)
        old_cfg = {"aws": {"region": "us-east-1"}}
        with open(tmp_config, "w") as f:
            json.dump(old_cfg, f)
        cfg = load_config()
        assert "regions" in cfg["aws"]
        assert cfg["aws"]["regions"] == ["us-east-1"]

    def test_existing_regions_list_preserved(self, tmp_config):
        explicit = {"aws": {"regions": ["ap-southeast-1", "us-west-2"], "region": "ap-southeast-1"}}
        with open(tmp_config, "w") as f:
            json.dump(explicit, f)
        cfg = load_config()
        assert cfg["aws"]["regions"] == ["ap-southeast-1", "us-west-2"]

    def test_primary_region_equals_first_region(self, tmp_config):
        explicit = {"aws": {"regions": ["ap-southeast-1", "us-west-2"]}}
        with open(tmp_config, "w") as f:
            json.dump(explicit, f)
        cfg = load_config()
        assert cfg["aws"]["region"] == cfg["aws"]["regions"][0]


# ── Masking tests ─────────────────────────────────────────────────────────────

class TestMasking:
    def test_empty_secrets_return_empty_string(self, tmp_config):
        # Default config has empty strings for secrets
        masked = get_masked_config()
        assert masked["aws"]["secret_access_key"] == ""
        assert masked["aws"]["access_key_id"] == ""

    def test_aws_secret_access_key_fully_masked(self, tmp_config, sample_config):
        save_config(sample_config)
        masked = get_masked_config()
        assert masked["aws"]["secret_access_key"] == "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"

    def test_access_key_id_fully_masked(self, tmp_config, sample_config):
        save_config(sample_config)
        masked = get_masked_config()
        assert masked["aws"]["access_key_id"] == "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"

    def test_twilio_auth_token_masked(self, tmp_config):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["notifications"]["channels"]["whatsapp"]["twilio_auth_token"] = "secret-twilio-token"
        save_config(cfg)
        masked = get_masked_config()
        assert masked["notifications"]["channels"]["whatsapp"]["twilio_auth_token"] == "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"

    def test_smtp_password_masked(self, tmp_config):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["notifications"]["channels"]["email"]["smtp_password"] = "my-smtp-pass"
        save_config(cfg)
        masked = get_masked_config()
        assert masked["notifications"]["channels"]["email"]["smtp_password"] == "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"

    def test_telegram_bot_token_masked(self, tmp_config):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["notifications"]["channels"]["telegram"]["bot_token"] = "123456:ABC-DEF"
        save_config(cfg)
        masked = get_masked_config()
        assert masked["notifications"]["channels"]["telegram"]["bot_token"] == "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"

    def test_slack_webhook_masked(self, tmp_config):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["notifications"]["channels"]["slack"]["webhook_url"] = "https://hooks.slack.com/services/T00/B00/xxx"
        save_config(cfg)
        masked = get_masked_config()
        assert masked["notifications"]["channels"]["slack"]["webhook_url"] == "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"

    def test_discord_webhook_masked(self, tmp_config):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["notifications"]["channels"]["discord"]["webhook_url"] = "https://discord.com/api/webhooks/123/abc"
        save_config(cfg)
        masked = get_masked_config()
        assert masked["notifications"]["channels"]["discord"]["webhook_url"] == "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"

    def test_teams_webhook_masked(self, tmp_config):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["notifications"]["channels"]["teams"]["webhook_url"] = "https://outlook.office.com/webhook/xxx"
        save_config(cfg)
        masked = get_masked_config()
        assert masked["notifications"]["channels"]["teams"]["webhook_url"] == "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"

    def test_openrouter_api_key_masked(self, tmp_config):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["ai"]["openrouter_api_key"] = "sk-or-v1-abc123"
        save_config(cfg)
        masked = get_masked_config()
        assert masked["ai"]["openrouter_api_key"] == "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"

    def test_gcp_service_account_json_masked(self, tmp_config):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["gcp"]["service_account_json"] = '{"type":"service_account","project_id":"my-proj"}'
        save_config(cfg)
        masked = get_masked_config()
        assert masked["gcp"]["service_account_json"] == "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"

    def test_auth_password_hash_masked(self, tmp_config):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["auth"]["password_hash"] = "pbkdf2:sha256:260000$abc"
        save_config(cfg)
        masked = get_masked_config()
        assert masked["auth"]["password_hash"] == "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"
