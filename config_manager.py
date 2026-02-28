"""
Configuration Manager
======================
JSON-based config that persists to disk. The UI settings page reads/writes
through the Flask API, so everything is configurable without touching files.
"""

import os
import json
import logging

logger = logging.getLogger(__name__)

CONFIG_PATH = os.getenv("CONFIG_PATH", os.path.join(os.path.dirname(__file__), "config.json"))

DEFAULT_CONFIG = {
    "aws": {
        "region": "eu-west-2",
        "regions": ["eu-west-2"],
        "access_key_id": "",
        "secret_access_key": "",
    },
    "monitoring": {
        "check_interval_seconds": 300,
        "cpu_threshold": 80.0,
        "deployment_lookback_hours": 24,
        "uptime_alert_hours": 24,
        "monitor_ec2": True,
        "monitor_codedeploy": True,
        "monitor_ecs": True,
        "monitor_medialive": False,
        "monitor_mediaconnect": False,
        "monitor_mediapackage": False,
        "monitor_cloudfront": False,
        "monitor_ivs": False,
    },
    "ai": {
        "openrouter_api_key": "",
        "model": "anthropic/claude-sonnet-4.6",
        "max_tokens": 2048,
        "temperature": 0.3,
    },
    "auth": {
        "username": "admin",
        "password_hash": "",
    },
    "alert_rules": [],
    "endpoints": [],
    "notifications": {
        "enabled": True,
        "on_ec2_issues": True,
        "on_deploy_failures": True,
        "on_ecs_issues": True,
        "on_media_issues": True,
        "send_daily_summary": False,
        "daily_summary_hour": 9,
        "channels": {
            "whatsapp": {
                "enabled": False,
                "twilio_account_sid": "",
                "twilio_auth_token": "",
                "from_number": "whatsapp:+14155238886",
                "to_number": "",
            },
            "email": {
                "enabled": False,
                "provider": "smtp",
                "smtp_host": "",
                "smtp_port": 587,
                "smtp_username": "",
                "smtp_password": "",
                "smtp_use_tls": True,
                "ses_region": "eu-west-2",
                "from_address": "",
                "to_addresses": [],
            },
            "telegram": {
                "enabled": False,
                "bot_token": "",
                "chat_id": "",
                "parse_mode": "HTML",
            },
            "slack": {
                "enabled": False,
                "webhook_url": "",
            },
        },
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config() -> dict:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                saved = json.load(f)
            config = _deep_merge(DEFAULT_CONFIG, saved)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to load config: {e}")
            config = json.loads(json.dumps(DEFAULT_CONFIG))
    else:
        config = json.loads(json.dumps(DEFAULT_CONFIG))

    # Migrate single region to regions list
    aws = config.get("aws", {})
    if "regions" not in aws and "region" in aws:
        aws["regions"] = [aws["region"]]
    if aws.get("regions"):
        aws["region"] = aws["regions"][0]
    return config


def save_config(config: dict) -> bool:
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(config, f, indent=2)
        os.chmod(CONFIG_PATH, 0o600)
        return True
    except IOError as e:
        logger.error(f"Failed to save config: {e}")
        return False


def update_config(partial: dict) -> dict:
    current = load_config()
    updated = _deep_merge(current, partial)
    save_config(updated)
    return updated


def get_masked_config() -> dict:
    config = load_config()

    def mask(val: str) -> str:
        if not val:
            return ""
        if len(val) <= 4:
            return "••••"
        return "••••••••" + val[-4:]

    c = json.loads(json.dumps(config))

    # AWS
    if c["aws"]["secret_access_key"]:
        c["aws"]["secret_access_key"] = mask(c["aws"]["secret_access_key"])
    if c["aws"]["access_key_id"]:
        c["aws"]["access_key_id"] = mask(c["aws"]["access_key_id"])

    # Notification channels
    wh = c["notifications"]["channels"]["whatsapp"]
    if wh["twilio_auth_token"]:
        wh["twilio_auth_token"] = mask(wh["twilio_auth_token"])
    if wh["twilio_account_sid"]:
        wh["twilio_account_sid"] = mask(wh["twilio_account_sid"])

    em = c["notifications"]["channels"]["email"]
    if em["smtp_password"]:
        em["smtp_password"] = mask(em["smtp_password"])

    tg = c["notifications"]["channels"]["telegram"]
    if tg["bot_token"]:
        tg["bot_token"] = mask(tg["bot_token"])

    sl = c["notifications"]["channels"].get("slack", {})
    if sl.get("webhook_url"):
        sl["webhook_url"] = mask(sl["webhook_url"])

    # Auth
    if c.get("auth", {}).get("password_hash"):
        c["auth"]["password_hash"] = "••••••••"

    # AI
    if c.get("ai", {}).get("openrouter_api_key"):
        c["ai"]["openrouter_api_key"] = mask(c["ai"]["openrouter_api_key"])

    return c
