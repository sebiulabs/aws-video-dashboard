"""
Slack Notification Module
===========================
Sends alerts to a Slack channel via an Incoming Webhook URL.
No extra dependencies — just requests.

Setup:
  1. Go to https://api.slack.com/apps → Create New App → From Scratch
  2. Enable "Incoming Webhooks" → Add New Webhook to Workspace
  3. Pick a channel → Copy the webhook URL
  4. Paste the URL in Settings → Slack → Webhook URL
"""

import logging
from typing import Optional

import requests

from config_manager import load_config

logger = logging.getLogger(__name__)


def _format_slack_text(text: str) -> str:
    """Convert our alert format to Slack mrkdwn."""
    import re
    # *bold* stays the same in Slack mrkdwn
    # Just ensure clean line breaks
    return text


def send_slack(message: str, config: Optional[dict] = None) -> bool:
    """Send a message to Slack via Incoming Webhook."""
    if config is None:
        config = load_config()

    sl = config["notifications"]["channels"].get("slack", {})

    if not sl.get("enabled"):
        logger.debug("Slack notifications disabled")
        return False

    webhook_url = sl.get("webhook_url", "")

    if not webhook_url:
        logger.warning("Slack webhook URL not configured — skipping")
        return False

    text = _format_slack_text(message)

    try:
        response = requests.post(webhook_url, json={"text": text}, timeout=10)

        if response.status_code == 200 and response.text == "ok":
            logger.info("Slack message sent")
            return True
        else:
            logger.error(f"Slack webhook error: {response.status_code} {response.text}")
            return False

    except requests.RequestException as e:
        logger.error(f"Slack send failed: {e}")
        return False
