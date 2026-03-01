"""
Microsoft Teams Notification Module
======================================
Sends alerts to a Teams channel via an Incoming Webhook URL.
No extra dependencies — just requests.

Setup:
  1. In Teams: open channel → ••• → Connectors (or Workflows)
  2. Add "Incoming Webhook" connector
  3. Give it a name (e.g. "AWS Dashboard"), optionally set an icon
  4. Copy the webhook URL
  5. Paste the URL in Settings → Microsoft Teams → Webhook URL

Note: Microsoft is migrating from O365 Connectors to Workflows webhooks.
This module supports both formats:
  - Legacy: https://outlook.office.com/webhook/...
  - Workflows: https://prod-xx.westus.logic.azure.com:443/workflows/...
Both accept the same Adaptive Card JSON payload.
"""

import logging
from typing import Optional

import requests

from config_manager import load_config

logger = logging.getLogger(__name__)


def _build_adaptive_card(text: str) -> dict:
    """Build a Teams Adaptive Card from alert text.

    Adaptive Cards are the modern Teams message format. They render
    nicely on desktop, mobile, and web. We split the text into sections
    for better readability.
    """
    import re

    # Convert *bold* to **bold** for Adaptive Card markdown
    text = re.sub(r'(?<!\*)\*([^*]+)\*(?!\*)', r'**\1**', text)

    # Split into sections on double newlines
    sections = [s.strip() for s in text.split("\n\n") if s.strip()]

    body = []
    for section in sections:
        body.append({
            "type": "TextBlock",
            "text": section,
            "wrap": True,
            "size": "Small",
        })

    if not body:
        body.append({"type": "TextBlock", "text": text, "wrap": True})

    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "https://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {
                        "type": "TextBlock",
                        "text": "AWS Dashboard Alert",
                        "weight": "Bolder",
                        "size": "Medium",
                        "color": "Attention",
                    },
                    *body,
                ],
            },
        }],
    }


def send_teams(message: str, config: Optional[dict] = None) -> bool:
    """Send a message to Microsoft Teams via Incoming Webhook."""
    if config is None:
        config = load_config()

    teams = config.get("notifications", {}).get("channels", {}).get("teams", {})

    if not teams.get("enabled"):
        logger.debug("Teams notifications disabled")
        return False

    webhook_url = teams.get("webhook_url", "")

    if not webhook_url:
        logger.warning("Teams webhook URL not configured — skipping")
        return False

    if not webhook_url.startswith("https://"):
        logger.error("Invalid Teams webhook URL — must use HTTPS")
        return False

    payload = _build_adaptive_card(message)

    try:
        response = requests.post(webhook_url, json=payload, timeout=15, allow_redirects=False)

        # Workflows webhooks return 202 Accepted, legacy returns 200
        if response.status_code in (200, 202):
            logger.info("Teams message sent")
            return True
        else:
            logger.error(f"Teams webhook error: {response.status_code} {response.text[:200]}")
            return False

    except requests.RequestException as e:
        logger.error(f"Teams send failed: {e}")
        return False
