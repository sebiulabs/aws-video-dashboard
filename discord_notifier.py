"""
Discord Notification Module
==============================
Sends alerts to a Discord channel via a Webhook URL.
No extra dependencies — just requests.

Setup:
  1. In Discord: Server Settings → Integrations → Webhooks → New Webhook
  2. Pick a channel, optionally customise the name/avatar
  3. Copy the webhook URL
  4. Paste the URL in Settings → Discord → Webhook URL
"""

import logging
from typing import Optional

import requests

from config_manager import load_config

logger = logging.getLogger(__name__)


def _format_discord_text(text: str) -> str:
    """Convert our alert format to Discord markdown.

    Discord uses standard markdown:  **bold**, *italic*, `code`, etc.
    Our alert format already uses *bold* so convert to **bold**.
    """
    import re
    # Convert single *bold* to **bold** (Discord bold)
    text = re.sub(r'(?<!\*)\*([^*]+)\*(?!\*)', r'**\1**', text)
    return text


def send_discord(message: str, config: Optional[dict] = None) -> bool:
    """Send a message to Discord via Webhook."""
    if config is None:
        config = load_config()

    dc = config.get("notifications", {}).get("channels", {}).get("discord", {})

    if not dc.get("enabled"):
        logger.debug("Discord notifications disabled")
        return False

    webhook_url = dc.get("webhook_url", "")

    if not webhook_url:
        logger.warning("Discord webhook URL not configured — skipping")
        return False

    if not (webhook_url.startswith("https://discord.com/api/webhooks/") or webhook_url.startswith("https://discordapp.com/api/webhooks/")):
        logger.error("Invalid Discord webhook URL")
        return False

    text = _format_discord_text(message)

    # Discord webhook has a 2000 character limit per message
    if len(text) > 1900:
        text = text[:1900] + "\n… (truncated)"

    payload = {
        "content": text,
        "username": dc.get("username", "AWS Dashboard"),
    }

    try:
        response = requests.post(webhook_url, json=payload, timeout=10, allow_redirects=False)

        # Discord returns 204 No Content on success
        if response.status_code in (200, 204):
            logger.info("Discord message sent")
            return True
        else:
            logger.error(f"Discord webhook error: {response.status_code} {response.text[:200]}")
            return False

    except requests.RequestException as e:
        logger.error(f"Discord send failed: {e}")
        return False
