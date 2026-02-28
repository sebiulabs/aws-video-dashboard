"""
Telegram Notification Module
==============================
Uses the Telegram Bot API directly via requests — no extra dependencies.

Setup:
  1. Message @BotFather on Telegram → /newbot → get the bot token
  2. Add the bot to your group or start a DM with it
  3. Get your chat_id:
     - For personal DMs: message the bot, then visit
       https://api.telegram.org/bot<TOKEN>/getUpdates
     - For groups: add the bot, send a message, check getUpdates
     - For channels: use @channelusername or the numeric ID
"""

import logging
from typing import Optional

import requests

from config_manager import load_config

logger = logging.getLogger(__name__)

TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"


def _convert_to_html(text: str) -> str:
    """Convert our alert format (markdown-ish) to Telegram HTML."""
    # Bold markers: *text* → <b>text</b>
    import re
    text = re.sub(r'\*([^*]+)\*', r'<b>\1</b>', text)
    # Bullet points stay as-is (Telegram renders them fine)
    return text


def send_telegram(message: str, config: Optional[dict] = None) -> bool:
    """Send a message via Telegram Bot API."""
    if config is None:
        config = load_config()

    tg = config["notifications"]["channels"]["telegram"]

    if not tg["enabled"]:
        logger.debug("Telegram notifications disabled")
        return False

    bot_token = tg["bot_token"]
    chat_id = tg["chat_id"]

    if not bot_token or not chat_id:
        logger.warning("Telegram not configured — skipping")
        logger.info(f"[WOULD SEND Telegram]: {message}")
        return False

    parse_mode = tg.get("parse_mode", "HTML")
    if parse_mode == "HTML":
        message = _convert_to_html(message)

    url = TELEGRAM_API.format(token=bot_token)

    try:
        response = requests.post(url, json={
            "chat_id": chat_id,
            "text": message,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True,
        }, timeout=10)

        data = response.json()
        if data.get("ok"):
            logger.info(f"Telegram sent to chat {chat_id}")
            return True
        else:
            logger.error(f"Telegram API error: {data.get('description', 'Unknown error')}")
            return False

    except requests.RequestException as e:
        logger.error(f"Telegram send failed: {e}")
        return False


def get_bot_info(bot_token: str) -> Optional[dict]:
    """Verify a bot token is valid by calling getMe."""
    try:
        url = f"https://api.telegram.org/bot{bot_token}/getMe"
        resp = requests.get(url, timeout=5)
        data = resp.json()
        if data.get("ok"):
            return data["result"]
    except Exception as e:
        logger.error(f"getMe failed: {e}")
    return None
