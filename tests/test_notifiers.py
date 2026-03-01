"""
Tests for notification modules
================================
Covers email_notifier, telegram_notifier, slack_notifier,
discord_notifier, and teams_notifier.
"""

import copy
import os
import sys
from unittest.mock import patch, MagicMock, call

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from email_notifier import _build_html_email, send_email_smtp, send_email_ses, send_email
from telegram_notifier import _convert_to_html, send_telegram
from slack_notifier import _format_slack_text, send_slack
from discord_notifier import _format_discord_text, send_discord
from teams_notifier import _build_adaptive_card, send_teams


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers: reusable config builders
# ═══════════════════════════════════════════════════════════════════════════════

def _email_config(enabled=True, provider="smtp", host="smtp.gmail.com", port=587,
                  username="user@gmail.com", password="secret", use_tls=True,
                  from_addr="user@gmail.com", to_addrs=None):
    return {
        "aws": {"region": "eu-west-2"},
        "notifications": {"channels": {"email": {
            "enabled": enabled,
            "provider": provider,
            "smtp_host": host,
            "smtp_port": port,
            "smtp_username": username,
            "smtp_password": password,
            "smtp_use_tls": use_tls,
            "from_address": from_addr,
            "to_addresses": to_addrs or ["dest@example.com"],
            "ses_region": "eu-west-2",
        }}},
    }


def _telegram_config(enabled=True, bot_token="123456:ABC", chat_id="-100999",
                     parse_mode="HTML"):
    return {
        "notifications": {"channels": {"telegram": {
            "enabled": enabled,
            "bot_token": bot_token,
            "chat_id": chat_id,
            "parse_mode": parse_mode,
        }}},
    }


def _slack_config(enabled=True, webhook_url="https://hooks.slack.com/services/T00/B00/xxx"):
    return {
        "notifications": {"channels": {"slack": {
            "enabled": enabled,
            "webhook_url": webhook_url,
        }}},
    }


def _discord_config(enabled=True,
                    webhook_url="https://discord.com/api/webhooks/12345/token",
                    username="AWS Dashboard"):
    return {
        "notifications": {"channels": {"discord": {
            "enabled": enabled,
            "webhook_url": webhook_url,
            "username": username,
        }}},
    }


def _teams_config(enabled=True,
                  webhook_url="https://outlook.office.com/webhook/abc123"):
    return {
        "notifications": {"channels": {"teams": {
            "enabled": enabled,
            "webhook_url": webhook_url,
        }}},
    }


# ═══════════════════════════════════════════════════════════════════════════════
# EMAIL NOTIFIER
# ═══════════════════════════════════════════════════════════════════════════════

class TestBuildHtmlEmail:
    """Pure-logic tests for _build_html_email."""

    def test_contains_subject(self):
        html = _build_html_email("Server Down", "Details here")
        assert "Server Down" in html

    def test_newlines_converted_to_br(self):
        html = _build_html_email("Alert", "line1\nline2\nline3")
        assert "line1<br>line2<br>line3" in html

    def test_html_special_chars_escaped(self):
        html = _build_html_email("Test <script>", "a < b & c > d")
        # Subject and body should have HTML-escaped chars
        assert "&lt;script&gt;" in html
        assert "a &lt; b &amp; c &gt; d" in html


class TestSendEmailSmtp:
    """Mocked tests for send_email_smtp."""

    @patch("email_notifier.smtplib.SMTP")
    def test_success_starttls(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value = mock_server
        cfg = _email_config(port=587, use_tls=True)

        result = send_email_smtp("Subj", "Body", config=cfg)

        assert result is True
        mock_smtp_cls.assert_called_once_with("smtp.gmail.com", 587)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("user@gmail.com", "secret")
        mock_server.sendmail.assert_called_once()
        mock_server.quit.assert_called_once()

    @patch("email_notifier.smtplib.SMTP_SSL")
    def test_success_ssl_port465(self, mock_smtp_ssl_cls):
        mock_server = MagicMock()
        mock_smtp_ssl_cls.return_value = mock_server
        cfg = _email_config(port=465, use_tls=True)

        result = send_email_smtp("Subj", "Body", config=cfg)

        assert result is True
        mock_smtp_ssl_cls.assert_called_once()
        mock_server.login.assert_called_once()
        mock_server.sendmail.assert_called_once()

    def test_disabled_returns_false(self):
        cfg = _email_config(enabled=False)
        # send_email (the unified sender) checks enabled flag
        result = send_email("Subj", "Body", config=cfg)
        assert result is False

    def test_not_configured_returns_false(self):
        cfg = _email_config(host="", to_addrs=[])
        result = send_email_smtp("Subj", "Body", config=cfg)
        assert result is False


class TestSendEmailSes:
    """Mocked tests for send_email_ses."""

    @patch("email_notifier.boto3.client")
    def test_ses_success(self, mock_boto_client):
        mock_ses = MagicMock()
        mock_ses.send_email.return_value = {"MessageId": "abc-123"}
        mock_boto_client.return_value = mock_ses

        cfg = _email_config(provider="ses", from_addr="noreply@example.com",
                            to_addrs=["dest@example.com"])
        result = send_email_ses("Alert", "Body text", config=cfg)

        assert result is True
        mock_boto_client.assert_called_once_with("ses", region_name="eu-west-2")
        mock_ses.send_email.assert_called_once()
        call_kwargs = mock_ses.send_email.call_args
        assert call_kwargs[1]["Source"] == "noreply@example.com"


class TestSendEmailRouter:
    """Tests for the unified send_email function."""

    @patch("email_notifier.send_email_ses")
    def test_routes_to_ses(self, mock_ses):
        mock_ses.return_value = True
        cfg = _email_config(provider="ses")
        result = send_email("Subj", "Body", config=cfg)
        assert result is True
        mock_ses.assert_called_once()

    @patch("email_notifier.send_email_smtp")
    def test_routes_to_smtp(self, mock_smtp):
        mock_smtp.return_value = True
        cfg = _email_config(provider="smtp")
        result = send_email("Subj", "Body", config=cfg)
        assert result is True
        mock_smtp.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════════
# TELEGRAM NOTIFIER
# ═══════════════════════════════════════════════════════════════════════════════

class TestConvertToHtml:
    """Pure-logic tests for _convert_to_html."""

    def test_escapes_angle_brackets_and_ampersand(self):
        result = _convert_to_html("a < b & c > d")
        assert "&lt;" in result
        assert "&gt;" in result
        assert "&amp;" in result

    def test_converts_bold_markers(self):
        result = _convert_to_html("This is *bold* text")
        assert "<b>bold</b>" in result
        assert "*bold*" not in result


class TestSendTelegram:
    """Mocked tests for send_telegram."""

    @patch("telegram_notifier.requests.post")
    def test_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"ok": True, "result": {}}
        mock_post.return_value = mock_resp

        cfg = _telegram_config()
        result = send_telegram("Hello", config=cfg)

        assert result is True
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert "123456:ABC" in call_kwargs[0][0]  # URL contains token
        assert call_kwargs[1]["json"]["chat_id"] == "-100999"

    def test_disabled_returns_false(self):
        cfg = _telegram_config(enabled=False)
        result = send_telegram("Hello", config=cfg)
        assert result is False

    def test_not_configured_no_token(self):
        cfg = _telegram_config(bot_token="", chat_id="")
        result = send_telegram("Hello", config=cfg)
        assert result is False

    @patch("telegram_notifier.requests.post")
    def test_api_error(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"ok": False, "description": "Bad Request"}
        mock_post.return_value = mock_resp

        cfg = _telegram_config()
        result = send_telegram("Hello", config=cfg)
        assert result is False

    @patch("telegram_notifier.requests.post")
    def test_network_error(self, mock_post):
        import requests as req
        mock_post.side_effect = req.ConnectionError("Connection refused")

        cfg = _telegram_config()
        result = send_telegram("Hello", config=cfg)
        assert result is False


# ═══════════════════════════════════════════════════════════════════════════════
# SLACK NOTIFIER
# ═══════════════════════════════════════════════════════════════════════════════

class TestFormatSlackText:
    """Pure-logic tests for _format_slack_text."""

    def test_basic_formatting_passthrough(self):
        result = _format_slack_text("*bold* and normal")
        assert "*bold*" in result
        assert "normal" in result


class TestSendSlack:
    """Mocked tests for send_slack."""

    @patch("slack_notifier.requests.post")
    def test_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "ok"
        mock_post.return_value = mock_resp

        cfg = _slack_config()
        result = send_slack("Alert!", config=cfg)

        assert result is True
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args[0][0] == "https://hooks.slack.com/services/T00/B00/xxx"
        assert call_args[1]["json"]["text"] == "Alert!"

    def test_disabled_returns_false(self):
        cfg = _slack_config(enabled=False)
        result = send_slack("Alert!", config=cfg)
        assert result is False

    def test_invalid_url_returns_false(self):
        cfg = _slack_config(webhook_url="https://evil.com/hooks")
        result = send_slack("Alert!", config=cfg)
        assert result is False

    @patch("slack_notifier.requests.post")
    def test_bad_response_status(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "invalid_token"
        mock_post.return_value = mock_resp

        cfg = _slack_config()
        result = send_slack("Alert!", config=cfg)
        assert result is False

    @patch("slack_notifier.requests.post")
    def test_uses_allow_redirects_false(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "ok"
        mock_post.return_value = mock_resp

        cfg = _slack_config()
        send_slack("Alert!", config=cfg)

        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["allow_redirects"] is False


# ═══════════════════════════════════════════════════════════════════════════════
# DISCORD NOTIFIER
# ═══════════════════════════════════════════════════════════════════════════════

class TestFormatDiscordText:
    """Pure-logic tests for _format_discord_text."""

    def test_converts_single_bold_to_double_bold(self):
        result = _format_discord_text("This is *bold* text")
        assert "**bold**" in result
        assert result.count("*") == 4  # exactly **bold**


class TestSendDiscord:
    """Mocked tests for send_discord."""

    @patch("discord_notifier.requests.post")
    def test_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        mock_resp.text = ""
        mock_post.return_value = mock_resp

        cfg = _discord_config()
        result = send_discord("Alert!", config=cfg)

        assert result is True
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["json"]["content"] == "Alert!"
        assert call_kwargs["json"]["username"] == "AWS Dashboard"

    def test_disabled_returns_false(self):
        cfg = _discord_config(enabled=False)
        result = send_discord("Alert!", config=cfg)
        assert result is False

    def test_invalid_url_returns_false(self):
        cfg = _discord_config(webhook_url="https://evil.com/webhooks/123")
        result = send_discord("Alert!", config=cfg)
        assert result is False

    @patch("discord_notifier.requests.post")
    def test_message_truncation(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        mock_resp.text = ""
        mock_post.return_value = mock_resp

        cfg = _discord_config()
        long_message = "A" * 2500
        send_discord(long_message, config=cfg)

        sent_content = mock_post.call_args[1]["json"]["content"]
        # Truncated to 1900 + the truncation suffix
        assert len(sent_content) < 2000
        assert "truncated" in sent_content

    @patch("discord_notifier.requests.post")
    def test_uses_allow_redirects_false(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        mock_resp.text = ""
        mock_post.return_value = mock_resp

        cfg = _discord_config()
        send_discord("Alert!", config=cfg)

        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["allow_redirects"] is False


# ═══════════════════════════════════════════════════════════════════════════════
# TEAMS NOTIFIER
# ═══════════════════════════════════════════════════════════════════════════════

class TestBuildAdaptiveCard:
    """Pure-logic tests for _build_adaptive_card."""

    def test_returns_dict_with_correct_schema(self):
        card = _build_adaptive_card("Hello world")
        assert card["type"] == "message"
        assert len(card["attachments"]) == 1
        content = card["attachments"][0]["content"]
        assert content["$schema"] == "https://adaptivecards.io/schemas/adaptive-card.json"
        assert content["type"] == "AdaptiveCard"
        assert content["version"] == "1.4"

    def test_splits_text_into_sections(self):
        text = "Section one\n\nSection two\n\nSection three"
        card = _build_adaptive_card(text)
        content = card["attachments"][0]["content"]
        # First body item is the header, then 3 sections
        body = content["body"]
        assert body[0]["text"] == "AWS Dashboard Alert"
        # The remaining items are the sections
        section_texts = [b["text"] for b in body[1:]]
        assert len(section_texts) == 3
        assert "Section one" in section_texts[0]
        assert "Section two" in section_texts[1]
        assert "Section three" in section_texts[2]


class TestSendTeams:
    """Mocked tests for send_teams."""

    @patch("teams_notifier.requests.post")
    def test_success_200_legacy(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "1"
        mock_post.return_value = mock_resp

        cfg = _teams_config(webhook_url="https://outlook.office.com/webhook/abc")
        result = send_teams("Alert!", config=cfg)

        assert result is True
        mock_post.assert_called_once()

    @patch("teams_notifier.requests.post")
    def test_success_202_workflows(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 202
        mock_resp.text = ""
        mock_post.return_value = mock_resp

        cfg = _teams_config(
            webhook_url="https://prod-00.westus.logic.azure.com:443/workflows/abc"
        )
        result = send_teams("Alert!", config=cfg)

        assert result is True
        mock_post.assert_called_once()

    def test_disabled_returns_false(self):
        cfg = _teams_config(enabled=False)
        result = send_teams("Alert!", config=cfg)
        assert result is False

    def test_invalid_url_not_https(self):
        cfg = _teams_config(webhook_url="http://not-secure.com/hook")
        result = send_teams("Alert!", config=cfg)
        assert result is False

    @patch("teams_notifier.requests.post")
    def test_uses_allow_redirects_false(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "1"
        mock_post.return_value = mock_resp

        cfg = _teams_config()
        send_teams("Alert!", config=cfg)

        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["allow_redirects"] is False
