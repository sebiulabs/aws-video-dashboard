"""
Email Notification Module
==========================
Supports two providers:
  - SMTP (Gmail, Outlook, any SMTP server)
  - AWS SES (if you're already in the AWS ecosystem)
"""

import logging
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

import boto3
from botocore.exceptions import ClientError

from config_manager import load_config

logger = logging.getLogger(__name__)


# ─── HTML Email Template ────────────────────────────────────────────────────

def _build_html_email(subject: str, body_text: str) -> str:
    """Wrap alert text in a styled HTML email."""
    import html
    subject = html.escape(subject)
    body_text = html.escape(body_text)
    # Convert newlines and markdown-ish formatting
    body_html = body_text.replace("\n", "<br>")
    body_html = body_html.replace("🚨", '<span style="font-size:1.2em">🚨</span>')
    body_html = body_html.replace("⚠️", '<span style="font-size:1.2em">⚠️</span>')
    body_html = body_html.replace("✅", '<span style="font-size:1.2em">✅</span>')

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f4f4f7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f7;padding:32px 0;">
    <tr><td align="center">
      <table width="580" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
        <!-- Header -->
        <tr>
          <td style="background:#0f1117;padding:20px 32px;">
            <h1 style="margin:0;color:#58a6ff;font-size:18px;">AWS Infrastructure Alert</h1>
          </td>
        </tr>
        <!-- Body -->
        <tr>
          <td style="padding:24px 32px;color:#24292f;font-size:14px;line-height:1.6;">
            <h2 style="margin:0 0 16px;font-size:16px;color:#1a1a1a;">{subject}</h2>
            <div style="background:#f6f8fa;border:1px solid #d0d7de;border-radius:6px;padding:16px;font-family:monospace;font-size:13px;">
              {body_html}
            </div>
          </td>
        </tr>
        <!-- Footer -->
        <tr>
          <td style="padding:16px 32px;background:#f6f8fa;border-top:1px solid #d0d7de;font-size:12px;color:#8b949e;">
            Sent by AWS Monitoring Dashboard
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""


# ─── SMTP Sender ────────────────────────────────────────────────────────────

def send_email_smtp(subject: str, body: str, config: Optional[dict] = None) -> bool:
    """Send email via SMTP (Gmail, Outlook, custom server, etc.)."""
    if config is None:
        config = load_config()

    email_cfg = config["notifications"]["channels"]["email"]
    host = email_cfg["smtp_host"]
    port = email_cfg["smtp_port"]
    username = email_cfg["smtp_username"]
    password = email_cfg["smtp_password"]
    use_tls = email_cfg["smtp_use_tls"]
    from_addr = email_cfg["from_address"]
    to_addrs = email_cfg["to_addresses"]

    if not host or not to_addrs:
        logger.warning("SMTP not configured — skipping email")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_addr or username
    msg["To"] = ", ".join(to_addrs)

    # Plain text part
    msg.attach(MIMEText(body, "plain"))
    # HTML part
    msg.attach(MIMEText(_build_html_email(subject, body), "html"))

    server = None
    try:
        ctx = ssl.create_default_context()

        if use_tls:
            if port == 465:
                server = smtplib.SMTP_SSL(host, port, context=ctx)
            else:
                server = smtplib.SMTP(host, port)
                server.starttls(context=ctx)
        else:
            server = smtplib.SMTP(host, port)

        if username and password:
            server.login(username, password)
        server.sendmail(from_addr or username, to_addrs, msg.as_string())
        logger.info(f"Email sent to {to_addrs}")
        return True
    except Exception as e:
        logger.error(f"SMTP send failed: {e}")
        return False
    finally:
        if server:
            try:
                server.quit()
            except Exception:
                pass


# ─── AWS SES Sender ─────────────────────────────────────────────────────────

def send_email_ses(subject: str, body: str, config: Optional[dict] = None) -> bool:
    """Send email via AWS SES."""
    if config is None:
        config = load_config()

    email_cfg = config["notifications"]["channels"]["email"]
    ses_region = email_cfg.get("ses_region", config["aws"]["region"])
    from_addr = email_cfg["from_address"]
    to_addrs = email_cfg["to_addresses"]

    if not from_addr or not to_addrs:
        logger.warning("SES not configured — skipping email")
        return False

    try:
        ses = boto3.client("ses", region_name=ses_region)
        response = ses.send_email(
            Source=from_addr,
            Destination={"ToAddresses": to_addrs},
            Message={
                "Subject": {"Data": subject, "Charset": "UTF-8"},
                "Body": {
                    "Text": {"Data": body, "Charset": "UTF-8"},
                    "Html": {"Data": _build_html_email(subject, body), "Charset": "UTF-8"},
                },
            },
        )
        logger.info(f"SES email sent: {response['MessageId']}")
        return True

    except ClientError as e:
        logger.error(f"SES send failed: {e}")
        return False


# ─── Unified Sender ─────────────────────────────────────────────────────────

def send_email(subject: str, body: str, config: Optional[dict] = None) -> bool:
    """Send email using whichever provider is configured."""
    if config is None:
        config = load_config()

    email_cfg = config["notifications"]["channels"]["email"]
    if not email_cfg["enabled"]:
        logger.debug("Email notifications disabled")
        return False

    provider = email_cfg.get("provider", "smtp")

    if provider == "ses":
        return send_email_ses(subject, body, config)
    else:
        return send_email_smtp(subject, body, config)
