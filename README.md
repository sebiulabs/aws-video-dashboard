# AWS Video Dashboard

A real-time monitoring dashboard for AWS infrastructure, built for video engineers and broadcast professionals managing live events in the cloud.

Monitor EC2 instances, AWS Media Services (MediaLive, MediaConnect, MediaPackage, CloudFront, IVS), track uptime, set alert rules, and query your infrastructure using AI — all from a single web interface.

## Features

- **EC2 Monitoring** — Instance status, CPU utilization, uptime tracking with configurable alerts
- **AWS Media Services** — MediaLive channels, MediaConnect flows, MediaPackage, CloudFront CDN, IVS streams
- **Alert Rules** — Custom threshold-based alerts with templates for common scenarios
- **Endpoint Monitoring** — HTTP/TCP/UDP health checks for any service
- **AI Assistant** — Natural language infrastructure queries powered by OpenRouter (Claude, GPT, Gemini, and more)
- **Multi-channel Notifications** — Email (SMTP/SES), Slack, WhatsApp (Twilio), Telegram
- **Uptime Alerts** — Get notified when EC2 instances run longer than expected (prevent cost overruns)

## Quick Start

```bash
# Clone the repo
git clone https://github.com/sebiulabs/aws-video-dashboard.git
cd aws-video-dashboard

# Create virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run with gunicorn (recommended)
gunicorn --bind 0.0.0.0:5000 --workers 4 --threads 4 --timeout 120 app:app

# Or run directly
python app.py
```

Visit `http://localhost:5000` and configure your AWS credentials in Settings.

## Configuration

All configuration is done through the web UI at `/settings`:

- **AWS Credentials** — Access key, secret key, region
- **Monitoring Toggles** — Enable/disable individual services
- **Alert Thresholds** — CPU threshold, uptime alert hours
- **AI Assistant** — OpenRouter API key and model selection
- **Notifications** — Email, WhatsApp, Telegram setup

Configuration is stored in `config.json` (auto-created, gitignored).

## Requirements

- Python 3.10+
- AWS account with IAM credentials (ReadOnlyAccess policy recommended)
- OpenRouter API key (optional, for AI assistant)

## Architecture

```
app.py              — Flask web application, all routes and UI
monitor.py          — EC2, CodeDeploy, ECS monitoring + notifications
video_monitor.py    — MediaLive, MediaConnect, MediaPackage, CloudFront, IVS
alert_rules.py      — Custom alert rule engine
easy_monitor.py     — HTTP/TCP/UDP endpoint health checks
config_manager.py   — JSON config persistence
openrouter_ai.py    — AI assistant via OpenRouter
email_notifier.py   — Email notifications (SMTP/SES)
telegram_notifier.py — Telegram bot notifications
slack_notifier.py   — Slack incoming webhook notifications
```

## Designed For

- vMix operators running productions on AWS EC2 GPU instances
- Broadcast engineers managing MediaLive/MediaConnect workflows
- Live event producers monitoring SRT/NDI/RTMP ingest pipelines
- Anyone running video infrastructure on AWS

## License

This project is licensed under the GNU General Public License v3.0 — see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome. Please open an issue first to discuss what you would like to change.

---

Built by [Sebiu Labs](https://sebiulabs.co.uk)
