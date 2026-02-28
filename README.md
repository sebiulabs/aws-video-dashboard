# AWS Video Dashboard

A real-time monitoring dashboard for AWS infrastructure, built for video engineers and broadcast professionals managing live events in the cloud.

Monitor EC2 instances, AWS Media Services (MediaLive, MediaConnect, MediaPackage, CloudFront, IVS), track uptime, set alert rules, and query your infrastructure using AI — all from a single web interface.

## Features

- **EC2 Monitoring** — Instance status, CPU utilization, uptime tracking with configurable alerts
- **AWS Media Services** — MediaLive channels, MediaConnect flows, MediaPackage, CloudFront CDN, IVS streams
- **Multi-Region** — Monitor across 18 AWS regions simultaneously
- **Alert Rules** — Custom threshold-based alerts with templates for common scenarios
- **Endpoint Monitoring** — HTTP/TCP/Ping/JSON API health checks for any service
- **Trend Graphs** — 24-hour history with Chart.js visualisation
- **AI Assistant** — Natural language infrastructure queries powered by OpenRouter (Claude, GPT, Gemini, and more)
- **Multi-channel Notifications** — Email (SMTP/SES), Slack, WhatsApp (Twilio), Telegram
- **Login Authentication** — Password-protected access with rate limiting
- **Uptime Alerts** — Get notified when EC2 instances run longer than expected (prevent cost overruns)
- **Configurable Interval** — Check frequency adjustable from the UI (1-60 minutes)

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
gunicorn --bind 0.0.0.0:5000 --workers 2 --threads 4 --timeout 120 --preload app:app

# Or run directly
python app.py
```

Visit `http://localhost:5000` and configure your AWS credentials in Settings.

## Deployment

### Local / Bare Metal

Run directly on any Linux server or Mac:

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
gunicorn --bind 0.0.0.0:5000 --workers 2 --threads 4 --timeout 120 --preload app:app
```

To run as a background service with systemd:

```ini
# /etc/systemd/system/aws-dashboard.service
[Unit]
Description=AWS Video Dashboard
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/opt/aws-video-dashboard
ExecStart=/opt/aws-video-dashboard/venv/bin/gunicorn --bind 0.0.0.0:5000 --workers 2 --threads 4 --timeout 120 --preload app:app
Restart=always
RestartSec=5
Environment=FLASK_SECRET_KEY=your-secret-key-here

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable aws-dashboard
sudo systemctl start aws-dashboard
```

### Docker

```dockerfile
# Dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "120", "--preload", "app:app"]
```

```bash
docker build -t aws-video-dashboard .
docker run -d -p 5000:5000 \
  -e FLASK_SECRET_KEY=your-secret-key \
  -v $(pwd)/config.json:/app/config.json \
  -v $(pwd)/history.db:/app/history.db \
  aws-video-dashboard
```

### Docker Compose

```yaml
# docker-compose.yml
version: "3.8"
services:
  dashboard:
    build: .
    ports:
      - "5000:5000"
    environment:
      - FLASK_SECRET_KEY=change-me-to-a-random-string
    volumes:
      - ./config.json:/app/config.json
      - ./history.db:/app/history.db
    restart: unless-stopped
```

```bash
docker compose up -d
```

### AWS EC2

1. Launch an Ubuntu EC2 instance (t3.micro is sufficient)
2. Open port 5000 (or 80/443 with a reverse proxy) in the security group
3. SSH in and run:

```bash
sudo apt update && sudo apt install -y python3-venv
git clone https://github.com/sebiulabs/aws-video-dashboard.git
cd aws-video-dashboard
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
gunicorn --bind 0.0.0.0:5000 --workers 2 --threads 4 --timeout 120 --preload app:app
```

For production, set up the systemd service above and optionally add Nginx as a reverse proxy:

```nginx
# /etc/nginx/sites-available/dashboard
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### AWS IAM Policy

The dashboard needs read-only access. Create an IAM user with this policy (or use `ReadOnlyAccess`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "cloudwatch:GetMetricStatistics",
        "codedeploy:List*",
        "codedeploy:Get*",
        "ecs:List*",
        "ecs:Describe*",
        "medialive:List*",
        "medialive:Describe*",
        "mediaconnect:List*",
        "mediaconnect:Describe*",
        "mediapackage:List*",
        "mediapackage:Describe*",
        "cloudfront:List*",
        "cloudfront:Get*",
        "ivs:List*",
        "ivs:Get*"
      ],
      "Resource": "*"
    }
  ]
}
```

## Configuration

All configuration is done through the web UI at `/settings`:

- **AWS Credentials** — Access key, secret key, multi-region selection
- **Monitoring Toggles** — Enable/disable individual services
- **Check Interval** — How often to poll AWS (default: 5 minutes)
- **Alert Thresholds** — CPU threshold, uptime alert hours
- **AI Assistant** — OpenRouter API key and model selection
- **Notifications** — Email, Slack, WhatsApp, Telegram setup
- **Security** — Set login username and password

Configuration is stored in `config.json` (auto-created, gitignored, chmod 600).

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FLASK_SECRET_KEY` | Session signing key | Auto-generated and persisted to `.flask_secret` |
| `CONFIG_PATH` | Path to config file | `./config.json` |

## Requirements

- Python 3.10+
- AWS account with IAM credentials (ReadOnlyAccess policy recommended)
- OpenRouter API key (optional, for AI assistant)

## Architecture

```
app.py               — Flask web application, all routes and UI
monitor.py            — EC2, CodeDeploy, ECS monitoring + notifications
video_monitor.py      — MediaLive, MediaConnect, MediaPackage, CloudFront, IVS
alert_rules.py        — Custom alert rule engine
easy_monitor.py       — HTTP/TCP/Ping/JSON endpoint health checks
config_manager.py     — JSON config persistence
history_db.py         — SQLite history storage for trend graphs
openrouter_ai.py      — AI assistant via OpenRouter
email_notifier.py     — Email notifications (SMTP/SES)
telegram_notifier.py  — Telegram bot notifications
slack_notifier.py     — Slack incoming webhook notifications
```

## Security

- Login authentication with bcrypt password hashing
- Login rate limiting (5 attempts per 5 minutes per IP)
- Session cookies with HttpOnly and SameSite=Lax flags
- CSRF protection on all POST API routes
- SSRF protection on endpoint monitoring (blocks private/internal IPs)
- XSS escaping on all user-generated content
- Config file restricted to owner-only permissions (chmod 600)
- Secrets masked in the UI (only last 4 characters shown)

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
