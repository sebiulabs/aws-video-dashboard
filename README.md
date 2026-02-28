# AWS Video Dashboard

Real-time monitoring for AWS infrastructure — built for video engineers and broadcast professionals managing live events in the cloud.

One dashboard for EC2 instances, Media Services (MediaLive, MediaConnect, MediaPackage, CloudFront, IVS), deployments, ECS, custom endpoints, alert rules, and an AI assistant. Configure everything from the web UI — no YAML, no config files to edit.

[![CI](https://github.com/sebiulabs/aws-video-dashboard/actions/workflows/ci.yml/badge.svg)](https://github.com/sebiulabs/aws-video-dashboard/actions/workflows/ci.yml)

---

## Features

| Feature | Description |
|---------|-------------|
| **EC2 Monitoring** | Instance status, CPU, uptime tracking, health checks |
| **Media Services** | MediaLive, MediaConnect, MediaPackage, CloudFront, IVS |
| **Multi-Region** | 18 AWS regions monitored simultaneously |
| **Alert Rules** | Threshold-based alerts with pre-built templates |
| **Endpoint Monitoring** | HTTP, TCP, Ping, JSON API health checks |
| **Trend Graphs** | 24-hour history charts (Chart.js) |
| **AI Assistant** | Ask questions about your infrastructure (OpenRouter) |
| **Notifications** | Email (SMTP/SES), Slack, WhatsApp, Telegram |
| **Authentication** | Password login with rate limiting |
| **Configurable Interval** | 1-60 minute check frequency from the UI |

---

## Deploy

Pick whichever method suits your setup. The dashboard runs on a single port (5000) with no external database — just Python and your AWS credentials.

### Option 1: Docker (recommended)

```bash
git clone https://github.com/sebiulabs/aws-video-dashboard.git
cd aws-video-dashboard
docker compose up -d
```

Open `http://localhost:5000` and add your AWS credentials in Settings.

To use a custom secret key:

```bash
FLASK_SECRET_KEY=$(openssl rand -hex 32) docker compose up -d
```

### Option 2: Docker Run (no Compose)

```bash
docker build -t aws-video-dashboard .
docker run -d -p 5000:5000 \
  -e FLASK_SECRET_KEY=$(openssl rand -hex 32) \
  -v aws-dashboard-data:/app/data \
  --restart unless-stopped \
  aws-video-dashboard
```

### Option 3: AWS EC2

Launch an Ubuntu instance (t3.micro is enough), open port 5000 in the security group, then SSH in:

```bash
sudo apt update && sudo apt install -y python3-venv git
git clone https://github.com/sebiulabs/aws-video-dashboard.git
cd aws-video-dashboard
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
gunicorn --bind 0.0.0.0:5000 --workers 2 --threads 4 --timeout 120 --preload app:app
```

For a persistent service, copy the systemd unit below and run:

```bash
sudo cp aws-dashboard.service /etc/systemd/system/
sudo systemctl enable --now aws-dashboard
```

**Tip:** If the EC2 instance has an IAM role with the right permissions, you don't need to enter AWS credentials at all — boto3 picks them up automatically.

### Option 4: On-Premises / Bare Metal

Works on any Linux or Mac with Python 3.10+:

```bash
git clone https://github.com/sebiulabs/aws-video-dashboard.git
cd aws-video-dashboard
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
gunicorn --bind 0.0.0.0:5000 --workers 2 --threads 4 --timeout 120 --preload app:app
```

Or run directly for development:

```bash
python app.py
```

---

## Production Setup

### Systemd Service

```ini
# /etc/systemd/system/aws-dashboard.service
[Unit]
Description=AWS Video Dashboard
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/opt/aws-video-dashboard
ExecStart=/opt/aws-video-dashboard/venv/bin/gunicorn --bind 127.0.0.1:5000 --workers 2 --threads 4 --timeout 120 --preload app:app
Restart=always
RestartSec=5
Environment=FLASK_SECRET_KEY=your-secret-key-here

[Install]
WantedBy=multi-user.target
```

### Nginx Reverse Proxy

Put Nginx in front for HTTPS, custom domain, or port 80:

```nginx
# /etc/nginx/sites-available/dashboard
server {
    listen 80;
    server_name dashboard.example.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/dashboard /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Add HTTPS with Certbot:

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d dashboard.example.com
```

---

## AWS Setup

### IAM Credentials

The dashboard needs **read-only** access. Two options:

**Option A: IAM Role (EC2 only, no keys needed)**
Attach this policy to your EC2 instance's IAM role. No credentials to configure in the dashboard.

**Option B: IAM User (any deployment)**
Create an IAM user, generate access keys, enter them in Settings.

Minimal policy:

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

Or just use the AWS managed policy `ReadOnlyAccess` if you prefer.

### Supported Regions

The dashboard supports 18 regions out of the box, selectable from Settings:

`us-east-1` `us-east-2` `us-west-1` `us-west-2` `eu-west-1` `eu-west-2` `eu-west-3` `eu-central-1` `eu-north-1` `ap-southeast-1` `ap-southeast-2` `ap-northeast-1` `ap-northeast-2` `ap-south-1` `sa-east-1` `ca-central-1` `me-south-1` `af-south-1`

---

## Configuration

Everything is configured through the web UI at `/settings`. No files to edit.

| Setting | What it does |
|---------|-------------|
| **AWS Credentials** | Access key, secret key (or use IAM role) |
| **Regions** | Tick the regions you want to monitor |
| **Services** | Toggle EC2, ECS, MediaLive, CloudFront, etc. |
| **Check Interval** | How often to poll AWS (default: 5 min) |
| **Notifications** | Email, Slack, WhatsApp, Telegram |
| **Alert Thresholds** | CPU %, uptime hours |
| **AI Assistant** | OpenRouter API key + model |
| **Security** | Username + password for login |

Config is stored in `config.json` (auto-created on first run, gitignored).

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FLASK_SECRET_KEY` | Session signing key | Auto-generated, persisted to `.flask_secret` |
| `CONFIG_PATH` | Path to config file | `./config.json` |

---

## Architecture

```
app.py               — Flask web app (all routes + inline UI)
monitor.py            — EC2, CodeDeploy, ECS checks + notification dispatch
video_monitor.py      — MediaLive, MediaConnect, MediaPackage, CloudFront, IVS
alert_rules.py        — Threshold-based alert rule engine
easy_monitor.py       — HTTP/TCP/Ping/JSON endpoint health checks
config_manager.py     — JSON config persistence (chmod 600)
history_db.py         — SQLite ring buffer for trend graphs
openrouter_ai.py      — AI assistant via OpenRouter API
email_notifier.py     — Email (SMTP + AWS SES)
telegram_notifier.py  — Telegram Bot API
slack_notifier.py     — Slack Incoming Webhooks
```

No external database. SQLite for history, JSON for config. Single-process friendly.

---

## Security

- Password authentication with bcrypt hashing
- Login rate limiting (5 attempts / 5 minutes per IP)
- Session cookies: HttpOnly, SameSite=Lax
- CSRF protection on all state-changing API routes
- SSRF blocklist on endpoint monitor (private IPs, IMDS, localhost)
- XSS escaping on all user-generated content
- Config file restricted to owner-only (chmod 600)
- Secrets masked in the UI (last 4 characters only)
- CDN scripts pinned with SRI integrity hashes

---

## Who This Is For

- **vMix operators** running productions on AWS EC2 GPU instances
- **Broadcast engineers** managing MediaLive/MediaConnect workflows
- **Live event producers** monitoring SRT/NDI/RTMP ingest pipelines
- **DevOps teams** watching video infrastructure during live events
- **Anyone** running video workloads on AWS

---

## Requirements

- Python 3.10+ (or Docker)
- AWS account with IAM credentials
- OpenRouter API key (optional — only needed for the AI assistant)

---

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).

---

Built by [Sebiu Labs](https://sebiulabs.co.uk)
