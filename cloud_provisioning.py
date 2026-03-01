"""
Cloud Provisioning — Provisioning scripts and orchestration for EC2 media instances
=====================================================================================
Provides Linux provisioning scripts for each media template category,
a unified lookup function, and AMI build orchestration.
"""

import logging

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# MEDIA PROVISIONING SCRIPTS — Linux (bash)
# ═══════════════════════════════════════════════════════════════════════════════

MEDIA_PROVISIONING_SCRIPTS = {
    # ── Video Encoding ──
    "encoding": """#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
exec > /var/log/provisioning.log 2>&1
echo "=== Video Encoder Provisioning ==="
apt-get update
apt-get install -y ffmpeg x264 x265 libx264-dev libx265-dev \
    libfdk-aac-dev libopus-dev libvpx-dev libaom-dev \
    mediainfo mkvtoolnix \
    python3-pip git curl wget htop
# SVT-AV1
apt-get install -y cmake nasm
cd /tmp && git clone --depth 1 https://gitlab.com/AOMediaCodec/SVT-AV1.git
cd SVT-AV1/Build && cmake .. -DCMAKE_BUILD_TYPE=Release && make -j$(nproc) && make install
ldconfig
echo "Encoding provisioning complete" > /var/log/provisioning_complete.txt
""",

    # ── Streaming Media Server ──
    "streaming_server": """#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
exec > /var/log/provisioning.log 2>&1
echo "=== Streaming Media Server Provisioning ==="
apt-get update
apt-get install -y ffmpeg nginx libnginx-mod-rtmp \
    python3-pip git curl wget htop stunnel4
# SRS (Simple Realtime Server)
cd /opt && git clone --depth 1 https://github.com/ossrs/srs.git
cd srs/trunk && ./configure && make -j$(nproc)
# MediaMTX
MEDIAMTX_VER="1.5.0"
cd /opt && wget -q "https://github.com/bluenviron/mediamtx/releases/download/v${MEDIAMTX_VER}/mediamtx_v${MEDIAMTX_VER}_linux_amd64.tar.gz"
tar xzf mediamtx_*.tar.gz && rm -f mediamtx_*.tar.gz
# Nginx-RTMP config
cat > /etc/nginx/nginx.conf << 'NGINX_CONF'
worker_processes auto;
events { worker_connections 1024; }
rtmp {
    server {
        listen 1935;
        application live {
            live on;
            record off;
            hls on;
            hls_path /var/www/hls;
            hls_fragment 3;
        }
    }
}
http {
    server {
        listen 8080;
        location /hls { alias /var/www/hls; add_header Access-Control-Allow-Origin *; }
        location /stat { rtmp_stat all; }
    }
}
NGINX_CONF
mkdir -p /var/www/hls
systemctl restart nginx
echo "Streaming server provisioning complete" > /var/log/provisioning_complete.txt
""",

    # ── GPU Encoding ──
    "gpu_encoding": """#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
exec > /var/log/provisioning.log 2>&1
echo "=== GPU Encoder Provisioning (NVENC) ==="
apt-get update
apt-get install -y ffmpeg git curl wget htop python3-pip \
    build-essential pkg-config
# NVIDIA driver should be pre-installed on g4dn AMIs
# Verify GPU
nvidia-smi || echo "WARNING: nvidia-smi not available"
# Install NVIDIA codec headers for FFmpeg NVENC
cd /tmp && git clone --depth 1 https://git.videolan.org/git/ffmpeg/nv-codec-headers.git
cd nv-codec-headers && make install
# Build FFmpeg with NVENC support
apt-get install -y libx264-dev libx265-dev libfdk-aac-dev libopus-dev nasm yasm
echo "GPU encoder provisioning complete" > /var/log/provisioning_complete.txt
""",

    # ── DaVinci Resolve / Blackmagic ──
    "blackmagic": """#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
exec > /var/log/provisioning.log 2>&1
echo "=== DaVinci Resolve Workstation Provisioning ==="
apt-get update
apt-get install -y xfce4 xrdp dbus-x11 \
    libfuse2 libapr1 libaprutil1 \
    libglu1-mesa ocl-icd-opencl-dev \
    ffmpeg mediainfo git curl wget htop
# Enable XRDP for remote desktop access
systemctl enable xrdp
sed -i 's/^port=3389/port=3389/' /etc/xrdp/xrdp.ini
echo "xfce4-session" > /etc/skel/.xsession
systemctl restart xrdp
# GPU check
nvidia-smi || echo "WARNING: NVIDIA GPU not detected"
echo "DaVinci Resolve workstation provisioning complete" > /var/log/provisioning_complete.txt
echo "NOTE: Download DaVinci Resolve from https://www.blackmagicdesign.com/products/davinciresolve"
""",

    # ── NDI Hub ──
    "ndi_hub": """#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
exec > /var/log/provisioning.log 2>&1
echo "=== NDI Network Hub Provisioning ==="
apt-get update
apt-get install -y ffmpeg avahi-daemon libnss-mdns \
    python3-pip git curl wget htop
# NDI SDK
cd /tmp && wget -q "https://downloads.ndi.tv/SDK/NDI_SDK_Linux/Install_NDI_SDK_v6_Linux.tar.gz" || true
if [ -f Install_NDI_SDK_v6_Linux.tar.gz ]; then
    tar xzf Install_NDI_SDK_v6_Linux.tar.gz
    yes | PAGER=cat ./Install_NDI_SDK_v6_Linux.sh || true
fi
# Enable Avahi for NDI discovery
systemctl enable avahi-daemon
systemctl start avahi-daemon
echo "NDI hub provisioning complete" > /var/log/provisioning_complete.txt
""",

    # ── Docker Media Hub ──
    "docker_media": """#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
exec > /var/log/provisioning.log 2>&1
echo "=== Docker Media Hub Provisioning ==="
apt-get update
apt-get install -y curl wget htop git
# Install Docker via official apt repo (avoids curl|sh)
apt-get install -y ca-certificates gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
usermod -aG docker ubuntu
# Docker Compose already installed as docker-compose-plugin above
# Create media docker-compose
mkdir -p /opt/media-stack
cat > /opt/media-stack/docker-compose.yml << 'DCOMPOSE'
version: '3.8'
services:
  nginx-rtmp:
    image: tiangolo/nginx-rtmp
    ports:
      - "1935:1935"
      - "8080:80"
    restart: unless-stopped
DCOMPOSE
cd /opt/media-stack && docker compose up -d || true
echo "Docker media hub provisioning complete" > /var/log/provisioning_complete.txt
""",

    # ── Playout Automation ──
    "playout": """#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
exec > /var/log/provisioning.log 2>&1
echo "=== Playout Automation Server Provisioning ==="
apt-get update
apt-get install -y ffmpeg python3-pip git curl wget htop \
    python3-watchdog
# ffplayout
pip3 install ffplayout || true
# CasparCG dependencies
apt-get install -y libboost-all-dev libsfml-dev libglew-dev \
    libtbb-dev libfreeimage-dev || true
# Create playout directory structure
mkdir -p /opt/playout/{media,playlists,logs}
# Simple playout scheduler script
cat > /opt/playout/start.sh << 'PLAYOUT'
#!/bin/bash
# Basic ffplayout wrapper
echo "Playout system ready — configure playlist in /opt/playout/playlists/"
PLAYOUT
chmod +x /opt/playout/start.sh
echo "Playout automation provisioning complete" > /var/log/provisioning_complete.txt
""",

    # ── Recording Station ──
    "recording": """#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
exec > /var/log/provisioning.log 2>&1
echo "=== Recording Station Provisioning ==="
apt-get update
apt-get install -y ffmpeg python3-pip git curl wget htop \
    awscli mediainfo
# Create recording directory
mkdir -p /opt/recordings/{ingest,archive,segments}
# Recording wrapper script
cat > /opt/recordings/record.sh << 'RECORD'
#!/bin/bash
# Multi-channel recording with segmented output
# Usage: ./record.sh <input_url> <output_prefix>
INPUT="${1:?Usage: record.sh <input_url> <output_prefix>}"
PREFIX="${2:-/opt/recordings/segments/recording}"
ffmpeg -i "$INPUT" \
    -c copy \
    -f segment \
    -segment_time 3600 \
    -segment_format mp4 \
    -reset_timestamps 1 \
    "${PREFIX}_%03d.mp4"
RECORD
chmod +x /opt/recordings/record.sh
# S3 sync cron (every hour)
cat > /opt/recordings/sync_s3.sh << 'SYNC'
#!/bin/bash
# Sync completed segments to S3
BUCKET="${S3_BUCKET:-}"
if [ -n "$BUCKET" ]; then
    aws s3 sync /opt/recordings/archive/ "s3://$BUCKET/recordings/" --storage-class STANDARD_IA
fi
SYNC
chmod +x /opt/recordings/sync_s3.sh
echo "Recording station provisioning complete" > /var/log/provisioning_complete.txt
""",
}


# ═══════════════════════════════════════════════════════════════════════════════
# TEMPLATE LOOKUP
# ═══════════════════════════════════════════════════════════════════════════════

try:
    from ec2_manager import EC2_MEDIA_TEMPLATES, WINDOWS_EC2_TEMPLATES
except ImportError:
    EC2_MEDIA_TEMPLATES = []
    WINDOWS_EC2_TEMPLATES = []


def get_provisioning_script(template_id):
    """
    Look up the provisioning script for a given template ID.

    Searches EC2_MEDIA_TEMPLATES and WINDOWS_EC2_TEMPLATES for the template,
    then returns the corresponding script from MEDIA_PROVISIONING_SCRIPTS.
    """
    all_templates = list(EC2_MEDIA_TEMPLATES) + list(WINDOWS_EC2_TEMPLATES)

    for tmpl in all_templates:
        if tmpl["id"] == template_id:
            category = tmpl.get("category", "")
            if tmpl.get("os") == "windows":
                try:
                    from ec2_manager import WINDOWS_PROVISIONING_SCRIPTS
                    return WINDOWS_PROVISIONING_SCRIPTS.get("base", "")
                except ImportError:
                    return ""
            return MEDIA_PROVISIONING_SCRIPTS.get(category, MEDIA_PROVISIONING_SCRIPTS.get("encoding", ""))

    # Direct category lookup as fallback
    if template_id in MEDIA_PROVISIONING_SCRIPTS:
        return MEDIA_PROVISIONING_SCRIPTS[template_id]

    return ""


# ═══════════════════════════════════════════════════════════════════════════════
# AMI BUILD ORCHESTRATION
# ═══════════════════════════════════════════════════════════════════════════════

def build_ec2_ami(config, instance_id, name, description=None, region=None):
    """
    Build an AMI from an EC2 instance.

    Delegates to ec2_manager.create_ami_from_instance().
    """
    from ec2_manager import create_ami_from_instance
    return create_ami_from_instance(config, instance_id, name, description, region)
