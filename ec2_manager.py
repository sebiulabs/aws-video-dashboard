"""
EC2 Manager — Launch media instances, build AMIs, manage lifecycle
===================================================================
Parallel to the dashboard's monitoring capabilities, this module adds
the ability to launch pre-configured EC2 instances for broadcast/media
workloads, build reusable AMIs, and manage instance lifecycle.

Supports both Linux (Ubuntu 22.04) and Windows Server 2022 templates.
"""

import base64
import logging
import re
import time
from typing import Optional

import boto3
from botocore.exceptions import ClientError

from config_manager import load_config

logger = logging.getLogger(__name__)


def _sanitize_error(error):
    """Sanitize AWS error messages to avoid leaking credentials or internal details."""
    msg = str(error)
    # Strip AWS access key IDs (including temporary credentials) if they appear in error messages
    msg = re.sub(r"(AKIA|ASIA|AIDA|AROA|AIPA)[A-Z0-9]{12,}", "****", msg)
    # Strip account IDs
    msg = re.sub(r"\b\d{12}\b", "****", msg)
    # Strip ARNs
    msg = re.sub(r"arn:aws:[a-zA-Z0-9-]+:[a-z0-9-]*:\d{12}:[^\s\"']+", "arn:aws:***", msg)
    return msg

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS — AMI lookups
# ═══════════════════════════════════════════════════════════════════════════════

# Ubuntu 22.04 LTS HVM SSD — updated periodically
UBUNTU_AMIS = {
    "us-east-1": "ami-0c7217cdde317cfec",
    "us-east-2": "ami-05fb0b8c1424f266b",
    "us-west-1": "ami-0ce2cb35386fc22e9",
    "us-west-2": "ami-008fe2fc65df48dac",
    "ca-central-1": "ami-0a7154091c5c6623e",
    "eu-west-1": "ami-0905a3c97561e0b69",
    "eu-west-2": "ami-0e5f882be1900e43b",
    "eu-west-3": "ami-01d21b7be69801c2f",
    "eu-central-1": "ami-0faab6bdbac9486fb",
    "eu-north-1": "ami-0014ce3e52571e775",
    "ap-south-1": "ami-03f4878755434977f",
    "ap-southeast-1": "ami-0fa377108253bf620",
    "ap-southeast-2": "ami-04f5097681773b989",
    "ap-northeast-1": "ami-07c589821f2b353aa",
    "ap-northeast-2": "ami-0f3a440bbcff3d043",
    "sa-east-1": "ami-0fb4cf3a99aa89f72",
    "me-south-1": "ami-0b98fa71853e26f42",
    "af-south-1": "ami-0b3d2e068cced65f2",
}

# Windows Server 2022 Base
WINDOWS_AMIS = {
    "us-east-1": "ami-0be0e902919675894",
    "us-east-2": "ami-0e38fa17744b2f6a5",
    "us-west-1": "ami-0d7c1dfc83e5f1b4a",
    "us-west-2": "ami-0b2b4f9e4e2a62c68",
    "ca-central-1": "ami-0d3a3a3c5e1c9e5e0",
    "eu-west-1": "ami-0e1a6b5a6a1b2c3d4",
    "eu-west-2": "ami-0d8e6b5a6a1b2c3d4",
    "eu-central-1": "ami-0c5e6b5a6a1b2c3d4",
    "eu-north-1": "ami-0d9e6b5a6a1b2c3d4",
    "ap-south-1": "ami-0a3e6b5a6a1b2c3d4",
    "ap-southeast-1": "ami-0b4e6b5a6a1b2c3d4",
    "ap-southeast-2": "ami-0c5e6b5a6a1b2c3d4",
    "ap-northeast-1": "ami-0d6e6b5a6a1b2c3d4",
    "ap-northeast-2": "ami-0e7e6b5a6a1b2c3d4",
    "sa-east-1": "ami-0f8e6b5a6a1b2c3d4",
}


def _get_boto_client(service, config, region=None):
    """Create a boto3 client, reusing the pattern from the dashboard's monitor."""
    aws = config.get("aws", {})
    region = region or (aws.get("regions", []) or ["us-east-1"])[0]
    kwargs = {"region_name": region}
    ak = aws.get("access_key_id", "")
    sk = aws.get("secret_access_key", "")
    if ak and sk and "••••" not in ak and "••••" not in sk:
        kwargs["aws_access_key_id"] = ak
        kwargs["aws_secret_access_key"] = sk
    return boto3.client(service, **kwargs)


def _get_latest_ami(config, region, os_type="linux"):
    """Look up the latest AMI via SSM Parameter Store, fall back to hardcoded dict."""
    try:
        ssm = _get_boto_client("ssm", config, region)
        if os_type == "windows":
            param = "/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base"
        else:
            param = "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
        resp = ssm.get_parameter(Name=param)
        return resp["Parameter"]["Value"]
    except Exception:
        if os_type == "windows":
            return WINDOWS_AMIS.get(region, WINDOWS_AMIS.get("us-east-1"))
        return UBUNTU_AMIS.get(region, UBUNTU_AMIS.get("us-east-1"))


# ═══════════════════════════════════════════════════════════════════════════════
# EC2 MEDIA TEMPLATES — Linux
# ═══════════════════════════════════════════════════════════════════════════════

EC2_MEDIA_TEMPLATES = [
    {
        "id": "ec2_encoding",
        "name": "Video Encoder",
        "category": "encoding",
        "instance_type": "c5.2xlarge",
        "os": "linux",
        "description": "High-performance CPU-based video encoding with FFmpeg, x264/x265, and SVT-AV1",
        "icon": "film",
    },
    {
        "id": "ec2_streaming_server",
        "name": "Streaming Media Server",
        "category": "streaming_server",
        "instance_type": "c5.xlarge",
        "os": "linux",
        "description": "RTMP/SRT/HLS streaming with Nginx-RTMP, SRS, and MediaMTX",
        "icon": "cast",
    },
    {
        "id": "ec2_gpu_encoder",
        "name": "GPU Encoder (NVENC)",
        "category": "gpu_encoding",
        "instance_type": "g4dn.xlarge",
        "os": "linux",
        "description": "NVIDIA GPU-accelerated encoding with NVENC/NVDEC support",
        "icon": "gpu-card",
    },
    {
        "id": "ec2_blackmagic",
        "name": "DaVinci Resolve Workstation",
        "category": "blackmagic",
        "instance_type": "g4dn.2xlarge",
        "os": "linux",
        "description": "GPU workstation for DaVinci Resolve, color grading, and post-production",
        "icon": "palette",
    },
    {
        "id": "ec2_ndi_hub",
        "name": "NDI Network Hub",
        "category": "ndi_hub",
        "instance_type": "c5.xlarge",
        "os": "linux",
        "description": "NDI routing, monitoring, and bridging hub for IP video workflows",
        "icon": "diagram-3",
    },
    {
        "id": "ec2_docker_media",
        "name": "Docker Media Hub",
        "category": "docker_media",
        "instance_type": "c5.xlarge",
        "os": "linux",
        "description": "Containerised media services: Plex, Jellyfin, EasyRTMP, and more",
        "icon": "box",
    },
    {
        "id": "ec2_playout",
        "name": "Playout Automation Server",
        "category": "playout",
        "instance_type": "c5.xlarge",
        "os": "linux",
        "description": "Automated playout with CasparCG, ffplayout, and scheduling tools",
        "icon": "play-circle",
    },
    {
        "id": "ec2_recording",
        "name": "Recording Station",
        "category": "recording",
        "instance_type": "c5.xlarge",
        "os": "linux",
        "description": "Multi-channel recording with segmented output and S3 archival",
        "icon": "record-circle",
    },
]

# ═══════════════════════════════════════════════════════════════════════════════
# EC2 WINDOWS TEMPLATES
# ═══════════════════════════════════════════════════════════════════════════════

WINDOWS_EC2_TEMPLATES = [
    {
        "id": "ec2_win_vmix",
        "name": "vMix Live Production",
        "category": "vmix",
        "instance_type": "g4dn.2xlarge",
        "os": "windows",
        "description": "GPU instance for vMix live production — install vMix after launch",
        "icon": "camera-video",
    },
    {
        "id": "ec2_win_wirecast",
        "name": "Wirecast Production",
        "category": "wirecast",
        "instance_type": "g4dn.xlarge",
        "os": "windows",
        "description": "GPU instance for Telestream Wirecast — install Wirecast after launch",
        "icon": "broadcast",
    },
    {
        "id": "ec2_win_resolve",
        "name": "DaVinci Resolve Studio",
        "category": "resolve_win",
        "instance_type": "g4dn.2xlarge",
        "os": "windows",
        "description": "GPU workstation for DaVinci Resolve Studio on Windows",
        "icon": "palette",
    },
    {
        "id": "ec2_win_adobe",
        "name": "Adobe Creative Cloud",
        "category": "adobe",
        "instance_type": "g4dn.2xlarge",
        "os": "windows",
        "description": "GPU instance for Adobe Premiere Pro, After Effects, Media Encoder",
        "icon": "layers",
    },
    {
        "id": "ec2_win_obs",
        "name": "OBS Advanced Workstation",
        "category": "obs_win",
        "instance_type": "g4dn.xlarge",
        "os": "windows",
        "description": "OBS Studio auto-installed via Chocolatey with GPU encoding support",
        "icon": "record-circle",
    },
]

# ═══════════════════════════════════════════════════════════════════════════════
# WINDOWS PROVISIONING SCRIPTS
# ═══════════════════════════════════════════════════════════════════════════════

WINDOWS_PROVISIONING_SCRIPTS = {
    "base": """<powershell>
# ─── Windows Base Provisioning for Media Instances ───
$ErrorActionPreference = "Continue"
$logFile = "C:\\provisioning_log.txt"

function Log($msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts - $msg" | Out-File -Append $logFile
    Write-Host "$ts - $msg"
}

Log "Starting Windows media instance provisioning..."

# ── Install Chocolatey ──
Log "Installing Chocolatey package manager..."
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
try {
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    Log "Chocolatey installed successfully"
} catch {
    Log "Chocolatey install failed: $_"
}

# Refresh PATH
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

# ── Install core media tools ──
$packages = @("ffmpeg", "vlc", "obs-studio", "git", "7zip", "ndi-runtime")
foreach ($pkg in $packages) {
    Log "Installing $pkg..."
    try {
        choco install $pkg -y --no-progress 2>&1 | Out-File -Append $logFile
        Log "$pkg installed"
    } catch {
        Log "Failed to install ${pkg}: $_"
    }
}

# ── Validate NVIDIA GPU driver (g4dn / g5 instances) ──
Log "Checking for NVIDIA GPU..."
$gpu = Get-WmiObject Win32_VideoController | Where-Object { $_.Name -match "NVIDIA" }
if ($gpu) {
    Log "NVIDIA GPU detected: $($gpu.Name)"
    # Check if nvidia-smi is available
    $nvidiaSmi = Get-Command nvidia-smi -ErrorAction SilentlyContinue
    if ($nvidiaSmi) {
        $driverInfo = & nvidia-smi --query-gpu=driver_version,name --format=csv,noheader 2>&1
        Log "NVIDIA Driver: $driverInfo"
    } else {
        Log "nvidia-smi not found — NVIDIA driver may need manual installation"
    }
} else {
    Log "No NVIDIA GPU detected (expected on non-GPU instance types)"
}

# ── Create completion marker ──
$completionMsg = "Provisioning completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$completionMsg | Out-File "C:\\provisioning_complete.txt"
Log $completionMsg
Log "Windows base provisioning finished."
</powershell>
""",
}

# ═══════════════════════════════════════════════════════════════════════════════
# EC2 INSTANCE MANAGEMENT FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════


def _verify_dashboard_managed(ec2, instance_id):
    """Check instance has dashboard-managed=true tag."""
    try:
        resp = ec2.describe_instances(
            InstanceIds=[instance_id],
            Filters=[{"Name": "tag:dashboard-managed", "Values": ["true"]}]
        )
        return len(resp.get("Reservations", [])) > 0
    except Exception:
        return False


def check_ec2_instances(config, region=None):
    """List EC2 instances tagged with dashboard-managed=true."""
    try:
        if region is None:
            aws = config.get("aws", {})
            region = (aws.get("regions", []) or ["us-east-1"])[0]

        ec2 = _get_boto_client("ec2", config, region)
        resp = ec2.describe_instances(
            Filters=[{"Name": "tag:dashboard-managed", "Values": ["true"]}]
        )

        instances = []
        for reservation in resp.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                instances.append({
                    "instance_id": inst["InstanceId"],
                    "name": tags.get("Name", "unnamed"),
                    "state": inst["State"]["Name"],
                    "instance_type": inst.get("InstanceType", ""),
                    "public_ip": inst.get("PublicIpAddress", ""),
                    "private_ip": inst.get("PrivateIpAddress", ""),
                    "launch_time": inst.get("LaunchTime", "").isoformat() if inst.get("LaunchTime") else "",
                    "template_id": tags.get("template-id", ""),
                    "ami_builder": tags.get("ami-builder", "false") == "true",
                    "region": region,
                    "os": tags.get("os-type", "linux"),
                })

        return {"ok": True, "instances": instances, "count": len(instances), "region": region}
    except ClientError as e:
        logger.error(f"check_ec2_instances failed: {e}")
        return {"ok": False, "error": _sanitize_error(e), "instances": [], "count": 0}
    except Exception as e:
        logger.error(f"check_ec2_instances failed: {e}")
        return {"ok": False, "error": _sanitize_error(e), "instances": [], "count": 0}


def launch_ec2_instance(config, params):
    """
    Launch an EC2 instance from a media template.

    params:
        template_id: str — ID from EC2_MEDIA_TEMPLATES or WINDOWS_EC2_TEMPLATES
        region: str (optional)
        instance_type: str (optional override)
        key_name: str (optional)
        security_group_id: str (optional)
        subnet_id: str (optional)
        build_ami: bool — tag for AMI building
        instance_name: str (optional)
    """
    try:
        template_id = params.get("template_id", "")
        region = params.get("region")
        build_ami = params.get("build_ami", False)
        instance_name = params.get("instance_name", "")

        # Find template
        all_templates = EC2_MEDIA_TEMPLATES + WINDOWS_EC2_TEMPLATES
        template = None
        for t in all_templates:
            if t["id"] == template_id:
                template = t
                break

        if not template:
            return {"ok": False, "error": f"Template '{template_id}' not found"}

        aws = config.get("aws", {})
        if not region:
            region = (aws.get("regions", []) or ["us-east-1"])[0]

        ec2 = _get_boto_client("ec2", config, region)
        os_type = template.get("os", "linux")
        ami_id = _get_latest_ami(config, region, os_type)
        instance_type = params.get("instance_type") or template["instance_type"]

        # Build UserData provisioning script
        if os_type == "windows":
            user_data = WINDOWS_PROVISIONING_SCRIPTS.get("base", "")
        else:
            # Get Linux provisioning script from cloud_provisioning
            try:
                from cloud_provisioning import get_provisioning_script
                script = get_provisioning_script(template_id)
            except ImportError:
                script = "#!/bin/bash\napt-get update && apt-get install -y ffmpeg"
            user_data = script

        # Tags
        name = instance_name or f"media-{template['name']}"
        tags = [
            {"Key": "Name", "Value": name},
            {"Key": "dashboard-managed", "Value": "true"},
            {"Key": "template-id", "Value": template_id},
            {"Key": "os-type", "Value": os_type},
        ]
        if build_ami:
            tags.append({"Key": "ami-builder", "Value": "true"})

        # Launch params
        launch_kwargs = {
            "ImageId": ami_id,
            "InstanceType": instance_type,
            "MinCount": 1,
            "MaxCount": 1,
            "UserData": user_data,
            "TagSpecifications": [{"ResourceType": "instance", "Tags": tags}],
        }

        if params.get("key_name"):
            launch_kwargs["KeyName"] = params["key_name"]

        if params.get("security_group_id"):
            launch_kwargs["SecurityGroupIds"] = [params["security_group_id"]]

        if params.get("subnet_id"):
            launch_kwargs["SubnetId"] = params["subnet_id"]

        resp = ec2.run_instances(**launch_kwargs)
        instance = resp["Instances"][0]
        instance_id = instance["InstanceId"]

        # Wait briefly for public IP
        public_ip = instance.get("PublicIpAddress", "")

        logger.info(f"Launched EC2 instance {instance_id} from template {template_id}")
        return {
            "ok": True,
            "instance_id": instance_id,
            "public_ip": public_ip,
            "instance_type": instance_type,
            "region": region,
            "template_id": template_id,
            "ami_builder": build_ami,
            "message": f"Instance {instance_id} launched from '{template['name']}' in {region}",
        }

    except ClientError as e:
        logger.error(f"launch_ec2_instance failed: {e}")
        return {"ok": False, "error": _sanitize_error(e)}
    except Exception as e:
        logger.error(f"launch_ec2_instance failed: {e}")
        return {"ok": False, "error": _sanitize_error(e)}


def ec2_instance_action(config, instance_id, action, region=None):
    """Perform start/stop/reboot on an EC2 instance."""
    if not re.match(r'^i-[0-9a-f]{8,17}$', instance_id):
        return {"ok": False, "error": "Invalid instance ID format"}
    try:
        aws = config.get("aws", {})
        if not region:
            region = (aws.get("regions", []) or ["us-east-1"])[0]

        ec2 = _get_boto_client("ec2", config, region)

        if not _verify_dashboard_managed(ec2, instance_id):
            return {"ok": False, "error": "Instance is not managed by this dashboard"}

        if action == "start":
            ec2.start_instances(InstanceIds=[instance_id])
            msg = f"Instance {instance_id} starting"
        elif action == "stop":
            ec2.stop_instances(InstanceIds=[instance_id])
            msg = f"Instance {instance_id} stopping"
        elif action == "reboot":
            ec2.reboot_instances(InstanceIds=[instance_id])
            msg = f"Instance {instance_id} rebooting"
        else:
            return {"ok": False, "error": f"Unknown action: {action}"}

        logger.info(msg)
        return {"ok": True, "message": msg, "action": action, "instance_id": instance_id}

    except ClientError as e:
        logger.error(f"ec2_instance_action failed: {e}")
        return {"ok": False, "error": _sanitize_error(e)}
    except Exception as e:
        logger.error(f"ec2_instance_action failed: {e}")
        return {"ok": False, "error": _sanitize_error(e)}


def terminate_ec2_instance(config, instance_id, region=None):
    """Terminate an EC2 instance."""
    try:
        aws = config.get("aws", {})
        if not region:
            region = (aws.get("regions", []) or ["us-east-1"])[0]

        ec2 = _get_boto_client("ec2", config, region)

        if not _verify_dashboard_managed(ec2, instance_id):
            return {"ok": False, "error": "Instance is not managed by this dashboard"}

        ec2.terminate_instances(InstanceIds=[instance_id])

        msg = f"Instance {instance_id} terminating"
        logger.info(msg)
        return {"ok": True, "message": msg, "instance_id": instance_id}

    except ClientError as e:
        logger.error(f"terminate_ec2_instance failed: {e}")
        return {"ok": False, "error": _sanitize_error(e)}
    except Exception as e:
        logger.error(f"terminate_ec2_instance failed: {e}")
        return {"ok": False, "error": _sanitize_error(e)}


def create_ami_from_instance(config, instance_id, name, description=None, region=None):
    """
    Create an AMI from a running/stopped EC2 instance.

    1. Stop the instance
    2. Wait for stopped state
    3. Create AMI
    4. Tag AMI with dashboard-managed=true
    5. Return AMI details
    """
    try:
        aws = config.get("aws", {})
        if not region:
            region = (aws.get("regions", []) or ["us-east-1"])[0]

        ec2 = _get_boto_client("ec2", config, region)

        if not _verify_dashboard_managed(ec2, instance_id):
            return {"ok": False, "error": "Instance is not managed by this dashboard"}

        # Get instance info for tags
        desc_resp = ec2.describe_instances(InstanceIds=[instance_id])
        inst = desc_resp["Reservations"][0]["Instances"][0]
        inst_tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
        current_state = inst["State"]["Name"]

        # Stop instance if running
        if current_state == "running":
            logger.info(f"Stopping instance {instance_id} for AMI creation...")
            ec2.stop_instances(InstanceIds=[instance_id])
            # Wait for stopped state (up to 5 minutes)
            waiter = ec2.get_waiter("instance_stopped")
            waiter.wait(
                InstanceIds=[instance_id],
                WaiterConfig={"Delay": 10, "MaxAttempts": 30}
            )
            logger.info(f"Instance {instance_id} stopped")

        # Create AMI
        if not description:
            description = f"Dashboard-managed AMI from {instance_id} ({inst_tags.get('template-id', 'custom')})"

        ami_resp = ec2.create_image(
            InstanceId=instance_id,
            Name=name,
            Description=description,
            NoReboot=True,
            TagSpecifications=[{
                "ResourceType": "image",
                "Tags": [
                    {"Key": "dashboard-managed", "Value": "true"},
                    {"Key": "source-template", "Value": inst_tags.get("template-id", "custom")},
                    {"Key": "source-instance", "Value": instance_id},
                    {"Key": "Name", "Value": name},
                ],
            }],
        )

        ami_id = ami_resp["ImageId"]
        logger.info(f"AMI {ami_id} created from instance {instance_id}")

        return {
            "ok": True,
            "ami_id": ami_id,
            "name": name,
            "source_instance": instance_id,
            "region": region,
            "message": f"AMI '{name}' ({ami_id}) created from {instance_id}",
        }

    except ClientError as e:
        logger.error(f"create_ami_from_instance failed: {e}")
        return {"ok": False, "error": _sanitize_error(e)}
    except Exception as e:
        logger.error(f"create_ami_from_instance failed: {e}")
        return {"ok": False, "error": _sanitize_error(e)}


def list_custom_amis(config, region=None):
    """List custom AMIs owned by this account (dashboard-managed)."""
    try:
        aws = config.get("aws", {})
        if not region:
            region = (aws.get("regions", []) or ["us-east-1"])[0]

        ec2 = _get_boto_client("ec2", config, region)
        resp = ec2.describe_images(Owners=["self"])

        amis = []
        for img in resp.get("Images", []):
            tags = {t["Key"]: t["Value"] for t in img.get("Tags", [])}
            amis.append({
                "ami_id": img["ImageId"],
                "name": img.get("Name", "unnamed"),
                "description": img.get("Description", ""),
                "state": img.get("State", ""),
                "created": img.get("CreationDate", ""),
                "source_template": tags.get("source-template", ""),
                "source_instance": tags.get("source-instance", ""),
                "dashboard_managed": tags.get("dashboard-managed") == "true",
                "region": region,
            })

        # Sort by creation date descending
        amis.sort(key=lambda x: x.get("created", ""), reverse=True)

        return {"ok": True, "amis": amis, "count": len(amis), "region": region}

    except ClientError as e:
        logger.error(f"list_custom_amis failed: {e}")
        return {"ok": False, "error": _sanitize_error(e), "amis": [], "count": 0}
    except Exception as e:
        logger.error(f"list_custom_amis failed: {e}")
        return {"ok": False, "error": _sanitize_error(e), "amis": [], "count": 0}


def deregister_ami(config, ami_id, region=None):
    """Deregister (delete) a custom AMI."""
    try:
        aws = config.get("aws", {})
        if not region:
            region = (aws.get("regions", []) or ["us-east-1"])[0]

        ec2 = _get_boto_client("ec2", config, region)

        # Get associated snapshots before deregistering
        img_resp = ec2.describe_images(ImageIds=[ami_id])
        snapshot_ids = []
        for img in img_resp.get("Images", []):
            for bdm in img.get("BlockDeviceMappings", []):
                ebs = bdm.get("Ebs", {})
                if ebs.get("SnapshotId"):
                    snapshot_ids.append(ebs["SnapshotId"])

        # Deregister AMI
        ec2.deregister_image(ImageId=ami_id)
        logger.info(f"Deregistered AMI {ami_id}")

        # Clean up associated snapshots
        deleted = []
        skipped = []
        for snap_id in snapshot_ids:
            try:
                # Check if snapshot is used by other AMIs
                other_images = ec2.describe_images(Filters=[
                    {'Name': 'block-device-mapping.snapshot-id', 'Values': [snap_id]}
                ])
                if len(other_images.get('Images', [])) > 0:
                    skipped.append(snap_id)
                    continue
                ec2.delete_snapshot(SnapshotId=snap_id)
                logger.info(f"Deleted snapshot {snap_id}")
                deleted.append(snap_id)
            except Exception as e:
                logger.warning(f"Could not delete snapshot {snap_id}: {e}")

        return {
            "ok": True,
            "ami_id": ami_id,
            "snapshots_deleted": deleted,
            "snapshots_skipped": skipped,
            "message": f"AMI {ami_id} deregistered, {len(deleted)} snapshot(s) cleaned up, {len(skipped)} snapshot(s) skipped (shared)",
        }

    except ClientError as e:
        logger.error(f"deregister_ami failed: {e}")
        return {"ok": False, "error": _sanitize_error(e)}
    except Exception as e:
        logger.error(f"deregister_ami failed: {e}")
        return {"ok": False, "error": _sanitize_error(e)}


def list_security_groups(config, region=None):
    """List security groups for the UI dropdown."""
    try:
        aws = config.get("aws", {})
        if not region:
            region = (aws.get("regions", []) or ["us-east-1"])[0]

        ec2 = _get_boto_client("ec2", config, region)
        resp = ec2.describe_security_groups()

        groups = []
        for sg in resp.get("SecurityGroups", []):
            groups.append({
                "id": sg["GroupId"],
                "name": sg.get("GroupName", ""),
                "description": sg.get("Description", ""),
                "vpc_id": sg.get("VpcId", ""),
            })

        return {"ok": True, "security_groups": groups, "region": region}

    except ClientError as e:
        logger.error(f"list_security_groups failed: {e}")
        return {"ok": False, "error": _sanitize_error(e), "security_groups": []}
    except Exception as e:
        logger.error(f"list_security_groups failed: {e}")
        return {"ok": False, "error": _sanitize_error(e), "security_groups": []}


def list_key_pairs(config, region=None):
    """List key pairs for the UI dropdown."""
    try:
        aws = config.get("aws", {})
        if not region:
            region = (aws.get("regions", []) or ["us-east-1"])[0]

        ec2 = _get_boto_client("ec2", config, region)
        resp = ec2.describe_key_pairs()

        keys = []
        for kp in resp.get("KeyPairs", []):
            keys.append({
                "name": kp["KeyName"],
                "fingerprint": kp.get("KeyFingerprint", ""),
                "type": kp.get("KeyType", ""),
            })

        return {"ok": True, "key_pairs": keys, "region": region}

    except ClientError as e:
        logger.error(f"list_key_pairs failed: {e}")
        return {"ok": False, "error": _sanitize_error(e), "key_pairs": []}
    except Exception as e:
        logger.error(f"list_key_pairs failed: {e}")
        return {"ok": False, "error": _sanitize_error(e), "key_pairs": []}
