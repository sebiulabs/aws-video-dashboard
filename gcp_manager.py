"""
GCP Manager -- Google Cloud Platform monitoring and management for the Video Engineering Dashboard
====================================================================================================
Mirrors the AWS monitoring approach (ec2_manager.py, aws_services_monitor.py) but for GCP services.

Monitored services:
  - Compute Engine (GCE)  -- Virtual machines, status, IPs, zones
  - GKE                   -- Kubernetes clusters, node counts, versions
  - Cloud Run             -- Serverless container services
  - Cloud Storage (GCS)   -- Object storage buckets

Management capabilities:
  - Launch GCE instances from media templates
  - Start / stop / reset / delete GCE instances
  - Create machine images from instances

Setup:
  1. Install the GCP client libraries:
       pip install google-cloud-compute google-cloud-container google-cloud-run google-cloud-storage google-auth
  2. Add a ``gcp`` section to config.json:
       {
         "gcp": {
           "project_id": "my-gcp-project",
           "service_account_json": "{ ... }"   // JSON string of the service-account key
         }
       }
  3. The module degrades gracefully -- if GCP packages are not installed,
     all functions return empty results and log a warning.
"""

import json
import logging
import re
import time

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Conditional GCP imports -- the module must be importable even without
# google-cloud packages installed.
# ---------------------------------------------------------------------------
_GCP_AVAILABLE = False

try:
    from google.oauth2 import service_account as _sa
    _GCP_AVAILABLE = True
except ImportError:
    _sa = None

try:
    from google.cloud import compute_v1 as _compute_v1
except ImportError:
    _compute_v1 = None

try:
    from google.cloud import container_v1 as _container_v1
except ImportError:
    _container_v1 = None

try:
    from google.cloud import run_v2 as _run_v2
except ImportError:
    _run_v2 = None

try:
    from google.cloud import storage as _storage
except ImportError:
    _storage = None

if not _GCP_AVAILABLE:
    logger.info("GCP client libraries not installed -- GCP features disabled")


# ===========================================================================
# HELPERS
# ===========================================================================

def _sanitize_error(error):
    """Sanitize GCP error messages to avoid leaking credentials or project details."""
    msg = str(error)
    # Strip project IDs that look like identifiers
    msg = re.sub(r"projects/[a-z][a-z0-9-]{4,28}[a-z0-9]", "projects/***", msg)
    # Strip service-account emails
    msg = re.sub(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.iam\.gserviceaccount\.com", "***@***.iam.gserviceaccount.com", msg)
    return msg


def _get_credentials(config):
    """Get GCP credentials from config.

    Returns (credentials, project_id) or (None, None) on failure.
    The config is expected to contain::

        config["gcp"]["service_account_json"]  -- JSON string of the SA key
        config["gcp"]["project_id"]            -- GCP project ID
    """
    try:
        gcp_cfg = config.get("gcp", {})
        sa_json_str = gcp_cfg.get("service_account_json", "")
        project_id = gcp_cfg.get("project_id", "")

        if not sa_json_str or not _GCP_AVAILABLE or _sa is None:
            return None, None

        sa_info = json.loads(sa_json_str)
        credentials = _sa.Credentials.from_service_account_info(sa_info)

        # Fall back to the project_id embedded in the service-account key
        if not project_id:
            project_id = sa_info.get("project_id", "")

        return credentials, project_id

    except Exception as exc:
        logger.warning("Failed to load GCP credentials: %s", _sanitize_error(exc))
        return None, None


def _empty_result(error_msg=None):
    """Return the canonical empty monitoring result."""
    result = {"total": 0, "healthy": 0, "items": []}
    if error_msg:
        result["error"] = error_msg
    return result


# ===========================================================================
# GCE MEDIA TEMPLATES
# ===========================================================================

GCE_MEDIA_TEMPLATES = [
    {
        "id": "gce_encoding",
        "name": "Video Encoder",
        "machine_type": "n2-standard-8",
        "description": "8 vCPU encoder for live transcoding",
    },
    {
        "id": "gce_streaming",
        "name": "Streaming Server",
        "machine_type": "n2-standard-4",
        "description": "4 vCPU streaming origin server",
    },
    {
        "id": "gce_gpu_encoder",
        "name": "GPU Encoder",
        "machine_type": "n1-standard-8",
        "description": "GPU-accelerated encoder (attach GPU separately)",
    },
    {
        "id": "gce_storage",
        "name": "Storage Server",
        "machine_type": "n2-standard-2",
        "description": "2 vCPU media storage and NFS server",
    },
    {
        "id": "gce_monitoring",
        "name": "Monitoring Node",
        "machine_type": "e2-standard-2",
        "description": "2 vCPU monitoring and alerting node",
    },
]


# ===========================================================================
# MONITORING FUNCTIONS
# ===========================================================================

# -- 1. Compute Engine (GCE) ------------------------------------------------

def check_gce_instances(config, region=None):
    """List Compute Engine VMs.

    Returns ``{"total": int, "healthy": int, "items": [...]}``.
    Each item contains: name, zone, machine_type, status, internal_ip,
    external_ip, creation_timestamp.  Healthy means status == "RUNNING".
    """
    if not _GCP_AVAILABLE or _compute_v1 is None:
        logger.warning("google-cloud-compute not installed -- skipping GCE check")
        return _empty_result("google-cloud-compute not installed")

    try:
        credentials, project_id = _get_credentials(config)
        if credentials is None or not project_id:
            return _empty_result("GCP credentials not configured")

        client = _compute_v1.InstancesClient(credentials=credentials)
        items = []

        # AggregatedList returns instances across all zones
        agg_list = client.aggregated_list(project=project_id)

        for zone_scope_pair in agg_list:
            zone_name = zone_scope_pair[0]  # e.g. "zones/us-central1-a"
            instances_scoped = zone_scope_pair[1]

            if not instances_scoped.instances:
                continue

            # If a region filter is provided, only include matching zones
            if region and region not in zone_name:
                continue

            for inst in instances_scoped.instances:
                # Extract short zone name
                short_zone = zone_name.replace("zones/", "")

                # Machine type is a full URL; extract the short name
                mt = inst.machine_type or ""
                if "/" in mt:
                    mt = mt.rsplit("/", 1)[-1]

                # Network interfaces for IPs
                internal_ip = ""
                external_ip = ""
                if inst.network_interfaces:
                    ni = inst.network_interfaces[0]
                    internal_ip = ni.network_i_p or ""
                    if ni.access_configs:
                        external_ip = ni.access_configs[0].nat_i_p or ""

                items.append({
                    "name": inst.name or "",
                    "zone": short_zone,
                    "machine_type": mt,
                    "status": inst.status or "",
                    "internal_ip": internal_ip,
                    "external_ip": external_ip,
                    "creation_timestamp": inst.creation_timestamp or "",
                })

        healthy = sum(1 for i in items if i["status"] == "RUNNING")
        return {"total": len(items), "healthy": healthy, "items": items}

    except Exception as exc:
        logger.warning("GCE instances check failed: %s", _sanitize_error(exc))
        return _empty_result(_sanitize_error(exc))


# -- 2. GKE Clusters --------------------------------------------------------

def check_gke_clusters(config):
    """List GKE clusters.

    Returns ``{"total": int, "healthy": int, "items": [...]}``.
    Each item contains: name, location, status, node_count,
    current_master_version, endpoint.  Healthy means status == "RUNNING".
    """
    if not _GCP_AVAILABLE or _container_v1 is None:
        logger.warning("google-cloud-container not installed -- skipping GKE check")
        return _empty_result("google-cloud-container not installed")

    try:
        credentials, project_id = _get_credentials(config)
        if credentials is None or not project_id:
            return _empty_result("GCP credentials not configured")

        client = _container_v1.ClusterManagerClient(credentials=credentials)
        parent = f"projects/{project_id}/locations/-"
        response = client.list_clusters(parent=parent)

        items = []
        for cluster in response.clusters:
            # Total node count across all node pools
            node_count = 0
            if cluster.node_pools:
                for pool in cluster.node_pools:
                    if pool.autoscaling and pool.autoscaling.enabled:
                        node_count += pool.autoscaling.total_min_node_count or pool.initial_node_count
                    else:
                        node_count += pool.initial_node_count or 0

            # Status is an enum; convert to string name
            status_name = cluster.status.name if hasattr(cluster.status, "name") else str(cluster.status)

            items.append({
                "name": cluster.name or "",
                "location": cluster.location or "",
                "status": status_name,
                "node_count": node_count,
                "current_master_version": cluster.current_master_version or "",
                "endpoint": cluster.endpoint or "",
            })

        healthy = sum(1 for i in items if i["status"] == "RUNNING")
        return {"total": len(items), "healthy": healthy, "items": items}

    except Exception as exc:
        logger.warning("GKE clusters check failed: %s", _sanitize_error(exc))
        return _empty_result(_sanitize_error(exc))


# -- 3. Cloud Run ------------------------------------------------------------

def check_cloud_run(config, region=None):
    """List Cloud Run services.

    Returns ``{"total": int, "healthy": int, "items": [...]}``.
    Each item contains: name, region, url, latest_revision, condition_status.
    Healthy means the latest ready condition is True.
    """
    if not _GCP_AVAILABLE or _run_v2 is None:
        logger.warning("google-cloud-run not installed -- skipping Cloud Run check")
        return _empty_result("google-cloud-run not installed")

    try:
        credentials, project_id = _get_credentials(config)
        if credentials is None or not project_id:
            return _empty_result("GCP credentials not configured")

        client = _run_v2.ServicesClient(credentials=credentials)

        # If a region is provided, list services in that region only;
        # otherwise use "-" to list across all regions.
        location = region if region else "-"
        parent = f"projects/{project_id}/locations/{location}"
        services = client.list_services(parent=parent)

        items = []
        for svc in services:
            # Extract region from the service name
            # Format: projects/PROJECT/locations/REGION/services/NAME
            parts = (svc.name or "").split("/")
            svc_region = parts[3] if len(parts) > 3 else ""
            svc_name = parts[-1] if parts else ""

            # Determine health from conditions
            condition_status = "Unknown"
            is_healthy = False
            if svc.conditions:
                for cond in svc.conditions:
                    if cond.type_ == "Ready":
                        condition_status = cond.state.name if hasattr(cond.state, "name") else str(cond.state)
                        is_healthy = condition_status == "CONDITION_SUCCEEDED"
                        break

            # Latest revision
            latest_revision = ""
            if svc.latest_ready_revision:
                rev_parts = svc.latest_ready_revision.split("/")
                latest_revision = rev_parts[-1] if rev_parts else svc.latest_ready_revision

            items.append({
                "name": svc_name,
                "region": svc_region,
                "url": svc.uri or "",
                "latest_revision": latest_revision,
                "condition_status": condition_status,
            })

        healthy = sum(1 for i in items if i.get("condition_status") == "CONDITION_SUCCEEDED")
        return {"total": len(items), "healthy": healthy, "items": items}

    except Exception as exc:
        logger.warning("Cloud Run check failed: %s", _sanitize_error(exc))
        return _empty_result(_sanitize_error(exc))


# -- 4. Cloud Storage (GCS) -------------------------------------------------

def check_gcs_buckets(config):
    """List Cloud Storage buckets.

    Returns ``{"total": int, "healthy": int, "items": [...]}``.
    Each item contains: name, location, storage_class, created,
    versioning_enabled.  All existing buckets are considered healthy.
    """
    if not _GCP_AVAILABLE or _storage is None:
        logger.warning("google-cloud-storage not installed -- skipping GCS check")
        return _empty_result("google-cloud-storage not installed")

    try:
        credentials, project_id = _get_credentials(config)
        if credentials is None or not project_id:
            return _empty_result("GCP credentials not configured")

        client = _storage.Client(credentials=credentials, project=project_id)
        buckets = client.list_buckets()

        items = []
        for bucket in buckets:
            created = ""
            if bucket.time_created:
                created = bucket.time_created.isoformat() if hasattr(bucket.time_created, "isoformat") else str(bucket.time_created)

            versioning_enabled = False
            if bucket.versioning_enabled is not None:
                versioning_enabled = bucket.versioning_enabled

            items.append({
                "name": bucket.name or "",
                "location": bucket.location or "",
                "storage_class": bucket.storage_class or "",
                "created": created,
                "versioning_enabled": versioning_enabled,
            })

        # All buckets that exist are "healthy"
        return {"total": len(items), "healthy": len(items), "items": items}

    except Exception as exc:
        logger.warning("GCS buckets check failed: %s", _sanitize_error(exc))
        return _empty_result(_sanitize_error(exc))


# ===========================================================================
# MANAGEMENT FUNCTIONS
# ===========================================================================

# -- 5. Launch GCE Instance -------------------------------------------------

def launch_gce_instance(config, name, zone, machine_type, image_project, image_family, startup_script=""):
    """Create a new GCE instance.

    Args:
        config:         Application config dict.
        name:           Instance name.
        zone:           Target zone (e.g. ``us-central1-a``).
        machine_type:   Machine type (e.g. ``n2-standard-8``).
        image_project:  Image project (e.g. ``ubuntu-os-cloud``).
        image_family:   Image family (e.g. ``ubuntu-2204-lts``).
        startup_script: Optional startup script text.

    Returns:
        dict with instance info or error.
    """
    if not _GCP_AVAILABLE or _compute_v1 is None:
        return {"ok": False, "error": "google-cloud-compute not installed"}

    try:
        credentials, project_id = _get_credentials(config)
        if credentials is None or not project_id:
            return {"ok": False, "error": "GCP credentials not configured"}

        client = _compute_v1.InstancesClient(credentials=credentials)

        # Build the instance resource
        machine_type_full = f"zones/{zone}/machineTypes/{machine_type}"

        # Boot disk from image family
        boot_disk = _compute_v1.AttachedDisk(
            auto_delete=True,
            boot=True,
            initialize_params=_compute_v1.AttachedDiskInitializeParams(
                source_image=f"projects/{image_project}/global/images/family/{image_family}",
                disk_size_gb=50,
            ),
        )

        # Network interface with external access
        access_config = _compute_v1.AccessConfig(
            name="External NAT",
            type_="ONE_TO_ONE_NAT",
        )
        network_interface = _compute_v1.NetworkInterface(
            access_configs=[access_config],
        )

        # Metadata for startup script
        metadata_items = []
        if startup_script:
            metadata_items.append(
                _compute_v1.Items(key="startup-script", value=startup_script)
            )
        metadata = _compute_v1.Metadata(items=metadata_items) if metadata_items else None

        instance_resource = _compute_v1.Instance(
            name=name,
            machine_type=machine_type_full,
            disks=[boot_disk],
            network_interfaces=[network_interface],
            metadata=metadata,
        )

        operation = client.insert(
            project=project_id,
            zone=zone,
            instance_resource=instance_resource,
        )

        # Wait for the operation to complete (blocking)
        operation.result()

        logger.info("Launched GCE instance %s in %s", name, zone)
        return {
            "ok": True,
            "name": name,
            "zone": zone,
            "machine_type": machine_type,
            "project_id": project_id,
            "message": f"Instance '{name}' launched in {zone} ({machine_type})",
        }

    except Exception as exc:
        logger.error("launch_gce_instance failed: %s", _sanitize_error(exc))
        return {"ok": False, "error": _sanitize_error(exc)}


# -- 6. GCE Instance Action -------------------------------------------------

def gce_instance_action(config, instance_name, zone, action):
    """Perform a lifecycle action on a GCE instance.

    Args:
        config:         Application config dict.
        instance_name:  Name of the instance.
        zone:           Zone of the instance.
        action:         One of ``start``, ``stop``, ``reset``, ``delete``.

    Returns:
        ``{"ok": True/False, "message": str}``
    """
    if not _GCP_AVAILABLE or _compute_v1 is None:
        return {"ok": False, "message": "google-cloud-compute not installed"}

    try:
        credentials, project_id = _get_credentials(config)
        if credentials is None or not project_id:
            return {"ok": False, "message": "GCP credentials not configured"}

        client = _compute_v1.InstancesClient(credentials=credentials)

        if action == "start":
            operation = client.start(project=project_id, zone=zone, instance=instance_name)
            operation.result()
            msg = f"Instance '{instance_name}' started in {zone}"

        elif action == "stop":
            operation = client.stop(project=project_id, zone=zone, instance=instance_name)
            operation.result()
            msg = f"Instance '{instance_name}' stopped in {zone}"

        elif action == "reset":
            operation = client.reset(project=project_id, zone=zone, instance=instance_name)
            operation.result()
            msg = f"Instance '{instance_name}' reset in {zone}"

        elif action == "delete":
            operation = client.delete(project=project_id, zone=zone, instance=instance_name)
            operation.result()
            msg = f"Instance '{instance_name}' deleted from {zone}"

        else:
            return {"ok": False, "message": f"Unknown action: {action}"}

        logger.info(msg)
        return {"ok": True, "message": msg}

    except Exception as exc:
        logger.error("gce_instance_action (%s) failed: %s", action, _sanitize_error(exc))
        return {"ok": False, "message": _sanitize_error(exc)}


# -- 7. Create GCE Image ----------------------------------------------------

def create_gce_image(config, source_instance, zone, image_name):
    """Create a machine image from a GCE instance.

    The instance is stopped first (if running), then a disk image is created
    from its boot disk.

    Args:
        config:           Application config dict.
        source_instance:  Name of the source instance.
        zone:             Zone of the source instance.
        image_name:       Name for the new image.

    Returns:
        dict with image info or error.
    """
    if not _GCP_AVAILABLE or _compute_v1 is None:
        return {"ok": False, "error": "google-cloud-compute not installed"}

    try:
        credentials, project_id = _get_credentials(config)
        if credentials is None or not project_id:
            return {"ok": False, "error": "GCP credentials not configured"}

        instances_client = _compute_v1.InstancesClient(credentials=credentials)
        images_client = _compute_v1.ImagesClient(credentials=credentials)

        # Retrieve the instance to find its boot disk and current status
        instance = instances_client.get(
            project=project_id,
            zone=zone,
            instance=source_instance,
        )

        # Track whether instance was running so we can restart it after imaging
        was_running = instance.status == "RUNNING"

        # Stop the instance if it is running
        if was_running:
            logger.info("Stopping instance %s for image creation...", source_instance)
            stop_op = instances_client.stop(
                project=project_id,
                zone=zone,
                instance=source_instance,
            )
            stop_op.result()
            logger.info("Instance %s stopped", source_instance)

            # Brief pause to let disk state settle
            time.sleep(5)

        # Find the boot disk
        boot_disk_source = None
        for disk in instance.disks:
            if disk.boot:
                boot_disk_source = disk.source
                break

        if not boot_disk_source:
            return {"ok": False, "error": f"No boot disk found on instance '{source_instance}'"}

        # Create the image from the boot disk
        image_resource = _compute_v1.Image(
            name=image_name,
            source_disk=boot_disk_source,
            description=f"Image created from instance '{source_instance}' in {zone}",
        )

        operation = images_client.insert(
            project=project_id,
            image_resource=image_resource,
        )
        operation.result()

        logger.info("Image '%s' created from instance '%s'", image_name, source_instance)
        result = {
            "ok": True,
            "image_name": image_name,
            "source_instance": source_instance,
            "zone": zone,
            "project_id": project_id,
            "message": f"Image '{image_name}' created from instance '{source_instance}'",
        }

        # Restart the instance if it was running before imaging
        if was_running:
            instances_client.start(project=project_id, zone=zone, instance=source_instance).result()
            result["restarted"] = True
            result["warning"] = "Instance was stopped for imaging and has been restarted"
            logger.info("Instance %s restarted after image creation", source_instance)

        return result

    except Exception as exc:
        logger.error("create_gce_image failed: %s", _sanitize_error(exc))
        return {"ok": False, "error": _sanitize_error(exc)}
