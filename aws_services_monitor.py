"""
AWS Services & Networking Monitor
====================================
Monitors core AWS infrastructure services and networking resources for
the Video Engineering Dashboard:

  AWS Services:
  - RDS           — Relational database instances, engine info, status, multi-AZ
  - Lambda        — Serverless functions, runtimes, memory, code size, state
  - S3            — Object storage buckets and creation dates (global)
  - SQS           — Message queues, approximate message counts, timestamps
  - Route53       — DNS hosted zones and health checks (global)
  - API Gateway   — REST API endpoints, types, and configurations

  Networking:
  - VPCs          — Virtual private clouds, CIDR blocks, subnets
  - Load Balancers — ALBs and NLBs via elbv2, target groups, health
  - Elastic IPs   — Static public IP allocations and associations
  - NAT Gateways  — Managed NAT for private subnet internet access
  - Security Groups — Firewall rules, open-to-world detection
  - VPN Connections — Site-to-site VPN tunnels and transit gateways

Each function accepts (config, region=None) and returns a dict with
{"total": int, "healthy": int, "items": [list of dicts]}.

Credentials are read from config["aws"]["access_key_id"],
config["aws"]["secret_access_key"], and config["aws"]["region"].

All configurable from the Settings UI via monitoring toggles.
"""

import logging
import re
from datetime import datetime, timezone
from typing import Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


# ═════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def _sanitize_error(error):
    """Sanitize AWS error messages to avoid leaking credentials or internal details."""
    msg = str(error)
    msg = re.sub(r"(AKIA|ASIA|AIDA|AROA|AIPA)[A-Z0-9]{12,}", "****", msg)
    msg = re.sub(r"\b\d{12}\b", "****", msg)
    msg = re.sub(r"arn:aws:[a-zA-Z0-9-]+:[a-z0-9-]*:\d{12}:[^\s\"']+", "arn:aws:***", msg)
    return msg


def _get_session(config: dict, region: str = None) -> boto3.Session:
    """Create a boto3 Session using dashboard config credentials."""
    kwargs = _get_boto_kwargs(config, region)
    return boto3.Session(**kwargs)


def _get_boto_kwargs(config: dict, region: str = None) -> dict:
    """Build boto3 client kwargs from config, matching video_monitor pattern."""
    aws = config.get("aws", {})
    kwargs = {"region_name": region or aws.get("region", "eu-west-2")}
    ak = aws.get("access_key_id", "")
    sk = aws.get("secret_access_key", "")
    if ak and sk and "\u2022\u2022" not in ak:
        kwargs["aws_access_key_id"] = ak
        kwargs["aws_secret_access_key"] = sk
    return kwargs


def _safe_isoformat(dt_val):
    """Safely convert a datetime to ISO format string."""
    if dt_val is None:
        return ""
    if hasattr(dt_val, "isoformat"):
        return dt_val.isoformat()
    return str(dt_val)


def _get_name_tag(tags_list):
    """Extract the Name tag value from a list of AWS tag dicts."""
    if not tags_list:
        return ""
    for tag in tags_list:
        if tag.get("Key") == "Name":
            return tag.get("Value", "")
    return ""


# ═════════════════════════════════════════════════════════════════════════════
# AWS SERVICES
# ═════════════════════════════════════════════════════════════════════════════


# ─────────────────────────────────────────────────────────────────────────────
# 1. RDS
# ─────────────────────────────────────────────────────────────────────────────

def check_rds(config: dict, region: str = None) -> dict:
    """
    Check all RDS database instances: identifier, engine, engine version,
    status, multi-AZ, instance class, allocated storage, and endpoint.
    """
    try:
        client = boto3.client("rds", **_get_boto_kwargs(config, region))
        items = []

        paginator = client.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                identifier = db.get("DBInstanceIdentifier", "")
                engine = db.get("Engine", "")
                engine_version = db.get("EngineVersion", "")
                status = db.get("DBInstanceStatus", "unknown")
                multi_az = db.get("MultiAZ", False)
                instance_class = db.get("DBInstanceClass", "")
                storage_gb = db.get("AllocatedStorage", 0)
                endpoint = db.get("Endpoint", {})

                items.append({
                    "identifier": identifier,
                    "engine": engine,
                    "engine_version": engine_version,
                    "status": status,
                    "multi_az": multi_az,
                    "instance_class": instance_class,
                    "storage_gb": storage_gb,
                    "endpoint": endpoint.get("Address", ""),
                    "port": endpoint.get("Port", 0),
                    "healthy": status == "available",
                })

        return {
            "total": len(items),
            "healthy": sum(1 for i in items if i["healthy"]),
            "items": items,
        }

    except (ClientError, Exception) as e:
        logger.warning(f"RDS check failed: {_sanitize_error(e)}")
        return {"total": 0, "healthy": 0, "items": [], "error": _sanitize_error(e)}


# ─────────────────────────────────────────────────────────────────────────────
# 2. Lambda
# ─────────────────────────────────────────────────────────────────────────────

def check_lambda(config: dict, region: str = None) -> dict:
    """
    Check all Lambda functions: name, runtime, memory, code size,
    handler, last modified, and state.
    """
    try:
        client = boto3.client("lambda", **_get_boto_kwargs(config, region))
        items = []

        paginator = client.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                name = fn.get("FunctionName", "")
                runtime = fn.get("Runtime", "N/A")
                memory_mb = fn.get("MemorySize", 0)
                code_size = fn.get("CodeSize", 0)
                handler = fn.get("Handler", "")
                last_modified = fn.get("LastModified", "")
                state = fn.get("State", "Active")

                items.append({
                    "name": name,
                    "runtime": runtime,
                    "memory_mb": memory_mb,
                    "code_size_bytes": code_size,
                    "code_size_mb": round(code_size / (1024 * 1024), 2) if code_size else 0,
                    "handler": handler,
                    "last_modified": last_modified,
                    "state": state,
                    "description": fn.get("Description", ""),
                    "timeout_seconds": fn.get("Timeout", 0),
                    "healthy": state == "Active",
                })

        return {
            "total": len(items),
            "healthy": sum(1 for i in items if i["healthy"]),
            "items": items,
        }

    except (ClientError, Exception) as e:
        logger.warning(f"Lambda check failed: {_sanitize_error(e)}")
        return {"total": 0, "healthy": 0, "items": [], "error": _sanitize_error(e)}


# ─────────────────────────────────────────────────────────────────────────────
# 3. S3 (global — region parameter is accepted but ignored)
# ─────────────────────────────────────────────────────────────────────────────

def check_s3(config: dict, region: str = None) -> dict:
    """
    Check all S3 buckets: name and creation date.
    S3 is a global service; the region parameter is accepted but ignored.
    """
    try:
        client = boto3.client("s3", **_get_boto_kwargs(config, region))
        items = []

        resp = client.list_buckets()
        for bucket in resp.get("Buckets", []):
            name = bucket.get("Name", "")
            creation_date = bucket.get("CreationDate")

            items.append({
                "name": name,
                "creation_date": _safe_isoformat(creation_date),
                "healthy": True,  # Buckets are always considered healthy if they exist
            })

        return {
            "total": len(items),
            "healthy": sum(1 for i in items if i["healthy"]),
            "items": items,
        }

    except (ClientError, Exception) as e:
        logger.warning(f"S3 check failed: {_sanitize_error(e)}")
        return {"total": 0, "healthy": 0, "items": [], "error": _sanitize_error(e)}


# ─────────────────────────────────────────────────────────────────────────────
# 4. SQS
# ─────────────────────────────────────────────────────────────────────────────

def check_sqs(config: dict, region: str = None) -> dict:
    """
    Check all SQS queues: name, approximate message count,
    approximate messages not visible, and created timestamp.
    """
    try:
        client = boto3.client("sqs", **_get_boto_kwargs(config, region))
        items = []

        resp = client.list_queues()
        queue_urls = resp.get("QueueUrls", [])

        for url in queue_urls:
            queue_name = url.split("/")[-1]
            approx_messages = 0
            approx_not_visible = 0
            created_timestamp = ""

            try:
                attr_resp = client.get_queue_attributes(
                    QueueUrl=url,
                    AttributeNames=[
                        "ApproximateNumberOfMessages",
                        "ApproximateNumberOfMessagesNotVisible",
                        "CreatedTimestamp",
                    ],
                )
                attr_map = attr_resp.get("Attributes", {})
                approx_messages = int(attr_map.get("ApproximateNumberOfMessages", 0))
                approx_not_visible = int(attr_map.get("ApproximateNumberOfMessagesNotVisible", 0))
                raw_ts = attr_map.get("CreatedTimestamp", "")
                if raw_ts:
                    try:
                        created_timestamp = datetime.fromtimestamp(
                            int(raw_ts), tz=timezone.utc
                        ).isoformat()
                    except (ValueError, OSError):
                        created_timestamp = raw_ts
            except ClientError:
                pass

            items.append({
                "name": queue_name,
                "queue_url": url,
                "approximate_message_count": approx_messages,
                "approximate_not_visible": approx_not_visible,
                "created_timestamp": created_timestamp,
                "healthy": True,  # Queues are healthy if they exist and are queryable
            })

        return {
            "total": len(items),
            "healthy": sum(1 for i in items if i["healthy"]),
            "items": items,
        }

    except (ClientError, Exception) as e:
        logger.warning(f"SQS check failed: {_sanitize_error(e)}")
        return {"total": 0, "healthy": 0, "items": [], "error": _sanitize_error(e)}


# ─────────────────────────────────────────────────────────────────────────────
# 5. Route53 (global)
# ─────────────────────────────────────────────────────────────────────────────

def check_route53(config: dict, region: str = None) -> dict:
    """
    Check Route53 hosted zones and health checks.
    Route53 is a global service; the region parameter is accepted but ignored.
    """
    items = []
    health_checks = []

    try:
        client = boto3.client("route53", **_get_boto_kwargs(config, region))

        # ── Hosted Zones ──
        try:
            paginator = client.get_paginator("list_hosted_zones")
            for page in paginator.paginate():
                for zone in page.get("HostedZones", []):
                    zone_id = zone.get("Id", "").split("/")[-1]
                    zone_config = zone.get("Config", {})

                    items.append({
                        "zone_id": zone_id,
                        "name": zone.get("Name", ""),
                        "record_count": zone.get("ResourceRecordSetCount", 0),
                        "private_zone": zone_config.get("PrivateZone", False),
                        "comment": zone_config.get("Comment", ""),
                        "healthy": True,  # Hosted zones are healthy if they exist
                    })
        except ClientError as e:
            logger.warning(f"Route53 hosted zones check failed: {_sanitize_error(e)}")

        # ── Health Checks ──
        try:
            paginator = client.get_paginator("list_health_checks")
            for page in paginator.paginate():
                for hc in page.get("HealthChecks", []):
                    hc_id = hc.get("Id", "")
                    hc_config = hc.get("HealthCheckConfig", {})

                    # Get health check status
                    status_text = "UNKNOWN"
                    is_healthy = False
                    try:
                        status_resp = client.get_health_check_status(
                            HealthCheckId=hc_id
                        )
                        checkers = status_resp.get("HealthCheckObservations", [])
                        if checkers:
                            healthy_count = sum(
                                1 for c in checkers
                                if c.get("StatusReport", {}).get("Status", "").startswith("Success")
                            )
                            unhealthy_count = sum(
                                1 for c in checkers
                                if c.get("StatusReport", {}).get("Status", "").startswith("Failure")
                            )
                            is_healthy = unhealthy_count == 0 and healthy_count > 0
                            status_text = "HEALTHY" if is_healthy else "UNHEALTHY"
                    except ClientError:
                        pass

                    health_checks.append({
                        "health_check_id": hc_id,
                        "type": hc_config.get("Type", ""),
                        "fqdn": hc_config.get("FullyQualifiedDomainName", ""),
                        "ip_address": hc_config.get("IPAddress", ""),
                        "port": hc_config.get("Port", 0),
                        "resource_path": hc_config.get("ResourcePath", ""),
                        "status": status_text,
                        "healthy": is_healthy,
                    })
        except ClientError as e:
            logger.warning(f"Route53 health checks check failed: {_sanitize_error(e)}")

        return {
            "total": len(items),
            "healthy": sum(1 for i in items if i["healthy"]),
            "hosted_zones": items,
            "health_checks": health_checks,
            "health_checks_total": len(health_checks),
            "health_checks_healthy": sum(1 for hc in health_checks if hc["healthy"]),
            "items": items + health_checks,
        }

    except (ClientError, Exception) as e:
        logger.warning(f"Route53 check failed: {_sanitize_error(e)}")
        return {
            "total": 0, "healthy": 0, "items": [],
            "hosted_zones": [], "health_checks": [],
            "health_checks_total": 0, "health_checks_healthy": 0,
            "error": _sanitize_error(e),
        }


# ─────────────────────────────────────────────────────────────────────────────
# 6. API Gateway
# ─────────────────────────────────────────────────────────────────────────────

def check_apigateway(config: dict, region: str = None) -> dict:
    """
    Check all API Gateway REST APIs: name, id, endpoint type, and created date.
    """
    try:
        client = boto3.client("apigateway", **_get_boto_kwargs(config, region))
        items = []

        paginator = client.get_paginator("get_rest_apis")
        for page in paginator.paginate():
            for api in page.get("items", []):
                api_id = api.get("id", "")
                name = api.get("name", "")
                description = api.get("description", "")
                created_date = api.get("createdDate")
                endpoint_config = api.get("endpointConfiguration", {})
                endpoint_types = endpoint_config.get("types", [])

                items.append({
                    "name": name,
                    "api_id": api_id,
                    "description": description,
                    "endpoint_type": ", ".join(endpoint_types) if endpoint_types else "UNKNOWN",
                    "created_date": _safe_isoformat(created_date),
                    "healthy": True,  # REST APIs are healthy if they exist
                })

        return {
            "total": len(items),
            "healthy": sum(1 for i in items if i["healthy"]),
            "items": items,
        }

    except (ClientError, Exception) as e:
        logger.warning(f"API Gateway check failed: {_sanitize_error(e)}")
        return {"total": 0, "healthy": 0, "items": [], "error": _sanitize_error(e)}


# ═════════════════════════════════════════════════════════════════════════════
# NETWORKING
# ═════════════════════════════════════════════════════════════════════════════


# ─────────────────────────────────────────────────────────────────────────────
# 7. VPCs
# ─────────────────────────────────────────────────────────────────────────────

def check_vpcs(config: dict, region: str = None) -> dict:
    """
    Check all VPCs: id, CIDR block, state, is_default, name tag, and subnet count.
    """
    try:
        client = boto3.client("ec2", **_get_boto_kwargs(config, region))
        items = []

        # Fetch all VPCs and all subnets in one pass for efficiency
        vpcs_resp = client.describe_vpcs()
        subnets_resp = client.describe_subnets()

        # Build subnet count per VPC
        subnet_counts = {}
        for subnet in subnets_resp.get("Subnets", []):
            vpc_id = subnet.get("VpcId", "")
            subnet_counts[vpc_id] = subnet_counts.get(vpc_id, 0) + 1

        for vpc in vpcs_resp.get("Vpcs", []):
            vpc_id = vpc.get("VpcId", "")
            cidr = vpc.get("CidrBlock", "")
            state = vpc.get("State", "unknown")
            is_default = vpc.get("IsDefault", False)
            name = _get_name_tag(vpc.get("Tags", []))

            items.append({
                "vpc_id": vpc_id,
                "cidr": cidr,
                "state": state,
                "is_default": is_default,
                "name": name,
                "subnet_count": subnet_counts.get(vpc_id, 0),
                "healthy": state == "available",
            })

        return {
            "total": len(items),
            "healthy": sum(1 for i in items if i["healthy"]),
            "items": items,
        }

    except (ClientError, Exception) as e:
        logger.warning(f"VPC check failed: {_sanitize_error(e)}")
        return {"total": 0, "healthy": 0, "items": [], "error": _sanitize_error(e)}


# ─────────────────────────────────────────────────────────────────────────────
# 8. Load Balancers (ALB/NLB via elbv2)
# ─────────────────────────────────────────────────────────────────────────────

def check_load_balancers(config: dict, region: str = None) -> dict:
    """
    Check all ALBs and NLBs via elbv2: name, type, state, DNS name,
    availability zones, and target group count.
    """
    try:
        client = boto3.client("elbv2", **_get_boto_kwargs(config, region))
        items = []

        paginator = client.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                lb_arn = lb.get("LoadBalancerArn", "")
                lb_name = lb.get("LoadBalancerName", "")
                lb_type = lb.get("Type", "unknown")
                state_obj = lb.get("State", {})
                state_code = state_obj.get("Code", "unknown")
                dns_name = lb.get("DNSName", "")
                scheme = lb.get("Scheme", "")
                vpc_id = lb.get("VpcId", "")

                # Get availability zones
                azs = [
                    az.get("ZoneName", "")
                    for az in lb.get("AvailabilityZones", [])
                ]

                # Count target groups for this load balancer
                target_group_count = 0
                try:
                    tg_resp = client.describe_target_groups(
                        LoadBalancerArn=lb_arn
                    )
                    target_group_count = len(tg_resp.get("TargetGroups", []))
                except ClientError:
                    pass

                items.append({
                    "name": lb_name,
                    "arn": lb_arn,
                    "type": lb_type,
                    "scheme": scheme,
                    "state": state_code,
                    "dns_name": dns_name,
                    "availability_zones": azs,
                    "target_group_count": target_group_count,
                    "vpc_id": vpc_id,
                    "healthy": state_code == "active",
                })

        return {
            "total": len(items),
            "healthy": sum(1 for i in items if i["healthy"]),
            "items": items,
        }

    except (ClientError, Exception) as e:
        logger.warning(f"Load Balancer check failed: {_sanitize_error(e)}")
        return {"total": 0, "healthy": 0, "items": [], "error": _sanitize_error(e)}


# ─────────────────────────────────────────────────────────────────────────────
# 9. Elastic IPs
# ─────────────────────────────────────────────────────────────────────────────

def check_elastic_ips(config: dict, region: str = None) -> dict:
    """
    Check all Elastic IPs: allocation ID, public IP, associated instance or
    ENI, and domain (vpc or standard).
    """
    try:
        client = boto3.client("ec2", **_get_boto_kwargs(config, region))
        items = []

        resp = client.describe_addresses()
        for addr in resp.get("Addresses", []):
            allocation_id = addr.get("AllocationId", "")
            public_ip = addr.get("PublicIp", "")
            instance_id = addr.get("InstanceId", "")
            eni_id = addr.get("NetworkInterfaceId", "")
            association_id = addr.get("AssociationId", "")
            domain = addr.get("Domain", "")
            is_associated = bool(instance_id or eni_id)

            items.append({
                "allocation_id": allocation_id,
                "public_ip": public_ip,
                "instance_id": instance_id,
                "network_interface_id": eni_id,
                "association_id": association_id,
                "domain": domain,
                "is_associated": is_associated,
                "healthy": is_associated,  # Unassociated EIPs are flagged (wasted cost)
            })

        return {
            "total": len(items),
            "healthy": sum(1 for i in items if i["healthy"]),
            "items": items,
        }

    except (ClientError, Exception) as e:
        logger.warning(f"Elastic IP check failed: {_sanitize_error(e)}")
        return {"total": 0, "healthy": 0, "items": [], "error": _sanitize_error(e)}


# ─────────────────────────────────────────────────────────────────────────────
# 10. NAT Gateways
# ─────────────────────────────────────────────────────────────────────────────

def check_nat_gateways(config: dict, region: str = None) -> dict:
    """
    Check all NAT gateways: id, state, subnet, VPC, and public IP address.
    """
    try:
        client = boto3.client("ec2", **_get_boto_kwargs(config, region))
        items = []

        paginator = client.get_paginator("describe_nat_gateways")
        for page in paginator.paginate():
            for ngw in page.get("NatGateways", []):
                ngw_id = ngw.get("NatGatewayId", "")
                state = ngw.get("State", "unknown")
                subnet_id = ngw.get("SubnetId", "")
                vpc_id = ngw.get("VpcId", "")
                connectivity_type = ngw.get("ConnectivityType", "")
                name = _get_name_tag(ngw.get("Tags", []))

                # Extract public IP from NAT gateway addresses
                public_ip = ""
                nat_addresses = ngw.get("NatGatewayAddresses", [])
                if nat_addresses:
                    public_ip = nat_addresses[0].get("PublicIp", "")

                items.append({
                    "nat_gateway_id": ngw_id,
                    "name": name,
                    "state": state,
                    "subnet_id": subnet_id,
                    "vpc_id": vpc_id,
                    "public_ip": public_ip,
                    "connectivity_type": connectivity_type,
                    "healthy": state == "available",
                })

        return {
            "total": len(items),
            "healthy": sum(1 for i in items if i["healthy"]),
            "items": items,
        }

    except (ClientError, Exception) as e:
        logger.warning(f"NAT Gateway check failed: {_sanitize_error(e)}")
        return {"total": 0, "healthy": 0, "items": [], "error": _sanitize_error(e)}


# ─────────────────────────────────────────────────────────────────────────────
# 11. Security Groups
# ─────────────────────────────────────────────────────────────────────────────

def check_security_groups(config: dict, region: str = None) -> dict:
    """
    Check all security groups: id, name, VPC, inbound/outbound rule counts,
    and whether any inbound rule is open to the world (0.0.0.0/0 on all ports).
    """
    try:
        client = boto3.client("ec2", **_get_boto_kwargs(config, region))
        items = []

        paginator = client.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                sg_id = sg.get("GroupId", "")
                sg_name = sg.get("GroupName", "")
                description = sg.get("Description", "")
                vpc_id = sg.get("VpcId", "")
                inbound_rules = sg.get("IpPermissions", [])
                outbound_rules = sg.get("IpPermissionsEgress", [])

                # Detect open-to-world: 0.0.0.0/0 or ::/0 with all-traffic or all-ports
                open_to_world = False
                for rule in inbound_rules:
                    from_port = rule.get("FromPort", -1)
                    to_port = rule.get("ToPort", -1)
                    ip_protocol = rule.get("IpProtocol", "")

                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            if ip_protocol == "-1" or (from_port == 0 and to_port == 65535):
                                open_to_world = True
                                break
                    if open_to_world:
                        break

                    for ipv6_range in rule.get("Ipv6Ranges", []):
                        if ipv6_range.get("CidrIpv6") == "::/0":
                            if ip_protocol == "-1" or (from_port == 0 and to_port == 65535):
                                open_to_world = True
                                break
                    if open_to_world:
                        break

                items.append({
                    "group_id": sg_id,
                    "group_name": sg_name,
                    "description": description,
                    "vpc_id": vpc_id,
                    "inbound_rule_count": len(inbound_rules),
                    "outbound_rule_count": len(outbound_rules),
                    "open_to_world": open_to_world,
                    "healthy": not open_to_world,  # Open-to-world SGs are flagged
                })

        return {
            "total": len(items),
            "healthy": sum(1 for i in items if i["healthy"]),
            "open_to_world_count": sum(1 for i in items if i["open_to_world"]),
            "items": items,
        }

    except (ClientError, Exception) as e:
        logger.warning(f"Security Groups check failed: {_sanitize_error(e)}")
        return {"total": 0, "healthy": 0, "items": [], "error": _sanitize_error(e)}


# ─────────────────────────────────────────────────────────────────────────────
# 12. VPN Connections & Transit Gateways
# ─────────────────────────────────────────────────────────────────────────────

def check_vpn_connections(config: dict, region: str = None) -> dict:
    """
    Check site-to-site VPN connections: id, state, type, and tunnel statuses.
    Also lists transit gateways in the region.
    """
    items = []
    transit_gateways = []

    try:
        client = boto3.client("ec2", **_get_boto_kwargs(config, region))

        # ── VPN Connections ──
        try:
            vpn_resp = client.describe_vpn_connections()
            for vpn in vpn_resp.get("VpnConnections", []):
                vpn_id = vpn.get("VpnConnectionId", "")
                state = vpn.get("State", "unknown")
                vpn_type = vpn.get("Type", "")
                name = _get_name_tag(vpn.get("Tags", []))

                # Extract tunnel statuses from VgwTelemetry
                tunnels = []
                for tun in vpn.get("VgwTelemetry", []):
                    tunnel_status = tun.get("Status", "UNKNOWN")
                    tunnels.append({
                        "outside_ip": tun.get("OutsideIpAddress", ""),
                        "status": tunnel_status,
                        "status_message": tun.get("StatusMessage", ""),
                        "last_status_change": _safe_isoformat(tun.get("LastStatusChange")),
                        "accepted_route_count": tun.get("AcceptedRouteCount", 0),
                    })

                tunnels_up = sum(1 for t in tunnels if t["status"] == "UP")

                items.append({
                    "vpn_connection_id": vpn_id,
                    "name": name,
                    "state": state,
                    "type": vpn_type,
                    "vpn_gateway_id": vpn.get("VpnGatewayId", ""),
                    "customer_gateway_id": vpn.get("CustomerGatewayId", ""),
                    "transit_gateway_id": vpn.get("TransitGatewayId", ""),
                    "tunnels": tunnels,
                    "tunnels_total": len(tunnels),
                    "tunnels_up": tunnels_up,
                    "healthy": state == "available" and tunnels_up > 0,
                })
        except ClientError as e:
            logger.warning(f"VPN Connections check failed: {_sanitize_error(e)}")

        # ── Transit Gateways ──
        try:
            tgw_resp = client.describe_transit_gateways()
            for tgw in tgw_resp.get("TransitGateways", []):
                tgw_id = tgw.get("TransitGatewayId", "")
                tgw_state = tgw.get("State", "unknown")
                tgw_name = _get_name_tag(tgw.get("Tags", []))

                transit_gateways.append({
                    "transit_gateway_id": tgw_id,
                    "name": tgw_name,
                    "state": tgw_state,
                    "owner_id": tgw.get("OwnerId", ""),
                    "description": tgw.get("Description", ""),
                    "amazon_side_asn": tgw.get("Options", {}).get("AmazonSideAsn", 0),
                    "healthy": tgw_state == "available",
                })
        except ClientError as e:
            logger.warning(f"Transit Gateways check failed: {_sanitize_error(e)}")

        return {
            "total": len(items),
            "healthy": sum(1 for i in items if i["healthy"]),
            "items": items,
            "transit_gateways": transit_gateways,
            "transit_gateways_total": len(transit_gateways),
            "transit_gateways_healthy": sum(1 for tg in transit_gateways if tg["healthy"]),
        }

    except (ClientError, Exception) as e:
        logger.warning(f"VPN check failed: {_sanitize_error(e)}")
        return {
            "total": 0, "healthy": 0, "items": [],
            "transit_gateways": [], "transit_gateways_total": 0,
            "transit_gateways_healthy": 0,
            "error": _sanitize_error(e),
        }
