"""
Easy Monitor — Endpoint & Service Monitoring
===============================================
Lightweight checks you can add from the UI to monitor anything:

  Types:
    http      — HTTP/HTTPS GET, check status code + response time + optional body match
    tcp       — TCP port open check (SRT ingest, RTMP, custom ports)
    json_api  — Fetch a JSON endpoint and extract a metric value via JSON path
    ping      — ICMP ping (requires system ping command)

  Each endpoint config:
    {
      "id": "ep_abc123",
      "name": "HLS Origin",
      "type": "http",                   # http, tcp, json_api, ping
      "enabled": true,
      "url": "https://origin.example.com/live/index.m3u8",
      "host": "",                        # for tcp/ping
      "port": 0,                         # for tcp
      "method": "GET",                   # for http
      "expected_status": 200,            # for http
      "body_contains": "#EXTM3U",        # optional: check response body
      "json_path": "status.healthy",     # for json_api: dot-notation path
      "timeout_seconds": 10,
      "interval_seconds": 60,
      "tags": ["streaming", "origin"],
      "last_result": null,               # filled after check
    }

  Typical video engineering endpoints to monitor:
    - HLS manifests (check for #EXTM3U)
    - DASH manifests (check for MPD)
    - WHIP/WHEP endpoints
    - SRT listener ports (TCP check on ingest IP)
    - RTMP ingest (TCP 1935)
    - OMT endpoints
    - CDN edge URLs
    - Encoding API health endpoints
"""

import ipaddress
import logging
import socket
import subprocess
import time
import uuid
import json
from datetime import datetime, timezone
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests

from config_manager import load_config, save_config

logger = logging.getLogger(__name__)

# Maximum concurrent checks
MAX_WORKERS = 10

# SSRF protection — block private/internal networks
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),       # link-local / IMDS
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),              # IPv6 private
    ipaddress.ip_network("fe80::/10"),             # IPv6 link-local
    ipaddress.ip_network("::ffff:0:0/96"),         # IPv4-mapped IPv6
]


def _is_blocked_host(hostname: str) -> bool:
    """Return True if hostname resolves to a private/blocked IP."""
    if not hostname:
        return True
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for family, _, _, _, sockaddr in addr_info:
            ip = ipaddress.ip_address(sockaddr[0])
            if hasattr(ip, 'ipv4_mapped') and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            for net in _BLOCKED_NETWORKS:
                if ip in net:
                    return True
    except (socket.gaierror, ValueError):
        return True  # unresolvable = blocked
    return False


# ─── Endpoint CRUD ──────────────────────────────────────────────────────────

def get_endpoints() -> list:
    config = load_config()
    return config.get("endpoints", [])


def save_endpoints(endpoints: list):
    config = load_config()
    config["endpoints"] = endpoints
    save_config(config)


def add_endpoint(data: dict) -> dict:
    endpoints = get_endpoints()
    ep = {
        "id": "ep_" + str(uuid.uuid4())[:8],
        "name": data.get("name", "Untitled"),
        "type": data.get("type", "http"),
        "enabled": data.get("enabled", True),
        "url": data.get("url", ""),
        "host": data.get("host", ""),
        "port": data.get("port", 0),
        "method": data.get("method", "GET"),
        "expected_status": data.get("expected_status", 200),
        "body_contains": data.get("body_contains", ""),
        "json_path": data.get("json_path", ""),
        "timeout_seconds": data.get("timeout_seconds", 10),
        "tags": data.get("tags", []),
        "last_result": None,
    }
    endpoints.append(ep)
    save_endpoints(endpoints)
    return ep


def update_endpoint(ep_id: str, updates: dict) -> Optional[dict]:
    endpoints = get_endpoints()
    for i, ep in enumerate(endpoints):
        if ep["id"] == ep_id:
            endpoints[i].update(updates)
            endpoints[i]["id"] = ep_id
            save_endpoints(endpoints)
            return endpoints[i]
    return None


def delete_endpoint(ep_id: str) -> bool:
    endpoints = get_endpoints()
    new_eps = [ep for ep in endpoints if ep["id"] != ep_id]
    if len(new_eps) < len(endpoints):
        save_endpoints(new_eps)
        return True
    return False


# ─── Preset Templates ───────────────────────────────────────────────────────

ENDPOINT_TEMPLATES = [
    {
        "name": "HLS Manifest Check",
        "type": "http",
        "url": "https://your-origin.com/live/index.m3u8",
        "expected_status": 200,
        "body_contains": "#EXTM3U",
        "tags": ["streaming", "hls"],
    },
    {
        "name": "DASH Manifest Check",
        "type": "http",
        "url": "https://your-origin.com/live/manifest.mpd",
        "expected_status": 200,
        "body_contains": "MPD",
        "tags": ["streaming", "dash"],
    },
    {
        "name": "SRT Ingest Port",
        "type": "tcp",
        "host": "ingest.example.com",
        "port": 9000,
        "tags": ["ingest", "srt"],
    },
    {
        "name": "RTMP Ingest",
        "type": "tcp",
        "host": "rtmp.example.com",
        "port": 1935,
        "tags": ["ingest", "rtmp"],
    },
    {
        "name": "WHIP Endpoint",
        "type": "http",
        "url": "https://whip.example.com/whip",
        "expected_status": 405,  # WHIP returns 405 on GET (expects POST)
        "tags": ["ingest", "whip", "webrtc"],
    },
    {
        "name": "CDN Edge Health",
        "type": "http",
        "url": "https://cdn.example.com/health",
        "expected_status": 200,
        "tags": ["cdn"],
    },
    {
        "name": "Encoding API Health",
        "type": "json_api",
        "url": "https://encoder.example.com/api/health",
        "json_path": "status",
        "expected_status": 200,
        "tags": ["encoding", "api"],
    },
    {
        "name": "Origin Server Ping",
        "type": "ping",
        "host": "origin.example.com",
        "tags": ["infrastructure"],
    },
]


# ─── Check Functions ────────────────────────────────────────────────────────

def _check_http(ep: dict) -> dict:
    """HTTP/HTTPS endpoint check."""
    url = ep.get("url", "")
    method = ep.get("method", "GET").upper()
    expected = ep.get("expected_status", 200)
    body_match = ep.get("body_contains", "")
    timeout = ep.get("timeout_seconds", 10)

    result = {
        "status": "down",
        "response_time_ms": 0,
        "status_code": 0,
        "body_match": None,
        "error": None,
    }

    # URL scheme validation
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return {"status": "error", "response_time_ms": 0, "error": "Only http/https allowed"}

    # SSRF protection
    try:
        hostname = parsed.hostname or ""
    except Exception:
        hostname = ""
    if _is_blocked_host(hostname):
        result["error"] = "Blocked: private/internal address"
        return result

    try:
        start = time.monotonic()
        resp = requests.request(method, url, timeout=timeout, allow_redirects=False,
                                headers={"User-Agent": "AWS-Dashboard-Monitor/1.0"})
        elapsed = round((time.monotonic() - start) * 1000, 1)

        result["response_time_ms"] = elapsed
        result["status_code"] = resp.status_code

        # Status code check
        status_ok = resp.status_code == expected

        # Body match check
        body_ok = True
        if body_match:
            body_ok = body_match in resp.text
            result["body_match"] = body_ok

        result["status"] = "up" if (status_ok and body_ok) else "degraded"
        if not status_ok:
            result["error"] = f"Expected {expected}, got {resp.status_code}"
        elif not body_ok:
            result["error"] = f"Body missing: '{body_match}'"

    except requests.Timeout:
        result["error"] = f"Timeout ({timeout}s)"
        result["response_time_ms"] = timeout * 1000
    except requests.ConnectionError as e:
        result["error"] = f"Connection failed: {str(e)[:100]}"
    except Exception as e:
        result["error"] = str(e)[:200]

    return result


def _check_tcp(ep: dict) -> dict:
    """TCP port check."""
    host = ep.get("host", "")
    port = ep.get("port", 0)
    timeout = ep.get("timeout_seconds", 10)

    result = {"status": "down", "response_time_ms": 0, "error": None}

    # SSRF protection
    if _is_blocked_host(host):
        result["error"] = "Blocked: private/internal address"
        return result

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    start = time.monotonic()
    try:
        sock.connect((host, int(port)))
        elapsed = round((time.monotonic() - start) * 1000, 1)
        result["status"] = "up"
        result["response_time_ms"] = elapsed
    except socket.timeout:
        result["error"] = f"Timeout ({timeout}s)"
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except socket.gaierror:
        result["error"] = f"DNS lookup failed for {host}"
    except Exception as e:
        result["error"] = str(e)[:200]
    finally:
        sock.close()

    return result


def _resolve_json_path(data: dict, path: str):
    """Resolve dot-notation path like 'status.healthy' on a dict."""
    keys = path.split(".")
    current = data
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        elif isinstance(current, list):
            try:
                current = current[int(key)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


def _check_json_api(ep: dict) -> dict:
    """JSON API endpoint — fetch once and extract a value via json_path."""
    url = ep.get("url", "")
    method = ep.get("method", "GET").upper()
    expected = ep.get("expected_status", 200)
    body_match = ep.get("body_contains", "")
    timeout = ep.get("timeout_seconds", 10)

    result = {
        "status": "down",
        "response_time_ms": 0,
        "status_code": 0,
        "body_match": None,
        "error": None,
        "json_value": None,
        "json_path": ep.get("json_path", ""),
    }

    # SSRF protection
    try:
        hostname = urlparse(url).hostname or ""
    except Exception:
        hostname = ""
    if _is_blocked_host(hostname):
        result["error"] = "Blocked: private/internal address"
        return result

    try:
        start = time.monotonic()
        resp = requests.request(method, url, timeout=timeout, allow_redirects=False,
                                headers={"User-Agent": "AWS-Dashboard-Monitor/1.0"})
        elapsed = round((time.monotonic() - start) * 1000, 1)

        result["response_time_ms"] = elapsed
        result["status_code"] = resp.status_code

        # Status code check
        status_ok = resp.status_code == expected

        # Body match check
        body_ok = True
        if body_match:
            body_ok = body_match in resp.text
            result["body_match"] = body_ok

        result["status"] = "up" if (status_ok and body_ok) else "degraded"
        if not status_ok:
            result["error"] = f"Expected {expected}, got {resp.status_code}"
        elif not body_ok:
            result["error"] = f"Body missing: '{body_match}'"

        # JSON path extraction (using the same response, no second request)
        if ep.get("json_path"):
            try:
                data = resp.json()
                value = _resolve_json_path(data, ep["json_path"])
                result["json_value"] = value
            except Exception as e:
                result["error"] = f"JSON parse error: {str(e)[:100]}"

    except requests.Timeout:
        result["error"] = f"Timeout ({timeout}s)"
        result["response_time_ms"] = timeout * 1000
    except requests.ConnectionError as e:
        result["error"] = f"Connection failed: {str(e)[:100]}"
    except Exception as e:
        result["error"] = str(e)[:200]

    return result


def _check_ping(ep: dict) -> dict:
    """ICMP ping via system ping command."""
    host = ep.get("host", "")
    timeout = ep.get("timeout_seconds", 5)

    result = {"status": "down", "response_time_ms": 0, "error": None, "packet_loss": 100}

    # SSRF protection
    if _is_blocked_host(host):
        result["error"] = "Blocked: private/internal address"
        return result

    # Sanitise host to prevent command injection (only allow alphanumeric, dots, hyphens)
    import re
    if not re.match(r'^[a-zA-Z0-9._-]+$', host):
        result["error"] = "Invalid hostname"
        return result

    try:
        # Linux ping: -c count, -W timeout
        cmd = ["ping", "-c", "3", "-W", str(timeout), host]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)

        if proc.returncode == 0:
            result["status"] = "up"
            # Parse average RTT from ping output
            for line in proc.stdout.split("\n"):
                if "avg" in line or "rtt" in line:
                    # Format: rtt min/avg/max/mdev = 1.234/2.345/3.456/0.567 ms
                    parts = line.split("=")
                    if len(parts) >= 2:
                        times = parts[1].strip().split("/")
                        if len(times) >= 2:
                            result["response_time_ms"] = round(float(times[1]), 1)
                if "packet loss" in line:
                    # Parse "3 packets transmitted, 3 received, 0% packet loss"
                    for part in line.split(","):
                        if "loss" in part:
                            loss_str = part.strip().split("%")[0].strip().split()[-1]
                            try:
                                result["packet_loss"] = float(loss_str)
                            except ValueError:
                                pass
        else:
            result["error"] = "Host unreachable"

    except subprocess.TimeoutExpired:
        result["error"] = f"Ping timeout ({timeout}s)"
    except FileNotFoundError:
        result["error"] = "ping command not found"
    except Exception as e:
        result["error"] = str(e)[:200]

    return result


# ─── Check Router ───────────────────────────────────────────────────────────

CHECK_FUNCS = {
    "http": _check_http,
    "tcp": _check_tcp,
    "json_api": _check_json_api,
    "ping": _check_ping,
}


def check_single_endpoint(ep: dict) -> dict:
    """Run a single endpoint check and return the result."""
    check_type = ep.get("type", "http")
    func = CHECK_FUNCS.get(check_type, _check_http)

    result = func(ep)
    result["checked_at"] = datetime.now(timezone.utc).isoformat()
    result["endpoint_id"] = ep["id"]
    result["endpoint_name"] = ep["name"]
    result["endpoint_type"] = check_type
    result["tags"] = ep.get("tags", [])

    return result


def run_endpoint_checks() -> dict:
    """Run all enabled endpoint checks in parallel. Returns summary."""
    endpoints = get_endpoints()
    enabled = [ep for ep in endpoints if ep.get("enabled", True)]

    if not enabled:
        return {"total": 0, "up": 0, "down": 0, "degraded": 0, "endpoints": []}

    results = []

    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(enabled))) as pool:
        futures = {pool.submit(check_single_endpoint, ep): ep for ep in enabled}
        for future in as_completed(futures):
            ep = futures[future]
            try:
                result = future.result()
                results.append(result)

                # Update last_result in config
                for i, stored_ep in enumerate(endpoints):
                    if stored_ep["id"] == ep["id"]:
                        endpoints[i]["last_result"] = result
                        break
            except Exception as e:
                logger.error(f"Check failed for {ep.get('name', '?')}: {e}")
                results.append({
                    "endpoint_id": ep["id"],
                    "endpoint_name": ep.get("name", "?"),
                    "endpoint_type": ep.get("type", "?"),
                    "status": "down",
                    "error": str(e)[:200],
                    "response_time_ms": 0,
                    "checked_at": datetime.now(timezone.utc).isoformat(),
                    "tags": ep.get("tags", []),
                })

    # Persist last results
    save_endpoints(endpoints)

    up = sum(1 for r in results if r["status"] == "up")
    down = sum(1 for r in results if r["status"] == "down")
    degraded = sum(1 for r in results if r["status"] == "degraded")

    return {
        "total": len(results),
        "up": up,
        "down": down,
        "degraded": degraded,
        "endpoints": results,
    }
