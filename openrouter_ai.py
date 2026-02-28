"""
OpenRouter AI Integration
==========================
Query your AWS infrastructure setup using natural language via OpenRouter.
Supports any model on OpenRouter (Claude, GPT-4, Llama, Mistral, etc.)

Usage from the dashboard:
  "Why is my MediaLive channel dropping frames?"
  "Summarise my current infrastructure"
  "What's the best way to reduce latency on my CloudFront distribution?"
  "Are there any cost savings I could make?"
"""

import json
import logging
from typing import Optional

import requests

from config_manager import load_config

logger = logging.getLogger(__name__)

OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"


def build_system_prompt(infra_data: dict, config: dict) -> str:
    """Build a system prompt that includes current infrastructure state."""

    # Summarise what monitoring is enabled
    mon = config.get("monitoring", {})
    enabled_services = []
    if mon.get("monitor_ec2"): enabled_services.append("EC2")
    if mon.get("monitor_codedeploy"): enabled_services.append("CodeDeploy")
    if mon.get("monitor_ecs"): enabled_services.append("ECS")
    if mon.get("monitor_medialive"): enabled_services.append("MediaLive")
    if mon.get("monitor_mediaconnect"): enabled_services.append("MediaConnect")
    if mon.get("monitor_mediapackage"): enabled_services.append("MediaPackage")
    if mon.get("monitor_cloudfront"): enabled_services.append("CloudFront")
    if mon.get("monitor_ivs"): enabled_services.append("IVS")

    # Build a clean JSON snapshot (strip huge lists if too big)
    snapshot = json.dumps(infra_data, indent=2, default=str)
    # Truncate if massive
    if len(snapshot) > 30000:
        snapshot = snapshot[:30000] + "\n... (truncated)"

    return f"""You are an expert AWS infrastructure and video engineering assistant.
You specialise in live video workflows, broadcast engineering, streaming infrastructure,
CDN optimisation, and AWS media services (MediaLive, MediaConnect, MediaPackage, IVS, CloudFront).

The user is a video engineer / broadcast consultant managing this AWS infrastructure.
Region: {config.get('aws', {}).get('region', 'unknown')}
Monitored services: {', '.join(enabled_services) or 'None configured'}

CURRENT INFRASTRUCTURE STATE:
{snapshot}

ALERT RULES CONFIGURED:
{json.dumps(config.get('alert_rules', []), indent=2, default=str)}

Instructions:
- Answer questions about the infrastructure based on the live data above
- Give specific, actionable advice referencing actual resource IDs and metrics
- For video engineering questions, reference specific protocols (SRT, RTMP, HLS, DASH, CMAF, WHIP/WHEP, OMT, NDI) where relevant
- Flag potential issues you spot even if not asked
- If asked about costs, reference instance types and service pricing
- Keep answers concise and practical — the user is technical
"""


def query_openrouter(
    user_message: str,
    infra_data: dict,
    config: Optional[dict] = None,
    conversation_history: Optional[list] = None,
) -> dict:
    """
    Send a query to OpenRouter with infrastructure context.

    Returns:
        {"response": str, "model": str, "tokens": int, "error": str|None}
    """
    if config is None:
        config = load_config()

    ai_config = config.get("ai", {})
    api_key = ai_config.get("openrouter_api_key", "")
    model = ai_config.get("model", "anthropic/claude-sonnet-4.6")
    max_tokens = ai_config.get("max_tokens", 2048)
    temperature = ai_config.get("temperature", 0.3)

    if not api_key:
        return {
            "response": "OpenRouter API key not configured. Go to Settings → AI Assistant to add your key.",
            "model": None,
            "tokens": 0,
            "error": "no_api_key",
        }

    system_prompt = build_system_prompt(infra_data, config)

    messages = [{"role": "system", "content": system_prompt}]

    # Include conversation history if provided
    if conversation_history:
        for msg in conversation_history[-10:]:  # Last 10 messages max
            messages.append({"role": msg["role"], "content": msg["content"]})

    messages.append({"role": "user", "content": user_message})

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://aws-dashboard.local",
        "X-Title": "AWS Video Engineering Dashboard",
    }

    payload = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }

    try:
        resp = requests.post(OPENROUTER_API_URL, headers=headers, json=payload, timeout=60)
        data = resp.json()

        if resp.status_code != 200:
            error_msg = data.get("error", {}).get("message", f"HTTP {resp.status_code}")
            logger.error(f"OpenRouter error: {error_msg}")
            return {
                "response": f"API error: {error_msg}",
                "model": model,
                "tokens": 0,
                "error": error_msg,
            }

        choice = data.get("choices", [{}])[0]
        content = choice.get("message", {}).get("content", "No response")
        usage = data.get("usage", {})
        total_tokens = usage.get("total_tokens", 0)

        return {
            "response": content,
            "model": data.get("model", model),
            "tokens": total_tokens,
            "error": None,
        }

    except requests.Timeout:
        return {"response": "Request timed out — try again or use a faster model.", "model": model, "tokens": 0, "error": "timeout"}
    except requests.RequestException as e:
        logger.error(f"OpenRouter request failed: {e}")
        return {"response": f"Connection error: {e}", "model": model, "tokens": 0, "error": str(e)}


def get_available_models() -> list:
    """Return a curated list of recommended models for infrastructure queries."""
    return [
        # ── Anthropic ──
        {"id": "anthropic/claude-sonnet-4.6", "name": "Claude Sonnet 4.6 (recommended)", "context": "1M"},
        {"id": "anthropic/claude-opus-4.6", "name": "Claude Opus 4.6 (most capable)", "context": "1M"},
        {"id": "anthropic/claude-sonnet-4.5", "name": "Claude Sonnet 4.5", "context": "1M"},
        {"id": "anthropic/claude-opus-4.5", "name": "Claude Opus 4.5", "context": "200k"},
        {"id": "anthropic/claude-haiku-4.5", "name": "Claude Haiku 4.5 (fast/cheap)", "context": "200k"},
        # ── OpenAI ──
        {"id": "openai/gpt-5.2", "name": "GPT-5.2 (latest)", "context": "400k"},
        {"id": "openai/gpt-5", "name": "GPT-5", "context": "400k"},
        {"id": "openai/gpt-5-mini", "name": "GPT-5 Mini (fast)", "context": "400k"},
        {"id": "openai/gpt-4.1", "name": "GPT-4.1", "context": "1M"},
        {"id": "openai/gpt-4.1-mini", "name": "GPT-4.1 Mini (budget)", "context": "1M"},
        {"id": "openai/o4-mini", "name": "o4-mini (reasoning)", "context": "200k"},
        {"id": "openai/o3-pro", "name": "o3 Pro (deep reasoning)", "context": "200k"},
        # ── Google ──
        {"id": "google/gemini-3.1-pro-preview", "name": "Gemini 3.1 Pro (latest)", "context": "1M"},
        {"id": "google/gemini-3-pro-preview", "name": "Gemini 3 Pro", "context": "1M"},
        {"id": "google/gemini-2.5-pro", "name": "Gemini 2.5 Pro", "context": "1M"},
        {"id": "google/gemini-3-flash-preview", "name": "Gemini 3 Flash (default - budget)", "context": "1M"},
        # ── xAI ──
        {"id": "x-ai/grok-4", "name": "Grok 4", "context": "256k"},
        {"id": "x-ai/grok-4-fast", "name": "Grok 4 Fast", "context": "2M"},
        # ── Meta ──
        {"id": "meta-llama/llama-4-maverick", "name": "Llama 4 Maverick", "context": "1M"},
        {"id": "meta-llama/llama-4-scout", "name": "Llama 4 Scout", "context": "512k"},
        # ── DeepSeek ──
        {"id": "deepseek/deepseek-v3.2", "name": "DeepSeek V3.2 (cheapest recommended)", "context": "164k"},
        {"id": "deepseek/deepseek-r1-0528", "name": "DeepSeek R1 (reasoning)", "context": "164k"},
        # ── Mistral ──
        {"id": "mistralai/mistral-large-2512", "name": "Mistral Large 3", "context": "256k"},
    ]
