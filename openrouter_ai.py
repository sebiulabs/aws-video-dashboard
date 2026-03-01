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


def _sanitize_infra_for_ai(infra_data):
    """Remove sensitive details before sending to external AI API."""
    import copy
    if not infra_data:
        return {}
    data = copy.deepcopy(infra_data)
    # Strip IPs, endpoints, and ARNs from all nested dicts/lists
    sensitive_keys = {"private_ip", "public_ip", "endpoint", "arn", "dns_name",
                      "external_ip", "internal_ip", "cluster_endpoint", "outside_ip",
                      "nat_gateway_ip", "allocation_id", "association_id",
                      "subnet_id", "vpc_id", "security_group_id"}
    def _strip(obj):
        if isinstance(obj, dict):
            return {k: ("***.***.***.***" if k in sensitive_keys and isinstance(v, str) else _strip(v))
                    for k, v in obj.items()}
        elif isinstance(obj, list):
            return [_strip(item) for item in obj]
        return obj
    return _strip(data)


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
    if mon.get("monitor_rds"): enabled_services.append("RDS")
    if mon.get("monitor_lambda"): enabled_services.append("Lambda")
    if mon.get("monitor_s3"): enabled_services.append("S3")
    if mon.get("monitor_sqs"): enabled_services.append("SQS")
    if mon.get("monitor_route53"): enabled_services.append("Route53")
    if mon.get("monitor_apigateway"): enabled_services.append("API Gateway")
    if mon.get("monitor_vpc"): enabled_services.append("VPCs")
    if mon.get("monitor_elb"): enabled_services.append("Load Balancers")
    if mon.get("monitor_eip"): enabled_services.append("Elastic IPs")
    if mon.get("monitor_nat"): enabled_services.append("NAT Gateways")
    if mon.get("monitor_security_groups"): enabled_services.append("Security Groups")
    if mon.get("monitor_vpn"): enabled_services.append("VPN Connections")

    # Build a clean JSON snapshot (strip huge lists if too big)
    sanitized_data = _sanitize_infra_for_ai(infra_data)
    snapshot = json.dumps(sanitized_data, indent=2, default=str)
    # Truncate if massive
    if len(snapshot) > 30000:
        snapshot = snapshot[:30000] + "\n... (truncated)"

    # Build action summary if available
    try:
        from ai_actions import get_action_summary
        action_summary = get_action_summary()
    except ImportError:
        action_summary = ""

    action_block = ""
    if action_summary:
        action_block = f"""

AVAILABLE ACTIONS:
You can propose actions for the user to execute. When proposing an action, use this format
on its own line so the dashboard can detect it:

ACTION_PROPOSAL: {{"action": "action_id", "params": {{"key": "value"}}, "reason": "why"}}

Available actions:
{action_summary}

For HIGH risk actions, always explain what will happen and let the user confirm.
For LOW risk actions, you may propose them proactively when relevant.
"""

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
{action_block}
Instructions:
- Answer questions about the infrastructure based on the live data above
- Give specific, actionable advice referencing actual resource IDs and metrics
- For video engineering questions, reference specific protocols (SRT, RTMP, HLS, DASH, CMAF, WHIP/WHEP, OMT, NDI) where relevant
- Flag potential issues you spot even if not asked
- If asked about costs, reference instance types and service pricing
- Keep answers concise and practical — the user is technical
- When the user asks you to do something (launch instance, build AMI, check status, etc.), propose the appropriate action
"""


AGENT_PROMPT_ADDENDUM = """

AGENT MODE PROTOCOL:
You are now operating in AGENT MODE — autonomous multi-step execution.
Follow this protocol strictly:

1. PLAN FIRST: Start your response with a plan on a single line:
   AGENT_PLAN: ["step 1 description", "step 2 description", ...]

2. ONE ACTION PER RESPONSE: Propose exactly ONE action using:
   ACTION_PROPOSAL: {"action": "action_id", "params": {"key": "value"}, "reason": "why"}
   Place this on its own line. Only propose one action per response.

3. WAIT FOR RESULTS: After proposing an action, stop. The system will execute it
   and feed the result back to you. Then you can propose the next action.

4. ADAPT: After seeing each action result, evaluate whether your plan needs adjusting.
   If an action fails, decide whether to retry, skip, or abort.

5. COMPLETION: When ALL tasks are done, end your response with:
   AGENT_COMPLETE: "Brief summary of everything that was accomplished"

6. ERROR: If something fails and you cannot recover, end with:
   AGENT_ERROR: "What went wrong and why you cannot continue"

RULES:
- Only propose actions from the available action list
- Briefly explain what you are doing before each ACTION_PROPOSAL
- Include AGENT_PLAN only in your FIRST response
- Do NOT propose multiple actions in a single response
- If the user's request doesn't require any actions, just respond normally and end with AGENT_COMPLETE
"""


def query_openrouter(
    user_message: str,
    infra_data: dict,
    config: Optional[dict] = None,
    conversation_history: Optional[list] = None,
    agent_mode: bool = False,
) -> dict:
    """
    Send a query to OpenRouter with infrastructure context.

    Args:
        agent_mode: When True, appends agent protocol instructions to system prompt.

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
    if agent_mode:
        system_prompt += AGENT_PROMPT_ADDENDUM

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
