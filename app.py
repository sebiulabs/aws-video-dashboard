"""
AWS Video Engineering Dashboard — Flask App
=============================================
Full web dashboard with 4 pages:
  1. Dashboard — EC2, deployments, ECS, MediaLive, MediaConnect, CloudFront, IVS
  2. Alerts — Easy alert rule builder with templates
  3. AI Assistant — OpenRouter-powered infrastructure Q&A
  4. Settings — All config: AWS, monitoring toggles, email/WhatsApp/Telegram, AI

Run:  python app.py
Visit: http://localhost:5000
"""

import json
from datetime import datetime
from flask import Flask, jsonify, render_template_string, request
from apscheduler.schedulers.background import BackgroundScheduler

from config_manager import load_config, save_config, update_config, get_masked_config
from monitor import run_check, send_whatsapp, send_notifications, send_daily_summary
from email_notifier import send_email
from telegram_notifier import send_telegram
from slack_notifier import send_slack
from openrouter_ai import query_openrouter, get_available_models
from alert_rules import (
    get_rules, add_rule, update_rule, delete_rule, add_template,
    SERVICE_METRICS, RULE_TEMPLATES,
)
from easy_monitor import (
    get_endpoints, add_endpoint, update_endpoint, delete_endpoint,
    check_single_endpoint, run_endpoint_checks, ENDPOINT_TEMPLATES,
)

app = Flask(__name__)

last_check = {"data": None, "timestamp": None}
ai_conversations = {}  # session-less conversation store (keyed by simple ID)


def scheduled_check():
    result = run_check(send_alerts=True)
    last_check["data"] = result
    last_check["timestamp"] = datetime.utcnow().isoformat()


# ═════════════════════════════════════════════════════════════════════════════
# API ROUTES
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/api/status")
def api_status():
    if last_check["data"] is None:
        try:
            scheduled_check()
        except Exception:
            last_check["data"] = {"ec2": {"total": 0, "running": 0, "healthy": 0, "alerts": 0, "instances": []},
                                  "deployments": {"total": 0, "succeeded": 0, "failed": 0, "in_progress": 0, "items": []},
                                  "ecs_services": []}
            last_check["timestamp"] = datetime.utcnow().isoformat()
    return jsonify(last_check)

@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    try:
        scheduled_check()
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
    return jsonify({"status": "ok", "timestamp": last_check["timestamp"]})


# ─── Config ──────────────────────────────────────────────────────────────────

@app.route("/api/config", methods=["GET"])
def api_get_config():
    return jsonify(get_masked_config())

@app.route("/api/config", methods=["POST"])
def api_save_config():
    incoming = request.json
    current = load_config()

    def preserve_masked(inc, cur, keys):
        for key in keys:
            if key in inc and isinstance(inc[key], str) and "••••" in inc[key]:
                inc[key] = cur.get(key, "")

    if "aws" in incoming:
        preserve_masked(incoming["aws"], current["aws"], ["access_key_id", "secret_access_key"])
    if "ai" in incoming:
        preserve_masked(incoming["ai"], current["ai"], ["openrouter_api_key"])
    if "notifications" in incoming and "channels" in incoming["notifications"]:
        ch = incoming["notifications"]["channels"]
        preserve_masked(ch.get("whatsapp", {}), current["notifications"]["channels"]["whatsapp"],
                        ["twilio_account_sid", "twilio_auth_token"])
        preserve_masked(ch.get("email", {}), current["notifications"]["channels"]["email"], ["smtp_password"])
        preserve_masked(ch.get("telegram", {}), current["notifications"]["channels"]["telegram"], ["bot_token"])
        em = ch.get("email", {})
        if "to_addresses" in em and isinstance(em["to_addresses"], str):
            em["to_addresses"] = [a.strip() for a in em["to_addresses"].split(",") if a.strip()]

    updated = update_config(incoming)
    return jsonify({"status": "ok", "config": get_masked_config()})


# ─── Test Notifications ──────────────────────────────────────────────────────

@app.route("/api/test/whatsapp", methods=["POST"])
def api_test_whatsapp():
    return jsonify({"sent": send_whatsapp("Test — WhatsApp is working!", load_config())})

@app.route("/api/test/email", methods=["POST"])
def api_test_email():
    return jsonify({"sent": send_email("AWS Dashboard Test", "Email notifications working!", load_config())})

@app.route("/api/test/telegram", methods=["POST"])
def api_test_telegram():
    return jsonify({"sent": send_telegram("Test — Telegram is working!", load_config())})

@app.route("/api/test/slack", methods=["POST"])
def api_test_slack():
    return jsonify({"sent": send_slack("Test — Slack is working!", load_config())})


# ─── Alert Rules API ────────────────────────────────────────────────────────

@app.route("/api/rules", methods=["GET"])
def api_get_rules():
    return jsonify({"rules": get_rules(), "metrics": SERVICE_METRICS, "templates": RULE_TEMPLATES})

@app.route("/api/rules", methods=["POST"])
def api_add_rule():
    rule = add_rule(request.json)
    return jsonify({"status": "ok", "rule": rule})

@app.route("/api/rules/<rule_id>", methods=["PUT"])
def api_update_rule(rule_id):
    rule = update_rule(rule_id, request.json)
    return jsonify({"status": "ok" if rule else "not_found", "rule": rule})

@app.route("/api/rules/<rule_id>", methods=["DELETE"])
def api_delete_rule(rule_id):
    ok = delete_rule(rule_id)
    return jsonify({"status": "ok" if ok else "not_found"})

@app.route("/api/rules/template", methods=["POST"])
def api_add_template():
    idx = request.json.get("index", 0)
    rule = add_template(idx)
    return jsonify({"status": "ok" if rule else "invalid_index", "rule": rule})


# ─── AI Assistant API ────────────────────────────────────────────────────────

@app.route("/api/ai/query", methods=["POST"])
def api_ai_query():
    data = request.json
    message = data.get("message", "")
    conv_id = data.get("conversation_id", "default")

    if not message:
        return jsonify({"error": "No message provided"}), 400

    config = load_config()
    infra = last_check.get("data") or {}

    # Get/create conversation history
    if conv_id not in ai_conversations:
        ai_conversations[conv_id] = []

    result = query_openrouter(message, infra, config, ai_conversations[conv_id])

    # Store in history
    ai_conversations[conv_id].append({"role": "user", "content": message})
    if result.get("response"):
        ai_conversations[conv_id].append({"role": "assistant", "content": result["response"]})

    # Keep last 20 messages
    ai_conversations[conv_id] = ai_conversations[conv_id][-20:]

    return jsonify(result)

@app.route("/api/ai/models", methods=["GET"])
def api_ai_models():
    return jsonify({"models": get_available_models()})

@app.route("/api/ai/clear", methods=["POST"])
def api_ai_clear():
    conv_id = request.json.get("conversation_id", "default")
    ai_conversations.pop(conv_id, None)
    return jsonify({"status": "ok"})


# ─── Easy Monitor Endpoints API ─────────────────────────────────────────────

@app.route("/api/endpoints", methods=["GET"])
def api_get_endpoints():
    return jsonify({"endpoints": get_endpoints(), "templates": ENDPOINT_TEMPLATES})

@app.route("/api/endpoints", methods=["POST"])
def api_add_endpoint():
    data = request.json
    if isinstance(data.get("tags"), str):
        data["tags"] = [t.strip() for t in data["tags"].split(",") if t.strip()]
    ep = add_endpoint(data)
    return jsonify({"status": "ok", "endpoint": ep})

@app.route("/api/endpoints/<ep_id>", methods=["PUT"])
def api_update_endpoint(ep_id):
    data = request.json
    if isinstance(data.get("tags"), str):
        data["tags"] = [t.strip() for t in data["tags"].split(",") if t.strip()]
    ep = update_endpoint(ep_id, data)
    return jsonify({"status": "ok" if ep else "not_found", "endpoint": ep})

@app.route("/api/endpoints/<ep_id>", methods=["DELETE"])
def api_delete_endpoint(ep_id):
    ok = delete_endpoint(ep_id)
    return jsonify({"status": "ok" if ok else "not_found"})

@app.route("/api/endpoints/<ep_id>/check", methods=["POST"])
def api_check_endpoint(ep_id):
    """Run a single endpoint check on demand."""
    endpoints = get_endpoints()
    for ep in endpoints:
        if ep["id"] == ep_id:
            result = check_single_endpoint(ep)
            # Persist result
            update_endpoint(ep_id, {"last_result": result})
            return jsonify({"status": "ok", "result": result})
    return jsonify({"status": "not_found"}), 404

@app.route("/api/endpoints/check-all", methods=["POST"])
def api_check_all_endpoints():
    """Run all endpoint checks now."""
    results = run_endpoint_checks()
    return jsonify({"status": "ok", "results": results})


# ═════════════════════════════════════════════════════════════════════════════
# SHARED HTML / CSS
# ═════════════════════════════════════════════════════════════════════════════

SHARED_STYLES = """<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f1117;color:#e1e4e8;padding:0}
a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}
code{background:#161b22;padding:2px 6px;border-radius:4px;font-size:0.85em;color:#f0883e}
.topnav{display:flex;align-items:center;gap:8px;padding:10px 20px;background:#161b22;border-bottom:1px solid #21262d;flex-wrap:wrap}
.topnav .logo{font-weight:700;font-size:1rem;color:#58a6ff;margin-right:12px}
.topnav a.nl{color:#8b949e;font-size:0.85rem;padding:5px 10px;border-radius:6px;transition:.15s}
.topnav a.nl:hover,.topnav a.nl.active{color:#e1e4e8;background:#21262d;text-decoration:none}
.container{max-width:1280px;margin:0 auto;padding:20px}
.btn{padding:7px 14px;border:1px solid #30363d;background:#21262d;color:#c9d1d9;border-radius:6px;cursor:pointer;font-size:.82rem;transition:.15s;display:inline-flex;align-items:center;gap:5px}
.btn:hover{background:#30363d}.btn.p{background:#238636;border-color:#2ea043;color:#fff}.btn.p:hover{background:#2ea043}
.btn.d{background:#da3633;border-color:#f85149;color:#fff}.btn.sm{padding:4px 8px;font-size:.75rem}
.btn:disabled{opacity:.5;cursor:not-allowed}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:20px}
.card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px}
.card .lb{font-size:.75rem;color:#8b949e;text-transform:uppercase;letter-spacing:.04em}
.card .vl{font-size:1.6rem;font-weight:700;margin-top:3px}
.green{color:#3fb950}.red{color:#f85149}.yellow{color:#d29922}.blue{color:#58a6ff}
.section{margin-bottom:20px}.section h2{font-size:1rem;margin-bottom:10px;color:#c9d1d9}
table{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #21262d;border-radius:8px;overflow:hidden}
th{background:#21262d;text-align:left;padding:8px 12px;font-size:.75rem;color:#8b949e;text-transform:uppercase}
td{padding:8px 12px;border-top:1px solid #21262d;font-size:.85rem}
tr:hover td{background:#1c2128}
.badge{display:inline-block;padding:2px 7px;border-radius:10px;font-size:.72rem;font-weight:600}
.badge.ok{background:#0d4429;color:#3fb950}.badge.warn{background:#3d2e00;color:#d29922}
.badge.error{background:#490202;color:#f85149}.badge.info{background:#0c2d6b;color:#58a6ff}
.badge.off{background:#21262d;color:#8b949e}
.toast{position:fixed;bottom:20px;right:20px;padding:10px 18px;border-radius:8px;font-size:.85rem;z-index:1000;transform:translateY(80px);opacity:0;transition:.3s}
.toast.show{transform:translateY(0);opacity:1}
.toast.success{background:#0d4429;color:#3fb950;border:1px solid #238636}
.toast.error{background:#490202;color:#f85149;border:1px solid #da3633}
.toast.info{background:#0c2d6b;color:#58a6ff;border:1px solid #1f6feb}
.panel{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:20px;margin-bottom:16px}
.panel h3{font-size:.9rem;color:#58a6ff;margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid #21262d;display:flex;align-items:center;gap:8px}
.field{margin-bottom:12px}
.field label{display:block;font-size:.75rem;color:#8b949e;margin-bottom:3px;text-transform:uppercase;letter-spacing:.03em}
.field input,.field select,.field textarea{width:100%;padding:7px 10px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#e1e4e8;font-size:.85rem;font-family:inherit}
.field input:focus,.field select:focus,.field textarea:focus{outline:none;border-color:#58a6ff;box-shadow:0 0 0 2px rgba(88,166,255,.15)}
.field .hint{font-size:.7rem;color:#484f58;margin-top:2px}
.toggle-row{display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid #21262d}
.toggle-row:last-child{border-bottom:none}
.switch{position:relative;width:40px;height:22px;flex-shrink:0}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;inset:0;background:#30363d;border-radius:22px;cursor:pointer;transition:.2s}
.slider::before{content:"";position:absolute;width:16px;height:16px;left:3px;bottom:3px;background:#8b949e;border-radius:50%;transition:.2s}
.switch input:checked+.slider{background:#238636}
.switch input:checked+.slider::before{transform:translateX(18px);background:#fff}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:900px){.grid2{grid-template-columns:1fr}}
.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}
@media(max-width:1000px){.grid3{grid-template-columns:1fr 1fr}}
@media(max-width:700px){.grid3{grid-template-columns:1fr}}
</style>"""

def nav(active):
    pages = [("Dashboard", "/", "dashboard"), ("Monitors", "/monitors", "monitors"), ("Alerts", "/alerts", "alerts"),
             ("AI Assistant", "/ai", "ai"), ("Settings", "/settings", "settings")]
    links = "".join(f'<a href="{url}" class="nl {"active" if key==active else ""}">{name}</a>' for name, url, key in pages)
    return f'<nav class="topnav"><span class="logo">AWS Video Dashboard</span>{links}</nav>'


# ═════════════════════════════════════════════════════════════════════════════
# 1. DASHBOARD PAGE — Unified command centre
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/")
def page_dashboard():
    return render_template_string("""<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AWS Video Dashboard</title>""" + SHARED_STYLES + """
<style>
.health-bar{display:flex;gap:6px;margin-bottom:20px;flex-wrap:wrap}
.health-pill{padding:8px 16px;border-radius:8px;border:1px solid #21262d;background:#161b22;cursor:pointer;transition:.15s;text-decoration:none;display:flex;align-items:center;gap:8px}
.health-pill:hover{border-color:#58a6ff;background:#1c2128;text-decoration:none}
.health-pill .dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.health-pill .dot.g{background:#3fb950}.health-pill .dot.r{background:#f85149}.health-pill .dot.y{background:#d29922}.health-pill .dot.b{background:#58a6ff}.health-pill .dot.off{background:#484f58}
.health-pill .hl{font-size:.85rem;font-weight:600;color:#e1e4e8}
.health-pill .sub{font-size:.72rem;color:#8b949e}
.dash-grid{display:grid;grid-template-columns:2fr 1fr;gap:16px}
@media(max-width:1000px){.dash-grid{grid-template-columns:1fr}}
.quick-actions{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.quick-actions a,.quick-actions button{padding:6px 14px;border-radius:6px;font-size:.8rem;border:1px solid #21262d;background:#161b22;color:#8b949e;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;gap:5px;transition:.15s}
.quick-actions a:hover,.quick-actions button:hover{border-color:#58a6ff;color:#58a6ff;text-decoration:none}
.sidebar-panel{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px;margin-bottom:12px}
.sidebar-panel h4{font-size:.82rem;color:#58a6ff;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center}
.mini-chat{display:flex;gap:6px;margin-top:8px}
.mini-chat input{flex:1;padding:6px 10px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#e1e4e8;font-size:.82rem}
.mini-chat input:focus{outline:none;border-color:#58a6ff}
.ai-response{font-size:.82rem;color:#c9d1d9;margin-top:8px;padding:10px;background:#0d1117;border:1px solid #21262d;border-radius:6px;max-height:200px;overflow-y:auto;display:none}
.issue-row{display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid #21262d;font-size:.82rem}
.issue-row:last-child{border-bottom:none}
.section-collapse{cursor:pointer;user-select:none}
.section-collapse:hover{color:#58a6ff}
</style>
</head><body>
""" + nav("dashboard") + """
<div class="container">

<!-- Header -->
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
    <div>
        <h1 style="font-size:1.3rem;color:#c9d1d9"><span id="si" style="display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:8px"></span>System Overview</h1>
        <div style="font-size:.75rem;color:#8b949e;margin-top:3px">Updated: <span id="ts">—</span> · Auto-refreshes every 60s</div>
    </div>
    <div style="display:flex;gap:8px">
        <button class="btn" onclick="refresh()" id="btn-refresh">Refresh</button>
    </div>
</div>

<!-- Health Bar — clickable pills linking to relevant pages -->
<div class="health-bar" id="health-bar"></div>

<!-- Quick Actions -->
<div class="quick-actions" id="quick-actions">
    <a href="/monitors">Manage Endpoints</a>
    <a href="/alerts">Alert Rules</a>
    <a href="/ai">AI Assistant</a>
    <a href="/settings">Settings</a>
    <button onclick="refresh()">Force Check</button>
</div>

<!-- Main Grid: Left=data, Right=sidebar -->
<div class="dash-grid">
<div>
    <!-- Active Issues Banner -->
    <div id="issues-banner" style="display:none" class="panel" style="border-color:#f85149">
        <h3 style="color:#f85149">Active Issues</h3>
        <div id="issues-list"></div>
    </div>

    <!-- Sections: each collapsible -->
    <div id="sec-ec2" class="section"></div>
    <div id="sec-deploy" class="section"></div>
    <div id="sec-ecs" class="section"></div>
    <div id="sec-medialive" class="section"></div>
    <div id="sec-mediaconnect" class="section"></div>
    <div id="sec-cloudfront" class="section"></div>
    <div id="sec-ivs" class="section"></div>
    <div id="sec-endpoints" class="section"></div>
</div>

<!-- Sidebar -->
<div>
    <!-- AI Quick Ask -->
    <div class="sidebar-panel">
        <h4>Quick Ask <a href="/ai" style="font-size:.72rem;font-weight:normal">Open full chat →</a></h4>
        <div class="mini-chat">
            <input type="text" id="ai-input" placeholder="Ask about your infra..." onkeydown="if(event.key==='Enter')quickAsk()">
            <button class="btn sm p" onclick="quickAsk()">Ask</button>
        </div>
        <div id="ai-response" class="ai-response"></div>
    </div>

    <!-- Alert Rules Summary -->
    <div class="sidebar-panel">
        <h4>Alert Rules <a href="/alerts" style="font-size:.72rem;font-weight:normal">Manage →</a></h4>
        <div id="rules-summary" style="font-size:.82rem;color:#8b949e">Loading...</div>
    </div>

    <!-- Triggered Alerts -->
    <div class="sidebar-panel" id="triggered-panel" style="display:none">
        <h4 style="color:#f0883e">Triggered Rules</h4>
        <div id="triggered-list"></div>
    </div>

    <!-- Notification Channels -->
    <div class="sidebar-panel">
        <h4>Channels <a href="/settings" style="font-size:.72rem;font-weight:normal">Configure →</a></h4>
        <div id="channels-status" style="font-size:.82rem;color:#8b949e">Loading...</div>
    </div>

    <!-- Endpoint Monitors Summary -->
    <div class="sidebar-panel">
        <h4>Endpoints <a href="/monitors" style="font-size:.72rem;font-weight:normal">Manage →</a></h4>
        <div id="ep-summary" style="font-size:.82rem;color:#8b949e">Loading...</div>
    </div>
</div>
</div>
</div>
<div id="toast" class="toast"></div>

<script>
function toast(m,t='info'){const e=document.getElementById('toast');e.textContent=m;e.className='toast '+t+' show';setTimeout(()=>e.classList.remove('show'),3000)}
function bg(t,c){return `<span class="badge ${c}">${t}</span>`}
function stBg(s){return bg(s,{running:'ok',stopped:'off',terminated:'error',pending:'warn'}[s]||'info')}
function dpBg(s){return bg(s,{Succeeded:'ok',Failed:'error',InProgress:'warn',Stopped:'error'}[s]||'info')}

async function fetchStatus(){try{const r=await fetch('/api/status');const j=await r.json();render(j);loadSidebar(j)}catch(e){console.error(e)}}
async function refresh(){document.getElementById('btn-refresh').textContent='...';await fetch('/api/refresh',{method:'POST'});await fetchStatus();document.getElementById('btn-refresh').textContent='Refresh';toast('Refreshed','success')}

// ── AI Quick Ask ──
async function quickAsk(){
    const input=document.getElementById('ai-input');
    const msg=input.value.trim();if(!msg)return;
    const resp=document.getElementById('ai-response');
    resp.style.display='block';resp.innerHTML='<span style="color:#8b949e">Thinking...</span>';
    input.value='';
    try{
        const r=await fetch('/api/ai/query',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:msg,conversation_id:'dashboard_quick'})});
        const j=await r.json();
        resp.innerHTML=j.response?j.response.replace(/\\n/g,'<br>').replace(/\*\*([^*]+)\*\*/g,'<b>$1</b>'):'<span style="color:#f85149">No response</span>';
        if(j.error==='no_api_key')resp.innerHTML='<span style="color:#d29922">Add your OpenRouter API key in <a href="/settings">Settings</a></span>';
    }catch(e){resp.innerHTML='<span style="color:#f85149">Error</span>'}
}

// ── Sidebar data ──
async function loadSidebar(statusData){
    // Rules summary
    try{
        const r=await fetch('/api/rules');const j=await r.json();
        const rules=j.rules||[];
        const enabled=rules.filter(r=>r.enabled).length;
        document.getElementById('rules-summary').innerHTML=rules.length?
            `${enabled} active / ${rules.length} total<br><span style="font-size:.72rem">${rules.filter(r=>r.severity==='critical'&&r.enabled).length} critical, ${rules.filter(r=>r.severity==='warning'&&r.enabled).length} warning</span>`:
            '<a href="/alerts">Add your first alert rule →</a>';
    }catch(e){}

    // Channels
    try{
        const r=await fetch('/api/config');const c=await r.json();
        const ch=c.notifications?.channels||{};
        const items=[];
        if(ch.email?.enabled)items.push(bg('Email','ok'));else items.push(bg('Email','off'));
        if(ch.whatsapp?.enabled)items.push(bg('WhatsApp','ok'));else items.push(bg('WhatsApp','off'));
        if(ch.telegram?.enabled)items.push(bg('Telegram','ok'));else items.push(bg('Telegram','off'));
        const master=c.notifications?.enabled;
        document.getElementById('channels-status').innerHTML=
            (master?'<span class="green" style="font-size:.75rem">● Notifications ON</span>':'<span class="red" style="font-size:.75rem">● Notifications OFF</span>')+
            '<div style="margin-top:6px;display:flex;gap:4px;flex-wrap:wrap">'+items.join('')+'</div>';
    }catch(e){}

    // Endpoint summary
    try{
        const r=await fetch('/api/endpoints');const j=await r.json();
        const eps=j.endpoints||[];
        if(!eps.length){document.getElementById('ep-summary').innerHTML='<a href="/monitors">Add your first endpoint →</a>';return}
        const up=eps.filter(e=>e.last_result?.status==='up').length;
        const down=eps.filter(e=>e.last_result?.status==='down').length;
        const unk=eps.filter(e=>!e.last_result).length;
        document.getElementById('ep-summary').innerHTML=
            `<span class="${down>0?'red':'green'}" style="font-weight:600">${up}/${eps.length} up</span>`+
            (down?` · <span class="red">${down} down</span>`:'')+
            (unk?` · <span style="color:#484f58">${unk} unchecked</span>`:'')+
            `<div style="margin-top:6px">${eps.slice(0,5).map(e=>{const s=e.last_result?.status||'unknown';return `<div class="issue-row"><span class="dot" style="width:6px;height:6px;border-radius:50%;background:${s==='up'?'#3fb950':s==='down'?'#f85149':'#484f58'}"></span>${e.name}</div>`}).join('')}${eps.length>5?`<div style="font-size:.72rem;color:#484f58;margin-top:4px">+${eps.length-5} more</div>`:''}</div>`;
    }catch(e){}
}

function render(j){
    const d=j.data;if(!d)return;
    document.getElementById('ts').textContent=new Date(j.timestamp).toLocaleString();

    // ── Collect all issues for the health bar and issues banner ──
    const issues=[];
    const ecAlerts=d.ec2.alerts||0;
    const depFails=d.deployments.failed||0;
    if(ecAlerts)issues.push(...d.ec2.instances.filter(i=>i.alerts&&i.alerts.length).map(i=>({svc:'EC2',name:i.name,detail:i.alerts.join(', ')})));
    if(depFails)issues.push(...d.deployments.items.filter(x=>x.status==='Failed').map(x=>({svc:'Deploy',name:x.application,detail:x.status})));
    const ml=d.medialive;if(ml&&ml.channels){ml.channels.filter(c=>!c.healthy&&c.state==='RUNNING').forEach(c=>issues.push({svc:'MediaLive',name:c.name,detail:c.input_loss?'Input Loss':'Unhealthy'}))}
    const mc=d.mediaconnect;if(mc&&mc.flows){mc.flows.filter(f=>!f.healthy).forEach(f=>issues.push({svc:'MediaConnect',name:f.name,detail:f.status}))}
    const cf=d.cloudfront;if(cf&&cf.distributions){cf.distributions.filter(x=>!x.healthy).forEach(x=>issues.push({svc:'CloudFront',name:x.name,detail:'5xx='+x.error_rate_5xx+'%'}))}
    const em=d.easy_monitor;if(em&&em.endpoints){em.endpoints.filter(e=>e.status!=='up').forEach(e=>issues.push({svc:'Endpoint',name:e.endpoint_name,detail:e.error||e.status}))}

    const totalIssues=issues.length;
    document.getElementById('si').style.background=totalIssues>0?'#f85149':'#3fb950';

    // ── Health Bar ──
    let hb='';
    // EC2
    const ecOk=d.ec2.healthy,ecTot=d.ec2.running;
    hb+=`<a class="health-pill" href="#sec-ec2"><span class="dot ${ecAlerts?'r':ecTot?'g':'off'}"></span><div><div class="hl">EC2</div><div class="sub">${ecOk}/${ecTot} healthy</div></div></a>`;
    // Deploys
    hb+=`<a class="health-pill" href="#sec-deploy"><span class="dot ${depFails?'r':d.deployments.succeeded?'g':'off'}"></span><div><div class="hl">Deploys</div><div class="sub">${d.deployments.succeeded} ok / ${depFails} fail</div></div></a>`;
    // Media services
    if(ml)hb+=`<a class="health-pill" href="#sec-medialive"><span class="dot ${ml.healthy<ml.running?'r':ml.running?'g':'off'}"></span><div><div class="hl">MediaLive</div><div class="sub">${ml.healthy}/${ml.running} ok</div></div></a>`;
    if(mc)hb+=`<a class="health-pill" href="#sec-mediaconnect"><span class="dot ${mc.flows.some(f=>!f.healthy)?'r':'g'}"></span><div><div class="hl">MediaConnect</div><div class="sub">${mc.total} flows</div></div></a>`;
    if(cf)hb+=`<a class="health-pill" href="#sec-cloudfront"><span class="dot ${cf.healthy<cf.total?'y':cf.total?'g':'off'}"></span><div><div class="hl">CloudFront</div><div class="sub">${cf.healthy}/${cf.total}</div></div></a>`;
    if(d.ivs)hb+=`<a class="health-pill" href="#sec-ivs"><span class="dot ${d.ivs.healthy<d.ivs.total?'r':'b'}"></span><div><div class="hl">IVS</div><div class="sub">${d.ivs.live} live</div></div></a>`;
    // Endpoints
    if(em&&em.total)hb+=`<a class="health-pill" href="#sec-endpoints"><span class="dot ${em.down?'r':em.degraded?'y':'g'}"></span><div><div class="hl">Endpoints</div><div class="sub">${em.up}/${em.total} up</div></div></a>`;

    document.getElementById('health-bar').innerHTML=hb;

    // ── Issues Banner ──
    if(totalIssues>0){
        document.getElementById('issues-banner').style.display='block';
        document.getElementById('issues-list').innerHTML=issues.map(i=>
            `<div class="issue-row">${bg(i.svc,'error')} <b>${i.name}</b> <span style="color:#8b949e">${i.detail}</span></div>`
        ).join('');
    }else{document.getElementById('issues-banner').style.display='none'}

    // ── Triggered rules ──
    if(d.rule_alerts&&d.rule_alerts.length){
        document.getElementById('triggered-panel').style.display='block';
        document.getElementById('triggered-list').innerHTML=d.rule_alerts.map(a=>
            `<div class="issue-row">${a.severity==='critical'?bg('CRIT','error'):a.severity==='warning'?bg('WARN','warn'):bg('INFO','info')} ${a.rule_name} <span style="color:#8b949e;font-size:.75rem">${a.resource}</span></div>`
        ).join('');
    }else{document.getElementById('triggered-panel').style.display='none'}

    // ── Data Tables ──
    if(d.ec2.instances.length){document.getElementById('sec-ec2').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ EC2 Instances (${d.ec2.running})</h2><table><thead><tr><th>Name</th><th>ID</th><th>Type</th><th>State</th><th>Uptime</th><th>Health</th><th>CPU</th><th>IP</th></tr></thead><tbody>${d.ec2.instances.map(i=>{const ut=i.uptime_display||'—';const utH=i.uptime_hours||0;const utClass=utH>72?'red':utH>24?'yellow':'green';return`<tr><td><b>${i.name}</b></td><td style="font-family:monospace;font-size:.78rem">${i.instance_id}</td><td>${i.instance_type}</td><td>${stBg(i.state)}</td><td class="${i.state==='running'?utClass:''}" style="font-weight:600">${i.state==='running'?ut:'—'}</td><td>${i.status_checks==='ok'?bg('OK','ok'):i.status_checks==='impaired'?bg('FAIL','error'):bg(i.status_checks,'warn')}</td><td>${i.cpu_utilization!==null?i.cpu_utilization+'%':'—'}</td><td style="font-family:monospace;font-size:.78rem">${i.public_ip||i.private_ip||'—'}</td></tr>`}).join('')}</tbody></table>`}else{document.getElementById('sec-ec2').innerHTML=''}

    if(d.deployments.items.length){document.getElementById('sec-deploy').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ Deployments (${d.deployments.total})</h2><table><thead><tr><th>App</th><th>Group</th><th>Status</th><th>Time</th></tr></thead><tbody>${d.deployments.items.map(x=>`<tr><td>${x.application}</td><td>${x.group}</td><td>${dpBg(x.status)}</td><td>${new Date(x.create_time).toLocaleString()}</td></tr>`).join('')}</tbody></table>`}else{document.getElementById('sec-deploy').innerHTML=''}

    if(d.medialive&&d.medialive.channels.length){document.getElementById('sec-medialive').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ MediaLive (${d.medialive.running} running)</h2><table><thead><tr><th>Channel</th><th>State</th><th>Pipelines</th><th>Input</th><th>Alerts</th></tr></thead><tbody>${d.medialive.channels.map(ch=>`<tr><td><b>${ch.name}</b></td><td>${ch.state==='RUNNING'?bg('RUNNING','ok'):bg(ch.state,'warn')}</td><td>${ch.pipelines_running}/${ch.pipeline_count}</td><td>${ch.input_loss?bg('LOSS','error'):bg('OK','ok')}</td><td>${ch.active_alerts>0?bg(ch.active_alerts,'error'):'—'}</td></tr>`).join('')}</tbody></table>`}else{document.getElementById('sec-medialive').innerHTML=''}

    if(d.mediaconnect&&d.mediaconnect.flows.length){document.getElementById('sec-mediaconnect').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ MediaConnect (${d.mediaconnect.total} flows)</h2><table><thead><tr><th>Flow</th><th>Status</th><th>Protocol</th><th>Outputs</th></tr></thead><tbody>${d.mediaconnect.flows.map(f=>`<tr><td><b>${f.name}</b></td><td>${f.status==='ACTIVE'?bg('ACTIVE','ok'):bg(f.status,'error')}</td><td>${f.source?.protocol||'—'}</td><td>${f.output_count}</td></tr>`).join('')}</tbody></table>`}else{document.getElementById('sec-mediaconnect').innerHTML=''}

    if(d.cloudfront&&d.cloudfront.distributions.length){document.getElementById('sec-cloudfront').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ CloudFront (${d.cloudfront.total})</h2><table><thead><tr><th>Name</th><th>Domain</th><th>Status</th><th>4xx%</th><th>5xx%</th><th>Req/15m</th></tr></thead><tbody>${d.cloudfront.distributions.map(x=>`<tr><td><b>${x.name}</b></td><td style="font-family:monospace;font-size:.78rem">${x.domain}</td><td>${x.healthy?bg('OK','ok'):bg(x.status,'warn')}</td><td>${x.error_rate_4xx}</td><td class="${x.error_rate_5xx>5?'red':''}">${x.error_rate_5xx}</td><td>${x.requests_15m}</td></tr>`).join('')}</tbody></table>`}else{document.getElementById('sec-cloudfront').innerHTML=''}

    if(d.ivs&&d.ivs.channels.length){document.getElementById('sec-ivs').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ IVS (${d.ivs.live} live)</h2><table><thead><tr><th>Channel</th><th>State</th><th>Health</th><th>Viewers</th></tr></thead><tbody>${d.ivs.channels.map(ch=>`<tr><td><b>${ch.name}</b></td><td>${ch.state==='LIVE'?bg('LIVE','ok'):bg('OFF','off')}</td><td>${ch.stream_health==='HEALTHY'?bg('OK','ok'):ch.stream_health==='UNHEALTHY'?bg('BAD','error'):bg(ch.stream_health,'off')}</td><td>${ch.viewer_count}</td></tr>`).join('')}</tbody></table>`}else{document.getElementById('sec-ivs').innerHTML=''}

    if(em&&em.endpoints.length){document.getElementById('sec-endpoints').innerHTML=`<h2 class="section-collapse" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">▾ Endpoints (${em.up}/${em.total} up)</h2><table><thead><tr><th>Name</th><th>Type</th><th>Status</th><th>Response</th><th>Error</th></tr></thead><tbody>${em.endpoints.map(e=>`<tr><td><b>${e.endpoint_name}</b></td><td>${bg(e.endpoint_type,'info')}</td><td>${e.status==='up'?bg('UP','ok'):e.status==='degraded'?bg('DEGRADED','warn'):bg('DOWN','error')}</td><td>${e.response_time_ms?e.response_time_ms+'ms':'—'}</td><td style="font-size:.78rem;color:#f85149;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${e.error||'—'}</td></tr>`).join('')}</tbody></table>`}else{document.getElementById('sec-endpoints').innerHTML=''}
}

fetchStatus();setInterval(fetchStatus,60000);
</script></body></html>""")


# ═════════════════════════════════════════════════════════════════════════════
# 1b. MONITORS PAGE — Easy endpoint monitoring
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/monitors")
def page_monitors():
    return render_template_string("""<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Monitors — AWS Video Dashboard</title>""" + SHARED_STYLES + """
<style>
.ep-card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:14px;margin-bottom:10px;display:grid;grid-template-columns:1fr auto;gap:10px;align-items:center}
.ep-card.down{border-color:#f85149}.ep-card.degraded{border-color:#d29922}
.ep-status{display:flex;align-items:center;gap:8px}
.ep-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.ep-dot.up{background:#3fb950}.ep-dot.down{background:#f85149}.ep-dot.degraded{background:#d29922}.ep-dot.unknown{background:#484f58}
.tpl-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:10px;margin-bottom:16px}
.tpl-card{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:12px;cursor:pointer;transition:.15s}
.tpl-card:hover{border-color:#58a6ff;background:#161b22}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;display:none;align-items:center;justify-content:center}
.modal-bg.show{display:flex}
.modal{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:24px;width:560px;max-width:95vw;max-height:90vh;overflow-y:auto}
.modal h3{margin-bottom:16px;color:#c9d1d9}
.type-fields{display:none}.type-fields.active{display:block}
</style>
</head><body>
""" + nav("monitors") + """
<div class="container">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
    <h1 style="font-size:1.2rem;color:#c9d1d9">Endpoint Monitors</h1>
    <div style="display:flex;gap:8px">
        <button class="btn" onclick="checkAll()" id="btn-check-all">Check All Now</button>
        <button class="btn p" onclick="showAddModal()">+ Add Endpoint</button>
    </div>
</div>

<!-- Summary Cards -->
<div class="cards" id="summary-cards"></div>

<!-- Quick Templates -->
<div class="panel">
    <h3>Quick Add Templates</h3>
    <p style="font-size:.78rem;color:#8b949e;margin-bottom:10px">Click to add — edit the URL/host after</p>
    <div class="tpl-grid" id="templates"></div>
</div>

<!-- Endpoint list -->
<div id="ep-list"></div>

<!-- Add/Edit Modal -->
<div id="modal" class="modal-bg" onclick="if(event.target===this)closeModal()">
<div class="modal">
    <h3 id="modal-title">Add Endpoint</h3>
    <div class="field"><label>Name</label><input type="text" id="ep-name" placeholder="e.g. HLS Origin, SRT Ingest"></div>
    <div class="field"><label>Type</label>
        <select id="ep-type" onchange="toggleType()">
            <option value="http">HTTP/HTTPS (URL check)</option>
            <option value="tcp">TCP Port (SRT, RTMP, etc.)</option>
            <option value="json_api">JSON API (extract metric)</option>
            <option value="ping">Ping (ICMP)</option>
        </select>
    </div>

    <!-- HTTP fields -->
    <div id="f-http" class="type-fields active">
        <div class="field"><label>URL</label><input type="text" id="ep-url" placeholder="https://origin.example.com/live/index.m3u8"></div>
        <div class="grid2">
            <div class="field"><label>Method</label><select id="ep-method"><option value="GET">GET</option><option value="HEAD">HEAD</option><option value="POST">POST</option></select></div>
            <div class="field"><label>Expected Status</label><input type="number" id="ep-status" value="200"></div>
        </div>
        <div class="field"><label>Body Contains (optional)</label><input type="text" id="ep-body" placeholder="e.g. #EXTM3U for HLS">
            <div class="hint">Check that the response body includes this string</div></div>
    </div>

    <!-- TCP fields -->
    <div id="f-tcp" class="type-fields">
        <div class="grid2">
            <div class="field"><label>Host</label><input type="text" id="ep-host" placeholder="ingest.example.com"></div>
            <div class="field"><label>Port</label><input type="number" id="ep-port" placeholder="9000"></div>
        </div>
    </div>

    <!-- JSON API fields -->
    <div id="f-json" class="type-fields">
        <div class="field"><label>URL</label><input type="text" id="ep-json-url" placeholder="https://api.example.com/health"></div>
        <div class="field"><label>JSON Path</label><input type="text" id="ep-json-path" placeholder="status.healthy">
            <div class="hint">Dot-notation path to extract, e.g. <code>data.encoder.fps</code></div></div>
        <div class="field"><label>Expected Status</label><input type="number" id="ep-json-status" value="200"></div>
    </div>

    <!-- Ping fields -->
    <div id="f-ping" class="type-fields">
        <div class="field"><label>Host</label><input type="text" id="ep-ping-host" placeholder="origin.example.com"></div>
    </div>

    <div class="grid2">
        <div class="field"><label>Timeout (seconds)</label><input type="number" id="ep-timeout" value="10" min="1" max="30"></div>
        <div class="field"><label>Tags (comma-sep)</label><input type="text" id="ep-tags" placeholder="streaming, srt, ingest"></div>
    </div>

    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px">
        <button class="btn" onclick="closeModal()">Cancel</button>
        <button class="btn p" id="modal-save" onclick="saveEndpoint()">Add Endpoint</button>
    </div>
</div>
</div>
</div>
<div id="toast" class="toast"></div>

<script>
let editingId=null;
function toast(m,t='info'){const e=document.getElementById('toast');e.textContent=m;e.className='toast '+t+' show';setTimeout(()=>e.classList.remove('show'),3000)}
function bg(t,c){return `<span class="badge ${c}">${t}</span>`}

function toggleType(){
    document.querySelectorAll('.type-fields').forEach(el=>el.classList.remove('active'));
    const t=document.getElementById('ep-type').value;
    const map={http:'f-http',tcp:'f-tcp',json_api:'f-json',ping:'f-ping'};
    document.getElementById(map[t]).classList.add('active');
}

function showAddModal(){
    editingId=null;
    document.getElementById('modal-title').textContent='Add Endpoint';
    document.getElementById('modal-save').textContent='Add Endpoint';
    ['ep-name','ep-url','ep-body','ep-host','ep-json-url','ep-json-path','ep-ping-host','ep-tags'].forEach(id=>{const e=document.getElementById(id);if(e)e.value=''});
    document.getElementById('ep-type').value='http';
    document.getElementById('ep-method').value='GET';
    document.getElementById('ep-status').value='200';
    document.getElementById('ep-json-status').value='200';
    document.getElementById('ep-port').value='';
    document.getElementById('ep-timeout').value='10';
    toggleType();
    document.getElementById('modal').classList.add('show');
}

function showEditModal(ep){
    editingId=ep.id;
    document.getElementById('modal-title').textContent='Edit Endpoint';
    document.getElementById('modal-save').textContent='Save Changes';
    document.getElementById('ep-name').value=ep.name||'';
    document.getElementById('ep-type').value=ep.type||'http';
    toggleType();
    document.getElementById('ep-url').value=ep.url||'';
    document.getElementById('ep-method').value=ep.method||'GET';
    document.getElementById('ep-status').value=ep.expected_status||200;
    document.getElementById('ep-body').value=ep.body_contains||'';
    document.getElementById('ep-host').value=ep.host||'';
    document.getElementById('ep-port').value=ep.port||'';
    document.getElementById('ep-json-url').value=ep.type==='json_api'?ep.url:'';
    document.getElementById('ep-json-path').value=ep.json_path||'';
    document.getElementById('ep-json-status').value=ep.expected_status||200;
    document.getElementById('ep-ping-host').value=ep.type==='ping'?ep.host:'';
    document.getElementById('ep-timeout').value=ep.timeout_seconds||10;
    document.getElementById('ep-tags').value=(ep.tags||[]).join(', ');
    document.getElementById('modal').classList.add('show');
}
function closeModal(){document.getElementById('modal').classList.remove('show')}

function gatherEndpoint(){
    const type=document.getElementById('ep-type').value;
    const base={
        name:document.getElementById('ep-name').value,
        type:type,
        enabled:true,
        timeout_seconds:parseInt(document.getElementById('ep-timeout').value)||10,
        tags:document.getElementById('ep-tags').value,
    };
    if(type==='http'){
        base.url=document.getElementById('ep-url').value;
        base.method=document.getElementById('ep-method').value;
        base.expected_status=parseInt(document.getElementById('ep-status').value)||200;
        base.body_contains=document.getElementById('ep-body').value;
    }else if(type==='tcp'){
        base.host=document.getElementById('ep-host').value;
        base.port=parseInt(document.getElementById('ep-port').value)||0;
    }else if(type==='json_api'){
        base.url=document.getElementById('ep-json-url').value;
        base.json_path=document.getElementById('ep-json-path').value;
        base.expected_status=parseInt(document.getElementById('ep-json-status').value)||200;
    }else if(type==='ping'){
        base.host=document.getElementById('ep-ping-host').value;
    }
    return base;
}

async function saveEndpoint(){
    const data=gatherEndpoint();
    if(!data.name){toast('Give it a name','error');return}
    if(editingId){
        await fetch('/api/endpoints/'+editingId,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
        toast('Endpoint updated','success');
    }else{
        await fetch('/api/endpoints',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
        toast('Endpoint added','success');
    }
    closeModal();loadEndpoints();
}

async function deleteEndpoint(id){
    if(!confirm('Delete this endpoint?'))return;
    await fetch('/api/endpoints/'+id,{method:'DELETE'});
    toast('Deleted','success');loadEndpoints();
}

async function toggleEndpoint(id,enabled){
    await fetch('/api/endpoints/'+id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:!enabled})});
    loadEndpoints();
}

async function checkOne(id){
    toast('Checking...','info');
    const r=await fetch('/api/endpoints/'+id+'/check',{method:'POST'});
    const j=await r.json();
    if(j.result)toast(j.result.status==='up'?'UP — '+j.result.response_time_ms+'ms':'Status: '+j.result.status,j.result.status==='up'?'success':'error');
    loadEndpoints();
}

async function checkAll(){
    const btn=document.getElementById('btn-check-all');btn.disabled=true;btn.textContent='Checking...';
    await fetch('/api/endpoints/check-all',{method:'POST'});
    btn.disabled=false;btn.textContent='Check All Now';
    toast('All checks complete','success');loadEndpoints();
}

async function addTemplate(idx){
    const tpls=(await(await fetch('/api/endpoints')).json()).templates;
    if(!tpls[idx])return;
    const t=tpls[idx];
    await fetch('/api/endpoints',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(t)});
    toast('Template added — edit the URL/host','success');loadEndpoints();
}

async function loadEndpoints(){
    const data=await(await fetch('/api/endpoints')).json();
    const eps=data.endpoints||[];
    const tpls=data.templates||[];

    // Summary
    const up=eps.filter(e=>e.last_result&&e.last_result.status==='up').length;
    const down=eps.filter(e=>e.last_result&&e.last_result.status==='down').length;
    const deg=eps.filter(e=>e.last_result&&e.last_result.status==='degraded').length;
    const unk=eps.filter(e=>!e.last_result).length;
    document.getElementById('summary-cards').innerHTML=`
        <div class="card"><div class="lb">Total</div><div class="vl blue">${eps.length}</div></div>
        <div class="card"><div class="lb">Up</div><div class="vl green">${up}</div></div>
        <div class="card"><div class="lb">Down</div><div class="vl ${down>0?'red':'green'}">${down}</div></div>
        <div class="card"><div class="lb">Degraded</div><div class="vl ${deg>0?'yellow':'green'}">${deg}</div></div>
        <div class="card"><div class="lb">Unchecked</div><div class="vl" style="color:#8b949e">${unk}</div></div>`;

    // Templates
    document.getElementById('templates').innerHTML=tpls.map((t,i)=>`
        <div class="tpl-card" onclick="addTemplate(${i})">
            <div style="font-weight:600;font-size:.85rem">${t.name}</div>
            <div style="font-size:.75rem;color:#8b949e">${t.type} ${t.host?t.host+':'+t.port:t.url||''}</div>
            <div style="margin-top:4px">${(t.tags||[]).map(tg=>'<span class="badge off" style="font-size:.65rem;margin-right:2px">'+tg+'</span>').join('')}</div>
        </div>`).join('');

    // Endpoint list
    if(!eps.length){
        document.getElementById('ep-list').innerHTML='<div style="text-align:center;padding:40px;color:#8b949e">No endpoints configured. Add one above or use a template.</div>';
        return;
    }

    document.getElementById('ep-list').innerHTML=eps.map(ep=>{
        const r=ep.last_result;
        const st=r?r.status:'unknown';
        const typeLabel={http:'HTTP',tcp:'TCP',json_api:'JSON API',ping:'PING'}[ep.type]||ep.type;
        const target=ep.url||((ep.host||'')+(ep.port?':'+ep.port:''));

        return `<div class="ep-card ${st==='down'?'down':st==='degraded'?'degraded':''}">
            <div>
                <div class="ep-status">
                    <span class="ep-dot ${st}"></span>
                    <b style="font-size:.9rem">${ep.name}</b>
                    ${bg(typeLabel,'info')}
                    ${st==='up'?bg('UP','ok'):st==='down'?bg('DOWN','error'):st==='degraded'?bg('DEGRADED','warn'):bg('UNCHECKED','off')}
                    ${r&&r.response_time_ms?`<span style="font-size:.78rem;color:#8b949e">${r.response_time_ms}ms</span>`:''}
                </div>
                <div style="font-size:.78rem;color:#484f58;margin-top:4px;font-family:monospace">${target}</div>
                ${r&&r.error?`<div style="font-size:.75rem;color:#f85149;margin-top:2px">${r.error}</div>`:''}
                <div style="margin-top:4px">${(ep.tags||[]).map(t=>'<span class="badge off" style="font-size:.65rem;margin-right:2px">'+t+'</span>').join('')}
                ${r?`<span style="font-size:.7rem;color:#484f58;margin-left:8px">${new Date(r.checked_at).toLocaleTimeString()}</span>`:''}</div>
            </div>
            <div style="display:flex;gap:5px;align-items:center">
                <button class="btn sm" onclick="checkOne('${ep.id}')" title="Check now"></button>
                <label class="switch"><input type="checkbox" ${ep.enabled?'checked':''} onchange="toggleEndpoint('${ep.id}',${ep.enabled})"><span class="slider"></span></label>
                <button class="btn sm" onclick='showEditModal(${JSON.stringify(ep)})'>Edit</button>
                <button class="btn sm d" onclick="deleteEndpoint('${ep.id}')">×</button>
            </div>
        </div>`;
    }).join('');
}

loadEndpoints();
</script></body></html>""")


# ═════════════════════════════════════════════════════════════════════════════
# 2. ALERTS PAGE
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/alerts")
def page_alerts():
    return render_template_string("""<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Alerts — AWS Video Dashboard</title>""" + SHARED_STYLES + """
<style>
.rule-card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px;margin-bottom:12px;display:grid;grid-template-columns:1fr auto;gap:12px;align-items:start}
.rule-card.disabled{opacity:.5}
.rule-meta{display:flex;gap:8px;flex-wrap:wrap;margin-top:6px}
.tpl-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:10px;margin-bottom:20px}
.tpl-card{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:14px;cursor:pointer;transition:.15s}
.tpl-card:hover{border-color:#58a6ff;background:#161b22}
.tpl-card .tname{font-weight:600;font-size:.9rem;margin-bottom:4px}
.tpl-card .tdesc{font-size:.78rem;color:#8b949e}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;display:none;align-items:center;justify-content:center}
.modal-bg.show{display:flex}
.modal{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:24px;width:520px;max-width:95vw;max-height:90vh;overflow-y:auto}
.modal h3{margin-bottom:16px;color:#c9d1d9}
</style>
</head><body>
""" + nav("alerts") + """
<div class="container">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
    <h1 style="font-size:1.2rem;color:#c9d1d9">Alert Rules</h1>
    <button class="btn p" onclick="showAddModal()">+ New Rule</button>
</div>

<!-- Quick Templates -->
<div class="panel">
    <h3>Quick Start Templates</h3>
    <p style="font-size:.8rem;color:#8b949e;margin-bottom:12px">Click to add a pre-configured alert rule instantly</p>
    <div id="templates" class="tpl-grid"></div>
</div>

<!-- Active Rules -->
<div id="rules-list"></div>

<!-- Add/Edit Modal -->
<div id="modal" class="modal-bg" onclick="if(event.target===this)closeModal()">
<div class="modal">
    <h3 id="modal-title">New Alert Rule</h3>
    <div class="field"><label>Rule Name</label><input type="text" id="r-name" placeholder="e.g. High CPU on encoder"></div>
    <div class="grid2">
        <div class="field"><label>Service</label>
            <select id="r-service" onchange="updateMetrics()">
                <option value="ec2">EC2</option><option value="medialive">MediaLive</option>
                <option value="mediaconnect">MediaConnect</option><option value="mediapackage">MediaPackage</option>
                <option value="cloudfront">CloudFront</option><option value="ivs">IVS</option>
                <option value="ecs">ECS</option>
                <option value="easy_monitor">Easy Monitor (endpoints)</option>
            </select>
        </div>
        <div class="field"><label>Metric</label><select id="r-metric"></select></div>
    </div>
    <div class="grid3">
        <div class="field"><label>Operator</label>
            <select id="r-op"><option value=">">&gt;</option><option value="<">&lt;</option>
            <option value=">=">&gt;=</option><option value="<=">&lt;=</option>
            <option value="==">==</option><option value="!=">!=</option>
            <option value="contains">contains</option><option value="not_contains">not contains</option></select>
        </div>
        <div class="field"><label>Threshold</label><input type="text" id="r-threshold" placeholder="80"></div>
        <div class="field"><label>Severity</label>
            <select id="r-severity"><option value="info">Info</option><option value="warning" selected>Warning</option><option value="critical">Critical</option></select>
        </div>
    </div>
    <div class="grid2">
        <div class="field"><label>Resource Filter</label><input type="text" id="r-filter" placeholder="* (all)" value="*">
            <div class="hint">Instance ID, channel name, or * for all</div></div>
        <div class="field"><label>Cooldown (minutes)</label><input type="number" id="r-cooldown" value="15" min="1"></div>
    </div>
    <div class="field"><label>Notify Via</label>
        <div style="display:flex;gap:16px;margin-top:6px">
            <label style="font-size:.85rem;display:flex;align-items:center;gap:4px"><input type="checkbox" id="r-ch-email" checked> Email</label>
            <label style="font-size:.85rem;display:flex;align-items:center;gap:4px"><input type="checkbox" id="r-ch-telegram" checked> Telegram</label>
            <label style="font-size:.85rem;display:flex;align-items:center;gap:4px"><input type="checkbox" id="r-ch-whatsapp" checked> WhatsApp</label>
        </div>
    </div>
    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px">
        <button class="btn" onclick="closeModal()">Cancel</button>
        <button class="btn p" id="modal-save" onclick="saveRule()">Add Rule</button>
    </div>
</div>
</div>
</div>
<div id="toast" class="toast"></div>

<script>
let allMetrics={},editingId=null;
function toast(m,t='info'){const e=document.getElementById('toast');e.textContent=m;e.className='toast '+t+' show';setTimeout(()=>e.classList.remove('show'),3000)}

function updateMetrics(){
    const svc=document.getElementById('r-service').value;
    const sel=document.getElementById('r-metric');
    sel.innerHTML='';
    (allMetrics[svc]||[]).forEach(m=>{sel.innerHTML+=`<option value="${m.id}">${m.name}</option>`});
}

function showAddModal(){
    editingId=null;
    document.getElementById('modal-title').textContent='New Alert Rule';
    document.getElementById('modal-save').textContent='Add Rule';
    document.getElementById('r-name').value='';
    document.getElementById('r-service').value='ec2';
    document.getElementById('r-op').value='>';
    document.getElementById('r-threshold').value='';
    document.getElementById('r-severity').value='warning';
    document.getElementById('r-filter').value='*';
    document.getElementById('r-cooldown').value='15';
    document.getElementById('r-ch-email').checked=true;
    document.getElementById('r-ch-telegram').checked=true;
    document.getElementById('r-ch-whatsapp').checked=true;
    updateMetrics();
    document.getElementById('modal').classList.add('show');
}

function showEditModal(rule){
    editingId=rule.id;
    document.getElementById('modal-title').textContent='Edit Rule';
    document.getElementById('modal-save').textContent='Save Changes';
    document.getElementById('r-name').value=rule.name;
    document.getElementById('r-service').value=rule.service;
    updateMetrics();
    document.getElementById('r-metric').value=rule.metric;
    document.getElementById('r-op').value=rule.operator;
    document.getElementById('r-threshold').value=rule.threshold;
    document.getElementById('r-severity').value=rule.severity;
    document.getElementById('r-filter').value=rule.resource_filter||'*';
    document.getElementById('r-cooldown').value=rule.cooldown_minutes;
    const ch=rule.channels||[];
    document.getElementById('r-ch-email').checked=ch.includes('email');
    document.getElementById('r-ch-telegram').checked=ch.includes('telegram');
    document.getElementById('r-ch-whatsapp').checked=ch.includes('whatsapp');
    document.getElementById('modal').classList.add('show');
}

function closeModal(){document.getElementById('modal').classList.remove('show')}

function gatherRule(){
    const channels=[];
    if(document.getElementById('r-ch-email').checked)channels.push('email');
    if(document.getElementById('r-ch-telegram').checked)channels.push('telegram');
    if(document.getElementById('r-ch-whatsapp').checked)channels.push('whatsapp');
    let thresh=document.getElementById('r-threshold').value;
    if(!isNaN(thresh)&&thresh!=='')thresh=parseFloat(thresh);
    return{
        name:document.getElementById('r-name').value,
        service:document.getElementById('r-service').value,
        metric:document.getElementById('r-metric').value,
        operator:document.getElementById('r-op').value,
        threshold:thresh,
        severity:document.getElementById('r-severity').value,
        resource_filter:document.getElementById('r-filter').value,
        cooldown_minutes:parseInt(document.getElementById('r-cooldown').value)||15,
        channels:channels,
        enabled:true,
    }
}

async function saveRule(){
    const data=gatherRule();
    if(!data.name){toast('Give the rule a name','error');return}
    if(editingId){
        await fetch('/api/rules/'+editingId,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
        toast('Rule updated','success');
    }else{
        await fetch('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
        toast('Rule added','success');
    }
    closeModal();loadRules();
}

async function deleteRule(id){
    if(!confirm('Delete this rule?'))return;
    await fetch('/api/rules/'+id,{method:'DELETE'});
    toast('Rule deleted','success');loadRules();
}

async function toggleRule(id,enabled){
    await fetch('/api/rules/'+id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:!enabled})});
    loadRules();
}

async function addTemplate(idx){
    await fetch('/api/rules/template',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({index:idx})});
    toast('Template added','success');loadRules();
}

function sevBadge(s){return s==='critical'?'<span class="badge error">CRITICAL</span>':s==='warning'?'<span class="badge warn">WARNING</span>':'<span class="badge info">INFO</span>'}

async function loadRules(){
    const res=await fetch('/api/rules');
    const data=await res.json();
    allMetrics=data.metrics;

    // Templates
    document.getElementById('templates').innerHTML=data.templates.map((t,i)=>`
        <div class="tpl-card" onclick="addTemplate(${i})">
            <div class="tname">${t.name}</div>
            <div class="tdesc">${t.service} → ${t.metric} ${t.operator} ${t.threshold} (${t.severity})</div>
        </div>`).join('');

    // Rules
    const rules=data.rules;
    if(!rules.length){
        document.getElementById('rules-list').innerHTML='<div style="text-align:center;padding:40px;color:#8b949e">No alert rules configured. Add one above or click a template.</div>';
        return;
    }
    document.getElementById('rules-list').innerHTML=rules.map(r=>`
        <div class="rule-card ${r.enabled?'':'disabled'}">
            <div>
                <div style="font-weight:600;font-size:.9rem">${r.name}</div>
                <div class="rule-meta">
                    ${sevBadge(r.severity)}
                    <span class="badge info">${r.service}</span>
                    <span style="font-size:.78rem;color:#8b949e">${r.metric} ${r.operator} ${r.threshold}</span>
                    <span style="font-size:.78rem;color:#484f58">cooldown: ${r.cooldown_minutes}m</span>
                    ${r.trigger_count?`<span style="font-size:.78rem;color:#f0883e">triggered ${r.trigger_count}x</span>`:''}
                </div>
                <div style="font-size:.75rem;color:#484f58;margin-top:4px">→ ${(r.channels||[]).join(', ')} ${r.resource_filter&&r.resource_filter!=='*'?'| filter: '+r.resource_filter:''}</div>
            </div>
            <div style="display:flex;gap:6px;align-items:center">
                <label class="switch"><input type="checkbox" ${r.enabled?'checked':''} onchange="toggleRule('${r.id}',${r.enabled})"><span class="slider"></span></label>
                <button class="btn sm" onclick='showEditModal(${JSON.stringify(r)})'>Edit</button>
                <button class="btn sm d" onclick="deleteRule('${r.id}')">×</button>
            </div>
        </div>`).join('');
}

loadRules();
</script></body></html>""")


# ═════════════════════════════════════════════════════════════════════════════
# 3. AI ASSISTANT PAGE
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/ai")
def page_ai():
    return render_template_string("""<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Assistant — AWS Video Dashboard</title>""" + SHARED_STYLES + """
<style>
.chat-wrap{display:flex;flex-direction:column;height:calc(100vh - 140px);max-height:800px}
.chat-messages{flex:1;overflow-y:auto;padding:16px;background:#0d1117;border:1px solid #21262d;border-radius:8px 8px 0 0}
.msg{margin-bottom:14px;max-width:85%}
.msg.user{margin-left:auto;text-align:right}
.msg.user .bubble{background:#1f6feb;color:#fff;border-radius:12px 12px 2px 12px;padding:10px 14px;display:inline-block;text-align:left}
.msg.ai .bubble{background:#161b22;border:1px solid #21262d;border-radius:12px 12px 12px 2px;padding:10px 14px;display:inline-block}
.msg .meta{font-size:.7rem;color:#484f58;margin-top:3px}
.msg.ai .bubble pre{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:10px;overflow-x:auto;margin:8px 0;font-size:.82rem}
.msg.ai .bubble code{background:#0d1117;padding:1px 4px;border-radius:3px;font-size:.82rem}
.msg.ai .bubble p{margin-bottom:8px}
.chat-input{display:flex;gap:8px;padding:12px;background:#161b22;border:1px solid #21262d;border-top:none;border-radius:0 0 8px 8px}
.chat-input input{flex:1;padding:10px 14px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#e1e4e8;font-size:.9rem}
.chat-input input:focus{outline:none;border-color:#58a6ff}
.suggestions{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
.suggestions button{background:#0d1117;border:1px solid #21262d;color:#8b949e;padding:6px 12px;border-radius:16px;cursor:pointer;font-size:.78rem;transition:.15s}
.suggestions button:hover{border-color:#58a6ff;color:#58a6ff}
</style>
</head><body>
""" + nav("ai") + """
<div class="container">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
    <h1 style="font-size:1.2rem;color:#c9d1d9">AI Infrastructure Assistant</h1>
    <div style="display:flex;gap:8px;align-items:center">
        <select id="ai-model" style="padding:5px 8px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#8b949e;font-size:.78rem"></select>
        <button class="btn sm" onclick="clearChat()">Clear Chat</button>
    </div>
</div>

<div class="suggestions" id="suggestions">
    <button onclick="ask(this.textContent)">Summarise my infrastructure</button>
    <button onclick="ask(this.textContent)">Any issues right now?</button>
    <button onclick="ask(this.textContent)">How can I reduce latency?</button>
    <button onclick="ask(this.textContent)">Review my alert rules</button>
    <button onclick="ask(this.textContent)">Cost optimisation suggestions</button>
    <button onclick="ask(this.textContent)">Best practice for SRT ingest</button>
    <button onclick="ask(this.textContent)">Compare WHIP vs RTMP for my setup</button>
    <button onclick="ask(this.textContent)">Why might my MediaLive channel drop frames?</button>
</div>

<div class="chat-wrap">
    <div class="chat-messages" id="messages">
        <div class="msg ai"><div class="bubble">I'm your infrastructure assistant. I can see your live AWS data and help with video engineering questions. What would you like to know?</div></div>
    </div>
    <div class="chat-input">
        <input type="text" id="input" placeholder="Ask about your infrastructure, video workflows, protocols..." onkeydown="if(event.key==='Enter')send()">
        <button class="btn p" onclick="send()" id="send-btn">Send</button>
    </div>
</div>
</div>
<div id="toast" class="toast"></div>

<script>
const convId='conv_'+Date.now();
function toast(m,t='info'){const e=document.getElementById('toast');e.textContent=m;e.className='toast '+t+' show';setTimeout(()=>e.classList.remove('show'),3000)}

// Simple markdown-ish rendering
function renderMd(text){
    return text
        .replace(/```([\s\S]*?)```/g,'<pre>$1</pre>')
        .replace(/`([^`]+)`/g,'<code>$1</code>')
        .replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>')
        .replace(/\*([^*]+)\*/g,'<em>$1</em>')
        .replace(/^### (.+)$/gm,'<h4 style="margin:8px 0 4px;color:#58a6ff">$1</h4>')
        .replace(/^## (.+)$/gm,'<h3 style="margin:10px 0 4px;color:#58a6ff">$1</h3>')
        .replace(/^- (.+)$/gm,'<div style="padding-left:12px">• $1</div>')
        .replace(/\\n\\n/g,'<br><br>')
        .replace(/\\n/g,'<br>');
}

function addMsg(role,content,meta=''){
    const el=document.getElementById('messages');
    const div=document.createElement('div');
    div.className='msg '+role;
    div.innerHTML=`<div class="bubble">${role==='ai'?renderMd(content):content}</div>${meta?'<div class="meta">'+meta+'</div>':''}`;
    el.appendChild(div);
    el.scrollTop=el.scrollHeight;
}

function ask(text){document.getElementById('input').value=text;send()}

async function send(){
    const input=document.getElementById('input');
    const msg=input.value.trim();if(!msg)return;
    input.value='';
    addMsg('user',msg);

    const btn=document.getElementById('send-btn');btn.disabled=true;btn.textContent='...';
    // Show typing indicator
    const typing=document.createElement('div');typing.className='msg ai';typing.id='typing';
    typing.innerHTML='<div class="bubble" style="color:#8b949e">Thinking...</div>';
    document.getElementById('messages').appendChild(typing);
    document.getElementById('messages').scrollTop=document.getElementById('messages').scrollHeight;

    try{
        const model=document.getElementById('ai-model').value;
        const res=await fetch('/api/ai/query',{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({message:msg,conversation_id:convId})});
        const data=await res.json();
        typing.remove();
        const meta=data.model?`${data.model} · ${data.tokens} tokens`:'';
        addMsg('ai',data.response,meta);
        if(data.error==='no_api_key')toast('Add your OpenRouter API key in Settings','error');
    }catch(e){
        typing.remove();
        addMsg('ai','Error connecting to AI. Check your OpenRouter API key in Settings.');
        toast('AI query failed','error');
    }
    btn.disabled=false;btn.textContent='Send';
}

async function clearChat(){
    await fetch('/api/ai/clear',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({conversation_id:convId})});
    document.getElementById('messages').innerHTML='<div class="msg ai"><div class="bubble">Chat cleared. How can I help?</div></div>';
}

async function loadModels(){
    const res=await fetch('/api/ai/models');
    const data=await res.json();
    const sel=document.getElementById('ai-model');
    data.models.forEach(m=>{sel.innerHTML+=`<option value="${m.id}">${m.name}</option>`});
}
loadModels();
</script></body></html>""")


# ═════════════════════════════════════════════════════════════════════════════
# 4. SETTINGS PAGE
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/settings")
def page_settings():
    return render_template_string("""<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Settings — AWS Video Dashboard</title>""" + SHARED_STYLES + """</head><body>
""" + nav("settings") + """
<div class="container">
<h1 style="font-size:1.2rem;color:#c9d1d9;margin-bottom:16px">Settings</h1>
<div class="grid2">

<!-- AWS -->
<div class="panel"><h3>AWS</h3>
    <div class="field"><label>Region</label><select id="aws-region">
        <option value="us-east-1">US East (Virginia)</option><option value="us-east-2">US East (Ohio)</option>
        <option value="us-west-1">US West (California)</option><option value="us-west-2">US West (Oregon)</option>
        <option value="eu-west-1">EU (Ireland)</option><option value="eu-west-2">EU (London)</option>
        <option value="eu-central-1">EU (Frankfurt)</option><option value="ap-southeast-1">AP (Singapore)</option>
        <option value="ap-northeast-1">AP (Tokyo)</option></select></div>
    <div class="field"><label>Access Key</label><input type="text" id="aws-key" placeholder="AKIA..."><div class="hint">Blank = use instance role / ~/.aws/credentials</div></div>
    <div class="field"><label>Secret Key</label><input type="password" id="aws-secret"></div>
</div>

<!-- Monitoring -->
<div class="panel"><h3>Monitoring</h3>
    <div class="grid2">
        <div class="field"><label>Check Interval (min)</label><input type="number" id="m-int" min="1" max="60" value="5"></div>
        <div class="field"><label>CPU Threshold (%)</label><input type="number" id="m-cpu" min="1" max="100" value="80"></div>
    </div>
    <div class="field"><label>Deploy Lookback (hrs)</label><input type="number" id="m-dep" min="1" max="168" value="24"></div>
    <div class="field"><label>EC2 Uptime Alert (hrs, 0=off)</label><input type="number" id="m-uptime" min="0" max="720" value="0"><small style="color:#8b949e;font-size:.72rem">Alert if EC2 running longer than this</small></div>
    <div style="margin-top:10px">
        <div style="font-size:.75rem;color:#8b949e;text-transform:uppercase;margin-bottom:8px">Infrastructure</div>
        <div class="toggle-row"><span style="font-size:.85rem">EC2</span><label class="switch"><input type="checkbox" id="m-ec2"><span class="slider"></span></label></div>
        <div class="toggle-row"><span style="font-size:.85rem">CodeDeploy</span><label class="switch"><input type="checkbox" id="m-cd"><span class="slider"></span></label></div>
        <div class="toggle-row"><span style="font-size:.85rem">ECS</span><label class="switch"><input type="checkbox" id="m-ecs"><span class="slider"></span></label></div>
        <div style="font-size:.75rem;color:#8b949e;text-transform:uppercase;margin:12px 0 8px">Video Engineering</div>
        <div class="toggle-row"><span style="font-size:.85rem">MediaLive</span><label class="switch"><input type="checkbox" id="m-ml"><span class="slider"></span></label></div>
        <div class="toggle-row"><span style="font-size:.85rem">MediaConnect</span><label class="switch"><input type="checkbox" id="m-mc"><span class="slider"></span></label></div>
        <div class="toggle-row"><span style="font-size:.85rem">MediaPackage</span><label class="switch"><input type="checkbox" id="m-mp"><span class="slider"></span></label></div>
        <div class="toggle-row"><span style="font-size:.85rem">CloudFront CDN</span><label class="switch"><input type="checkbox" id="m-cf"><span class="slider"></span></label></div>
        <div class="toggle-row"><span style="font-size:.85rem">IVS</span><label class="switch"><input type="checkbox" id="m-ivs"><span class="slider"></span></label></div>
    </div>
</div>

<!-- Email -->
<div class="panel"><h3>Email</h3>
    <div class="toggle-row" style="margin-bottom:10px"><span style="font-size:.85rem">Enable Email</span><label class="switch"><input type="checkbox" id="e-on"><span class="slider"></span></label></div>
    <div class="field"><label>Provider</label><select id="e-prov" onchange="toggleSmtp()"><option value="smtp">SMTP</option><option value="ses">AWS SES</option></select></div>
    <div id="smtp-f">
        <div class="grid2"><div class="field"><label>SMTP Host</label><input type="text" id="e-host" placeholder="smtp.gmail.com"></div>
        <div class="field"><label>Port</label><input type="number" id="e-port" value="587"></div></div>
        <div class="field"><label>Username</label><input type="text" id="e-user"></div>
        <div class="field"><label>Password</label><input type="password" id="e-pass"><div class="hint">Gmail: use App Password</div></div>
        <div class="toggle-row"><span style="font-size:.85rem">TLS</span><label class="switch"><input type="checkbox" id="e-tls" checked><span class="slider"></span></label></div>
    </div>
    <div id="ses-f" style="display:none"><div class="field"><label>SES Region</label><input type="text" id="e-ses" placeholder="eu-west-2"></div></div>
    <div class="field"><label>From</label><input type="email" id="e-from"></div>
    <div class="field"><label>To (comma-sep)</label><input type="text" id="e-to"></div>
</div>

<!-- WhatsApp -->
<div class="panel"><h3>WhatsApp</h3>
    <div class="toggle-row" style="margin-bottom:10px"><span style="font-size:.85rem">Enable WhatsApp</span><label class="switch"><input type="checkbox" id="w-on"><span class="slider"></span></label></div>
    <div class="field"><label>Twilio SID</label><input type="text" id="w-sid"></div>
    <div class="field"><label>Auth Token</label><input type="password" id="w-tok"></div>
    <div class="field"><label>From</label><input type="text" id="w-from" placeholder="whatsapp:+14155238886"></div>
    <div class="field"><label>To</label><input type="text" id="w-to" placeholder="whatsapp:+44..."></div>
</div>

<!-- Telegram -->
<div class="panel"><h3>Telegram</h3>
    <div class="toggle-row" style="margin-bottom:10px"><span style="font-size:.85rem">Enable Telegram</span><label class="switch"><input type="checkbox" id="t-on"><span class="slider"></span></label></div>
    <div class="field"><label>Bot Token</label><input type="password" id="t-tok"><div class="hint">From @BotFather → /newbot</div></div>
    <div class="field"><label>Chat ID</label><input type="text" id="t-cid"><div class="hint">DM the bot, then check /getUpdates</div></div>
    <div class="field"><label>Parse Mode</label><select id="t-pm"><option value="HTML">HTML</option><option value="Markdown">Markdown</option></select></div>
</div>

<!-- Slack -->
<div class="panel"><h3>Slack</h3>
    <div class="toggle-row" style="margin-bottom:10px"><span style="font-size:.85rem">Enable Slack</span><label class="switch"><input type="checkbox" id="s-on"><span class="slider"></span></label></div>
    <div class="field"><label>Webhook URL</label><input type="password" id="s-url" placeholder="https://hooks.slack.com/services/..."><div class="hint">Slack App → Incoming Webhooks → Add to channel → Copy URL</div></div>
</div>

<!-- AI Assistant -->
<div class="panel"><h3>AI Assistant (OpenRouter)</h3>
    <div class="field"><label>API Key</label><input type="password" id="ai-key" placeholder="sk-or-...">
    <div class="hint">Get a key at <a href="https://openrouter.ai/keys" target="_blank">openrouter.ai/keys</a> — pay per token, no subscription</div></div>
    <div class="field"><label>Model</label><select id="ai-model"></select></div>
    <div class="grid2">
        <div class="field"><label>Max Tokens</label><input type="number" id="ai-maxt" value="2048"></div>
        <div class="field"><label>Temperature</label><input type="number" id="ai-temp" value="0.3" step="0.1" min="0" max="1"></div>
    </div>
</div>

<!-- Notification Triggers -->
<div class="panel"><h3>Triggers</h3>
    <div class="toggle-row"><div><b style="font-size:.85rem">Master Switch</b><div style="font-size:.72rem;color:#8b949e">All notifications</div></div><label class="switch"><input type="checkbox" id="n-on"><span class="slider"></span></label></div>
    <div class="toggle-row"><span style="font-size:.85rem">EC2 Issues</span><label class="switch"><input type="checkbox" id="n-ec2"><span class="slider"></span></label></div>
    <div class="toggle-row"><span style="font-size:.85rem">Deploy Failures</span><label class="switch"><input type="checkbox" id="n-dep"><span class="slider"></span></label></div>
    <div class="toggle-row"><span style="font-size:.85rem">ECS Issues</span><label class="switch"><input type="checkbox" id="n-ecs"><span class="slider"></span></label></div>
    <div class="toggle-row"><span style="font-size:.85rem">Media Issues</span><label class="switch"><input type="checkbox" id="n-med"><span class="slider"></span></label></div>
    <div class="toggle-row"><span style="font-size:.85rem">Daily Summary</span><label class="switch"><input type="checkbox" id="n-daily"><span class="slider"></span></label></div>
    <div class="field" style="margin-top:8px"><label>Summary Hour (0-23)</label><input type="number" id="n-hr" min="0" max="23" value="9" style="width:70px"></div>
</div>

</div>

<!-- Action Bar -->
<div style="display:flex;justify-content:space-between;align-items:center;margin-top:20px;padding-top:14px;border-top:1px solid #21262d">
    <div style="display:flex;gap:8px">
        <button class="btn" onclick="testN('email')" id="bt-e">Test Email</button>
        <button class="btn" onclick="testN('whatsapp')" id="bt-w">Test WhatsApp</button>
        <button class="btn" onclick="testN('telegram')" id="bt-t">Test Telegram</button>
        <button class="btn" onclick="testN('slack')" id="bt-s2">Test Slack</button>
    </div>
    <button class="btn p" onclick="save()" id="bt-s" style="font-size:.95rem;padding:9px 24px">Save Settings</button>
</div>
</div>
<div id="toast" class="toast"></div>

<script>
function toast(m,t='info'){const e=document.getElementById('toast');e.textContent=m;e.className='toast '+t+' show';setTimeout(()=>e.classList.remove('show'),3000)}
function toggleSmtp(){document.getElementById('smtp-f').style.display=document.getElementById('e-prov').value==='smtp'?'block':'none';document.getElementById('ses-f').style.display=document.getElementById('e-prov').value==='ses'?'block':'none'}

async function loadCfg(){
    const c=await(await fetch('/api/config')).json();
    // AWS
    document.getElementById('aws-region').value=c.aws.region;
    document.getElementById('aws-key').value=c.aws.access_key_id;
    document.getElementById('aws-secret').value=c.aws.secret_access_key;
    // Monitoring
    document.getElementById('m-int').value=c.monitoring.check_interval_minutes;
    document.getElementById('m-cpu').value=c.monitoring.cpu_threshold;
    document.getElementById('m-dep').value=c.monitoring.deployment_lookback_hours;
    document.getElementById('m-uptime').value=c.monitoring.uptime_alert_hours||0;
    document.getElementById('m-ec2').checked=c.monitoring.monitor_ec2;
    document.getElementById('m-cd').checked=c.monitoring.monitor_codedeploy;
    document.getElementById('m-ecs').checked=c.monitoring.monitor_ecs;
    document.getElementById('m-ml').checked=c.monitoring.monitor_medialive;
    document.getElementById('m-mc').checked=c.monitoring.monitor_mediaconnect;
    document.getElementById('m-mp').checked=c.monitoring.monitor_mediapackage;
    document.getElementById('m-cf').checked=c.monitoring.monitor_cloudfront;
    document.getElementById('m-ivs').checked=c.monitoring.monitor_ivs;
    // Email
    const em=c.notifications.channels.email;
    document.getElementById('e-on').checked=em.enabled;
    document.getElementById('e-prov').value=em.provider;toggleSmtp();
    document.getElementById('e-host').value=em.smtp_host;
    document.getElementById('e-port').value=em.smtp_port;
    document.getElementById('e-user').value=em.smtp_username;
    document.getElementById('e-pass').value=em.smtp_password;
    document.getElementById('e-tls').checked=em.smtp_use_tls;
    document.getElementById('e-ses').value=em.ses_region;
    document.getElementById('e-from').value=em.from_address;
    document.getElementById('e-to').value=(em.to_addresses||[]).join(', ');
    // WhatsApp
    const wh=c.notifications.channels.whatsapp;
    document.getElementById('w-on').checked=wh.enabled;
    document.getElementById('w-sid').value=wh.twilio_account_sid;
    document.getElementById('w-tok').value=wh.twilio_auth_token;
    document.getElementById('w-from').value=wh.from_number;
    document.getElementById('w-to').value=wh.to_number;
    // Telegram
    const tg=c.notifications.channels.telegram||{};
    document.getElementById('t-on').checked=tg.enabled||false;
    document.getElementById('t-tok').value=tg.bot_token||'';
    document.getElementById('t-cid').value=tg.chat_id||'';
    document.getElementById('t-pm').value=tg.parse_mode||'HTML';
    // Slack
    const sl=c.notifications.channels.slack||{};
    document.getElementById('s-on').checked=sl.enabled||false;
    document.getElementById('s-url').value=sl.webhook_url||'';
    // AI
    const ai=c.ai||{};
    document.getElementById('ai-key').value=ai.openrouter_api_key||'';
    // Load models dynamically then set saved value
    fetch('/api/ai/models').then(r=>r.json()).then(d=>{
        const sel=document.getElementById('ai-model');
        sel.innerHTML='';
        d.models.forEach(m=>{sel.innerHTML+=`<option value="${m.id}">${m.name} (${m.context})</option>`});
        sel.value=ai.model||'anthropic/claude-sonnet-4.6';
    });
    document.getElementById('ai-maxt').value=ai.max_tokens||2048;
    document.getElementById('ai-temp').value=ai.temperature||0.3;
    // Triggers
    document.getElementById('n-on').checked=c.notifications.enabled;
    document.getElementById('n-ec2').checked=c.notifications.on_ec2_issues;
    document.getElementById('n-dep').checked=c.notifications.on_deploy_failures;
    document.getElementById('n-ecs').checked=c.notifications.on_ecs_issues;
    document.getElementById('n-med').checked=c.notifications.on_media_issues;
    document.getElementById('n-daily').checked=c.notifications.send_daily_summary;
    document.getElementById('n-hr').value=c.notifications.daily_summary_hour;
}

function gather(){return{
    aws:{region:document.getElementById('aws-region').value,access_key_id:document.getElementById('aws-key').value,secret_access_key:document.getElementById('aws-secret').value},
    monitoring:{
        check_interval_minutes:+document.getElementById('m-int').value,cpu_threshold:+document.getElementById('m-cpu').value,
        deployment_lookback_hours:+document.getElementById('m-dep').value,
        uptime_alert_hours:+document.getElementById('m-uptime').value,
        monitor_ec2:document.getElementById('m-ec2').checked,monitor_codedeploy:document.getElementById('m-cd').checked,
        monitor_ecs:document.getElementById('m-ecs').checked,monitor_medialive:document.getElementById('m-ml').checked,
        monitor_mediaconnect:document.getElementById('m-mc').checked,monitor_mediapackage:document.getElementById('m-mp').checked,
        monitor_cloudfront:document.getElementById('m-cf').checked,monitor_ivs:document.getElementById('m-ivs').checked,
    },
    ai:{openrouter_api_key:document.getElementById('ai-key').value,model:document.getElementById('ai-model').value,
        max_tokens:+document.getElementById('ai-maxt').value,temperature:+document.getElementById('ai-temp').value},
    notifications:{
        enabled:document.getElementById('n-on').checked,on_ec2_issues:document.getElementById('n-ec2').checked,
        on_deploy_failures:document.getElementById('n-dep').checked,on_ecs_issues:document.getElementById('n-ecs').checked,
        on_media_issues:document.getElementById('n-med').checked,send_daily_summary:document.getElementById('n-daily').checked,
        daily_summary_hour:+document.getElementById('n-hr').value,
        channels:{
            email:{enabled:document.getElementById('e-on').checked,provider:document.getElementById('e-prov').value,
                smtp_host:document.getElementById('e-host').value,smtp_port:+document.getElementById('e-port').value,
                smtp_username:document.getElementById('e-user').value,smtp_password:document.getElementById('e-pass').value,
                smtp_use_tls:document.getElementById('e-tls').checked,ses_region:document.getElementById('e-ses').value,
                from_address:document.getElementById('e-from').value,to_addresses:document.getElementById('e-to').value},
            whatsapp:{enabled:document.getElementById('w-on').checked,twilio_account_sid:document.getElementById('w-sid').value,
                twilio_auth_token:document.getElementById('w-tok').value,from_number:document.getElementById('w-from').value,
                to_number:document.getElementById('w-to').value},
            telegram:{enabled:document.getElementById('t-on').checked,bot_token:document.getElementById('t-tok').value,
                chat_id:document.getElementById('t-cid').value,parse_mode:document.getElementById('t-pm').value},
            slack:{enabled:document.getElementById('s-on').checked,webhook_url:document.getElementById('s-url').value},
        }
    }
}}

async function save(){
    const b=document.getElementById('bt-s');b.disabled=true;b.textContent='Saving...';
    try{const r=await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(gather())});
        const j=await r.json();toast(j.status==='ok'?'Saved!':'Save failed',j.status==='ok'?'success':'error')
    }catch(e){toast('Error: '+e.message,'error')}
    b.disabled=false;b.textContent='Save Settings';
}

async function testN(ch){
    const btn=document.getElementById({email:'bt-e',whatsapp:'bt-w',telegram:'bt-t',slack:'bt-s2'}[ch]);
    btn.disabled=true;
    try{const r=await fetch('/api/test/'+ch,{method:'POST'});const j=await r.json();
        toast(j.sent?ch+' test sent!':ch+' failed — check settings',j.sent?'success':'error')
    }catch(e){toast('Error','error')}
    btn.disabled=false;
}

loadCfg();
</script></body></html>""")


# ─── Scheduler ───────────────────────────────────────────────────────────────

def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(scheduled_check, "interval", minutes=5)
    # Daily summary — runs every hour, checks if it's the configured hour
    config = load_config()
    summary_hour = config.get("notifications", {}).get("daily_summary_hour", 9)
    scheduler.add_job(send_daily_summary, "cron", hour=summary_hour, minute=0)
    scheduler.start()
    try:
        scheduled_check()
    except Exception as e:
        print(f"Initial check failed (will retry later): {e}")

# Start scheduler once (works with both gunicorn and direct run)
start_scheduler()

if __name__ == "__main__":
    print("AWS Video Dashboard at http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
