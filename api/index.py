#!/usr/bin/env python3
"""VEILORA 预约购买管理后台 — FastAPI + Vercel KV (Serverless)"""

import asyncio, hashlib, json, os, secrets, time, uuid
from urllib.parse import quote
from fastapi import FastAPI, Request, HTTPException, Depends, Header, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
import httpx

# config
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
UPLOAD_DIR = os.path.join('/tmp', 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

KV_URL = os.environ.get('KV_REST_API_URL', '')
KV_TOKEN = os.environ.get('KV_REST_API_TOKEN', '')

app = FastAPI()

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

# --- Vercel KV helpers ---

async def _kv_retry(fn, *args, max_retries=3, **kwargs):
    """Retry KV operations with exponential backoff for transient failures."""
    for attempt in range(max_retries):
        try:
            result = await fn(*args, **kwargs)
            if result is not None and result is not False:
                return result
            if attempt < max_retries - 1:
                await asyncio.sleep(0.2 * (2 ** attempt))
        except Exception:
            if attempt < max_retries - 1:
                await asyncio.sleep(0.2 * (2 ** attempt))
    return None

async def kv_get(key: str):
    if not KV_URL:
        return None
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            f"{KV_URL}/get/{quote(key, safe='')}",
            headers={"Authorization": f"Bearer {KV_TOKEN}"}
        )
    if r.status_code == 200:
        data = r.json()
        return json.loads(data['result']) if data.get('result') else None
    return None

async def kv_set(key: str, value, ttl: int = None):
    if not KV_URL:
        return False
    body = json.dumps(value)
    url = f"{KV_URL}/set/{quote(key, safe='')}"
    if ttl:
        url += f"?ex={ttl}"
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(url, content=body, headers={"Authorization": f"Bearer {KV_TOKEN}"})
    return r.status_code == 200

async def kv_del(key: str):
    if not KV_URL:
        return False
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(
            f"{KV_URL}/del/{quote(key, safe='')}",
            headers={"Authorization": f"Bearer {KV_TOKEN}"}
        )
    return r.status_code == 200

async def kv_keys(pattern: str):
    if not KV_URL:
        return []
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            f"{KV_URL}/keys/{quote(pattern, safe='')}",
            headers={"Authorization": f"Bearer {KV_TOKEN}"}
        )
    if r.status_code == 200:
        data = r.json()
        return data.get('result', [])
    return []

async def kv_incr(key: str):
    """Increment counter, return new value"""
    current = await kv_get(key) or 0
    new_val = current + 1
    await kv_set(key, new_val)
    return new_val

# --- Auth helpers ---
def hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

async def _admin(auth: str = Header(None)):
    if not auth:
        raise HTTPException(401, detail="未授权")
    token = auth.replace('Bearer ', '')
    session = await _kv_retry(kv_get, f"admin:token:{token}")
    if not session:
        raise HTTPException(401, detail="未授权或已过期")
    return session

async def _dealer(auth: str = Header(None)):
    if not auth:
        raise HTTPException(401, detail="未授权")
    token = auth.replace('Bearer ', '')
    session = await _kv_retry(kv_get, f"dealer:token:{token}")
    if not session:
        raise HTTPException(401, detail="未授权或已过期")
    return session

async def fallback_admin_check():
    """Ensure default admin exists if KV is empty"""
    if not KV_URL:
        print("[startup] WARNING: KV_REST_API_URL not set, skipping admin seed")
        return
    existing = await kv_get("admin:username:admin")
    if not existing:
        await kv_set("admin:username:admin", {"password_hash": hash_pw("admin123")})

@app.on_event("startup")
async def startup():
    await fallback_admin_check()

# --- Health ---
@app.get("/api/health")
async def health_check():
    kv_ok = False
    if KV_URL:
        test = await kv_get("admin:username:admin")
        kv_ok = test is not None
    return {"ok": True, "kv_available": kv_ok, "kv_url_set": bool(KV_URL)}

# --- Auth routes ---
@app.post("/api/admin/login")
async def admin_login(req: Request):
    if not KV_URL:
        raise HTTPException(503, "KV 数据库未配置，请在 Vercel Dashboard → Storage → KV 中创建数据库并关联到此项目")
    d = await req.json()
    u = d.get('username', '').strip()
    p = d.get('password', '').strip()
    if not u or not p:
        raise HTTPException(400, "用户名和密码不能为空")
    entry = await kv_get(f"admin:username:{u}")
    if entry is None:
        raise HTTPException(503, "KV 数据库连接失败，请检查 Vercel KV 配置")
    if entry.get('password_hash') != hash_pw(p):
        raise HTTPException(401, "用户名或密码错误")
    token = secrets.token_hex(24)
    await kv_set(f"admin:token:{token}", {"type": "admin", "username": u}, ttl=86400)
    return {"token": token, "username": u}

@app.post("/api/dealer/login")
async def dealer_login(req: Request):
    if not KV_URL:
        raise HTTPException(503, "KV 数据库未配置，请在 Vercel Dashboard → Storage → KV 中创建数据库并关联到此项目")
    d = await req.json()
    u = d.get('username', '').strip()
    p = d.get('password', '').strip()
    if not u or not p:
        raise HTTPException(400, "用户名和密码不能为空")
    dealer_id = await kv_get(f"dealer:username:{u}")
    if not dealer_id:
        raise HTTPException(401, "用户名或密码错误")
    dealer = await kv_get(f"dealer:{dealer_id}")
    if not dealer or dealer.get('password_hash') != hash_pw(p):
        raise HTTPException(401, "用户名或密码错误")
    token = secrets.token_hex(24)
    await kv_set(f"dealer:token:{token}", {"type": "dealer", "id": dealer_id}, ttl=86400)
    return {"token": token, "dealer_id": dealer_id, "company_name": dealer.get('company_name', '')}

# --- Admin: dealer management ---
@app.post("/api/admin/dealers")
async def create_dealer(req: Request, _=Depends(_admin)):
    d = await req.json()
    u = d.get('username', '').strip()
    p = d.get('password', '').strip()
    cn = d.get('company_name', '').strip()
    if not u or not p or not cn:
        raise HTTPException(400, "用户名、密码、公司名不能为空")
    existing = await kv_get(f"dealer:username:{u}")
    if existing:
        raise HTTPException(409, "用户名已存在")
    dealer_id = await kv_incr("counter:dealer")
    dealer = {
        "id": dealer_id,
        "username": u,
        "password_hash": hash_pw(p),
        "company_name": cn,
        "logo_url": "",
        "price_standard_cn": 12888,
        "price_pro_cn": 15888,
        "price_standard_intl": 2300,
        "price_pro_intl": 2868,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    await kv_set(f"dealer:{dealer_id}", dealer)
    await kv_set(f"dealer:username:{u}", dealer_id)
    # Add to dealer list
    dealer_list = await kv_get("dealer:list") or []
    dealer_list.append(dealer_id)
    await kv_set("dealer:list", dealer_list)
    return {"ok": True, "message": "经销商账户创建成功"}

@app.get("/api/admin/dealers")
async def list_dealers(_=Depends(_admin)):
    dealer_ids = await kv_get("dealer:list") or []
    result = []
    for did in reversed(dealer_ids):
        d = await kv_get(f"dealer:{did}")
        if d:
            result.append({
                "id": d["id"], "username": d["username"],
                "company_name": d["company_name"], "logo_url": d.get("logo_url", ""),
                "created_at": d.get("created_at", "")
            })
    return result

@app.delete("/api/admin/dealers/{dealer_id}")
async def delete_dealer(dealer_id: int, _=Depends(_admin)):
    dealer = await kv_get(f"dealer:{dealer_id}")
    if dealer:
        await kv_del(f"dealer:username:{dealer['username']}")
    await kv_del(f"dealer:{dealer_id}")
    dealer_list = await kv_get("dealer:list") or []
    if dealer_id in dealer_list:
        dealer_list.remove(dealer_id)
        await kv_set("dealer:list", dealer_list)
    return {"ok": True, "message": "已删除"}

# --- Admin: leads ---
@app.get("/api/admin/leads")
async def admin_leads(dealer_id: int = None, _=Depends(_admin)):
    lead_ids = await kv_get("lead:list") or []
    result = []
    for lid in reversed(lead_ids):
        lead = await kv_get(f"lead:{lid}")
        if lead:
            if dealer_id and lead.get("dealer_id") != dealer_id:
                continue
            d = await kv_get(f"dealer:{lead.get('dealer_id', 0)}")
            lead["company_name"] = d["company_name"] if d else ""
            result.append(lead)
    return result

# --- Admin: stats ---
@app.get("/api/admin/stats")
async def admin_stats(_=Depends(_admin)):
    dealer_list = await kv_get("dealer:list") or []
    lead_ids = await kv_get("lead:list") or []
    sc = 0
    pc = 0
    for lid in lead_ids:
        lead = await kv_get(f"lead:{lid}")
        if lead:
            if lead.get("edition") == "standard":
                sc += 1
            elif lead.get("edition") == "pro":
                pc += 1
    return {"dealer_count": len(dealer_list), "lead_count": len(lead_ids),
            "standard_count": sc, "pro_count": pc}

# --- Dealer: profile ---
@app.get("/api/dealer/profile")
async def dealer_profile(entry=Depends(_dealer)):
    dealer = await kv_get(f"dealer:{entry['id']}")
    if not dealer:
        raise HTTPException(404, "经销商不存在")
    # Remove sensitive fields
    return {k: v for k, v in dealer.items() if k != "password_hash"}

@app.put("/api/dealer/profile")
async def update_dealer_profile(req: Request, entry=Depends(_dealer)):
    d = await req.json()
    dealer = await kv_get(f"dealer:{entry['id']}")
    if not dealer:
        raise HTTPException(404, "经销商不存在")
    updatable = ['company_name', 'logo_url', 'price_standard_cn',
                  'price_pro_cn', 'price_standard_intl', 'price_pro_intl']
    for field in updatable:
        if field in d and d[field] is not None:
            dealer[field] = d[field]
    await kv_set(f"dealer:{entry['id']}", dealer)
    return {k: v for k, v in dealer.items() if k != "password_hash"}

@app.put("/api/dealer/password")
async def change_dealer_password(req: Request, entry=Depends(_dealer)):
    d = await req.json()
    old = d.get('old_password', '').strip()
    new = d.get('new_password', '').strip()
    if not old or not new:
        raise HTTPException(400, "新旧密码不能为空")
    if len(new) < 6:
        raise HTTPException(400, "新密码至少6位")
    dealer = await kv_get(f"dealer:{entry['id']}")
    if not dealer or dealer.get('password_hash') != hash_pw(old):
        raise HTTPException(401, "原密码错误")
    dealer['password_hash'] = hash_pw(new)
    await kv_set(f"dealer:{entry['id']}", dealer)
    return {"ok": True, "message": "密码修改成功"}

# --- Dealer: leads ---
@app.get("/api/dealer/leads")
async def dealer_leads(entry=Depends(_dealer)):
    dealer_leads_key = f"lead:dealer:{entry['id']}"
    lead_ids = await kv_get(dealer_leads_key) or []
    result = []
    for lid in reversed(lead_ids):
        lead = await kv_get(f"lead:{lid}")
        if lead:
            result.append(lead)
    return result

# --- Dealer: logo upload ---
@app.post("/api/dealer/logo")
async def upload_logo(file: UploadFile = File(...), entry=Depends(_dealer)):
    ext = os.path.splitext(file.filename or 'logo')[1] or '.png'
    fname = f"{uuid.uuid4().hex}{ext}"
    fpath = os.path.join(UPLOAD_DIR, fname)
    content = await file.read()
    with open(fpath, 'wb') as f:
        f.write(content)
    logo_url = f"/uploads/{fname}"
    dealer = await kv_get(f"dealer:{entry['id']}")
    if dealer:
        dealer['logo_url'] = logo_url
        await kv_set(f"dealer:{entry['id']}", dealer)
    return {"ok": True, "logo_url": logo_url}

@app.get("/uploads/{path:path}")
async def serve_upload(path: str):
    fp = os.path.join(UPLOAD_DIR, path)
    if not os.path.isfile(fp):
        raise HTTPException(404)
    return FileResponse(fp)

# --- Public: brand page ---
@app.get("/api/brand/{dealer_id}")
async def brand_config(dealer_id: int):
    dealer = await kv_get(f"dealer:{dealer_id}")
    if not dealer:
        raise HTTPException(404, "经销商不存在")
    return {
        "id": dealer["id"],
        "company_name": dealer["company_name"],
        "logo_url": dealer.get("logo_url", ""),
        "price_standard_cn": dealer.get("price_standard_cn", 12888),
        "price_pro_cn": dealer.get("price_pro_cn", 15888),
        "price_standard_intl": dealer.get("price_standard_intl", 2300),
        "price_pro_intl": dealer.get("price_pro_intl", 2868)
    }

# --- Public: submit lead ---
@app.post("/api/leads")
async def submit_lead(req: Request):
    d = await req.json()
    dealer_id = d.get('dealer_id')
    edition = d.get('edition', 'standard')
    name = d.get('name', '').strip()
    phone = d.get('phone', '').strip()
    email = d.get('email', '').strip()
    if not name or not phone:
        raise HTTPException(400, "姓名和手机号不能为空")
    lead_id = await kv_incr("counter:lead")
    lead = {
        "id": lead_id,
        "dealer_id": dealer_id,
        "edition": edition,
        "name": name,
        "phone": phone,
        "email": email,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    await kv_set(f"lead:{lead_id}", lead)
    # Global lead list
    lead_list = await kv_get("lead:list") or []
    lead_list.append(lead_id)
    await kv_set("lead:list", lead_list)
    # Dealer-specific lead list
    if dealer_id:
        dl_key = f"lead:dealer:{dealer_id}"
        dl_list = await kv_get(dl_key) or []
        dl_list.append(lead_id)
        await kv_set(dl_key, dl_list)
    return {"ok": True, "message": "预约成功"}

# --- AI Chat ---
AGNES_API_KEY = os.environ.get('AGNES_API_KEY', '')
VEILORA_KNOWLEDGE = """你是 VEILORA（隐御）安全手机的智能客服助手。以下是产品核心知识，请严格据此回答用户问题：

【产品定位】VEILORA 是专注数字终端隐私保护与安全防护的专业操作系统，面向军队、警察、政府要员、高价值商务人士、科学家等。依托自研具身安全内核，整合网络安全、隐私管控、加密通信、隔离存储、应急防护、数据防提取、安全云备份、智能防御八大核心能力。

【隐私空间】VEILORA 支持全系统多层级隔离加密存储，可创建独立的隐私空间。通过设置「双 PIN 码」实现空间切换——输入主 PIN 进入日常主空间，输入隐私 PIN 进入隐私空间。支持跨空间文件同步（主空间→隐私空间）。

【防追踪画像】具备主动网络攻击防护，智能流量异常管控，防止被外界网络画像追踪。

【应用隐私防护】权限管控与风险审计，一键超级隐私防护模式，防止 APP 窃取隐私。

【加密通信】支持密写转换工具、加密消息通讯、加密文件发送与浏览、加密语音通讯。

【私有云备份】支持 WebDAV 云空间配置，可设置自动/手动备份计划，支持本地数据恢复。

【应急还原】支持还原整个手机、还原隐私空间、远程锁定与远程抹除。紧急情况下输入特定 PIN 可触发还原流程。

【设备安全】设备硬件唯一强绑定，恢复密语离线保管云端不留存，关键操作强制身份验证。核心秘钥仅保存在本地硬件安全模块中，官方服务器不备份、不存储任何解密凭证。

【免责声明】因用户遗失密语/遗忘密码导致的数据无法解密，官方无法提供强制破解或数据恢复服务。严禁非官方授权的 Root/解锁/刷机等操作。

请用中文回答，语气专业友善。如果问题超出上述知识范围，请诚实告知用户该问题暂无法解答，并建议联系官方客服。"""

@app.post("/api/chat")
async def ai_chat(req: Request):
    if not AGNES_API_KEY:
        return {"answer": "智能问答服务暂未配置 AI API Key，请在 Vercel 环境变量中设置 AGNES_API_KEY。"}
    try:
        d = await req.json()
        question = d.get('question', '').strip()
        if not question:
            return {"answer": "请输入您的问题。"}
    except Exception:
        return {"answer": "请求格式有误。"}

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "https://apihub.agnes-ai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {AGNES_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "agnes-2.0-flash",
                    "messages": [
                        {"role": "system", "content": VEILORA_KNOWLEDGE},
                        {"role": "user", "content": question}
                    ],
                    "temperature": 0.7,
                    "max_tokens": 500
                }
            )
        if resp.status_code == 200:
            data = resp.json()
            answer = data["choices"][0]["message"]["content"]
            return {"answer": answer}
        else:
            return {"answer": f"AI 服务返回错误 (HTTP {resp.status_code})，请稍后重试。"}
    except Exception as e:
        return {"answer": f"AI 服务请求失败：{str(e)[:100]}"}

# --- Network Scan (cloud fallback) ---
@app.get("/api/network-scan")
async def network_scan():
    return {
        "success": False,
        "error": "局域网设备扫描功能需要在本地运行。请将项目 clone 到本地后启动 server.py，通过 localhost 访问即可使用此功能。"
    }

# --- Static pages ---
@app.get("/brand/{dealer_id}")
async def brand_page(dealer_id: int):
    dealer = await kv_get(f"dealer:{dealer_id}")
    if not dealer:
        return HTMLResponse('<h1 style="text-align:center;margin-top:100px;color:#666;">经销商不存在</h1>', 404)
    return FileResponse(os.path.join(PROJECT_ROOT, 'index.html'))

@app.get("/admin")
async def serve_admin_page():
    return FileResponse(os.path.join(PROJECT_ROOT, 'admin.html'))

@app.get("/dealer")
async def serve_dealer_page():
    return FileResponse(os.path.join(PROJECT_ROOT, 'dealer.html'))

@app.get("/")
async def serve_index():
    return FileResponse(os.path.join(PROJECT_ROOT, 'index.html'))
