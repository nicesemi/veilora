#!/usr/bin/env python3
"""VEILORA 预约购买管理后台 — FastAPI + SQLite (Vercel Serverless)"""

import hashlib, os, secrets, sqlite3, uuid
from fastapi import FastAPI, Request, HTTPException, Depends, Header, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse

# config
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
DB_PATH = os.path.join('/tmp', 'veilora.db')
UPLOAD_DIR = os.path.join('/tmp', 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = FastAPI()

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

# --- db ---
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS dealers (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
            company_name TEXT NOT NULL DEFAULT '', logo_url TEXT DEFAULT '',
            price_standard_cn INTEGER DEFAULT 12888, price_pro_cn INTEGER DEFAULT 15888,
            price_standard_intl INTEGER DEFAULT 2300, price_pro_intl INTEGER DEFAULT 2868,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS leads (
            id INTEGER PRIMARY KEY AUTOINCREMENT, dealer_id INTEGER, edition TEXT,
            name TEXT NOT NULL, phone TEXT NOT NULL, email TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (dealer_id) REFERENCES dealers(id));
    """)
    c = db.execute("SELECT COUNT(*) FROM admins")
    if c.fetchone()[0] == 0:
        pw = hashlib.sha256('admin123'.encode()).hexdigest()
        db.execute("INSERT INTO admins (username, password_hash) VALUES (?, ?)", ('admin', pw))
    db.commit(); db.close()

@app.on_event("startup")
def startup():
    init_db()

# --- auth ---
tokens = {}
def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()

def _admin(auth: str = Header(None)):
    if not auth: raise HTTPException(401, detail="未授权")
    tk = auth.replace('Bearer ', '')
    e = tokens.get(tk)
    if not e or e['type'] != 'admin': raise HTTPException(401, detail="未授权")
    return e

def _dealer(auth: str = Header(None)):
    if not auth: raise HTTPException(401, detail="未授权")
    tk = auth.replace('Bearer ', '')
    e = tokens.get(tk)
    if not e or e['type'] != 'dealer': raise HTTPException(401, detail="未授权")
    return e

# --- auth routes ---
@app.post("/api/admin/login")
async def admin_login(req: Request):
    d = await req.json()
    u = d.get('username','').strip(); p = d.get('password','').strip()
    if not u or not p: raise HTTPException(400, "用户名和密码不能为空")
    db = get_db()
    row = db.execute("SELECT * FROM admins WHERE username = ?", (u,)).fetchone(); db.close()
    if not row or row['password_hash'] != hash_pw(p): raise HTTPException(401, "用户名或密码错误")
    tk = secrets.token_hex(24)
    tokens[tk] = {'type': 'admin', 'id': row['id']}
    return {'token': tk, 'username': row['username']}

@app.post("/api/dealer/login")
async def dealer_login(req: Request):
    d = await req.json()
    u = d.get('username','').strip(); p = d.get('password','').strip()
    if not u or not p: raise HTTPException(400, "用户名和密码不能为空")
    db = get_db()
    row = db.execute("SELECT * FROM dealers WHERE username = ?", (u,)).fetchone(); db.close()
    if not row or row['password_hash'] != hash_pw(p): raise HTTPException(401, "用户名或密码错误")
    tk = secrets.token_hex(24)
    tokens[tk] = {'type': 'dealer', 'id': row['id']}
    return {'token': tk, 'dealer_id': row['id'], 'company_name': row['company_name']}

# --- admin: dealers ---
@app.post("/api/admin/dealers")
async def create_dealer(req: Request, _=Depends(_admin)):
    d = await req.json()
    u = d.get('username','').strip(); p = d.get('password','').strip()
    cn = d.get('company_name','').strip()
    if not u or not p or not cn: raise HTTPException(400, "用户名、密码、公司名不能为空")
    db = get_db()
    if db.execute("SELECT id FROM dealers WHERE username = ?", (u,)).fetchone():
        db.close(); raise HTTPException(409, "用户名已存在")
    db.execute("INSERT INTO dealers (username, password_hash, company_name) VALUES (?, ?, ?)", (u, hash_pw(p), cn))
    db.commit(); db.close()
    return {'ok': True, 'message': '经销商账户创建成功'}

@app.get("/api/admin/dealers")
async def list_dealers(_=Depends(_admin)):
    db = get_db()
    rows = db.execute("SELECT id, username, company_name, logo_url, created_at FROM dealers ORDER BY id DESC").fetchall()
    db.close()
    return [dict(r) for r in rows]

@app.delete("/api/admin/dealers/{dealer_id}")
async def delete_dealer(dealer_id: int, _=Depends(_admin)):
    db = get_db()
    db.execute("DELETE FROM dealers WHERE id = ?", (dealer_id,))
    db.commit(); db.close()
    return {'ok': True, 'message': '已删除'}

# --- admin: leads ---
@app.get("/api/admin/leads")
async def admin_leads(dealer_id: int = None, _=Depends(_admin)):
    db = get_db()
    if dealer_id:
        rows = db.execute("SELECT l.*, d.company_name FROM leads l LEFT JOIN dealers d ON l.dealer_id = d.id WHERE l.dealer_id = ? ORDER BY l.created_at DESC", (dealer_id,)).fetchall()
    else:
        rows = db.execute("SELECT l.*, d.company_name FROM leads l LEFT JOIN dealers d ON l.dealer_id = d.id ORDER BY l.created_at DESC").fetchall()
    db.close()
    return [dict(r) for r in rows]

# --- admin: stats ---
@app.get("/api/admin/stats")
async def admin_stats(_=Depends(_admin)):
    db = get_db()
    dc = db.execute("SELECT COUNT(*) FROM dealers").fetchone()[0]
    lc = db.execute("SELECT COUNT(*) FROM leads").fetchone()[0]
    sc = db.execute("SELECT COUNT(*) FROM leads WHERE edition='standard'").fetchone()[0]
    pc = db.execute("SELECT COUNT(*) FROM leads WHERE edition='pro'").fetchone()[0]
    db.close()
    return {'dealer_count': dc, 'lead_count': lc, 'standard_count': sc, 'pro_count': pc}

# --- dealer: profile ---
@app.get("/api/dealer/profile")
async def dealer_profile(entry=Depends(_dealer)):
    db = get_db()
    row = db.execute("SELECT * FROM dealers WHERE id = ?", (entry['id'],)).fetchone(); db.close()
    if not row: raise HTTPException(404, "经销商不存在")
    return dict(row)

@app.put("/api/dealer/profile")
async def update_dealer_profile(req: Request, entry=Depends(_dealer)):
    d = await req.json()
    upd = []; vals = []
    for k, col in [('company_name','company_name'), ('logo_url','logo_url'),
                    ('price_standard_cn','price_standard_cn'), ('price_pro_cn','price_pro_cn'),
                    ('price_standard_intl','price_standard_intl'), ('price_pro_intl','price_pro_intl')]:
        if k in d and d[k] is not None:
            upd.append(f"{col} = ?"); vals.append(d[k])
    if upd:
        db = get_db()
        vals.append(entry['id'])
        db.execute(f"UPDATE dealers SET {', '.join(upd)} WHERE id = ?", vals)
        db.commit()
        row = db.execute("SELECT * FROM dealers WHERE id = ?", (entry['id'],)).fetchone()
        db.close()
        return dict(row)
    else:
        db = get_db()
        row = db.execute("SELECT * FROM dealers WHERE id = ?", (entry['id'],)).fetchone()
        db.close()
        return dict(row)

# --- dealer: leads ---
@app.get("/api/dealer/leads")
async def dealer_leads(entry=Depends(_dealer)):
    db = get_db()
    rows = db.execute("SELECT * FROM leads WHERE dealer_id = ? ORDER BY created_at DESC", (entry['id'],)).fetchall()
    db.close()
    return [dict(r) for r in rows]

@app.get("/api/dealer/brand-page-url")
async def brand_page_url(entry=Depends(_dealer)):
    return {'url': f'/brand/{entry["id"]}'}

@app.put("/api/dealer/password")
async def change_dealer_password(req: Request, entry=Depends(_dealer)):
    d = await req.json()
    old = d.get('old_password','').strip(); new = d.get('new_password','').strip()
    if not old or not new: raise HTTPException(400, "新旧密码不能为空")
    if len(new) < 6: raise HTTPException(400, "新密码至少6位")
    db = get_db()
    row = db.execute("SELECT password_hash FROM dealers WHERE id = ?", (entry['id'],)).fetchone()
    if not row or row['password_hash'] != hash_pw(old):
        db.close(); raise HTTPException(401, "原密码错误")
    db.execute("UPDATE dealers SET password_hash = ? WHERE id = ?", (hash_pw(new), entry['id']))
    db.commit(); db.close()
    return {'ok': True, 'message': '密码修改成功'}

# --- dealer: logo upload ---
@app.post("/api/dealer/logo")
async def upload_logo(file: UploadFile = File(...), entry=Depends(_dealer)):
    ext = os.path.splitext(file.filename or 'logo')[1] or '.png'
    fname = f'{uuid.uuid4().hex}{ext}'
    fpath = os.path.join(UPLOAD_DIR, fname)
    content = await file.read()
    with open(fpath, 'wb') as f: f.write(content)
    logo_url = f'/uploads/{fname}'
    db = get_db()
    db.execute("UPDATE dealers SET logo_url = ? WHERE id = ?", (logo_url, entry['id']))
    db.commit(); db.close()
    return {'ok': True, 'logo_url': logo_url}

@app.get("/uploads/{path:path}")
async def serve_upload(path: str):
    fp = os.path.join(UPLOAD_DIR, path)
    if not os.path.isfile(fp): raise HTTPException(404)
    return FileResponse(fp)

# --- public ---
@app.get("/api/brand/{dealer_id}")
async def brand_config(dealer_id: int):
    db = get_db()
    row = db.execute("SELECT id, company_name, logo_url, price_standard_cn, price_pro_cn, price_standard_intl, price_pro_intl FROM dealers WHERE id = ?", (dealer_id,)).fetchone()
    db.close()
    if not row: raise HTTPException(404, "经销商不存在")
    return dict(row)

@app.post("/api/leads")
async def submit_lead(req: Request):
    d = await req.json()
    dealer_id = d.get('dealer_id')
    edition = d.get('edition','standard')
    name = d.get('name','').strip(); phone = d.get('phone','').strip()
    email = d.get('email','').strip()
    if not name or not phone: raise HTTPException(400, "姓名和手机号不能为空")
    db = get_db()
    db.execute("INSERT INTO leads (dealer_id, edition, name, phone, email) VALUES (?, ?, ?, ?, ?)",
               (dealer_id, edition, name, phone, email))
    db.commit(); db.close()
    return {'ok': True, 'message': '预约成功'}

# --- brand page & static pages ---
@app.get("/brand/{dealer_id}")
async def brand_page(dealer_id: int):
    db = get_db()
    row = db.execute("SELECT id FROM dealers WHERE id = ?", (dealer_id,)).fetchone()
    db.close()
    if not row: return HTMLResponse('<h1 style="text-align:center;margin-top:100px;color:#666;">经销商不存在</h1>', 404)
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
