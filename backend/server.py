#!/usr/bin/env python3
"""VEILORA 预约购买管理后台 — Flask + SQLite"""

import hashlib
import os
import secrets
import sqlite3
import uuid
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, g, send_from_directory

# ---------- config ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, 'database.db')

app = Flask(__name__, static_folder=BASE_DIR, static_url_path='')

# ---------- CORS ----------
@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS'
    return response

# ---------- db helpers ----------
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS dealers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            company_name TEXT NOT NULL DEFAULT '',
            logo_url TEXT DEFAULT '',
            price_standard_cn INTEGER DEFAULT 12888,
            price_pro_cn INTEGER DEFAULT 15888,
            price_standard_intl INTEGER DEFAULT 2300,
            price_pro_intl INTEGER DEFAULT 2868,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS leads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dealer_id INTEGER,
            edition TEXT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            email TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (dealer_id) REFERENCES dealers(id)
        );
    """)
    # seed default admin
    cursor = db.execute("SELECT COUNT(*) FROM admins")
    if cursor.fetchone()[0] == 0:
        pw = hashlib.sha256('admin123'.encode()).hexdigest()
        db.execute("INSERT INTO admins (username, password_hash) VALUES (?, ?)", ('admin', pw))
    db.commit()
    db.close()

# ---------- token store (in-memory) ----------
tokens = {}  # token -> {'type': 'admin'|'dealer', 'id': ...}

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        token = auth.replace('Bearer ', '')
        entry = tokens.get(token)
        if not entry or entry['type'] != 'admin':
            return jsonify({'error': '未授权'}), 401
        return f(*args, **kwargs)
    return decorated

def require_dealer(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        token = auth.replace('Bearer ', '')
        entry = tokens.get(token)
        if not entry or entry['type'] != 'dealer':
            return jsonify({'error': '未授权'}), 401
        g.dealer_id = entry['id']
        return f(*args, **kwargs)
    return decorated

# ---------- auth ----------
@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    if not username or not password:
        return jsonify({'error': '用户名和密码不能为空'}), 400

    db = get_db()
    row = db.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()
    if not row or row['password_hash'] != hash_pw(password):
        return jsonify({'error': '用户名或密码错误'}), 401

    token = secrets.token_hex(24)
    tokens[token] = {'type': 'admin', 'id': row['id']}
    return jsonify({'token': token, 'username': row['username']})

@app.route('/api/dealer/login', methods=['POST'])
def dealer_login():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    if not username or not password:
        return jsonify({'error': '用户名和密码不能为空'}), 400

    db = get_db()
    row = db.execute("SELECT * FROM dealers WHERE username = ?", (username,)).fetchone()
    if not row or row['password_hash'] != hash_pw(password):
        return jsonify({'error': '用户名或密码错误'}), 401

    token = secrets.token_hex(24)
    tokens[token] = {'type': 'dealer', 'id': row['id']}
    return jsonify({'token': token, 'dealer_id': row['id'], 'company_name': row['company_name']})

# ---------- admin: dealers ----------
@app.route('/api/admin/dealers', methods=['POST'])
@require_admin
def create_dealer():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    company_name = data.get('company_name', '').strip()
    if not username or not password or not company_name:
        return jsonify({'error': '用户名、密码、公司名不能为空'}), 400

    db = get_db()
    existing = db.execute("SELECT id FROM dealers WHERE username = ?", (username,)).fetchone()
    if existing:
        return jsonify({'error': '用户名已存在'}), 409

    pw_hash = hash_pw(password)
    db.execute(
        "INSERT INTO dealers (username, password_hash, company_name) VALUES (?, ?, ?)",
        (username, pw_hash, company_name)
    )
    db.commit()
    return jsonify({'ok': True, 'message': '经销商账户创建成功'}), 201

@app.route('/api/admin/dealers', methods=['GET'])
@require_admin
def list_dealers():
    db = get_db()
    rows = db.execute("SELECT id, username, company_name, logo_url, created_at FROM dealers ORDER BY id DESC").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/admin/dealers/<int:dealer_id>', methods=['DELETE'])
@require_admin
def delete_dealer(dealer_id):
    db = get_db()
    db.execute("DELETE FROM dealers WHERE id = ?", (dealer_id,))
    db.commit()
    return jsonify({'ok': True, 'message': '已删除'})

# ---------- admin: leads ----------
@app.route('/api/admin/leads', methods=['GET'])
@require_admin
def admin_leads():
    db = get_db()
    dealer_id = request.args.get('dealer_id', '')
    if dealer_id:
        rows = db.execute(
            "SELECT l.*, d.company_name FROM leads l LEFT JOIN dealers d ON l.dealer_id = d.id WHERE l.dealer_id = ? ORDER BY l.created_at DESC",
            (int(dealer_id),)
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT l.*, d.company_name FROM leads l LEFT JOIN dealers d ON l.dealer_id = d.id ORDER BY l.created_at DESC"
        ).fetchall()
    return jsonify([dict(r) for r in rows])

# ---------- admin: stats ----------
@app.route('/api/admin/stats', methods=['GET'])
@require_admin
def admin_stats():
    db = get_db()
    dealer_count = db.execute("SELECT COUNT(*) FROM dealers").fetchone()[0]
    lead_count = db.execute("SELECT COUNT(*) FROM leads").fetchone()[0]
    standard_count = db.execute("SELECT COUNT(*) FROM leads WHERE edition='standard'").fetchone()[0]
    pro_count = db.execute("SELECT COUNT(*) FROM leads WHERE edition='pro'").fetchone()[0]
    return jsonify({
        'dealer_count': dealer_count,
        'lead_count': lead_count,
        'standard_count': standard_count,
        'pro_count': pro_count
    })

# ---------- dealer: profile ----------
@app.route('/api/dealer/profile', methods=['GET'])
@require_dealer
def dealer_profile():
    db = get_db()
    row = db.execute("SELECT * FROM dealers WHERE id = ?", (g.dealer_id,)).fetchone()
    if not row:
        return jsonify({'error': '经销商不存在'}), 404
    return jsonify(dict(row))

@app.route('/api/dealer/profile', methods=['PUT'])
@require_dealer
def update_dealer_profile():
    data = request.get_json() or {}
    db = get_db()

    company_name = data.get('company_name')
    logo_url = data.get('logo_url')
    price_standard_cn = data.get('price_standard_cn')
    price_pro_cn = data.get('price_pro_cn')
    price_standard_intl = data.get('price_standard_intl')
    price_pro_intl = data.get('price_pro_intl')

    updates = []
    params = []
    if company_name is not None:
        updates.append("company_name = ?")
        params.append(company_name)
    if logo_url is not None:
        updates.append("logo_url = ?")
        params.append(logo_url)
    if price_standard_cn is not None:
        updates.append("price_standard_cn = ?")
        params.append(int(price_standard_cn))
    if price_pro_cn is not None:
        updates.append("price_pro_cn = ?")
        params.append(int(price_pro_cn))
    if price_standard_intl is not None:
        updates.append("price_standard_intl = ?")
        params.append(int(price_standard_intl))
    if price_pro_intl is not None:
        updates.append("price_pro_intl = ?")
        params.append(int(price_pro_intl))

    if updates:
        params.append(g.dealer_id)
        db.execute(f"UPDATE dealers SET {', '.join(updates)} WHERE id = ?", params)
        db.commit()

    row = db.execute("SELECT * FROM dealers WHERE id = ?", (g.dealer_id,)).fetchone()
    return jsonify(dict(row))

# ---------- dealer: leads ----------
@app.route('/api/dealer/leads', methods=['GET'])
@require_dealer
def dealer_leads():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM leads WHERE dealer_id = ? ORDER BY created_at DESC", (g.dealer_id,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/dealer/brand-page-url', methods=['GET'])
@require_dealer
def dealer_brand_page_url():
    return jsonify({'url': f'/brand/{g.dealer_id}'})

@app.route('/api/dealer/password', methods=['PUT'])
@require_dealer
def update_dealer_password():
    data = request.get_json() or {}
    old_password = data.get('old_password', '').strip()
    new_password = data.get('new_password', '').strip()
    if not old_password or not new_password:
        return jsonify({'error': '新旧密码不能为空'}), 400
    if len(new_password) < 6:
        return jsonify({'error': '新密码至少6位'}), 400

    db = get_db()
    row = db.execute("SELECT password_hash FROM dealers WHERE id = ?", (g.dealer_id,)).fetchone()
    if not row or row['password_hash'] != hash_pw(old_password):
        return jsonify({'error': '原密码错误'}), 401

    db.execute("UPDATE dealers SET password_hash = ? WHERE id = ?", (hash_pw(new_password), g.dealer_id))
    db.commit()
    return jsonify({'ok': True, 'message': '密码修改成功'})

# ---------- brand page ----------
@app.route('/brand/<int:dealer_id>')
def brand_page(dealer_id):
    db = get_db()
    row = db.execute(
        "SELECT id, company_name, logo_url, price_standard_cn, price_pro_cn, price_standard_intl, price_pro_intl FROM dealers WHERE id = ?",
        (dealer_id,)
    ).fetchone()
    if not row:
        return '<h1 style="text-align:center;margin-top:100px;color:#666;">经销商不存在</h1>', 404
    return send_from_directory(BASE_DIR, 'index.html')

# ---------- uploads ----------
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.route('/api/dealer/logo', methods=['POST'])
@require_dealer
def upload_logo():
    if 'file' not in request.files:
        return jsonify({'error': '未选择文件'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '未选择文件'}), 400

    ext = os.path.splitext(file.filename)[1] or '.png'
    filename = f'{uuid.uuid4().hex}{ext}'
    filepath = os.path.join(UPLOAD_DIR, filename)
    file.save(filepath)

    logo_url = f'/uploads/{filename}'
    db = get_db()
    db.execute("UPDATE dealers SET logo_url = ? WHERE id = ?", (logo_url, g.dealer_id))
    db.commit()

    return jsonify({'ok': True, 'logo_url': logo_url})

@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    return send_from_directory(UPLOAD_DIR, filename)

# ---------- public ----------
@app.route('/api/brand/<int:dealer_id>', methods=['GET'])
def brand_config(dealer_id):
    db = get_db()
    row = db.execute(
        "SELECT id, company_name, logo_url, price_standard_cn, price_pro_cn, price_standard_intl, price_pro_intl FROM dealers WHERE id = ?",
        (dealer_id,)
    ).fetchone()
    if not row:
        return jsonify({'error': '经销商不存在'}), 404
    return jsonify(dict(row))

@app.route('/api/leads', methods=['POST'])
def submit_lead():
    data = request.get_json() or {}
    dealer_id = data.get('dealer_id')  # null for main site
    edition = data.get('edition', 'standard')
    name = data.get('name', '').strip()
    phone = data.get('phone', '').strip()
    email = data.get('email', '').strip()

    if not name or not phone:
        return jsonify({'error': '姓名和手机号不能为空'}), 400

    db = get_db()
    db.execute(
        "INSERT INTO leads (dealer_id, edition, name, phone, email) VALUES (?, ?, ?, ?, ?)",
        (dealer_id, edition, name, phone, email)
    )
    db.commit()
    return jsonify({'ok': True, 'message': '预约成功'}), 201

# ---------- static pages ----------
@app.route('/')
def serve_index():
    return send_from_directory(BASE_DIR, 'index.html')

@app.route('/admin')
def serve_admin():
    return send_from_directory(BASE_DIR, 'admin.html')

@app.route('/dealer')
def serve_dealer():
    return send_from_directory(BASE_DIR, 'dealer.html')

# ---------- main ----------
if __name__ == '__main__':
    init_db()
    print(f"数据库路径: {DB_PATH}")
    print("VEILORA 管理后台启动: http://0.0.0.0:9000")
    print("管理后台: http://localhost:9000/admin")
    print("经销商门户: http://localhost:9000/dealer")
    app.run(host='0.0.0.0', port=9000, debug=True)
