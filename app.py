import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, g, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'smartrent_master_key_2026'
app.config['TYPING'] = {}

# --- DIRECTORY CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
CHAT_UPLOAD_FOLDER = os.path.join(UPLOAD_FOLDER, 'chat')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['CHAT_UPLOAD_FOLDER'] = CHAT_UPLOAD_FOLDER

# Ensure upload folders exist
os.makedirs(CHAT_UPLOAD_FOLDER, exist_ok=True)

# --- DATABASE HELPERS ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('smartrent.db')
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None: 
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        # Users Table
        db.execute('''CREATE TABLE IF NOT EXISTS users 
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                       name TEXT, email TEXT UNIQUE, password TEXT)''')
        # Properties Table
        db.execute('''CREATE TABLE IF NOT EXISTS properties 
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                       title TEXT, description TEXT, price INTEGER, 
                       location TEXT, image_url TEXT, owner_id INTEGER, status TEXT DEFAULT 'active')''')
        # Transactions Table
        db.execute('''CREATE TABLE IF NOT EXISTS transactions (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER, amount INTEGER, status TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)
        ''')
        # Ensure transactions has columns to link to providers/rental requests/recipients
        curt = db.execute("PRAGMA table_info(transactions)").fetchall()
        tcols = [c['name'] for c in curt]
        if 'provider_id' not in tcols:
            try:
                db.execute("ALTER TABLE transactions ADD COLUMN provider_id INTEGER")
                db.commit()
            except Exception:
                pass
        if 'rental_request_id' not in tcols:
            try:
                db.execute("ALTER TABLE transactions ADD COLUMN rental_request_id INTEGER")
                db.commit()
            except Exception:
                pass
        if 'recipient_id' not in tcols:
            try:
                db.execute("ALTER TABLE transactions ADD COLUMN recipient_id INTEGER")
                db.commit()
            except Exception:
                pass
        if 'method' not in tcols:
            try:
                db.execute("ALTER TABLE transactions ADD COLUMN method TEXT")
                db.commit()
            except Exception:
                pass
        if 'note' not in tcols:
            try:
                db.execute("ALTER TABLE transactions ADD COLUMN note TEXT")
                db.commit()
            except Exception:
                pass
        # Service Bookings
        db.execute('''CREATE TABLE IF NOT EXISTS service_bookings (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER, service_type TEXT, description TEXT, status TEXT DEFAULT 'pending', timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)
        ''')
        # Service Providers (added by owners) - visible to everyone
        db.execute('''CREATE TABLE IF NOT EXISTS service_providers (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT, phone TEXT, service_type TEXT, details TEXT, upi_id TEXT, owner_id INTEGER, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)
        ''')
        # Rental Requests: tenant requests a property, owner accepts, then tenant pays
        db.execute('''CREATE TABLE IF NOT EXISTS rental_requests (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  property_id INTEGER, tenant_id INTEGER, owner_id INTEGER,
                  amount INTEGER, status TEXT DEFAULT 'requested', timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)
        ''')
        # Add amenities column to properties (comma-separated)
        curp = db.execute("PRAGMA table_info(properties)").fetchall()
        pcols = [c['name'] for c in curp]
        if 'amenities' not in pcols:
            try:
                db.execute("ALTER TABLE properties ADD COLUMN amenities TEXT DEFAULT ''")
                db.commit()
            except Exception:
                pass
        # Messages Table
        db.execute('''CREATE TABLE IF NOT EXISTS messages 
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                       sender_id INTEGER, receiver_id INTEGER, 
                       msg_text TEXT, msg_type TEXT DEFAULT 'text', 
                       file_path TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, status TEXT DEFAULT 'sent')''')
        db.commit()
        # Ensure 'status' column exists for older DBs
        cur = db.execute("PRAGMA table_info(messages)").fetchall()
        cols = [c['name'] for c in cur]
        if 'status' not in cols:
            db.execute("ALTER TABLE messages ADD COLUMN status TEXT DEFAULT 'sent'")
            db.commit()
        # Ensure 'status' column exists for properties table
        curp = db.execute("PRAGMA table_info(properties)").fetchall()
        pcols = [c['name'] for c in curp]
        if 'status' not in pcols:
            try:
                db.execute("ALTER TABLE properties ADD COLUMN status TEXT DEFAULT 'active'")
                db.commit()
            except Exception:
                pass

# --- AUTHENTICATION ROUTES ---
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    # show public landing page when not logged in
    return render_template('landing.html')

@app.route('/register_page')
def register_page():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register():
    db = get_db()
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    confirm = request.form.get('confirm_password')

    if not name or not email or not password or not confirm:
        return "All fields are required", 400

    if password != confirm:
        return "Passwords do not match", 400

    hashed_pw = generate_password_hash(password)
    try:
        db.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', 
                   (name, email, hashed_pw))
        db.commit()
        return redirect(url_for('login_page'))
    except sqlite3.IntegrityError:
        return "Email already registered. Please login.", 400

@app.route('/login_page')
def login_page():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    db = get_db()
    email = request.form.get('email')
    password = request.form.get('password')
    user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    
    if user and check_password_hash(user['password'], password):
        session.clear()
        session['user_id'] = user['id']
        session['username'] = user['name']
        session['current_view'] = 'tenant'
        return redirect(url_for('dashboard'))
    return "Invalid email or password", 401

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# --- DASHBOARD & PROPERTY ROUTES ---
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    
    db = get_db()
    if session.get('current_view') == 'owner':
        # Show only properties owned by current user
        props = db.execute('SELECT * FROM properties WHERE owner_id = ?', 
                           (session['user_id'],)).fetchall()
        # show recent service bookings to owners (for awareness)
        bookings = db.execute('SELECT * FROM service_bookings ORDER BY timestamp DESC LIMIT 20').fetchall()
        prop_count = len(props)
        return render_template('owner_hub.html', properties=props, bookings=bookings, prop_count=prop_count)
    
    # Tenant View: Show all properties
    props = db.execute('SELECT * FROM properties WHERE status = "active" AND owner_id != ?', (session['user_id'],)).fetchall()
    # tenant's own service bookings
    bookings = db.execute('SELECT * FROM service_bookings WHERE user_id = ? ORDER BY timestamp DESC', (session['user_id'],)).fetchall()
    return render_template('tenant.html', properties=props, bookings=bookings)

@app.route('/property/<int:id>')
def property_detail(id):
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    
    db = get_db()
    # Link property to owner name for the "Chat" section
    p_data = db.execute('''SELECT properties.*, users.name as owner_name 
                           FROM properties 
                           JOIN users ON properties.owner_id = users.id 
                           WHERE properties.id = ?''', (id,)).fetchone()
    
    if not p_data:
        return "Property not found", 404
    return render_template('property_detail.html', p=p_data)


@app.route('/api/request_rent', methods=['POST'])
def request_rent():
    if 'user_id' not in session:
        return jsonify({'status':'unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    prop_id = data.get('property_id')
    if not prop_id:
        return jsonify({'status':'bad_request'}), 400
    db = get_db()
    p = db.execute('SELECT * FROM properties WHERE id = ?', (prop_id,)).fetchone()
    if not p:
        return jsonify({'status':'not_found'}), 404
    owner_id = p['owner_id']
    amount = p['price']
    cur = db.execute('INSERT INTO rental_requests (property_id, tenant_id, owner_id, amount, status) VALUES (?,?,?,?,?)', (prop_id, session['user_id'], owner_id, amount, 'requested'))
    db.commit()
    rid = cur.lastrowid
    return jsonify({'status':'requested', 'rental_request_id': rid})


@app.route('/api/get_rental_requests')
def get_rental_requests():
    if 'user_id' not in session:
        return jsonify([])
    db = get_db()
    # If owner, return incoming requests for properties they own
    if session.get('current_view') == 'owner':
        rows = db.execute('''SELECT rr.*, u.name as tenant_name, p.title as property_title
                             FROM rental_requests rr
                             LEFT JOIN users u ON u.id = rr.tenant_id
                             LEFT JOIN properties p ON p.id = rr.property_id
                             WHERE rr.owner_id = ? ORDER BY rr.timestamp DESC''', (session['user_id'],)).fetchall()
    else:
        # tenant view: return requests made by this user
        rows = db.execute('''SELECT rr.*, u.name as tenant_name, p.title as property_title, ou.name as owner_name
                             FROM rental_requests rr
                             LEFT JOIN users u ON u.id = rr.tenant_id
                             LEFT JOIN properties p ON p.id = rr.property_id
                             LEFT JOIN users ou ON ou.id = rr.owner_id
                             WHERE rr.tenant_id = ? ORDER BY rr.timestamp DESC''', (session['user_id'],)).fetchall()
    out = []
    for r in rows:
        out.append({'id': r['id'], 'property_id': r['property_id'], 'property_title': r['property_title'], 'tenant_id': r['tenant_id'], 'tenant_name': r['tenant_name'], 'owner_id': r['owner_id'], 'amount': r['amount'], 'status': r['status'], 'timestamp': r['timestamp']})
    return jsonify(out)


@app.route('/api/respond_request', methods=['POST'])
def respond_request():
    if 'user_id' not in session:
        return jsonify({'status':'unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    rid = data.get('rental_request_id')
    action = data.get('action')  # 'accept' or 'reject'
    if not rid or action not in ('accept','reject'):
        return jsonify({'status':'bad_request'}), 400
    db = get_db()
    rr = db.execute('SELECT * FROM rental_requests WHERE id = ?', (rid,)).fetchone()
    if not rr:
        return jsonify({'status':'not_found'}), 404
    # only owner may accept/reject
    if rr['owner_id'] != session['user_id']:
        return jsonify({'status':'forbidden'}), 403
    new_status = 'accepted' if action == 'accept' else 'rejected'
    db.execute('UPDATE rental_requests SET status = ? WHERE id = ?', (new_status, rid))
    db.commit()
    # if accepted, create a pending transaction record for the tenant to pay
    if new_status == 'accepted':
        try:
            tenant_id = rr['tenant_id']
            amount = rr['amount']
            owner_id = rr['owner_id']
            # create a pending transaction for the tenant linked to this rental_request
            db.execute('INSERT INTO transactions (user_id, amount, status, rental_request_id, recipient_id, method, note) VALUES (?,?,?,?,?,?,?)',
                       (tenant_id, amount, 'pending', rid, owner_id, 'upi', f'Rent for property_id {rr["property_id"]}'))
            db.commit()
        except Exception:
            pass
    return jsonify({'status':'ok','new':new_status})

@app.route('/add_property', methods=['POST'])
def add_property():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
        
    file = request.files.get('image') or request.files.get('property_image')
    img_url = ""
    fname = None
    if file:
        fname = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], fname))
        img_url = fname
        
    db = get_db()
    status = request.form.get('status', 'active')
    amenities = request.form.getlist('amenities') or []
    amenities_str = ','.join(amenities)
    db.execute('''INSERT INTO properties (title, description, price, location, image_url, owner_id, status, amenities) 
                        VALUES (?,?,?,?,?,?,?,?)''',
                    (request.form['title'], request.form.get('description',''), 
                     request.form['price'], request.form.get('location', request.form.get('address','')), 
                     img_url, session['user_id'], status, amenities_str))
    db.commit()
    return redirect(url_for('dashboard'))

# --- CHAT SYSTEM ROUTES ---
@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    
    db = get_db()
    curr_id = session['user_id']
    target_id = request.args.get('target_id', type=int)

    # Sidebar: Fetch users you have a message history with
    partners = db.execute('''SELECT DISTINCT id, name FROM users 
                             WHERE id IN (
                                 SELECT receiver_id FROM messages WHERE sender_id = ? 
                                 UNION 
                                 SELECT sender_id FROM messages WHERE receiver_id = ?
                             ) AND id != ?''', (curr_id, curr_id, curr_id)).fetchall()

    messages = []
    target_user = None
    
    if target_id:
        # Fetch target user info (even if no messages exist yet)
        target_user = db.execute('SELECT id, name FROM users WHERE id = ?', (target_id,)).fetchone()
        if target_user:
            messages = db.execute('''SELECT * FROM messages 
                                     WHERE (sender_id=? AND receiver_id=?) 
                                     OR (sender_id=? AND receiver_id=?) 
                                     ORDER BY timestamp ASC''', 
                                  (curr_id, target_id, target_id, curr_id)).fetchall()
            # Mark incoming messages as read when opening the conversation
            try:
                db.execute("UPDATE messages SET status = 'read' WHERE sender_id = ? AND receiver_id = ? AND status != 'read'", (target_id, curr_id))
                db.commit()
            except Exception:
                pass
            # augment messages with rental_request info for request-type messages
            augmented = []
            for row in messages:
                m = dict(row)
                if m.get('msg_type') == 'request':
                    try:
                        parts = (m.get('msg_text') or '').split('|')
                        rrid = int(parts[0]) if parts and parts[0].isdigit() else None
                    except Exception:
                        rrid = None
                    if rrid:
                        rr = db.execute('SELECT * FROM rental_requests WHERE id = ?', (rrid,)).fetchone()
                        if rr:
                            m['request_status'] = rr['status']
                            m['rental_request_id'] = rr['id']
                            m['rental_amount'] = rr['amount']
                            m['rental_property_id'] = rr['property_id']
                            m['rental_owner_id'] = rr['owner_id']
                            m['rental_tenant_id'] = rr['tenant_id']
                        else:
                            m['request_status'] = None
                    else:
                        m['request_status'] = None
                augmented.append(m)
            messages = augmented

    return render_template('chat.html', 
                           partners=partners, 
                           messages=messages, 
                           target_user=target_user, 
                           current_user_id=curr_id)


@app.route('/payments')
def payments_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('payment_dashboard.html')


@app.route('/services')
def services_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    db = get_db()
    providers = db.execute('SELECT * FROM service_providers ORDER BY timestamp DESC').fetchall()
    return render_template('services.html', providers=providers)


@app.route('/api/tx_history')
def tx_history():
    if 'user_id' not in session:
        return jsonify([])
    db = get_db()
    rows = db.execute('''SELECT t.*, sp.name as provider_name, sp.phone as provider_phone, sp.upi_id as provider_upi,
                                u.name as recipient_name, pr.title as property_title, ou.name as owner_name
                         FROM transactions t
                         LEFT JOIN service_providers sp ON sp.id = t.provider_id
                         LEFT JOIN users u ON u.id = t.recipient_id
                         LEFT JOIN rental_requests rr ON rr.id = t.rental_request_id
                         LEFT JOIN properties pr ON pr.id = rr.property_id
                         LEFT JOIN users ou ON ou.id = rr.owner_id
                         WHERE t.user_id = ?
                         ORDER BY t.timestamp DESC''', (session['user_id'],)).fetchall()
    out = []
    for r in rows:
        entry = {'amount': r['amount'], 'status': r['status'], 'timestamp': r['timestamp'], 'method': r.get('method', None), 'note': r.get('note', '')}
        # determine recipient/payee
        if r['provider_id']:
            entry['to'] = {'type':'provider', 'name': r['provider_name'], 'phone': r['provider_phone'], 'id': r['provider_id'], 'upi': r['provider_upi']}
        elif r['rental_request_id']:
            entry['to'] = {'type':'rental', 'rental_request_id': r['rental_request_id'], 'property_title': r['property_title'], 'owner_name': r['owner_name']}
        elif r['recipient_id']:
            entry['to'] = {'type':'user', 'name': r['recipient_name'], 'id': r['recipient_id']}
        else:
            entry['to'] = None
        out.append(entry)
    return jsonify(out)


@app.route('/api/add_provider', methods=['POST'])
def add_provider():
    if 'user_id' not in session:
        return jsonify({'status':'unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    name = data.get('name')
    phone = data.get('phone')
    service_type = data.get('service_type')
    details = data.get('details','')
    upi_id = data.get('upi_id','')
    if not name or not phone or not service_type:
        return jsonify({'status':'bad_request'}), 400
    db = get_db()
    db.execute('INSERT INTO service_providers (name, phone, service_type, details, upi_id, owner_id) VALUES (?,?,?,?,?,?)', (name, phone, service_type, details, upi_id, session['user_id']))
    db.commit()
    return jsonify({'status':'ok'})


@app.route('/api/get_providers')
def get_providers():
    db = get_db()
    rows = db.execute('SELECT * FROM service_providers ORDER BY timestamp DESC').fetchall()
    out = []
    for r in rows:
        out.append({'id':r['id'],'name':r['name'],'phone':r['phone'],'service_type':r['service_type'],'details':r['details'],'upi_id':r['upi_id']})
    return jsonify(out)


@app.route('/api/record_payment', methods=['POST'])
def record_payment():
    if 'user_id' not in session:
        return jsonify({'status':'unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    provider_id = data.get('provider_id')
    amount = data.get('amount')
    method = data.get('method','upi')
    if not amount:
        return jsonify({'status':'bad_request'}), 400
    db = get_db()
    recipient_id = data.get('recipient_id')
    rental_request_id = data.get('rental_request_id')
    note = data.get('note','')
    # If paying for a rental_request, try to find a pending transaction and mark it paid
    if rental_request_id:
        try:
            cur = db.execute('SELECT * FROM transactions WHERE rental_request_id = ? AND user_id = ? AND status = ?', (rental_request_id, session['user_id'], 'pending')).fetchone()
            if cur:
                db.execute('UPDATE transactions SET status = ?, method = ?, note = ? WHERE id = ?', ('paid', method, note, cur['id']))
                db.commit()
                # mark rental_request paid
                db.execute('UPDATE rental_requests SET status = ? WHERE id = ?', ('paid', rental_request_id))
                db.commit()
                return jsonify({'status':'ok','updated':'existing'})
        except Exception:
            pass
    # otherwise create a new immediate-paid transaction
    db.execute('''INSERT INTO transactions (user_id, amount, status, provider_id, rental_request_id, recipient_id, method, note)
                  VALUES (?,?,?,?,?,?,?,?)''', (session['user_id'], amount, 'paid', provider_id, rental_request_id, recipient_id, method, note))
    db.commit()
    if rental_request_id:
        try:
            db.execute('UPDATE rental_requests SET status = ? WHERE id = ?', ('paid', rental_request_id))
            db.commit()
        except Exception:
            pass
    return jsonify({'status':'ok','created':'new'})

@app.route('/api/send_msg', methods=['POST'])
def send_msg():
    if 'user_id' not in session:
        return jsonify({"status": "unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    receiver_id = data.get('receiver_id')
    message = data.get('message', '')
    msg_type = data.get('msg_type', 'text')

    if not receiver_id:
        return jsonify({"status": "bad_request"}), 400

    db = get_db()
    # For location messages, expect message as object {lat, lng, label}
    if msg_type == 'location' and isinstance(message, dict):
        # store as lat|lng|label
        lat = str(message.get('lat', ''))
        lng = str(message.get('lng', ''))
        label = message.get('label', '') or ''
        stored = f"{lat}|{lng}|{label}"
        db.execute('INSERT INTO messages (sender_id, receiver_id, msg_text, msg_type, status) VALUES (?,?,?,?,?)',
                   (session['user_id'], receiver_id, stored, 'location', 'delivered'))
    else:
        db.execute('INSERT INTO messages (sender_id, receiver_id, msg_text, msg_type, status) VALUES (?,?,?,?,?)',
                   (session['user_id'], receiver_id, message, msg_type, 'delivered'))
    db.commit()
    return jsonify({"status": "success"})

@app.route('/api/upload_chat_file', methods=['POST'])
def upload_chat_file():
    if 'user_id' not in session:
        return jsonify({"status": "unauthorized"}), 401
        
    file = request.files.get('file')
    if file:
        fname = secure_filename(file.filename)
        file.save(os.path.join(app.config['CHAT_UPLOAD_FOLDER'], fname))
        db = get_db()
        msg_type = request.form.get('msg_type', '')
        # detect video
        if file.mimetype.startswith('video/'):
            msg_type = 'video'
        elif file.mimetype.startswith('image/'):
            msg_type = 'image'
        db.execute('''INSERT INTO messages (sender_id, receiver_id, msg_text, msg_type, file_path, status) 
                      VALUES (?,?,?,?,?,?)''',
                   (session['user_id'], request.form['receiver_id'], fname, 
                    msg_type, f'/static/uploads/chat/{fname}', 'delivered'))
        db.commit()
        return jsonify({"status": "success"})
    return jsonify({"status": "failed"}), 400


@app.route('/api/typing', methods=['POST'])
def set_typing():
    if 'user_id' not in session:
        return jsonify({"status": "unauthorized"}), 401
    data = request.get_json(silent=True) or request.form
    try:
        partner = int(data.get('partner_id'))
    except Exception:
        return jsonify({"status": "bad_request"}), 400
    is_typing = data.get('is_typing')
    # normalize
    if isinstance(is_typing, str):
        is_typing = is_typing.lower() in ['true', '1', 'yes']
    app.config['TYPING'][f"{session['user_id']}_{partner}"] = bool(is_typing)
    return jsonify({"status": "ok"})


@app.route('/api/get_typing')
def get_typing():
    if 'user_id' not in session:
        return jsonify({"status": "unauthorized"}), 401
    partner = request.args.get('partner_id', type=int)
    if not partner:
        return jsonify({"is_typing": False})
    val = app.config['TYPING'].get(f"{partner}_{session['user_id']}", False)
    return jsonify({"is_typing": bool(val)})

@app.route('/switch_role')
def switch_role():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    session['current_view'] = 'owner' if session.get('current_view') == 'tenant' else 'tenant'
    return redirect(url_for('dashboard'))


@app.route('/api/toggle_property_status', methods=['POST'])
def toggle_property_status():
    if 'user_id' not in session:
        return jsonify({'status':'unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    pid = data.get('property_id')
    if not pid:
        return jsonify({'status':'bad_request'}), 400
    db = get_db()
    p = db.execute('SELECT owner_id, status FROM properties WHERE id = ?', (pid,)).fetchone()
    if not p or p['owner_id'] != session['user_id']:
        return jsonify({'status':'forbidden'}), 403
    new = 'inactive' if p['status'] == 'active' else 'active'
    db.execute('UPDATE properties SET status = ? WHERE id = ?', (new, pid))
    db.commit()
    return jsonify({'status':'ok','new':new})


@app.route('/api/update_property', methods=['POST'])
def update_property():
    if 'user_id' not in session:
        return jsonify({'status':'unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    pid = data.get('property_id')
    field = data.get('field')
    value = data.get('value')
    if not pid or not field:
        return jsonify({'status':'bad_request'}), 400
    if field not in ('price','description','title','location','amenities'):
        return jsonify({'status':'invalid_field'}), 400
    db = get_db()
    p = db.execute('SELECT owner_id FROM properties WHERE id = ?', (pid,)).fetchone()
    if not p or p['owner_id'] != session['user_id']:
        return jsonify({'status':'forbidden'}), 403
    db.execute(f'UPDATE properties SET {field} = ? WHERE id = ?', (value, pid))
    db.commit()
    return jsonify({'status':'ok'})


@app.route('/api/pay_rent', methods=['POST'])
def pay_rent():
    if 'user_id' not in session:
        return jsonify({'status':'unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    amount = data.get('amount')
    if not amount:
        return jsonify({'status':'bad_request'}), 400
    db = get_db()
    db.execute('INSERT INTO transactions (user_id, amount, status) VALUES (?,?,?)', (session['user_id'], amount, 'paid'))
    db.commit()
    return jsonify({'status':'success'})


@app.route('/api/book_service', methods=['POST'])
def book_service():
    if 'user_id' not in session:
        return jsonify({'status':'unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    service = data.get('service_type')
    desc = data.get('description','')
    if not service:
        return jsonify({'status':'bad_request'}), 400
    db = get_db()
    db.execute('INSERT INTO service_bookings (user_id, service_type, description) VALUES (?,?,?)', (session['user_id'], service, desc))
    db.commit()
    return jsonify({'status':'booked'})


@app.route('/api/delete_property', methods=['POST'])
def delete_property():
    if 'user_id' not in session:
        return jsonify({'status':'unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    pid = data.get('property_id')
    if not pid:
        return jsonify({'status':'bad_request'}), 400
    db = get_db()
    p = db.execute('SELECT owner_id FROM properties WHERE id = ?', (pid,)).fetchone()
    if not p or p['owner_id'] != session['user_id']:
        return jsonify({'status':'forbidden'}), 403
    db.execute('DELETE FROM properties WHERE id = ?', (pid,))
    db.commit()
    return jsonify({'status':'ok'})

if __name__ == '__main__':
    init_db()
    app.run(debug=True)