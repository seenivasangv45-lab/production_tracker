import os
import hashlib
import secrets
import sqlite3
import json
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, send_file, g, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import io
import csv

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(hours=12)

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'production.db')
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ─── Database Connection ───────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# ─── Database Initialization ──────────────────────────────────────────
def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    cursor = db.cursor()

    cursor.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('Admin','User','Auditor')),
        user_type TEXT DEFAULT NULL CHECK(user_type IN ('Coder','Biller',NULL)),
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        created_by INTEGER REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        invoice_number TEXT UNIQUE NOT NULL,
        patient_name TEXT,
        received_date DATE,
        upload_date DATE DEFAULT (date('now')),
        status TEXT DEFAULT 'Unassigned' CHECK(status IN (
            'Unassigned','Assigned to Coder','Coding In Progress','Coded',
            'Assigned to Biller','Billing In Progress','Billed','Finalized',
            'Rework - Coder','Rework - Biller','Clarification Needed',
            'Audited - Passed','Audited - Failed'
        )),
        priority TEXT DEFAULT 'Normal' CHECK(priority IN ('Normal','High')),
        assigned_coder_id INTEGER REFERENCES users(id),
        assigned_biller_id INTEGER REFERENCES users(id),
        coder_comments TEXT,
        biller_comments TEXT,
        auditor_id INTEGER REFERENCES users(id),
        auditor_comments TEXT,
        audit_status TEXT CHECK(audit_status IN ('Passed','Failed',NULL)),
        coded_at TIMESTAMP,
        billed_at TIMESTAMP,
        finalized_at TIMESTAMP,
        audited_at TIMESTAMP,
        tat_days INTEGER,
        uploaded_by INTEGER REFERENCES users(id),
        extra_data TEXT
    );

    CREATE TABLE IF NOT EXISTS activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id INTEGER REFERENCES accounts(id),
        user_id INTEGER REFERENCES users(id),
        action TEXT NOT NULL,
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS upload_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        records_added INTEGER DEFAULT 0,
        duplicates_skipped INTEGER DEFAULT 0,
        uploaded_by INTEGER REFERENCES users(id),
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_accounts_invoice ON accounts(invoice_number);
    CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);
    CREATE INDEX IF NOT EXISTS idx_accounts_coder ON accounts(assigned_coder_id);
    CREATE INDEX IF NOT EXISTS idx_accounts_biller ON accounts(assigned_biller_id);
    CREATE INDEX IF NOT EXISTS idx_accounts_priority ON accounts(priority);
    CREATE INDEX IF NOT EXISTS idx_accounts_upload_date ON accounts(upload_date);
    CREATE INDEX IF NOT EXISTS idx_activity_account ON activity_log(account_id);
    ''')

    # Create default admin if not exists
    existing = cursor.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    if not existing:
        cursor.execute(
            "INSERT INTO users (username, password_hash, full_name, role) VALUES (?,?,?,?)",
            ('admin', generate_password_hash('Admin@123', method='pbkdf2:sha256:260000'), 'System Administrator', 'Admin')
        )

    db.commit()
    db.close()

init_db()

# ─── Auth Decorators ──────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') not in ('Admin', 'Auditor'):
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

def auditor_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') not in ('Auditor', 'Admin'):
            flash('Access denied.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

# ─── Helper Functions ─────────────────────────────────────────────────
def log_activity(account_id, user_id, action, details=None):
    db = get_db()
    db.execute(
        "INSERT INTO activity_log (account_id, user_id, action, details) VALUES (?,?,?,?)",
        (account_id, user_id, action, details)
    )
    db.commit()

def calculate_tat(received_date_str):
    if not received_date_str:
        return None
    try:
        rd = datetime.strptime(received_date_str, '%Y-%m-%d')
        return (datetime.now() - rd).days
    except:
        return None

# ─── Routes ───────────────────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=? AND is_active=1", (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['full_name'] = user['full_name']
            session['role'] = user['role']
            session['user_type'] = user['user_type']
            db.execute("UPDATE users SET last_login=? WHERE id=?", (datetime.now().isoformat(), user['id']))
            db.commit()
            log_activity(None, user['id'], 'Login', 'User logged in')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_activity(None, session['user_id'], 'Logout', 'User logged out')
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form.get('current_password', '')
        new_pw = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')
        if new_pw != confirm:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('change_password'))
        if len(new_pw) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return redirect(url_for('change_password'))
        db = get_db()
        user = db.execute("SELECT password_hash FROM users WHERE id=?", (session['user_id'],)).fetchone()
        if not check_password_hash(user['password_hash'], current):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('change_password'))
        db.execute("UPDATE users SET password_hash=? WHERE id=?",
                   (generate_password_hash(new_pw, method='pbkdf2:sha256:260000'), session['user_id']))
        db.commit()
        flash('Password changed successfully.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('change_password.html')

# ─── Dashboard ────────────────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    role = session['role']
    user_id = session['user_id']
    user_type = session.get('user_type')
    today = datetime.now().strftime('%Y-%m-%d')

    data = {}

    if role in ('Admin', 'Auditor'):
        data['total_accounts'] = db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
        data['today_received'] = db.execute("SELECT COUNT(*) FROM accounts WHERE upload_date=?", (today,)).fetchone()[0]
        data['unassigned'] = db.execute("SELECT COUNT(*) FROM accounts WHERE status='Unassigned'").fetchone()[0]
        data['coding_pending'] = db.execute("SELECT COUNT(*) FROM accounts WHERE status IN ('Assigned to Coder','Coding In Progress')").fetchone()[0]
        data['billing_pending'] = db.execute("SELECT COUNT(*) FROM accounts WHERE status IN ('Assigned to Biller','Billing In Progress')").fetchone()[0]
        data['finalized'] = db.execute("SELECT COUNT(*) FROM accounts WHERE status='Finalized'").fetchone()[0]
        data['high_priority'] = db.execute("SELECT COUNT(*) FROM accounts WHERE priority='High' AND status NOT IN ('Finalized','Audited - Passed')").fetchone()[0]
        data['rework_pending'] = db.execute("SELECT COUNT(*) FROM accounts WHERE status IN ('Rework - Coder','Rework - Biller')").fetchone()[0]

        # Aging accounts (TAT > 5 days, not finalized)
        data['aging_accounts'] = db.execute("""
            SELECT COUNT(*) FROM accounts
            WHERE received_date IS NOT NULL
            AND julianday('now') - julianday(received_date) > 5
            AND status NOT IN ('Finalized','Audited - Passed')
        """).fetchone()[0]

        # Last 7 days production
        data['daily_production'] = db.execute("""
            SELECT upload_date, COUNT(*) as cnt FROM accounts
            WHERE upload_date >= date('now','-7 days')
            GROUP BY upload_date ORDER BY upload_date
        """).fetchall()

        # Top coders
        data['coder_stats'] = db.execute("""
            SELECT u.full_name, COUNT(a.id) as completed
            FROM users u LEFT JOIN accounts a ON u.id = a.assigned_coder_id AND a.coded_at IS NOT NULL
            WHERE u.user_type='Coder' AND u.is_active=1
            GROUP BY u.id ORDER BY completed DESC LIMIT 10
        """).fetchall()

    if role == 'Auditor' or (role == 'Admin'):
        data['audit_total'] = db.execute("SELECT COUNT(*) FROM accounts WHERE audit_status IS NOT NULL").fetchone()[0]
        data['audit_passed'] = db.execute("SELECT COUNT(*) FROM accounts WHERE audit_status='Passed'").fetchone()[0]
        data['audit_failed'] = db.execute("SELECT COUNT(*) FROM accounts WHERE audit_status='Failed'").fetchone()[0]

    if role == 'User':
        if user_type == 'Coder':
            data['assigned'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_coder_id=? AND status IN ('Assigned to Coder','Coding In Progress','Rework - Coder')", (user_id,)).fetchone()[0]
            data['completed'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_coder_id=? AND coded_at IS NOT NULL", (user_id,)).fetchone()[0]
            data['rework'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_coder_id=? AND status='Rework - Coder'", (user_id,)).fetchone()[0]
            data['high_priority'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_coder_id=? AND priority='High' AND status IN ('Assigned to Coder','Coding In Progress','Rework - Coder')", (user_id,)).fetchone()[0]
        elif user_type == 'Biller':
            data['assigned'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_biller_id=? AND status IN ('Assigned to Biller','Billing In Progress','Rework - Biller')", (user_id,)).fetchone()[0]
            data['completed'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_biller_id=? AND billed_at IS NOT NULL", (user_id,)).fetchone()[0]
            data['rework'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_biller_id=? AND status='Rework - Biller'", (user_id,)).fetchone()[0]
            data['high_priority'] = db.execute("SELECT COUNT(*) FROM accounts WHERE assigned_biller_id=? AND priority='High' AND status IN ('Assigned to Biller','Billing In Progress','Rework - Biller')", (user_id,)).fetchone()[0]

    # Rework alerts for coders
    rework_alerts = []
    if role == 'User' and user_type == 'Coder':
        rework_alerts = db.execute("""
            SELECT id, invoice_number, auditor_comments FROM accounts
            WHERE assigned_coder_id=? AND status='Rework - Coder'
        """, (user_id,)).fetchall()

    return render_template('dashboard.html', data=data, rework_alerts=rework_alerts)

# ─── User Management ─────────────────────────────────────────────────
@app.route('/users')
@admin_required
def users_list():
    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY role, full_name").fetchall()
    return render_template('users.html', users=users)

@app.route('/users/add', methods=['GET', 'POST'])
@admin_required
def add_user():
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        full_name = request.form.get('full_name', '').strip()
        role = request.form.get('role', 'User')
        user_type = request.form.get('user_type') if role == 'User' else None

        if not username or not password or not full_name:
            flash('All fields are required.', 'error')
            return redirect(url_for('add_user'))
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return redirect(url_for('add_user'))

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, full_name, role, user_type, created_by) VALUES (?,?,?,?,?,?)",
                (username, generate_password_hash(password, method='pbkdf2:sha256:260000'),
                 full_name, role, user_type, session['user_id'])
            )
            db.commit()
            log_activity(None, session['user_id'], 'User Created', f'Created user: {username}')
            flash(f'User "{username}" created successfully.', 'success')
            return redirect(url_for('users_list'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'error')
    return render_template('add_user.html')

@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('users_list'))

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        role = request.form.get('role', 'User')
        user_type = request.form.get('user_type') if role == 'User' else None
        is_active = 1 if request.form.get('is_active') else 0
        new_password = request.form.get('new_password', '').strip()

        db.execute("UPDATE users SET full_name=?, role=?, user_type=?, is_active=? WHERE id=?",
                   (full_name, role, user_type, is_active, user_id))

        if new_password:
            if len(new_password) < 8:
                flash('Password must be at least 8 characters.', 'error')
                return redirect(url_for('edit_user', user_id=user_id))
            db.execute("UPDATE users SET password_hash=? WHERE id=?",
                       (generate_password_hash(new_password, method='pbkdf2:sha256:260000'), user_id))

        db.commit()
        log_activity(None, session['user_id'], 'User Updated', f'Updated user ID: {user_id}')
        flash('User updated successfully.', 'success')
        return redirect(url_for('users_list'))

    return render_template('edit_user.html', user=user)

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    db = get_db()
    # Prevent deleting yourself
    if user_id == session['user_id']:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('users_list'))

    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('users_list'))

    # Prevent deleting the default admin
    if user['username'] == 'admin':
        flash('The default admin account cannot be deleted.', 'error')
        return redirect(url_for('users_list'))

    # Check if user has any assigned accounts still in progress
    active_coder = db.execute(
        "SELECT COUNT(*) FROM accounts WHERE assigned_coder_id=? AND status IN ('Assigned to Coder','Coding In Progress','Rework - Coder')",
        (user_id,)
    ).fetchone()[0]
    active_biller = db.execute(
        "SELECT COUNT(*) FROM accounts WHERE assigned_biller_id=? AND status IN ('Assigned to Biller','Billing In Progress','Rework - Biller')",
        (user_id,)
    ).fetchone()[0]

    if active_coder + active_biller > 0:
        flash(f'Cannot delete "{user["full_name"]}" — they have {active_coder + active_biller} active account(s). Reassign their accounts first using Emergency Reassignment.', 'error')
        return redirect(url_for('users_list'))

    username = user['full_name']
    # Nullify references in completed accounts (preserve history)
    db.execute("UPDATE accounts SET assigned_coder_id=NULL WHERE assigned_coder_id=? AND status NOT IN ('Assigned to Coder','Coding In Progress','Rework - Coder')", (user_id,))
    db.execute("UPDATE accounts SET assigned_biller_id=NULL WHERE assigned_biller_id=? AND status NOT IN ('Assigned to Biller','Billing In Progress','Rework - Biller')", (user_id,))
    db.execute("UPDATE accounts SET auditor_id=NULL WHERE auditor_id=?", (user_id,))
    db.execute("UPDATE accounts SET uploaded_by=NULL WHERE uploaded_by=?", (user_id,))
    # Clear foreign key references in activity_log and upload_history
    db.execute("UPDATE activity_log SET user_id=NULL WHERE user_id=?", (user_id,))
    db.execute("UPDATE upload_history SET uploaded_by=NULL WHERE uploaded_by=?", (user_id,))
    db.execute("UPDATE users SET created_by=NULL WHERE created_by=?", (user_id,))
    # Delete the user
    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    log_activity(None, session['user_id'], 'User Deleted', f'Deleted user: {username} (ID: {user_id})')
    flash(f'User "{username}" has been permanently deleted.', 'success')
    return redirect(url_for('users_list'))

# ─── Inventory Upload ─────────────────────────────────────────────────
@app.route('/inventory/upload', methods=['GET', 'POST'])
@admin_required
def upload_inventory():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename == '':
            flash('No file selected.', 'error')
            return redirect(url_for('upload_inventory'))

        filename = secure_filename(file.filename)
        if not filename.lower().endswith('.csv'):
            flash('Only CSV files are accepted.', 'error')
            return redirect(url_for('upload_inventory'))

        content = file.stream.read().decode('utf-8', errors='replace')
        reader = csv.DictReader(io.StringIO(content))

        db = get_db()
        added = 0
        skipped = 0

        for row in reader:
            invoice = row.get('Invoice Number', row.get('invoice_number', row.get('InvoiceNumber', ''))).strip()
            if not invoice:
                continue

            existing = db.execute("SELECT id FROM accounts WHERE invoice_number=?", (invoice,)).fetchone()
            if existing:
                skipped += 1
                continue

            patient = row.get('Patient Name', row.get('patient_name', row.get('PatientName', ''))).strip()
            received = row.get('Received Date', row.get('received_date', row.get('ReceivedDate', ''))).strip()

            # Try to parse date
            parsed_date = None
            for fmt in ('%Y-%m-%d', '%m/%d/%Y', '%d/%m/%Y', '%m-%d-%Y', '%d-%m-%Y'):
                try:
                    parsed_date = datetime.strptime(received, fmt).strftime('%Y-%m-%d')
                    break
                except:
                    continue

            extra = json.dumps({k: v for k, v in row.items()
                                if k not in ('Invoice Number', 'invoice_number', 'InvoiceNumber',
                                             'Patient Name', 'patient_name', 'PatientName',
                                             'Received Date', 'received_date', 'ReceivedDate')})

            tat = calculate_tat(parsed_date) if parsed_date else None

            db.execute("""
                INSERT INTO accounts (invoice_number, patient_name, received_date, uploaded_by, tat_days, extra_data)
                VALUES (?,?,?,?,?,?)
            """, (invoice, patient, parsed_date, session['user_id'], tat, extra))
            added += 1

        db.execute("INSERT INTO upload_history (filename, records_added, duplicates_skipped, uploaded_by) VALUES (?,?,?,?)",
                   (filename, added, skipped, session['user_id']))
        db.commit()

        log_activity(None, session['user_id'], 'Inventory Upload',
                     f'File: {filename}, Added: {added}, Duplicates: {skipped}')
        flash(f'Upload complete: {added} new accounts added, {skipped} duplicates skipped.', 'success')
        return redirect(url_for('inventory_list'))

    return render_template('upload_inventory.html')

# ─── Inventory List ───────────────────────────────────────────────────
@app.route('/inventory')
@login_required
def inventory_list():
    db = get_db()
    role = session['role']
    user_id = session['user_id']
    user_type = session.get('user_type')

    # Filters
    status_filter = request.args.get('status', '')
    priority_filter = request.args.get('priority', '')
    date_filter = request.args.get('date', '')
    search_q = request.args.get('q', '').strip()
    page = max(1, int(request.args.get('page', 1)))
    per_page = 50

    query = "SELECT a.*, c.full_name as coder_name, b.full_name as biller_name FROM accounts a LEFT JOIN users c ON a.assigned_coder_id=c.id LEFT JOIN users b ON a.assigned_biller_id=b.id WHERE 1=1"
    params = []

    if role == 'User':
        if user_type == 'Coder':
            query += " AND a.assigned_coder_id=?"
            params.append(user_id)
        elif user_type == 'Biller':
            query += " AND a.assigned_biller_id=?"
            params.append(user_id)

    if status_filter:
        query += " AND a.status=?"
        params.append(status_filter)
    if priority_filter:
        query += " AND a.priority=?"
        params.append(priority_filter)
    if date_filter:
        query += " AND a.upload_date=?"
        params.append(date_filter)
    if search_q:
        query += " AND (a.invoice_number LIKE ? OR a.patient_name LIKE ?)"
        params.extend([f'%{search_q}%', f'%{search_q}%'])

    count_query = query.replace("SELECT a.*, c.full_name as coder_name, b.full_name as biller_name FROM accounts a LEFT JOIN users c ON a.assigned_coder_id=c.id LEFT JOIN users b ON a.assigned_biller_id=b.id", "SELECT COUNT(*) FROM accounts a")
    total = db.execute(count_query, params).fetchone()[0]

    query += " ORDER BY CASE WHEN a.priority='High' THEN 0 ELSE 1 END, a.upload_date DESC LIMIT ? OFFSET ?"
    params.extend([per_page, (page - 1) * per_page])

    accounts = db.execute(query, params).fetchall()
    total_pages = max(1, (total + per_page - 1) // per_page)

    coders = db.execute("SELECT id, full_name FROM users WHERE user_type='Coder' AND is_active=1").fetchall()
    billers = db.execute("SELECT id, full_name FROM users WHERE user_type='Biller' AND is_active=1").fetchall()

    return render_template('inventory.html', accounts=accounts, coders=coders, billers=billers,
                           page=page, total_pages=total_pages, total=total,
                           status_filter=status_filter, priority_filter=priority_filter,
                           date_filter=date_filter, search_q=search_q)

# ─── Account Detail & Actions ────────────────────────────────────────
@app.route('/account/<int:account_id>')
@login_required
def account_detail(account_id):
    db = get_db()
    account = db.execute("""
        SELECT a.*, c.full_name as coder_name, b.full_name as biller_name, au.full_name as auditor_name
        FROM accounts a
        LEFT JOIN users c ON a.assigned_coder_id=c.id
        LEFT JOIN users b ON a.assigned_biller_id=b.id
        LEFT JOIN users au ON a.auditor_id=au.id
        WHERE a.id=?
    """, (account_id,)).fetchone()
    if not account:
        flash('Account not found.', 'error')
        return redirect(url_for('inventory_list'))

    history = db.execute("""
        SELECT al.*, u.full_name FROM activity_log al
        LEFT JOIN users u ON al.user_id=u.id
        WHERE al.account_id=? ORDER BY al.created_at DESC
    """, (account_id,)).fetchall()

    return render_template('account_detail.html', account=account, history=history)

# ─── Assign Accounts ─────────────────────────────────────────────────
@app.route('/inventory/assign', methods=['POST'])
@admin_required
def assign_accounts():
    db = get_db()
    action = request.form.get('action')

    if action == 'assign_coder':
        account_ids = request.form.getlist('account_ids')
        coder_id = request.form.get('coder_id')
        if not account_ids or not coder_id:
            flash('Select accounts and a coder.', 'error')
            return redirect(url_for('inventory_list'))
        for aid in account_ids:
            db.execute("UPDATE accounts SET assigned_coder_id=?, status='Assigned to Coder' WHERE id=? AND status='Unassigned'",
                       (coder_id, aid))
            log_activity(int(aid), session['user_id'], 'Assigned to Coder', f'Coder ID: {coder_id}')
        db.commit()
        flash(f'{len(account_ids)} accounts assigned to coder.', 'success')

    elif action == 'assign_equal':
        coder_ids = request.form.getlist('coder_ids')
        if not coder_ids:
            flash('Select at least one coder.', 'error')
            return redirect(url_for('inventory_list'))
        unassigned = db.execute("SELECT id FROM accounts WHERE status='Unassigned' ORDER BY priority DESC, received_date ASC").fetchall()
        if not unassigned:
            flash('No unassigned accounts.', 'error')
            return redirect(url_for('inventory_list'))
        for i, acc in enumerate(unassigned):
            cid = coder_ids[i % len(coder_ids)]
            db.execute("UPDATE accounts SET assigned_coder_id=?, status='Assigned to Coder' WHERE id=?", (cid, acc['id']))
            log_activity(acc['id'], session['user_id'], 'Assigned to Coder (Equal)', f'Coder ID: {cid}')
        db.commit()
        flash(f'{len(unassigned)} accounts distributed equally among {len(coder_ids)} coders.', 'success')

    elif action == 'reassign':
        account_id = request.form.get('account_id')
        new_user_id = request.form.get('new_user_id')
        new_role = request.form.get('reassign_role', 'Coder')
        if account_id and new_user_id:
            if new_role == 'Coder':
                db.execute("UPDATE accounts SET assigned_coder_id=?, status='Assigned to Coder' WHERE id=?",
                           (new_user_id, account_id))
            else:
                db.execute("UPDATE accounts SET assigned_biller_id=?, status='Assigned to Biller' WHERE id=?",
                           (new_user_id, account_id))
            db.commit()
            log_activity(int(account_id), session['user_id'], 'Reassigned', f'To user ID: {new_user_id} as {new_role}')
            flash('Account reassigned.', 'success')

    elif action == 'set_priority':
        account_ids = request.form.getlist('account_ids')
        for aid in account_ids:
            db.execute("UPDATE accounts SET priority='High' WHERE id=?", (aid,))
            log_activity(int(aid), session['user_id'], 'Set High Priority', '')
        db.commit()
        flash(f'{len(account_ids)} accounts set to High Priority.', 'success')

    return redirect(url_for('inventory_list'))

# ─── Coder Actions ───────────────────────────────────────────────────
@app.route('/account/<int:account_id>/code', methods=['POST'])
@login_required
def code_account(account_id):
    if session.get('user_type') != 'Coder' and session.get('role') not in ('Admin', 'Auditor'):
        abort(403)
    db = get_db()
    account = db.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
    if not account:
        abort(404)

    action = request.form.get('action')
    comments = request.form.get('coder_comments', '').strip()

    if action == 'start':
        db.execute("UPDATE accounts SET status='Coding In Progress' WHERE id=?", (account_id,))
        log_activity(account_id, session['user_id'], 'Started Coding', '')
    elif action == 'complete':
        if not comments:
            flash('Coder comments are required.', 'error')
            return redirect(url_for('account_detail', account_id=account_id))
        # Auto-assign to biller or set as Coded
        db.execute("""UPDATE accounts SET status='Coded', coder_comments=?, coded_at=?
                      WHERE id=?""", (comments, datetime.now().isoformat(), account_id))
        log_activity(account_id, session['user_id'], 'Coding Completed', comments)

    db.commit()
    flash('Account updated.', 'success')
    return redirect(url_for('account_detail', account_id=account_id))

# ─── Biller Actions ──────────────────────────────────────────────────
@app.route('/account/<int:account_id>/bill', methods=['POST'])
@login_required
def bill_account(account_id):
    if session.get('user_type') != 'Biller' and session.get('role') not in ('Admin', 'Auditor'):
        abort(403)
    db = get_db()
    account = db.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
    if not account:
        abort(404)

    action = request.form.get('action')
    comments = request.form.get('biller_comments', '').strip()

    if action == 'start':
        db.execute("UPDATE accounts SET status='Billing In Progress' WHERE id=?", (account_id,))
        log_activity(account_id, session['user_id'], 'Started Billing', '')
    elif action == 'complete':
        if not comments:
            flash('Biller comments are required.', 'error')
            return redirect(url_for('account_detail', account_id=account_id))
        db.execute("""UPDATE accounts SET status='Finalized', biller_comments=?, billed_at=?, finalized_at=?
                      WHERE id=?""", (comments, datetime.now().isoformat(), datetime.now().isoformat(), account_id))
        log_activity(account_id, session['user_id'], 'Billing Completed / Finalized', comments)
    elif action == 'clarification':
        db.execute("""UPDATE accounts SET status='Clarification Needed', biller_comments=?, priority='High'
                      WHERE id=?""", (comments, account_id))
        log_activity(account_id, session['user_id'], 'Clarification Requested', comments)

    db.commit()
    flash('Account updated.', 'success')
    return redirect(url_for('account_detail', account_id=account_id))

# ─── Assign coded accounts to billers ─────────────────────────────────
@app.route('/inventory/assign-billers', methods=['POST'])
@admin_required
def assign_billers():
    db = get_db()
    account_ids = request.form.getlist('account_ids')
    biller_id = request.form.get('biller_id')
    action = request.form.get('action', 'assign_biller')

    if action == 'assign_biller' and account_ids and biller_id:
        for aid in account_ids:
            db.execute("UPDATE accounts SET assigned_biller_id=?, status='Assigned to Biller' WHERE id=?", (biller_id, aid))
            log_activity(int(aid), session['user_id'], 'Assigned to Biller', f'Biller ID: {biller_id}')
        db.commit()
        flash(f'{len(account_ids)} accounts assigned to biller.', 'success')
    elif action == 'assign_billers_equal':
        biller_ids = request.form.getlist('biller_ids')
        coded = db.execute("SELECT id FROM accounts WHERE status='Coded' ORDER BY priority DESC").fetchall()
        for i, acc in enumerate(coded):
            bid = biller_ids[i % len(biller_ids)]
            db.execute("UPDATE accounts SET assigned_biller_id=?, status='Assigned to Biller' WHERE id=?", (bid, acc['id']))
            log_activity(acc['id'], session['user_id'], 'Assigned to Biller (Equal)', f'Biller ID: {bid}')
        db.commit()
        flash(f'{len(coded)} coded accounts distributed among billers.', 'success')

    return redirect(url_for('inventory_list'))

# ─── Audit ────────────────────────────────────────────────────────────
@app.route('/audit')
@auditor_required
def audit_list():
    db = get_db()
    status_f = request.args.get('status', '')
    query = """SELECT a.*, c.full_name as coder_name, b.full_name as biller_name
               FROM accounts a LEFT JOIN users c ON a.assigned_coder_id=c.id
               LEFT JOIN users b ON a.assigned_biller_id=b.id
               WHERE a.status IN ('Finalized','Audited - Passed','Audited - Failed')"""
    params = []
    if status_f == 'pending':
        query = query.replace("WHERE a.status IN ('Finalized','Audited - Passed','Audited - Failed')",
                              "WHERE a.status='Finalized'")
    elif status_f == 'passed':
        query = query.replace("WHERE a.status IN ('Finalized','Audited - Passed','Audited - Failed')",
                              "WHERE a.audit_status='Passed'")
    elif status_f == 'failed':
        query = query.replace("WHERE a.status IN ('Finalized','Audited - Passed','Audited - Failed')",
                              "WHERE a.audit_status='Failed'")
    query += " ORDER BY a.finalized_at DESC"
    accounts = db.execute(query, params).fetchall()
    return render_template('audit.html', accounts=accounts, status_filter=status_f)

@app.route('/account/<int:account_id>/audit', methods=['POST'])
@auditor_required
def audit_account(account_id):
    db = get_db()
    result = request.form.get('audit_result')
    comments = request.form.get('auditor_comments', '').strip()

    if result == 'Passed':
        db.execute("""UPDATE accounts SET audit_status='Passed', auditor_id=?, auditor_comments=?,
                      audited_at=?, status='Audited - Passed' WHERE id=?""",
                   (session['user_id'], comments, datetime.now().isoformat(), account_id))
        log_activity(account_id, session['user_id'], 'Audit Passed', comments)
    elif result == 'Failed':
        if not comments:
            flash('Auditor comments are required for failed audits.', 'error')
            return redirect(url_for('account_detail', account_id=account_id))
        account = db.execute("SELECT assigned_coder_id FROM accounts WHERE id=?", (account_id,)).fetchone()
        db.execute("""UPDATE accounts SET audit_status='Failed', auditor_id=?, auditor_comments=?,
                      audited_at=?, status='Rework - Coder' WHERE id=?""",
                   (session['user_id'], comments, datetime.now().isoformat(), account_id))
        log_activity(account_id, session['user_id'], 'Audit Failed - Rework Assigned', comments)

    db.commit()
    flash('Audit recorded.', 'success')
    return redirect(url_for('audit_list'))

# ─── Production View ──────────────────────────────────────────────────
@app.route('/production')
@login_required
def production_view():
    db = get_db()
    user_id = session['user_id']
    role = session['role']
    user_type = session.get('user_type')

    if role == 'User' and user_type == 'Coder':
        accounts = db.execute("""
            SELECT * FROM accounts WHERE assigned_coder_id=?
            AND status IN ('Assigned to Coder','Coding In Progress','Rework - Coder','Clarification Needed')
            ORDER BY CASE WHEN priority='High' THEN 0 ELSE 1 END, received_date ASC
        """, (user_id,)).fetchall()
    elif role == 'User' and user_type == 'Biller':
        accounts = db.execute("""
            SELECT a.*, c.full_name as coder_name FROM accounts a
            LEFT JOIN users c ON a.assigned_coder_id=c.id
            WHERE a.assigned_biller_id=?
            AND a.status IN ('Assigned to Biller','Billing In Progress','Rework - Biller')
            ORDER BY CASE WHEN a.priority='High' THEN 0 ELSE 1 END, a.received_date ASC
        """, (user_id,)).fetchall()
    else:
        accounts = db.execute("""
            SELECT a.*, c.full_name as coder_name, b.full_name as biller_name
            FROM accounts a LEFT JOIN users c ON a.assigned_coder_id=c.id
            LEFT JOIN users b ON a.assigned_biller_id=b.id
            ORDER BY a.upload_date DESC LIMIT 200
        """).fetchall()

    stats = {
        'total': len(accounts),
        'completed': sum(1 for a in accounts if a['status'] in ('Coded', 'Finalized', 'Audited - Passed')),
        'pending': sum(1 for a in accounts if a['status'] not in ('Coded', 'Finalized', 'Audited - Passed', 'Audited - Failed')),
        'high_priority': sum(1 for a in accounts if a['priority'] == 'High'),
    }

    return render_template('production.html', accounts=accounts, stats=stats)

# ─── Export ───────────────────────────────────────────────────────────
@app.route('/export')
@admin_required
def export_data():
    db = get_db()
    date_from = request.args.get('from', '')
    date_to = request.args.get('to', '')

    query = """SELECT a.invoice_number, a.patient_name, a.received_date, a.upload_date,
               a.status, a.priority, c.full_name as coder, b.full_name as biller,
               a.coder_comments, a.biller_comments, a.audit_status,
               au.full_name as auditor, a.auditor_comments,
               a.coded_at, a.billed_at, a.finalized_at, a.audited_at, a.tat_days
               FROM accounts a
               LEFT JOIN users c ON a.assigned_coder_id=c.id
               LEFT JOIN users b ON a.assigned_biller_id=b.id
               LEFT JOIN users au ON a.auditor_id=au.id WHERE 1=1"""
    params = []
    if date_from:
        query += " AND a.upload_date >= ?"
        params.append(date_from)
    if date_to:
        query += " AND a.upload_date <= ?"
        params.append(date_to)
    query += " ORDER BY a.upload_date DESC"

    rows = db.execute(query, params).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Invoice Number', 'Patient Name', 'Received Date', 'Upload Date',
                     'Status', 'Priority', 'Coder', 'Biller', 'Coder Comments', 'Biller Comments',
                     'Audit Status', 'Auditor', 'Auditor Comments',
                     'Coded At', 'Billed At', 'Finalized At', 'Audited At', 'TAT Days'])
    for row in rows:
        writer.writerow([row[k] for k in row.keys()])

    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'production_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )

# ─── Database Backup ─────────────────────────────────────────────────
@app.route('/backup')
@admin_required
def backup_database():
    import shutil
    backup_name = f'production_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'
    backup_path = os.path.join(app.config['UPLOAD_FOLDER'], backup_name)
    shutil.copy2(DATABASE, backup_path)
    return send_file(backup_path, as_attachment=True, download_name=backup_name)

# ─── Reports ─────────────────────────────────────────────────────────
@app.route('/reports')
@admin_required
def reports():
    db = get_db()
    # Date-wise inventory
    date_inventory = db.execute("""
        SELECT upload_date, COUNT(*) as total,
        SUM(CASE WHEN status='Finalized' OR status='Audited - Passed' THEN 1 ELSE 0 END) as completed,
        SUM(CASE WHEN priority='High' THEN 1 ELSE 0 END) as high_priority
        FROM accounts GROUP BY upload_date ORDER BY upload_date DESC LIMIT 30
    """).fetchall()

    # User performance
    user_perf = db.execute("""
        SELECT u.full_name, u.user_type,
        COUNT(CASE WHEN u.user_type='Coder' THEN a.id END) as coder_count,
        COUNT(CASE WHEN u.user_type='Biller' THEN a2.id END) as biller_count
        FROM users u
        LEFT JOIN accounts a ON u.id=a.assigned_coder_id AND a.coded_at IS NOT NULL
        LEFT JOIN accounts a2 ON u.id=a2.assigned_biller_id AND a2.billed_at IS NOT NULL
        WHERE u.role='User' AND u.is_active=1
        GROUP BY u.id
    """).fetchall()

    # Quality metrics
    quality = db.execute("""
        SELECT c.full_name as coder,
        COUNT(*) as audited,
        SUM(CASE WHEN a.audit_status='Passed' THEN 1 ELSE 0 END) as passed,
        SUM(CASE WHEN a.audit_status='Failed' THEN 1 ELSE 0 END) as failed
        FROM accounts a JOIN users c ON a.assigned_coder_id=c.id
        WHERE a.audit_status IS NOT NULL
        GROUP BY a.assigned_coder_id
    """).fetchall()

    return render_template('reports.html', date_inventory=date_inventory,
                           user_perf=user_perf, quality=quality)

# ─── Emergency Reassignment ──────────────────────────────────────────
@app.route('/emergency-reassign', methods=['GET', 'POST'])
@admin_required
def emergency_reassign():
    db = get_db()
    if request.method == 'POST':
        from_user = request.form.get('from_user')
        to_user = request.form.get('to_user')
        if from_user and to_user:
            # Find all active accounts for the absent user
            updated_coder = db.execute("""
                UPDATE accounts SET assigned_coder_id=?, status='Assigned to Coder'
                WHERE assigned_coder_id=? AND status IN ('Assigned to Coder','Coding In Progress','Rework - Coder')
            """, (to_user, from_user)).rowcount
            updated_biller = db.execute("""
                UPDATE accounts SET assigned_biller_id=?, status='Assigned to Biller'
                WHERE assigned_biller_id=? AND status IN ('Assigned to Biller','Billing In Progress','Rework - Biller')
            """, (to_user, from_user)).rowcount
            db.commit()
            log_activity(None, session['user_id'], 'Emergency Reassignment',
                         f'From user {from_user} to {to_user}: {updated_coder} coder + {updated_biller} biller accounts')
            flash(f'Reassigned {updated_coder + updated_biller} accounts.', 'success')
            return redirect(url_for('dashboard'))

    users = db.execute("SELECT id, full_name, user_type, role FROM users WHERE is_active=1").fetchall()
    return render_template('emergency_reassign.html', users=users)

# ─── API endpoints for AJAX ──────────────────────────────────────────
@app.route('/api/dashboard-stats')
@login_required
def api_dashboard_stats():
    db = get_db()
    today = datetime.now().strftime('%Y-%m-%d')
    stats = {
        'total': db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0],
        'today': db.execute("SELECT COUNT(*) FROM accounts WHERE upload_date=?", (today,)).fetchone()[0],
        'finalized': db.execute("SELECT COUNT(*) FROM accounts WHERE status='Finalized'").fetchone()[0],
        'pending': db.execute("SELECT COUNT(*) FROM accounts WHERE status NOT IN ('Finalized','Audited - Passed')").fetchone()[0],
    }
    return jsonify(stats)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
