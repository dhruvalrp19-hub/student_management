from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, make_response
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from cryptography.fernet import Fernet
from functools import wraps
from datetime import datetime, timedelta
import hashlib
import secrets
import html
import re
import os
import csv
import io
import math

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change_this_secret_key_in_production')
app.permanent_session_lifetime = timedelta(minutes=30)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['student_management']
students_collection = db['students']
users_collection = db['users']
audit_collection = db['audit_logs']

# ============================================================
# ENCRYPTION & SECURITY HELPERS
# ============================================================

KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'encryption.key')

def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    return key

fernet = Fernet(load_or_create_key())

def encrypt_value(value):
    if not value:
        return ''
    return fernet.encrypt(value.encode('utf-8')).decode('utf-8')

def decrypt_value(token):
    if not token:
        return ''
    try:
        return fernet.decrypt(token.encode('utf-8')).decode('utf-8')
    except Exception:
        return token

def compute_integrity_hash(name, email, phone):
    raw = f"{name}|{email}|{phone}".encode('utf-8')
    return hashlib.sha256(raw).hexdigest()

def sanitize_input(value):
    if not value:
        return ''
    cleaned = re.sub(r'<[^>]*?>', '', value)
    return html.escape(cleaned.strip(), quote=False)

def decrypt_student(student):
    if not student:
        return student
    if student.get('is_encrypted'):
        student['phone'] = decrypt_value(student.get('phone', ''))
        student['address'] = decrypt_value(student.get('address', ''))
        student['pincode'] = decrypt_value(student.get('pincode', ''))
    return student

# ============================================================
# AUDIT LOGGING & RATE LIMITING
# ============================================================

login_attempts = {}

def is_rate_limited(ip):
    now = datetime.now()
    window = timedelta(minutes=5)
    attempts = [t for t in login_attempts.get(ip, []) if now - t < window]
    login_attempts[ip] = attempts
    return len(attempts) >= 5

def record_failed_login(ip):
    login_attempts.setdefault(ip, []).append(datetime.now())

def log_action(user, action, details):
    ip = request.remote_addr or '127.0.0.1'
    entry = {
        'timestamp': datetime.now(),
        'user': user,
        'action': action,
        'details': details,
        'ip_address': ip,
    }
    audit_collection.insert_one(entry)

    logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    os.makedirs(logs_dir, exist_ok=True)
    log_path = os.path.join(logs_dir, 'audit.log')
    with open(log_path, 'a', encoding='utf-8') as f:
        f.write(f"[{entry['timestamp'].isoformat()}] {ip} | {user} | {action} | {details}\n")

# ============================================================
# CSRF PROTECTION & SECURITY HEADERS
# ============================================================

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

def validate_csrf():
    token = session.get('_csrf_token')
    form_token = request.form.get('csrf_token')
    return token and form_token and secrets.compare_digest(token, form_token)

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# ============================================================
# DECORATORS & CONTEXT PROCESSOR
# ============================================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Admin access required for this action.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_user():
    if 'user_id' in session:
        return {
            'logged_in': True,
            'username': session.get('username', ''),
            'role': session.get('role', 'teacher')
        }
    return {'logged_in': False, 'username': '', 'role': ''}

# ============================================================
# AUTH ROUTES
# ============================================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if not validate_csrf():
            flash('Invalid CSRF token. Please try again.', 'danger')
            return render_template('register.html')

        username = sanitize_input(request.form.get('username', ''))
        email = sanitize_input(request.form.get('email', ''))
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        role = request.form.get('role', 'teacher')

        errors = []
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters.')
        if not email or '@' not in email:
            errors.append('Please enter a valid email address.')
        if not password or len(password) < 6:
            errors.append('Password must be at least 6 characters.')
        if password != confirm_password:
            errors.append('Passwords do not match.')
        if role not in ['admin', 'teacher']:
            errors.append('Invalid role selected.')

        if users_collection.find_one({'$or': [{'username': username}, {'email': email}]}):
            errors.append('Username or email already exists.')

        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('register.html')

        user_data = {
            'username': username,
            'email': email,
            'password': generate_password_hash(password, method='pbkdf2:sha256:260000'),
            'role': role,
            'is_active': True,
            'created_at': datetime.now(),
            'last_login': None,
        }
        users_collection.insert_one(user_data)
        log_action(username, 'USER_REGISTERED', f'Registered new {role} account')
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not validate_csrf():
            flash('Invalid CSRF token. Please try again.', 'danger')
            return render_template('login.html')

        ip = request.remote_addr or '127.0.0.1'
        if is_rate_limited(ip):
            flash('Too many failed login attempts. Please try again in 5 minutes.', 'danger')
            return render_template('login.html')

        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')

        user = users_collection.find_one({'username': username})
        if user and check_password_hash(user['password'], password):
            if not user.get('is_active', True):
                flash('Your account has been deactivated. Contact an administrator.', 'danger')
                return render_template('login.html')

            session.permanent = True
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            session['role'] = user['role']
            users_collection.update_one({'_id': user['_id']}, {'$set': {'last_login': datetime.now()}})
            log_action(user['username'], 'USER_LOGIN', 'Logged in successfully')
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(url_for('index'))
        else:
            record_failed_login(ip)
            log_action(username or 'anonymous', 'LOGIN_FAILED', 'Invalid username or password')
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    if 'user_id' in session:
        log_action(username, 'USER_LOGOUT', 'Logged out')
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        if not validate_csrf():
            flash('Invalid CSRF token. Please try again.', 'danger')
            return render_template('change_password.html')

        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
        if not user or not check_password_hash(user['password'], current_password):
            flash('Current password is incorrect.', 'danger')
            return render_template('change_password.html')

        if len(new_password) < 8:
            flash('New password must be at least 8 characters.', 'danger')
            return render_template('change_password.html')

        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return render_template('change_password.html')

        users_collection.update_one(
            {'_id': user['_id']},
            {'$set': {'password': generate_password_hash(new_password, method='pbkdf2:sha256:260000')}}
        )
        log_action(user['username'], 'PASSWORD_CHANGED', 'Updated account password')
        flash('Password updated successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('change_password.html')

# ============================================================
# MAIN ROUTES
# ============================================================

@app.route('/')
@login_required
def index():
    total_students = students_collection.count_documents({})
    total_users = users_collection.count_documents({})

    class_data = list(students_collection.aggregate([
        {'$group': {'_id': '$class', 'count': {'$sum': 1}}},
        {'$sort': {'_id': 1}}
    ]))
    city_data = list(students_collection.aggregate([
        {'$group': {'_id': '$city', 'count': {'$sum': 1}}},
        {'$sort': {'count': -1}},
        {'$limit': 10}
    ]))
    recent_logs = list(audit_collection.find().sort('timestamp', -1).limit(5))

    return render_template('index.html',
                           total_students=total_students,
                           total_users=total_users,
                           class_data=class_data,
                           city_data=city_data,
                           recent_logs=recent_logs)

# ============================================================
# STUDENT CRUD ROUTES
# ============================================================

@app.route('/add_student', methods=['GET', 'POST'])
@login_required
def add_student():
    if request.method == 'POST':
        if not validate_csrf():
            flash('Invalid CSRF token. Please try again.', 'danger')
            return render_template('add_student.html')

        name = sanitize_input(request.form.get('name', ''))
        age = request.form.get('age', '').strip()
        email = sanitize_input(request.form.get('email', ''))
        student_class = sanitize_input(request.form.get('class', ''))
        address = sanitize_input(request.form.get('address', ''))
        birthdate = sanitize_input(request.form.get('birthdate', ''))
        city = sanitize_input(request.form.get('city', ''))
        pincode = sanitize_input(request.form.get('pincode', ''))
        phone = sanitize_input(request.form.get('phone', ''))
        gender = sanitize_input(request.form.get('gender', ''))

        errors = []
        if not name or len(name) < 2:
            errors.append('Name must be at least 2 characters.')
        if not age or not age.isdigit() or int(age) < 5 or int(age) > 100:
            errors.append('Age must be a number between 5 and 100.')
        if not email or '@' not in email:
            errors.append('Please enter a valid email.')
        if not student_class:
            errors.append('Class is required.')
        if pincode and (not pincode.isdigit() or len(pincode) != 6):
            errors.append('Pincode must be a 6-digit number.')
        if phone and (not phone.isdigit() or len(phone) != 10):
            errors.append('Phone must be a 10-digit number.')
        if students_collection.find_one({'email': email}):
            errors.append('A student with this email already exists.')

        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('add_student.html')

        student_data = {
            'name': name,
            'age': int(age),
            'email': email,
            'class': student_class,
            'address': encrypt_value(address),
            'birthdate': birthdate,
            'city': city,
            'pincode': encrypt_value(pincode),
            'phone': encrypt_value(phone),
            'gender': gender,
            'is_encrypted': True,
            'integrity_hash': compute_integrity_hash(name, email, phone),
            'created_at': datetime.now(),
            'added_by': session.get('username', 'unknown')
        }
        students_collection.insert_one(student_data)
        log_action(session.get('username', 'unknown'), 'STUDENT_ADDED', f'Added student {name} ({email})')
        flash('Student added and encrypted successfully!', 'success')
        return redirect(url_for('view_students'))

    return render_template('add_student.html')

@app.route('/student/<student_id>')
@login_required
def student_profile(student_id):
    try:
        student = students_collection.find_one({'_id': ObjectId(student_id)})
    except Exception:
        flash('Invalid student ID.', 'danger')
        return redirect(url_for('view_students'))

    if not student:
        flash('Student not found.', 'danger')
        return redirect(url_for('view_students'))

    decrypt_student(student)
    expected_hash = compute_integrity_hash(
        student.get('name', ''),
        student.get('email', ''),
        student.get('phone', '')
    )
    stored_hash = student.get('integrity_hash', '')
    integrity_ok = (stored_hash == expected_hash) if stored_hash else True

    return render_template('student_profile.html', student=student, integrity_ok=integrity_ok)

@app.route('/edit_student/<student_id>', methods=['GET', 'POST'])
@login_required
def edit_student(student_id):
    try:
        student = students_collection.find_one({'_id': ObjectId(student_id)})
    except Exception:
        flash('Invalid student ID.', 'danger')
        return redirect(url_for('view_students'))

    if not student:
        flash('Student not found.', 'danger')
        return redirect(url_for('view_students'))

    if request.method == 'POST':
        if not validate_csrf():
            flash('Invalid CSRF token. Please try again.', 'danger')
            decrypt_student(student)
            return render_template('edit_student.html', student=student)

        name = sanitize_input(request.form.get('name', ''))
        email = sanitize_input(request.form.get('email', ''))
        phone = sanitize_input(request.form.get('phone', ''))
        address = sanitize_input(request.form.get('address', ''))
        pincode = sanitize_input(request.form.get('pincode', ''))

        updated_data = {
            'name': name,
            'age': int(request.form.get('age', 0)),
            'email': email,
            'class': sanitize_input(request.form.get('class', '')),
            'address': encrypt_value(address),
            'birthdate': sanitize_input(request.form.get('birthdate', '')),
            'city': sanitize_input(request.form.get('city', '')),
            'pincode': encrypt_value(pincode),
            'phone': encrypt_value(phone),
            'gender': sanitize_input(request.form.get('gender', '')),
            'is_encrypted': True,
            'integrity_hash': compute_integrity_hash(name, email, phone),
            'updated_at': datetime.now(),
            'updated_by': session.get('username', 'unknown')
        }
        students_collection.update_one({'_id': ObjectId(student_id)}, {'$set': updated_data})
        log_action(session.get('username', 'unknown'), 'STUDENT_UPDATED', f'Updated student {name}')
        flash('Student updated successfully!', 'success')
        return redirect(url_for('view_students'))

    decrypt_student(student)
    return render_template('edit_student.html', student=student)

@app.route('/delete_student/<student_id>')
@admin_required
def delete_student(student_id):
    try:
        student = students_collection.find_one({'_id': ObjectId(student_id)})
        result = students_collection.delete_one({'_id': ObjectId(student_id)})
        if result.deleted_count:
            name = student.get('name', student_id) if student else student_id
            log_action(session.get('username', 'unknown'), 'STUDENT_DELETED', f'Deleted student {name}')
            flash('Student deleted successfully!', 'success')
        else:
            flash('Student not found.', 'danger')
    except Exception:
        flash('Invalid student ID.', 'danger')
    return redirect(url_for('view_students'))

# ============================================================
# VIEW STUDENTS WITH SEARCH, FILTER, SORT & PAGINATION
# ============================================================

@app.route('/view_students')
@login_required
def view_students():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    search = request.args.get('search', '').strip()
    filter_class = request.args.get('filter_class', '').strip()
    filter_city = request.args.get('filter_city', '').strip()
    sort_by = request.args.get('sort_by', 'created_at')
    sort_order = request.args.get('sort_order', 'desc')

    query = {}
    if search:
        query['$or'] = [
            {'name': {'$regex': search, '$options': 'i'}},
            {'email': {'$regex': search, '$options': 'i'}}
        ]
    if filter_class:
        query['class'] = filter_class
    if filter_city:
        query['city'] = {'$regex': filter_city, '$options': 'i'}

    sort_dir = 1 if sort_order == 'asc' else -1
    allowed_sorts = {'name', 'age', 'class', 'city', 'created_at'}
    sort_field = sort_by if sort_by in allowed_sorts else 'created_at'

    total = students_collection.count_documents(query)
    total_pages = math.ceil(total / per_page) if total > 0 else 1
    students = list(
        students_collection.find(query)
        .sort(sort_field, sort_dir)
        .skip((page - 1) * per_page)
        .limit(per_page)
    )
    for s in students:
        decrypt_student(s)

    all_classes = students_collection.distinct('class')
    all_cities = students_collection.distinct('city')

    return render_template('view_students.html',
                           students=students,
                           page=page,
                           total_pages=total_pages,
                           total=total,
                           search=search,
                           filter_class=filter_class,
                           filter_city=filter_city,
                           sort_by=sort_by,
                           sort_order=sort_order,
                           all_classes=all_classes,
                           all_cities=all_cities)

# ============================================================
# EXPORT TO CSV
# ============================================================

@app.route('/export_csv')
@login_required
def export_csv():
    students = list(students_collection.find())

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Name', 'Age', 'Email', 'Class', 'Address', 'Birthdate', 'City', 'Pincode', 'Phone', 'Gender'])

    for s in students:
        decrypt_student(s)
        writer.writerow([
            s.get('name', ''),
            s.get('age', ''),
            s.get('email', ''),
            s.get('class', ''),
            s.get('address', ''),
            s.get('birthdate', ''),
            s.get('city', ''),
            s.get('pincode', ''),
            s.get('phone', ''),
            s.get('gender', '')
        ])

    log_action(session.get('username', 'unknown'), 'CSV_EXPORTED', f'Exported {len(students)} student records')
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=students_export.csv'
    response.headers['Content-Type'] = 'text/csv'
    return response

# ============================================================
# DASHBOARD
# ============================================================

@app.route('/dashboard')
@login_required
def dashboard():
    total_students = students_collection.count_documents({})
    total_users = users_collection.count_documents({})

    class_data = list(students_collection.aggregate([
        {'$group': {'_id': '$class', 'count': {'$sum': 1}}},
        {'$sort': {'_id': 1}}
    ]))
    city_data = list(students_collection.aggregate([
        {'$group': {'_id': '$city', 'count': {'$sum': 1}}},
        {'$sort': {'count': -1}},
        {'$limit': 10}
    ]))
    gender_data = list(students_collection.aggregate([
        {'$group': {'_id': '$gender', 'count': {'$sum': 1}}}
    ]))
    recent_students = list(students_collection.find().sort('created_at', -1).limit(5))

    return render_template('dashboard.html',
                           total_students=total_students,
                           total_users=total_users,
                           class_data=class_data,
                           city_data=city_data,
                           gender_data=gender_data,
                           recent_students=recent_students)

# ============================================================
# ENCRYPTION DEMO & ADMIN ROUTES
# ============================================================

@app.route('/encryption_demo', methods=['GET', 'POST'])
@login_required
def encryption_demo():
    result = None
    if request.method == 'POST':
        action = request.form.get('action')
        text = request.form.get('text', '')
        if action == 'encrypt':
            result = {
                'action': 'encrypt',
                'original': text,
                'encrypted': encrypt_value(text),
                'hash_sha256': hashlib.sha256(text.encode('utf-8')).hexdigest()
            }
        elif action == 'decrypt':
            result = {
                'action': 'decrypt',
                'original': text,
                'decrypted': decrypt_value(text)
            }
    return render_template('encryption_demo.html', result=result)

@app.route('/audit_logs')
@admin_required
def audit_logs():
    page = request.args.get('page', 1, type=int)
    per_page = 15
    action_filter = request.args.get('action', '').strip()

    query = {'action': action_filter} if action_filter else {}
    total = audit_collection.count_documents(query)
    total_pages = math.ceil(total / per_page) if total > 0 else 1
    logs = list(
        audit_collection.find(query)
        .sort('timestamp', -1)
        .skip((page - 1) * per_page)
        .limit(per_page)
    )
    all_actions = audit_collection.distinct('action')

    return render_template('audit_logs.html',
                           logs=logs,
                           page=page,
                           total_pages=total_pages,
                           total=total,
                           action_filter=action_filter,
                           all_actions=all_actions)

@app.route('/manage_users')
@admin_required
def manage_users():
    users = list(users_collection.find().sort('created_at', -1))
    return render_template('manage_users.html', users=users)

@app.route('/toggle_user/<user_id>')
@admin_required
def toggle_user(user_id):
    if user_id == session.get('user_id'):
        flash('You cannot deactivate your own account.', 'warning')
        return redirect(url_for('manage_users'))
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if user:
            new_state = not user.get('is_active', True)
            users_collection.update_one({'_id': user['_id']}, {'$set': {'is_active': new_state}})
            status_text = 'activated' if new_state else 'deactivated'
            log_action(session.get('username', 'unknown'), 'USER_TOGGLED', f'{status_text} user {user["username"]}')
            flash(f'User {user["username"]} {status_text}.', 'success')
    except Exception:
        flash('Invalid user ID.', 'danger')
    return redirect(url_for('manage_users'))

@app.route('/delete_user/<user_id>')
@admin_required
def delete_user(user_id):
    if user_id == session.get('user_id'):
        flash('You cannot delete your own account.', 'warning')
        return redirect(url_for('manage_users'))
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        result = users_collection.delete_one({'_id': ObjectId(user_id)})
        if result.deleted_count:
            username = user.get('username', user_id) if user else user_id
            log_action(session.get('username', 'unknown'), 'USER_DELETED', f'Deleted user {username}')
            flash(f'User {username} deleted.', 'success')
    except Exception:
        flash('Invalid user ID.', 'danger')
    return redirect(url_for('manage_users'))

# ============================================================
# REST API ENDPOINTS
# ============================================================

@app.route('/api/students', methods=['GET'])
def api_get_students():
    search = request.args.get('search', '')
    query = {}
    if search:
        query['$or'] = [
            {'name': {'$regex': search, '$options': 'i'}},
            {'email': {'$regex': search, '$options': 'i'}}
        ]

    students = list(students_collection.find(query))
    for s in students:
        s['_id'] = str(s['_id'])
        decrypt_student(s)
    return jsonify({'success': True, 'data': students, 'count': len(students)})

@app.route('/api/students/<student_id>', methods=['GET'])
def api_get_student(student_id):
    try:
        student = students_collection.find_one({'_id': ObjectId(student_id)})
        if student:
            student['_id'] = str(student['_id'])
            decrypt_student(student)
            return jsonify({'success': True, 'data': student})
        return jsonify({'success': False, 'message': 'Student not found'}), 404
    except Exception:
        return jsonify({'success': False, 'message': 'Invalid ID'}), 400

@app.route('/api/students', methods=['POST'])
def api_add_student():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400

    for field in ['name', 'age', 'email', 'class']:
        if field not in data:
            return jsonify({'success': False, 'message': f'Missing field: {field}'}), 400

    data['created_at'] = datetime.now()
    data['added_by'] = 'api'
    result = students_collection.insert_one(data)
    return jsonify({'success': True, 'message': 'Student added', 'id': str(result.inserted_id)}), 201

@app.route('/api/students/<student_id>', methods=['PUT'])
def api_update_student(student_id):
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400
    try:
        data['updated_at'] = datetime.now()
        result = students_collection.update_one({'_id': ObjectId(student_id)}, {'$set': data})
        if result.matched_count:
            return jsonify({'success': True, 'message': 'Student updated'})
        return jsonify({'success': False, 'message': 'Student not found'}), 404
    except Exception:
        return jsonify({'success': False, 'message': 'Invalid ID'}), 400

@app.route('/api/students/<student_id>', methods=['DELETE'])
def api_delete_student(student_id):
    try:
        result = students_collection.delete_one({'_id': ObjectId(student_id)})
        if result.deleted_count:
            return jsonify({'success': True, 'message': 'Student deleted'})
        return jsonify({'success': False, 'message': 'Student not found'}), 404
    except Exception:
        return jsonify({'success': False, 'message': 'Invalid ID'}), 400

@app.route('/api/stats', methods=['GET'])
def api_stats():
    total = students_collection.count_documents({})
    class_data = list(students_collection.aggregate([
        {'$group': {'_id': '$class', 'count': {'$sum': 1}}}
    ]))
    city_data = list(students_collection.aggregate([
        {'$group': {'_id': '$city', 'count': {'$sum': 1}}}
    ]))
    return jsonify({
        'success': True,
        'total_students': total,
        'by_class': class_data,
        'by_city': city_data
    })

# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html'), 500

# ============================================================
# RUN
# ============================================================

if __name__ == '__main__':
    app.run(debug=True)
