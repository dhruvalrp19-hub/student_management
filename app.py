from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, make_response
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from functools import wraps
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import csv
import io
import math
import os
import re
import random
import hashlib
import secrets
import logging
from logging.handlers import RotatingFileHandler

# ============================================================
# APP CONFIGURATION
# ============================================================

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# ============================================================
# LOGGING SETUP (Audit Trail)
# ============================================================

if not os.path.exists('logs'):
    os.makedirs('logs')

file_handler = RotatingFileHandler('logs/audit.log', maxBytes=1024 * 1024, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s | %(levelname)s | %(message)s'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Student Management System started')

# ============================================================
# MONGODB CONNECTION
# ============================================================

client = MongoClient('mongodb://localhost:27017/')
db = client['student_management']
students_collection = db['students']
users_collection = db['users']
audit_collection = db['audit_logs']

# Create indexes for performance (safe for existing data)
try:
    students_collection.create_index([('name', 1)])
    students_collection.create_index([('class', 1)])
    students_collection.create_index([('email', 1)])
    users_collection.create_index([('username', 1)], unique=True, sparse=True)
    users_collection.create_index([('email', 1)], unique=True, sparse=True)
except Exception:
    pass  # Indexes may already exist or duplicates prevent unique index

# ============================================================
# AES ENCRYPTION MODULE (INS Feature)
# ============================================================

ENCRYPTION_KEY_FILE = 'encryption.key'

def load_or_generate_key():
    """Load existing Fernet key or generate a new one."""
    if os.path.exists(ENCRYPTION_KEY_FILE):
        with open(ENCRYPTION_KEY_FILE, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(ENCRYPTION_KEY_FILE, 'wb') as f:
            f.write(key)
        return key

FERNET_KEY = load_or_generate_key()
cipher = Fernet(FERNET_KEY)

def encrypt_data(plain_text):
    """Encrypt sensitive data using AES (Fernet = AES-128-CBC + HMAC)."""
    if not plain_text:
        return plain_text
    return cipher.encrypt(plain_text.encode()).decode()

def decrypt_data(encrypted_text):
    """Decrypt data encrypted with AES."""
    if not encrypted_text:
        return encrypted_text
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception:
        return encrypted_text  # Return as-is if not encrypted (backward compat)

def hash_data_sha256(data):
    """Create SHA-256 hash for data integrity verification."""
    return hashlib.sha256(data.encode()).hexdigest()

# ============================================================
# AUTO SEED DATA (fills MongoDB automatically - no manual entry)
# ============================================================

SEED_FIRST_NAMES = [
    'Aarav', 'Vivaan', 'Aditya', 'Krish', 'Arjun', 'Rohan', 'Dev', 'Harsh',
    'Jay', 'Meet', 'Yash', 'Parth', 'Om', 'Raj', 'Kunal',
    'Ananya', 'Diya', 'Isha', 'Kavya', 'Meera', 'Nisha', 'Priya', 'Riya',
    'Sneha', 'Tanvi', 'Zoya', 'Pooja', 'Komal', 'Hetal', 'Jinal',
]
SEED_LAST_NAMES = [
    'Patel', 'Shah', 'Mehta', 'Desai', 'Joshi', 'Trivedi', 'Parmar', 'Solanki',
    'Vyas', 'Thakkar', 'Modi', 'Chauhan', 'Rathod', 'Gandhi', 'Bhatt',
    'Sharma', 'Verma', 'Singh', 'Pandya', 'Raval',
]
SEED_CITIES = {
    'Nadiad': '387001', 'Ahmedabad': '380001', 'Vadodara': '390001',
    'Surat': '395001', 'Rajkot': '360001', 'Anand': '388001',
    'Gandhinagar': '382010', 'Bharuch': '392001', 'Kheda': '387411',
    'Mehsana': '384001',
}
SEED_CLASS_AGE = {
    '5th': 10, '6th': 11, '7th': 12, '8th': 13, '9th': 14, '10th': 15,
    '11th': 16, '12th': 17, 'FY BCA': 18, 'SY BCA': 19, 'TY BCA': 20,
}
SEED_STREETS = ['Station Road', 'MG Road', 'College Road', 'Gandhi Chowk',
                'Ring Road', 'Society Area', 'Main Bazaar', 'Park Lane']


def seed_default_users():
    """Create default admin + teacher accounts if they don't exist."""
    users = [
        ('admin', 'admin@school.com', 'Admin@123', 'admin'),
        ('teacher', 'teacher@school.com', 'Teacher@123', 'teacher'),
    ]
    added = 0
    for username, email, password, role in users:
        if users_collection.find_one({'$or': [{'username': username}, {'email': email}]}):
            continue
        users_collection.insert_one({
            'username': username,
            'email': email,
            'password': generate_password_hash(password, method='pbkdf2:sha256:260000'),
            'role': role,
            'created_at': datetime.now(),
            'last_login': None,
            'is_active': True
        })
        added += 1
    return added


def _make_seed_student(index):
    first = random.choice(SEED_FIRST_NAMES)
    last = random.choice(SEED_LAST_NAMES)
    name = f'{first} {last}'
    email = f'{first.lower()}.{last.lower()}{index}{random.randint(10, 99)}@example.com'
    student_class = random.choice(list(SEED_CLASS_AGE))
    age = SEED_CLASS_AGE[student_class] + random.randint(0, 1)
    city = random.choice(list(SEED_CITIES))
    pincode = SEED_CITIES[city]
    phone = str(random.choice([6, 7, 8, 9])) + ''.join(random.choices('0123456789', k=9))
    address = f'{random.randint(1, 250)}, {random.choice(SEED_STREETS)}, {city}'
    birthdate = (datetime.now() - timedelta(days=age * 365 + random.randint(0, 364))).strftime('%Y-%m-%d')

    return {
        'name': name,
        'age': age,
        'email': email,
        'class': student_class,
        'address': encrypt_data(address),
        'birthdate': birthdate,
        'city': city,
        'pincode': encrypt_data(pincode),
        'phone': encrypt_data(phone),
        'gender': random.choice(['Male', 'Female']),
        'is_encrypted': True,
        'data_hash': hash_data_sha256(f'{name}{email}{phone}'),
        'created_at': datetime.now() - timedelta(days=random.randint(0, 60)),
        'added_by': 'auto_seed'
    }


def seed_sample_students(count=50):
    """Insert random sample students (skips emails that already exist)."""
    docs = [_make_seed_student(i) for i in range(count)]
    existing = {d['email'] for d in students_collection.find({}, {'email': 1})}
    docs = [d for d in docs if d['email'] not in existing]
    if docs:
        students_collection.insert_many(docs)
    return len(docs)


def auto_seed_database(student_count=50):
    """Runs at startup. Seeds only when the collections are empty."""
    try:
        users_added = seed_default_users() if users_collection.count_documents({}) == 0 else 0
        students_added = seed_sample_students(student_count) if students_collection.count_documents({}) == 0 else 0
        if users_added or students_added:
            audit_collection.insert_one({
                'timestamp': datetime.now(),
                'user': 'auto_seed',
                'action': 'DATA_SEEDED',
                'details': f'{students_added} students, {users_added} users auto-created',
                'ip_address': 'system',
                'user_agent': 'system'
            })
            app.logger.info(f'AUTO SEED | {students_added} students, {users_added} users')
            print(f'[AUTO SEED] {students_added} students and {users_added} users created.')
            if users_added:
                print('[AUTO SEED] Login: admin / Admin@123  or  teacher / Teacher@123')
    except Exception as e:
        print(f'[AUTO SEED] Skipped: {e}')

# ============================================================
# CSRF PROTECTION (INS Feature)
# ============================================================

def generate_csrf_token():
    """Generate a CSRF token and store in session."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

def validate_csrf_token():
    """Validate the CSRF token from form submission."""
    token = session.get('_csrf_token', None)
    form_token = request.form.get('csrf_token', None)
    if not token or token != form_token:
        return False
    return True

app.jinja_env.globals['csrf_token'] = generate_csrf_token

# ============================================================
# AUDIT LOGGING (INS Feature)
# ============================================================

def log_audit(action, details, user=None):
    """Log an audit trail entry to both file and MongoDB."""
    username = user or session.get('username', 'anonymous')
    entry = {
        'timestamp': datetime.now(),
        'user': username,
        'action': action,
        'details': details,
        'ip_address': request.remote_addr if request else 'system',
        'user_agent': request.headers.get('User-Agent', 'unknown') if request else 'system'
    }
    audit_collection.insert_one(entry)
    app.logger.info(f"AUDIT | {username} | {action} | {details}")

# ============================================================
# RATE LIMITING (INS Feature)
# ============================================================

login_attempts = {}  # Simple in-memory rate limiter

def check_rate_limit(identifier, max_attempts=5, window_seconds=300):
    """Check if login attempts exceed the limit."""
    now = datetime.now()
    if identifier in login_attempts:
        attempts = login_attempts[identifier]
        attempts = [t for t in attempts if (now - t).total_seconds() < window_seconds]
        login_attempts[identifier] = attempts
        if len(attempts) >= max_attempts:
            return False
    return True

def record_login_attempt(identifier):
    """Record a failed login attempt."""
    if identifier not in login_attempts:
        login_attempts[identifier] = []
    login_attempts[identifier].append(datetime.now())

# ============================================================
# INPUT VALIDATION & SANITIZATION (INS Feature)
# ============================================================

def sanitize_input(text):
    """Sanitize input to prevent XSS attacks."""
    if not text:
        return text
    text = re.sub(r'<[^>]+>', '', text)
    text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
    text = re.sub(r'on\w+\s*=', '', text, flags=re.IGNORECASE)
    return text.strip()

def validate_email(email):
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_phone(phone):
    """Validate 10-digit phone number."""
    return re.match(r'^\d{10}$', phone) is not None

def validate_pincode(pincode):
    """Validate 6-digit pincode."""
    return re.match(r'^\d{6}$', pincode) is not None

# ============================================================
# PASSWORD STRENGTH CHECKER (INS Feature)
# ============================================================

def check_password_strength(password):
    """Check password strength and return score + feedback."""
    score = 0
    feedback = []

    if len(password) >= 8:
        score += 1
    else:
        feedback.append('Password should be at least 8 characters.')

    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append('Add uppercase letters.')

    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append('Add lowercase letters.')

    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append('Add numbers.')

    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    else:
        feedback.append('Add special characters (!@#$%^&*).')

    strength = 'Weak'
    if score >= 4:
        strength = 'Strong'
    elif score >= 3:
        strength = 'Medium'

    return {'score': score, 'strength': strength, 'feedback': feedback}

# ============================================================
# DECORATORS
# ============================================================

def login_required(f):
    """Decorator to require login for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role for a route."""
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

# ============================================================
# CONTEXT PROCESSOR
# ============================================================

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
# SECURITY HEADERS MIDDLEWARE (INS Feature)
# ============================================================

@app.after_request
def add_security_headers(response):
    """Add security headers to every response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response

# ============================================================
# AUTH ROUTES
# ============================================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if not validate_csrf_token():
            flash('Invalid request. Please try again.', 'danger')
            return render_template('register.html')

        username = sanitize_input(request.form.get('username', ''))
        email = sanitize_input(request.form.get('email', ''))
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        role = request.form.get('role', 'teacher')

        errors = []
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters.')
        if not validate_email(email):
            errors.append('Please enter a valid email address.')

        pwd_check = check_password_strength(password)
        if pwd_check['score'] < 3:
            errors.append(f'Password too weak ({pwd_check["strength"]}). {" ".join(pwd_check["feedback"])}')

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
            'created_at': datetime.now(),
            'last_login': None,
            'is_active': True
        }
        users_collection.insert_one(user_data)
        log_audit('USER_REGISTERED', f'New user registered: {username} ({role})')
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not validate_csrf_token():
            flash('Invalid request. Please try again.', 'danger')
            return render_template('login.html')

        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')

        if not check_rate_limit(request.remote_addr):
            flash('Too many login attempts. Please wait 5 minutes.', 'danger')
            log_audit('LOGIN_RATE_LIMITED', f'Rate limited IP: {request.remote_addr}', user=username)
            return render_template('login.html')

        user = users_collection.find_one({'username': username})
        if user and check_password_hash(user['password'], password):
            if not user.get('is_active', True):
                flash('Account is deactivated. Contact admin.', 'danger')
                return render_template('login.html')

            session.permanent = True
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            session['role'] = user['role']
            session['login_time'] = datetime.now().isoformat()

            users_collection.update_one(
                {'_id': user['_id']},
                {'$set': {'last_login': datetime.now()}}
            )

            log_audit('LOGIN_SUCCESS', f'User logged in: {username}')
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(url_for('index'))
        else:
            record_login_attempt(request.remote_addr)
            log_audit('LOGIN_FAILED', f'Failed login attempt for: {username}')
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    log_audit('LOGOUT', f'User logged out: {username}')
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# ============================================================
# CHANGE PASSWORD (INS Feature)
# ============================================================

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        if not validate_csrf_token():
            flash('Invalid request.', 'danger')
            return render_template('change_password.html')

        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        user = users_collection.find_one({'_id': ObjectId(session['user_id'])})

        if not check_password_hash(user['password'], current_password):
            flash('Current password is incorrect.', 'danger')
            return render_template('change_password.html')

        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return render_template('change_password.html')

        pwd_check = check_password_strength(new_password)
        if pwd_check['score'] < 3:
            flash(f'New password too weak. {" ".join(pwd_check["feedback"])}', 'danger')
            return render_template('change_password.html')

        users_collection.update_one(
            {'_id': ObjectId(session['user_id'])},
            {'$set': {'password': generate_password_hash(new_password, method='pbkdf2:sha256:260000')}}
        )
        log_audit('PASSWORD_CHANGED', f'Password changed for: {session["username"]}')
        flash('Password changed successfully!', 'success')
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

    pipeline = [
        {'$group': {'_id': '$class', 'count': {'$sum': 1}}},
        {'$sort': {'_id': 1}}
    ]
    class_data = list(students_collection.aggregate(pipeline))

    city_pipeline = [
        {'$group': {'_id': '$city', 'count': {'$sum': 1}}},
        {'$sort': {'count': -1}},
        {'$limit': 10}
    ]
    city_data = list(students_collection.aggregate(city_pipeline))

    recent_logs = list(audit_collection.find().sort('timestamp', -1).limit(5))

    return render_template('index.html',
                           total_students=total_students,
                           total_users=total_users,
                           class_data=class_data,
                           city_data=city_data,
                           recent_logs=recent_logs)

# ============================================================
# STUDENT CRUD ROUTES (with Encryption)
# ============================================================

@app.route('/add_student', methods=['GET', 'POST'])
@login_required
def add_student():
    if request.method == 'POST':
        if not validate_csrf_token():
            flash('Invalid request. Please try again.', 'danger')
            return render_template('add_student.html')

        name = sanitize_input(request.form.get('name', ''))
        age = request.form.get('age', '')
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
        if not validate_email(email):
            errors.append('Please enter a valid email.')
        if not student_class:
            errors.append('Class is required.')
        if pincode and not validate_pincode(pincode):
            errors.append('Pincode must be a 6-digit number.')
        if phone and not validate_phone(phone):
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
            'address': encrypt_data(address),
            'birthdate': birthdate,
            'city': city,
            'pincode': encrypt_data(pincode),
            'phone': encrypt_data(phone),
            'gender': gender,
            'is_encrypted': True,
            'data_hash': hash_data_sha256(f"{name}{email}{phone}"),
            'created_at': datetime.now(),
            'added_by': session.get('username', 'unknown')
        }
        students_collection.insert_one(student_data)
        log_audit('STUDENT_ADDED', f'Student added: {name} ({email})')
        flash('Student added successfully! Sensitive data encrypted with AES.', 'success')
        return redirect(url_for('view_students'))
    return render_template('add_student.html')

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

    if student.get('is_encrypted'):
        student['address'] = decrypt_data(student.get('address', ''))
        student['pincode'] = decrypt_data(student.get('pincode', ''))
        student['phone'] = decrypt_data(student.get('phone', ''))

    if request.method == 'POST':
        if not validate_csrf_token():
            flash('Invalid request.', 'danger')
            return render_template('edit_student.html', student=student)

        name = sanitize_input(request.form.get('name', ''))
        phone = sanitize_input(request.form.get('phone', ''))
        address = sanitize_input(request.form.get('address', ''))
        pincode = sanitize_input(request.form.get('pincode', ''))
        email = sanitize_input(request.form.get('email', ''))

        updated_data = {
            'name': name,
            'age': int(request.form.get('age', 0) or 0),
            'email': email,
            'class': sanitize_input(request.form.get('class', '')),
            'address': encrypt_data(address),
            'birthdate': sanitize_input(request.form.get('birthdate', '')),
            'city': sanitize_input(request.form.get('city', '')),
            'pincode': encrypt_data(pincode),
            'phone': encrypt_data(phone),
            'gender': sanitize_input(request.form.get('gender', '')),
            'is_encrypted': True,
            'data_hash': hash_data_sha256(f"{name}{email}{phone}"),
            'updated_at': datetime.now(),
            'updated_by': session.get('username', 'unknown')
        }
        students_collection.update_one({'_id': ObjectId(student_id)}, {'$set': updated_data})
        log_audit('STUDENT_UPDATED', f'Student updated: {name} (ID: {student_id})')
        flash('Student updated successfully!', 'success')
        return redirect(url_for('view_students'))

    return render_template('edit_student.html', student=student)

@app.route('/delete_student/<student_id>')
@admin_required
def delete_student(student_id):
    try:
        student = students_collection.find_one({'_id': ObjectId(student_id)})
        result = students_collection.delete_one({'_id': ObjectId(student_id)})
        if result.deleted_count:
            student_name = student.get('name', 'Unknown') if student else 'Unknown'
            log_audit('STUDENT_DELETED', f'Student deleted: {student_name} (ID: {student_id})')
            flash('Student deleted successfully!', 'success')
        else:
            flash('Student not found.', 'danger')
    except Exception:
        flash('Invalid student ID.', 'danger')
    return redirect(url_for('view_students'))

# ============================================================
# VIEW STUDENTS WITH SEARCH, FILTER & PAGINATION
# ============================================================

@app.route('/view_students')
@login_required
def view_students():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    search = sanitize_input(request.args.get('search', ''))
    filter_class = sanitize_input(request.args.get('filter_class', ''))
    filter_city = sanitize_input(request.args.get('filter_city', ''))
    sort_by = request.args.get('sort_by', 'name')
    sort_order = request.args.get('sort_order', 'asc')

    # Only allow sorting by known fields
    if sort_by not in ['name', 'age', 'email', 'class', 'city', 'created_at']:
        sort_by = 'name'

    query = {}
    if search:
        safe_search = re.escape(search)
        query['$or'] = [
            {'name': {'$regex': safe_search, '$options': 'i'}},
            {'email': {'$regex': safe_search, '$options': 'i'}}
        ]
    if filter_class:
        query['class'] = filter_class
    if filter_city:
        query['city'] = {'$regex': re.escape(filter_city), '$options': 'i'}

    sort_dir = 1 if sort_order == 'asc' else -1

    total = students_collection.count_documents(query)
    total_pages = math.ceil(total / per_page) if total > 0 else 1
    students = list(
        students_collection.find(query)
        .sort(sort_by, sort_dir)
        .skip((page - 1) * per_page)
        .limit(per_page)
    )

    for s in students:
        if s.get('is_encrypted'):
            s['address'] = decrypt_data(s.get('address', ''))
            s['pincode'] = decrypt_data(s.get('pincode', ''))
            s['phone'] = decrypt_data(s.get('phone', ''))

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
# STUDENT PROFILE VIEW
# ============================================================

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

    if student.get('is_encrypted'):
        student['address'] = decrypt_data(student.get('address', ''))
        student['pincode'] = decrypt_data(student.get('pincode', ''))
        student['phone'] = decrypt_data(student.get('phone', ''))

    expected_hash = hash_data_sha256(f"{student.get('name','')}{student.get('email','')}{student.get('phone','')}")
    integrity_ok = expected_hash == student.get('data_hash', '')

    return render_template('student_profile.html', student=student, integrity_ok=integrity_ok)

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
        address = decrypt_data(s.get('address', '')) if s.get('is_encrypted') else s.get('address', '')
        pincode = decrypt_data(s.get('pincode', '')) if s.get('is_encrypted') else s.get('pincode', '')
        phone = decrypt_data(s.get('phone', '')) if s.get('is_encrypted') else s.get('phone', '')

        writer.writerow([
            s.get('name', ''),
            s.get('age', ''),
            s.get('email', ''),
            s.get('class', ''),
            address,
            s.get('birthdate', ''),
            s.get('city', ''),
            pincode,
            phone,
            s.get('gender', '')
        ])

    log_audit('DATA_EXPORTED', f'CSV exported by {session.get("username", "unknown")} ({len(students)} records)')

    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename=students_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    response.headers['Content-Type'] = 'text/csv'
    return response

# ============================================================
# DASHBOARD WITH ANALYTICS
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

    try:
        age_data = list(students_collection.aggregate([
            {'$bucket': {
                'groupBy': '$age',
                'boundaries': [0, 10, 15, 18, 22, 30, 100],
                'default': 'Other',
                'output': {'count': {'$sum': 1}}
            }}
        ]))
    except Exception:
        age_data = []

    recent_students = list(students_collection.find().sort('created_at', -1).limit(5))
    for s in recent_students:
        if s.get('is_encrypted'):
            s['phone'] = decrypt_data(s.get('phone', ''))

    return render_template('dashboard.html',
                           total_students=total_students,
                           total_users=total_users,
                           class_data=class_data,
                           city_data=city_data,
                           gender_data=gender_data,
                           age_data=age_data,
                           recent_students=recent_students)

# ============================================================
# AUDIT LOG VIEWER (Admin Only)
# ============================================================

@app.route('/audit_logs')
@admin_required
def audit_logs():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    action_filter = request.args.get('action', '')

    query = {}
    if action_filter:
        query['action'] = action_filter

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

# ============================================================
# USER MANAGEMENT (Admin Only)
# ============================================================

@app.route('/manage_users')
@admin_required
def manage_users():
    users = list(users_collection.find())
    return render_template('manage_users.html', users=users)

@app.route('/toggle_user/<user_id>')
@admin_required
def toggle_user(user_id):
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if user:
            new_status = not user.get('is_active', True)
            users_collection.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {'is_active': new_status}}
            )
            status_text = 'activated' if new_status else 'deactivated'
            log_audit('USER_STATUS_CHANGED', f'User {user["username"]} {status_text}')
            flash(f'User {user["username"]} {status_text}.', 'success')
    except Exception:
        flash('Invalid user ID.', 'danger')
    return redirect(url_for('manage_users'))

@app.route('/delete_user/<user_id>')
@admin_required
def delete_user(user_id):
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if user and str(user['_id']) != session.get('user_id'):
            users_collection.delete_one({'_id': ObjectId(user_id)})
            log_audit('USER_DELETED', f'User deleted: {user["username"]}')
            flash(f'User {user["username"]} deleted.', 'success')
        else:
            flash('Cannot delete your own account.', 'danger')
    except Exception:
        flash('Invalid user ID.', 'danger')
    return redirect(url_for('manage_users'))

# ============================================================
# ADMIN: ADD MORE SAMPLE DATA WITH ONE CLICK
# ============================================================

@app.route('/seed_data')
@admin_required
def seed_data_route():
    """Admin-only: visit /seed_data?count=30 to add more random students."""
    count = request.args.get('count', 30, type=int)
    count = max(1, min(count, 500))
    added = seed_sample_students(count)
    log_audit('DATA_SEEDED', f'{added} sample students added by admin')
    flash(f'{added} sample students added automatically.', 'success')
    return redirect(url_for('view_students'))

# ============================================================
# ENCRYPTION DEMO PAGE (INS Feature)
# ============================================================

@app.route('/encryption_demo', methods=['GET', 'POST'])
@login_required
def encryption_demo():
    result = None
    if request.method == 'POST':
        text = request.form.get('text', '')
        action = request.form.get('action', 'encrypt')

        if action == 'encrypt':
            encrypted = encrypt_data(text)
            hashed = hash_data_sha256(text)
            result = {
                'original': text,
                'encrypted': encrypted,
                'hash_sha256': hashed,
                'action': 'encrypt'
            }
        elif action == 'decrypt':
            decrypted = decrypt_data(text)
            result = {
                'original': text,
                'decrypted': decrypted,
                'action': 'decrypt'
            }

    return render_template('encryption_demo.html', result=result)

# ============================================================
# REST API ENDPOINTS
# ============================================================

@app.route('/api/students', methods=['GET'])
def api_get_students():
    """API: Get all students with optional search."""
    search = request.args.get('search', '')
    query = {}
    if search:
        safe_search = re.escape(search)
        query['$or'] = [
            {'name': {'$regex': safe_search, '$options': 'i'}},
            {'email': {'$regex': safe_search, '$options': 'i'}}
        ]

    students = list(students_collection.find(query))
    for s in students:
        s['_id'] = str(s['_id'])
        if s.get('is_encrypted'):
            s['phone'] = decrypt_data(s.get('phone', ''))
            s['address'] = decrypt_data(s.get('address', ''))
            s['pincode'] = decrypt_data(s.get('pincode', ''))
        s.pop('data_hash', None)
        s.pop('is_encrypted', None)
    return jsonify({'success': True, 'data': students, 'count': len(students)})

@app.route('/api/students/<student_id>', methods=['GET'])
def api_get_student(student_id):
    """API: Get a single student by ID."""
    try:
        student = students_collection.find_one({'_id': ObjectId(student_id)})
        if student:
            student['_id'] = str(student['_id'])
            if student.get('is_encrypted'):
                student['phone'] = decrypt_data(student.get('phone', ''))
                student['address'] = decrypt_data(student.get('address', ''))
                student['pincode'] = decrypt_data(student.get('pincode', ''))
            return jsonify({'success': True, 'data': student})
        return jsonify({'success': False, 'message': 'Student not found'}), 404
    except Exception:
        return jsonify({'success': False, 'message': 'Invalid ID'}), 400

@app.route('/api/students', methods=['POST'])
def api_add_student():
    """API: Add a new student via JSON."""
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400

    required_fields = ['name', 'age', 'email', 'class']
    for field in required_fields:
        if field not in data:
            return jsonify({'success': False, 'message': f'Missing field: {field}'}), 400

    if 'address' in data:
        data['address'] = encrypt_data(data['address'])
    if 'phone' in data:
        data['phone'] = encrypt_data(data['phone'])
    if 'pincode' in data:
        data['pincode'] = encrypt_data(data['pincode'])

    data['is_encrypted'] = True
    data['created_at'] = datetime.now()
    data['added_by'] = 'api'
    data['data_hash'] = hash_data_sha256(f"{data.get('name','')}{data.get('email','')}{data.get('phone','')}")
    result = students_collection.insert_one(data)
    return jsonify({'success': True, 'message': 'Student added', 'id': str(result.inserted_id)}), 201

@app.route('/api/students/<student_id>', methods=['PUT'])
def api_update_student(student_id):
    """API: Update a student."""
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400
    try:
        if 'address' in data:
            data['address'] = encrypt_data(data['address'])
        if 'phone' in data:
            data['phone'] = encrypt_data(data['phone'])
        if 'pincode' in data:
            data['pincode'] = encrypt_data(data['pincode'])
        data['is_encrypted'] = True
        data['updated_at'] = datetime.now()
        result = students_collection.update_one({'_id': ObjectId(student_id)}, {'$set': data})
        if result.matched_count:
            return jsonify({'success': True, 'message': 'Student updated'})
        return jsonify({'success': False, 'message': 'Student not found'}), 404
    except Exception:
        return jsonify({'success': False, 'message': 'Invalid ID'}), 400

@app.route('/api/students/<student_id>', methods=['DELETE'])
def api_delete_student(student_id):
    """API: Delete a student."""
    try:
        result = students_collection.delete_one({'_id': ObjectId(student_id)})
        if result.deleted_count:
            return jsonify({'success': True, 'message': 'Student deleted'})
        return jsonify({'success': False, 'message': 'Student not found'}), 404
    except Exception:
        return jsonify({'success': False, 'message': 'Invalid ID'}), 400

@app.route('/api/stats', methods=['GET'])
def api_stats():
    """API: Get dashboard statistics."""
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
    # Flask debug reloader starts the app twice; seed only in the real worker
    if os.environ.get('WERKZEUG_RUN_MAIN') == 'true' or not app.debug:
        auto_seed_database(student_count=50)
    app.run(debug=True)
