# 🛡️ Student Management System (Secure)

A **full-stack web application** built with **Flask + MongoDB** featuring comprehensive **Information & Network Security (INS)** implementations.

---

## 🚀 Features

### Core Features
- ✅ **Full CRUD Operations** — Create, Read, Update, Delete students
- ✅ **User Authentication** — Login, Register, Logout with session management
- ✅ **Role-Based Access Control (RBAC)** — Admin and Teacher roles
- ✅ **Search & Filter** — Search by name/email, filter by class/city
- ✅ **Pagination & Sorting** — Paginated results with column sorting
- ✅ **Student Profile** — Detailed student profile view
- ✅ **CSV Export** — Download all student data as CSV
- ✅ **Dashboard Analytics** — Interactive charts (class, city, gender distribution)
- ✅ **REST API** — Full RESTful API endpoints (GET, POST, PUT, DELETE)
- ✅ **User Management** — Admin can activate/deactivate/delete users
- ✅ **Responsive UI** — Modern dark-themed design with Bootstrap 5

### 🔒 Security Features (INS)
- ✅ **AES-128 Encryption (Fernet)** — Sensitive data (phone, address, pincode) encrypted at rest
- ✅ **SHA-256 Hashing** — Data integrity verification for each student record
- ✅ **Password Hashing (PBKDF2-SHA256)** — 260,000 iterations with random salt
- ✅ **CSRF Protection** — Token-based cross-site request forgery prevention
- ✅ **XSS Prevention** — Input sanitization removes HTML/script tags
- ✅ **Rate Limiting** — Brute-force login protection (5 attempts / 5 minutes)
- ✅ **Security Headers** — X-Frame-Options, X-XSS-Protection, nosniff, etc.
- ✅ **Session Security** — HTTPOnly cookies, 30-minute timeout, SameSite policy
- ✅ **Audit Logging** — Complete activity trail stored in MongoDB + log files
- ✅ **Encryption Demo Page** — Interactive encrypt/decrypt/hash demonstration
- ✅ **Data Integrity Check** — SHA-256 hash verification on student profiles
- ✅ **Account Lockout** — Deactivate/activate user accounts
- ✅ **Password Strength Meter** — Real-time password strength checker
- ✅ **Error Handling** — Custom 404 and 500 error pages

---

## 🛠️ Tech Stack

| Technology | Purpose |
|-----------|---------|
| **Python 3.x** | Backend language |
| **Flask** | Web framework |
| **MongoDB** | NoSQL database |
| **PyMongo** | MongoDB driver |
| **Cryptography (Fernet)** | AES-128 encryption |
| **Werkzeug** | Password hashing (PBKDF2) |
| **Bootstrap 5** | Frontend UI framework |
| **Chart.js** | Dashboard charts |
| **Jinja2** | Template engine |

---

## 📁 Project Structure

```
student_management_system/
├── app.py                      # Main Flask application (600+ lines)
├── requirements.txt            # Python dependencies
├── encryption.key              # AES encryption key (auto-generated)
├── README.md                   # Project documentation
├── logs/
│   └── audit.log               # Audit trail log file
└── templates/
    ├── base.html               # Base template (navbar, footer, styles)
    ├── index.html              # Home page with stats & quick actions
    ├── login.html              # Login page with CSRF protection
    ├── register.html           # Registration with password strength
    ├── add_student.html        # Add student form (encrypted fields)
    ├── edit_student.html       # Edit student form
    ├── view_students.html      # Students table with search/filter
    ├── student_profile.html    # Student profile with integrity check
    ├── dashboard.html          # Analytics with Chart.js
    ├── change_password.html    # Change password page
    ├── encryption_demo.html    # Interactive encryption demo
    ├── audit_logs.html         # Audit log viewer (admin)
    ├── manage_users.html       # User management (admin)
    ├── 404.html                # Custom 404 page
    └── 500.html                # Custom 500 page
```

---

## ⚙️ Installation & Setup

### Prerequisites
- Python 3.8+
- MongoDB (running on localhost:27017)

### Steps

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start MongoDB** (make sure it's running on port 27017)

3. **Run the application:**
   ```bash
   python app.py
   ```

4. **Open browser:** Navigate to `http://127.0.0.1:5000`

5. **Register** a new account and start using the system!

---

## 🔐 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/students` | Get all students (with optional `?search=`) |
| GET | `/api/students/<id>` | Get student by ID |
| POST | `/api/students` | Add new student (JSON body) |
| PUT | `/api/students/<id>` | Update student (JSON body) |
| DELETE | `/api/students/<id>` | Delete student |
| GET | `/api/stats` | Get dashboard statistics |

---

## 🔒 Security Implementation Details

### AES Encryption (Fernet)
- Uses `cryptography.fernet.Fernet` (AES-128-CBC + HMAC-SHA256)
- Encrypts: Phone number, Address, Pincode
- Key stored in `encryption.key` file
- Data decrypted only when displayed to authenticated users

### Password Security
- Hashed with `PBKDF2:SHA256` with 260,000 iterations
- Random salt added per password
- Never stored in plain text

### Data Integrity
- SHA-256 hash computed on `name + email + phone`
- Hash stored alongside student record
- Verified on profile view to detect tampering

---

## 👨‍💻 Author

Built as a Semester 6 INS (Information & Network Security) Project

---

## 📜 License

This project is for educational purposes.