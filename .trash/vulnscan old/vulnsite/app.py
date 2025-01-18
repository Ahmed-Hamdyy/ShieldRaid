# app.py

from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
import sqlite3
import os
import subprocess
import logging
from datetime import datetime
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Hardcoded secret key (not secure)

# Set up logging
if not os.path.exists('logs'):
    os.makedirs('logs')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.FileHandler("logs/honeypot.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# Mail configuration (replace with your email server settings)
app.config['MAIL_SERVER'] = 'smtp.example.com'      # Replace with your SMTP server
app.config['MAIL_PORT'] = 587                       # Replace with your SMTP port
app.config['MAIL_USERNAME'] = 'your_email@example.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'your_email_password'     # Replace with your email password
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

# Database setup
def init_db():
    conn = sqlite3.connect('vulnerable_app.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    ''')
    c.execute('''
        INSERT OR IGNORE INTO users (username, password, role) VALUES ('admin', 'adminpass', 'admin')
    ''')
    # Table for logging activities
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip_address TEXT,
            endpoint TEXT,
            method TEXT,
            headers TEXT,
            params TEXT,
            data TEXT,
            user_agent TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Helper function to log requests
def log_request(request):
    conn = sqlite3.connect('vulnerable_app.db')
    c = conn.cursor()
    c.execute('''
        INSERT INTO logs (timestamp, ip_address, endpoint, method, headers, params, data, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        request.remote_addr,
        request.path,
        request.method,
        str(dict(request.headers)),
        str(request.args.to_dict()),
        str(request.form.to_dict()),
        request.headers.get('User-Agent')
    ))
    conn.commit()
    conn.close()

    # Log to file
    logger.info(f"IP: {request.remote_addr}, Endpoint: {request.path}, Method: {request.method}, Params: {request.args.to_dict()}, Data: {request.form.to_dict()}, User-Agent: {request.headers.get('User-Agent')}")

    # Detect potential SQL injection in parameters
    sql_injection_patterns = ["'", '"', '--', ';', '/*', '*/', '@@', '@', 'char', 'nchar', 'varchar', 'nvarchar',
                              'alter', 'begin', 'cast', 'create', 'cursor', 'declare', 'delete', 'drop', 'end',
                              'exec', 'execute', 'fetch', 'insert', 'kill', 'open', 'select', 'sys', 'sysobjects',
                              'syscolumns', 'table', 'update']
    combined_params = str(request.args.to_dict()) + str(request.form.to_dict())
    if any(pattern in combined_params.lower() for pattern in sql_injection_patterns):
        alert_subject = "Honeypot Alert: Potential SQL Injection Detected"
        alert_body = f"""
A potential SQL injection attempt was detected.

IP Address: {request.remote_addr}
Endpoint: {request.path}
Method: {request.method}
Params: {request.args.to_dict()}
Data: {request.form.to_dict()}
User-Agent: {request.headers.get('User-Agent')}
"""
        logger.warning("Potential SQL injection detected.")
        send_alert(alert_subject, alert_body)

# Function to send alert emails
def send_alert(subject, body):
    try:
        msg = Message(subject, sender=app.config['MAIL_USERNAME'], recipients=['admin@example.com'])  # Replace with your admin email
        msg.body = body
        mail.send(msg)
        logger.info("Alert email sent.")
    except Exception as e:
        logger.error(f"Failed to send alert email: {e}")

# Before request handler to log all incoming requests
@app.before_request
def before_request():
    log_request(request)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

# SQL Injection Vulnerable Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        # Vulnerable SQL query
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('vulnerable_app.db')
        c = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        c.execute(query)
        user = c.fetchone()
        conn.close()
        if user:
            session['username'] = user[1]
            session['role'] = user[3]
            return redirect('/dashboard')
        else:
            error = 'Invalid credentials'
    return render_template('login.html', error=error)

# Reflected XSS
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Displaying user input directly without sanitization
    return render_template('search.html', query=query)

# Insecure File Upload
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        f = request.files['file']
        # Saving the uploaded file without validation
        upload_path = os.path.join('uploads', f.filename)
        f.save(upload_path)
        return f"File uploaded to {upload_path}"
    return render_template('upload.html')

# IDOR Vulnerability
@app.route('/user/<int:user_id>')
def user_profile(user_id):
    # Directly accessing user profiles without authorization checks
    conn = sqlite3.connect('vulnerable_app.db')
    c = conn.cursor()
    c.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        return render_template('profile.html', user=user)
    else:
        return "User not found"

# Command Injection
@app.route('/ping', methods=['GET', 'POST'])
def ping():
    result = ''
    if request.method == 'POST':
        target = request.form['target']
        # Unsafe use of subprocess with user input
        cmd = f"ping -c 4 {target}"
        result = subprocess.getoutput(cmd)
    return render_template('ping.html', result=result)

# Directory Traversal
@app.route('/download')
def download():
    filename = request.args.get('file')
    # No validation of the file path
    return send_from_directory('.', filename, as_attachment=True)

# Open Redirect
@app.route('/redirect')
def open_redirect():
    url = request.args.get('url')
    return redirect(url)

# CSRF Vulnerable Form
@app.route('/update_profile', methods=['GET', 'POST'])
def update_profile():
    if request.method == 'POST':
        # No CSRF token implemented
        # Update user profile logic here (omitted for brevity)
        return "Profile updated"
    return render_template('update_profile.html')

# Missing Security Headers
@app.after_request
def add_headers(response):
    # Intentionally not setting security headers
    return response

# Weak Password Policy and Mass Assignment
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Weak password policy (no validation)
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'user')  # Mass Assignment Vulnerability
        conn = sqlite3.connect('vulnerable_app.db')
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))
        conn.commit()
        conn.close()
        return "Registration successful"
    return render_template('register.html')

# Clickjacking Vulnerability
@app.route('/frame_me')
def frame_me():
    # This page can be framed
    return render_template('frame_me.html')

# Error Handling (Information Disclosure)
@app.route('/cause_error')
def cause_error():
    # Deliberately cause an error to display a stack trace
    return 1 / 0

# Admin Dashboard (requires authentication)
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'], role=session.get('role', 'user'))
    else:
        return redirect('/login')

# View Logs (Admin Interface)
@app.route('/admin/logs')
def view_logs():
    if session.get('role') == 'admin':
        conn = sqlite3.connect('vulnerable_app.db')
        c = conn.cursor()
        c.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100")
        logs = c.fetchall()
        conn.close()
        return render_template('logs.html', logs=logs)
    else:
        return "Access denied", 403

# Logout Functionality
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
