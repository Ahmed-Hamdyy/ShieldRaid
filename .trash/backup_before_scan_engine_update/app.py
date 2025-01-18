# app.py

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, Response, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from supabase import create_client
import os
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps
import json
import time
import requests
from queue import Queue
import queue
from flask import stream_with_context
import threading
from threading import Lock
import asyncio
import aiohttp
import sqlite3
import html
import random
from flask_socketio import SocketIO, emit
from dotenv import load_dotenv

# Import scanner manager
from scan_tools.scanner_manager import ScannerManager

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-here')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
socketio = SocketIO(app)

# Initialize Supabase clients
supabase_url = os.getenv('SUPABASE_URL')
supabase_key = os.getenv('SUPABASE_KEY')
supabase = create_client(supabase_url, supabase_key)

# Initialize service role client for admin operations
supabase_service_key = os.getenv('SUPABASE_SECRET')
supabase_admin = create_client(supabase_url, supabase_service_key)

# Configure Logging
logging.basicConfig(level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')
logger = logging.getLogger(__name__)

# Initialize progress queue
progress_queue = Queue()

# Initialize scanner manager
scanner_manager = ScannerManager()

# Add datetime filter to Jinja
@app.template_filter('datetime')
def format_datetime(value, format='%Y-%m-%d %H:%M:%S'):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            return value
    return value.strftime(format)

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

async def perform_scan(target_url, selected_modules=None):
    logger.info(f"Starting scan for {target_url} with modules: {selected_modules}")
    
    try:
        # Clear any old progress updates
        while not progress_queue.empty():
            progress_queue.get_nowait()
            
        # Initial connection test
        progress_queue.put_nowait({
            'progress': 0,
            'status': 'testing',
            'message': 'Testing connection...'
        })
        
        # Run scan using scanner manager
        scan_results = await scanner_manager.run_scan(target_url, selected_modules, progress_queue)
        
        logger.info(f"Scan completed for {target_url}")
        return scan_results['vulnerabilities']
        
    except Exception as e:
        logger.error(f"Error during scan: {e}")
        progress_queue.put_nowait({
            'progress': -1,
            'status': 'error',
            'message': f'Scan error: {str(e)}'
        })
        return [{
            "type": "Scan Error",
            "description": f"Error during scan: {str(e)}",
            "location": "Scan Function",
            "severity": "Error"
        }]

def perform_scan_async(target_url, selected_modules=None):
    """Run the scan in a background thread"""
    def run_scan():
        try:
            # Create event loop for the thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Run initial progress update
            progress_queue.put({
                'progress': 0,
                'status': 'starting',
                'message': 'Starting scan...'
            })
            
            # Perform scan
            scan_results = loop.run_until_complete(scanner_manager.run_scan(target_url, selected_modules, progress_queue))
            
            # Store results in session
            session['latest_scan_results'] = {
                'vulnerabilities': scan_results.get('vulnerabilities', []),
                'scan_duration': round(time.time() - session.get('scan_start_time', time.time()), 2),
                'target_url': target_url,
                'stats': scan_results.get('stats', {})
            }
            
            # Send completion update
            progress_queue.put({
                'progress': 100,
                'status': 'complete',
                'message': 'Scan completed successfully'
            })
            
            # Close the event loop
            loop.close()
            
        except Exception as e:
            logger.error(f"Error in scan thread: {str(e)}")
            progress_queue.put({
                'progress': -1,
                'status': 'error',
                'message': f'Scan error: {str(e)}'
            })
    
    # Start scan in background thread
    scan_thread = threading.Thread(target=run_scan)
    scan_thread.daemon = True
    scan_thread.start()
    return scan_thread

@app.route('/')
def index():
    try:
        # Redirect to vulnscan if user is logged in
        if 'user_id' in session:
            return redirect(url_for('vulnscan'))
        return render_template('landing.html')
    except Exception as e:
        logger.error(f"Error in landing page route: {str(e)}")
        return render_template('landing.html')

@app.route('/landing')
def landing():
    # Redirect to vulnscan if user is logged in
    if 'user_id' in session:
        return redirect(url_for('vulnscan'))
    return render_template('landing.html')

@app.route('/vulnscan')
@login_required
def vulnscan():
    try:
        # Get recent scans for the user
        recent_scans = []
        user_id = session.get('user_id')
        scans_response = supabase_admin.table('scans')\
            .select('*')\
            .eq('user_id', user_id)\
            .order('created_at', desc=True)\
            .limit(5)\
            .execute()
            
        if scans_response.data:
            for scan in scans_response.data:
                try:
                    vulnerabilities = json.loads(scan.get('vulnerabilities', '[]'))
                    stats = json.loads(scan.get('stats', '{}'))
                    
                    recent_scans.append({
                        'target_url': scan.get('target_url'),
                        'created_at': scan.get('created_at'),
                        'vulnerabilities': vulnerabilities,
                        'stats': stats,
                        'scan_duration': scan.get('scan_duration', 0)
                    })
                except Exception as e:
                    logger.error(f"Error processing scan {scan.get('id')}: {str(e)}")
                    continue

        return render_template('index.html', recent_scans=recent_scans)
    except Exception as e:
        logger.error(f"Error in vulnscan route: {str(e)}")
        return render_template('index.html', recent_scans=[])

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Redirect to vulnscan if already logged in
    if 'user_id' in session:
        return redirect(url_for('vulnscan'))
        
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            if not all([username, email, password, confirm_password]):
                flash('Please fill in all fields', 'danger')
                return render_template('register.html')
                
            if password != confirm_password:
                flash('Passwords do not match', 'danger')
                return render_template('register.html')
                
            # Check if username or email already exists
            existing_user = supabase_admin.table('users')\
                .select('*')\
                .or_(f"username.eq.{username},email.eq.{email}")\
                .execute()
                
            if existing_user.data:
                flash('Username or email already exists', 'danger')
                return render_template('register.html')
                
            # Create new user
            hashed_password = generate_password_hash(password)
            confirmation_code = ''.join(random.choices('0123456789', k=6))
            
            new_user = {
                'username': username,
                'email': email,
                'password': hashed_password,
                'email_verified': False,
                'confirmation_code': confirmation_code
            }
            
            response = supabase_admin.table('users').insert(new_user).execute()
            
            if not response.data:
                flash('Error creating account', 'danger')
                return render_template('register.html')
                
            # Send confirmation email
            send_confirmation_email(email, confirmation_code)
            
            flash('Registration successful! Please verify your email.', 'success')
            return redirect(url_for('verify_email', email=email))
            
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            flash('An error occurred during registration', 'danger')
            return render_template('register.html')
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Redirect to vulnscan if already logged in
    if 'user_id' in session:
        return redirect(url_for('vulnscan'))
        
    if request.method == 'POST':
        try:
            login = request.form.get('login')
            password = request.form.get('password')
            remember_me = request.form.get('remember_me')
            
            if not login or not password:
                flash('Please provide both username/email and password', 'danger')
                return render_template('login.html')
            
            # Try to find user by username or email
            auth_response = supabase.auth.sign_in_with_password({
                "email": login,
                "password": password
            })
            
            if auth_response.user:
                # Get user details from our users table
                user_data = supabase.table('users').select('*').eq('id', auth_response.user.id).execute()
                
                if user_data.data:
                    user = user_data.data[0]
                    session['user_id'] = user['id']
                    if remember_me:
                        session.permanent = True
                    flash('Login successful!', 'success')
                    return redirect(url_for('vulnscan'))
                    
            flash('Invalid login credentials', 'danger')
            return render_template('login.html')
            
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('Invalid username/email or password', 'danger')
            return render_template('login.html')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        # Get all scans for the current user from database using service role client
        scans = supabase_admin.table('scans').select('*').eq('user_id', session['user_id']).execute()

        if not scans.data:
            return render_template('dashboard.html', 
                                total_scans=0,
                                total_vulnerabilities=0,
                                scan_history=[])

        # Calculate stats
        total_scans = len(scans.data)
        total_vulnerabilities = 0
        scan_history = []

        for scan in scans.data:
            try:
                # Parse vulnerabilities JSON string
                vulnerabilities = json.loads(scan.get('vulnerabilities', '[]'))
                total_vulnerabilities += len(vulnerabilities)
                
                # Format scan data for display
                scan_data = {
                    'target_url': scan.get('target_url'),
                    'created_at': scan.get('created_at'),
                    'scan_duration': scan.get('scan_duration'),
                    'vulnerabilities': vulnerabilities
                }
                scan_history.append(scan_data)
                
            except json.JSONDecodeError as e:
                logger.error(f"Error processing scan stats: {e}")
                continue

        # Sort scan history by created_at in descending order
        scan_history.sort(key=lambda x: x['created_at'], reverse=True)

        return render_template('dashboard.html',
                            total_scans=total_scans,
                            total_vulnerabilities=total_vulnerabilities,
                            scan_history=scan_history)

    except Exception as e:
        logger.error(f"Error loading dashboard: {str(e)}")
        flash('Error loading dashboard data', 'error')
        return redirect(url_for('index'))

@app.route('/scan', methods=['POST'])
@login_required
def scan():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'No URL provided'}), 400

        url = data['url']
        selected_modules = data.get('modules', [])
        logger.info(f"Starting scan for URL: {url} with modules: {selected_modules}")

        # Initialize scanner manager if not already done
        if not hasattr(app, 'scanner_manager'):
            app.scanner_manager = ScannerManager()

        # Perform scan with selected modules
        scan_results = app.scanner_manager.scan_url(url, selected_modules)
        
        if scan_results is None:
            return jsonify({'error': 'Scan failed'}), 500

        try:
            # Try to save scan results to database using service role client
            scan_data = {
                'user_id': session['user_id'],
                'target_url': url,
                'vulnerabilities': json.dumps(scan_results['vulnerabilities']),
                'stats': json.dumps(scan_results['stats']),
                'scan_duration': scan_results['scan_duration'],
                'created_at': datetime.now().strftime('%Y-%m-%d %I:%M:%S.%f')
            }
            
            supabase_admin.table('scans').insert(scan_data).execute()
        except Exception as db_error:
            # Log database error but continue with scan results
            logger.error(f"Database error (continuing anyway): {str(db_error)}")

        # Return scan results even if database save failed
        return jsonify(scan_results)

    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/scan_results')
def scan_results():
    try:
        results = session.get('scan_results')
        if not results:
            return jsonify({'error': 'No scan results found'}), 404
            
        # Return raw results for frontend to handle formatting
        return jsonify(results)
        
    except Exception as e:
        app.logger.error(f"Error retrieving scan results: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/upload_to_database', methods=['POST'])
def upload_to_database():
    try:
        # Get results from session
        results = session.get('scan_results')
        if not results:
            return jsonify({'error': 'No scan results found'}), 404
            
        # Get user ID from session
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'User not authenticated'}), 401
            
        # Insert into database
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        
        scan_data = {
            'user_id': user_id,
            'target_url': results['target_url'],
            'vulnerabilities': json.dumps(results['vulnerabilities']),
            'scan_duration': results.get('scan_duration', 0),
            'stats': json.dumps(results['stats'])
        }
        
        response = supabase.table('scans').insert(scan_data).execute()
        
        if response.data:
            return jsonify({
                'status': 'success',
                'message': 'Results saved to database'
            })
        else:
            return jsonify({'error': 'Failed to save to database'}), 500
            
    except Exception as e:
        app.logger.error(f"Error saving to database: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/auth/confirm')
def confirm_token():
    token = request.args.get('token')
    type = request.args.get('type', 'signup')  # signup or recovery
    error = None

    try:
        if not token:
            error = "No confirmation token provided."
        else:
            # Verify the token with Supabase Auth
            if type == 'signup':
                result = supabase.auth.verify_signup({
                    "token": token,
                    "type": "signup"
                })
                if result.user:
                    return render_template('confirm_token.html')
            elif type == 'recovery':
                # Handle password recovery confirmation
                result = supabase.auth.verify_otp({
                    "token": token,
                    "type": "recovery"
                })
                if result.user:
                    return render_template('confirm_token.html')
            
            error = "Invalid or expired confirmation token."
    except Exception as e:
        error = str(e)
        logger.error(f"Token confirmation error: {error}")

    return render_template('confirm_token.html', error=error)

@app.route('/auth/verify')
def verify_email():
    """Handle email verification callback from Supabase"""
    token = request.args.get('token')
    if not token:
        return redirect(url_for('confirm_token', error="No verification token provided"))
    
    return redirect(url_for('confirm_token', token=token, type='signup'))

@app.route('/auth/recovery')
def password_recovery():
    """Handle password recovery callback from Supabase"""
    token = request.args.get('token')
    if not token:
        return redirect(url_for('confirm_token', error="No recovery token provided"))
    
    return redirect(url_for('confirm_token', token=token, type='recovery'))

@app.route('/verify-email')
def verify_email_page():
    """Show email verification page"""
    if 'pending_verification_email' not in session:
        return redirect(url_for('login'))
    
    return render_template('verify_email.html', email=session['pending_verification_email'])

@app.route('/verify-email/code', methods=['POST'])
def verify_email_code():
    """Handle OTP code verification"""
    if 'pending_verification_email' not in session:
        return redirect(url_for('login'))
    
    code = request.form.get('code')
    email = session['pending_verification_email']
    
    try:
        # Verify OTP with Supabase
        result = supabase.auth.verify_otp({
            "email": email,
            "token": code,
            "type": "signup"
        })
        
        if result.user:
            # Clear verification session
            session.pop('pending_verification_email', None)
            
            # Set login session
            session['access_token'] = result.session.access_token
            session['user_id'] = result.user.id
            session['email'] = result.user.email
            
            # Get username
            user_data = supabase.table('users').select('username').eq('id', result.user.id).execute()
            if user_data.data:
                session['username'] = user_data.data[0]['username']
            
            flash('Email verified successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid verification code.', 'error')
            return redirect(url_for('verify_email_page'))
            
    except Exception as e:
        flash(f'Verification failed: {str(e)}', 'error')
        return redirect(url_for('verify_email_page'))

@app.route('/resend-verification', methods=['POST'])
def resend_verification():
    """Resend verification email"""
    if 'pending_verification_email' not in session:
        return redirect(url_for('login'))
    
    email = session['pending_verification_email']
    
    try:
        # Request new verification email by initiating a new sign up
        # This will resend the verification email without creating a new user
        # if the email already exists
        supabase.auth.sign_up({
            "email": email,
            "password": "temporary-password",  # This won't affect existing account
            "options": {
                "data": {
                    "email": email
                },
                "redirect_to": url_for('verify_email_page', _external=True)
            }
        })
        
        flash('New verification email sent! Please check your inbox.', 'success')
    except Exception as e:
        if "User already registered" in str(e):
            flash('New verification email sent! Please check your inbox.', 'success')
        else:
            flash(f'Failed to send verification email: {str(e)}', 'error')
    
    return redirect(url_for('verify_email_page'))

@app.route('/test/vulnerable', methods=['GET'])
def vulnerable_test_page():
    """Test page with intentional vulnerabilities for scanner testing"""
    return render_template('vulnerable_test.html')

@app.route('/test/sql', methods=['GET', 'POST'])
def sql_vulnerable():
    """Vulnerable SQL injection endpoint"""
    result = None
    error = None
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        try:
            # Intentionally vulnerable SQL query
            conn = sqlite3.connect('test.db')
            cursor = conn.cursor()
            # DO NOT USE THIS IN PRODUCTION - THIS IS INTENTIONALLY VULNERABLE
            query = f"SELECT * FROM users WHERE username = '{username}'"
            cursor.execute(query)
            result = cursor.fetchall()
            conn.close()
        except Exception as e:
            error = str(e)
    
    return render_template('sql_test.html', result=result, error=error)

@app.route('/test/xss', methods=['GET', 'POST'])
def xss_vulnerable():
    """Vulnerable XSS endpoint"""
    if request.method == 'POST':
        # Intentionally vulnerable to XSS
        message = request.form.get('message', '')
        # DO NOT USE THIS IN PRODUCTION - THIS IS INTENTIONALLY VULNERABLE
        return f"<p>Your message: {message}</p>"
    return render_template('xss_test.html')

@app.route('/test/csrf', methods=['GET', 'POST'])
def csrf_vulnerable():
    """Vulnerable CSRF endpoint"""
    if request.method == 'POST':
        # Intentionally vulnerable to CSRF - no token validation
        new_email = request.form.get('email', '')
        return f"Email updated to: {new_email}"
    return render_template('csrf_test.html')

@app.route('/test/open_redirect', methods=['GET'])
def open_redirect_vulnerable():
    """Vulnerable open redirect endpoint"""
    # Intentionally vulnerable to open redirect
    redirect_url = request.args.get('url', '')
    if redirect_url:
        return redirect(redirect_url)
    return render_template('redirect_test.html')

@app.route('/test/create_db')
def create_test_db():
    """Create test database with some data"""
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT
        )
    ''')
    # Add some test data
    cursor.execute("INSERT OR IGNORE INTO users (username, password, email) VALUES ('admin', 'admin123', 'admin@test.com')")
    cursor.execute("INSERT OR IGNORE INTO users (username, password, email) VALUES ('user', 'user123', 'user@test.com')")
    conn.commit()
    conn.close()
    return "Test database created"

def run_scan_task(target_url, selected_modules, progress_queue):
    """Run the scan in a background task."""
    try:
        scanner = ScannerManager()
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(scanner.run_scan(target_url, selected_modules, progress_queue))
        loop.close()
        session['latest_scan_results'] = results
    except Exception as e:
        logger.error(f"Error in scan task: {e}")
        if progress_queue:
            progress_queue.put_nowait({
                'progress': -1,
                'status': 'error',
                'message': f'Scan error: {str(e)}'
            })

@app.route('/user_stats')
@login_required
def get_user_stats():
    """Get user's scanning statistics."""
    try:
        # Get user stats from database
        stats = supabase.table('user_stats').select('*').eq('user_id', session['user_id']).execute()
        
        if not stats.data:
            return jsonify({
                'total_scans': 0,
                'total_vulnerabilities': 0,
                'success_rate': 0,
                'avg_scan_time': 0
            })
        
        user_stats = stats.data[0]
        total_scans = user_stats.get('total_scans', 0)
        success_rate = (user_stats.get('successful_scans', 0) / total_scans * 100) if total_scans > 0 else 0
        avg_scan_time = (user_stats.get('total_scan_time', 0) / total_scans) if total_scans > 0 else 0
        
        return jsonify({
            'total_scans': total_scans,
            'total_vulnerabilities': user_stats.get('total_vulnerabilities', 0),
            'success_rate': round(success_rate, 1),
            'avg_scan_time': round(avg_scan_time, 1)
        })
        
    except Exception as e:
        logger.error(f"Error getting user stats: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/save_scan', methods=['POST'])
@login_required
def save_scan():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        # Get user ID from session
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'success': False, 'error': 'User not authenticated'}), 401

        # Prepare scan data
        scan_data = {
            'user_id': user_id,
            'target_url': data.get('target_url'),
            'created_at': datetime.utcnow().isoformat(),
            'vulnerabilities': json.dumps(data.get('vulnerabilities', [])),
            'stats': json.dumps(data.get('stats', {})),
            'scan_duration': data.get('scan_duration', 0)
        }

        # Use service role client to insert scan data
        result = supabase_admin.table('scans').insert(scan_data).execute()

        if result.data:
            logger.info(f"Scan results saved successfully for user {user_id}")
            return jsonify({'success': True})
        else:
            logger.error(f"Failed to save scan results for user {user_id}")
            return jsonify({'success': False, 'error': 'Failed to save scan results'}), 500

    except Exception as e:
        logger.error(f"Error saving scan results: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/calculate_stats')
def calculate_stats():
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({
                'total_scans': 0,
                'total_vulnerabilities': 0,
                'success_rate': 0,
                'average_scan_time': 0,
                'recent_scans': []
            })

        # Get all scans for the user
        scans_response = supabase_admin.table('scans')\
            .select('*')\
            .eq('user_id', user_id)\
            .order('created_at', desc=True)\
            .execute()

        if not scans_response.data:
            return jsonify({
                'total_scans': 0,
                'total_vulnerabilities': 0,
                'success_rate': 0,
                'average_scan_time': 0,
                'recent_scans': []
            })

        total_scans = len(scans_response.data)
        total_vulnerabilities = 0
        total_scan_time = 0
        successful_scans = 0

        # Process scan data
        for scan in scans_response.data:
            try:
                vulnerabilities = json.loads(scan.get('vulnerabilities', '[]'))
                total_vulnerabilities += len(vulnerabilities)
                scan_duration = scan.get('scan_duration', 0)
                if scan_duration > 0:
                    total_scan_time += scan_duration
                    successful_scans += 1
            except Exception as e:
                logger.error(f"Error processing scan {scan.get('id')}: {str(e)}")

        # Calculate statistics
        success_rate = round((successful_scans / total_scans) * 100, 1) if total_scans > 0 else 0
        average_scan_time = round(total_scan_time / successful_scans, 1) if successful_scans > 0 else 0

        # Get recent scans for trend chart (last 24 hours)
        recent_scans = []
        twenty_four_hours_ago = datetime.utcnow() - timedelta(hours=24)
        
        for scan in scans_response.data:
            try:
                # Parse ISO format timestamp
                created_at = scan.get('created_at')
                # Remove timezone info and parse
                scan_date = datetime.fromisoformat(created_at.split('+')[0])
                
                if scan_date >= twenty_four_hours_ago:
                    # Format time as HH:MM and include date for sorting
                    recent_scans.append({
                        'timestamp': scan_date.strftime('%H:%M'),
                        'full_timestamp': scan_date.strftime('%Y-%m-%d %H:%M'),
                        'vulnerabilities': scan.get('vulnerabilities', '[]')
                    })
            except Exception as e:
                logger.error(f"Error processing scan date {scan.get('created_at')}: {str(e)}")
                continue

        # Sort scans by full timestamp
        recent_scans.sort(key=lambda x: datetime.strptime(x['full_timestamp'], '%Y-%m-%d %H:%M'))

        return jsonify({
            'total_scans': total_scans,
            'total_vulnerabilities': total_vulnerabilities,
            'success_rate': success_rate,
            'average_scan_time': average_scan_time,
            'recent_scans': recent_scans
        })

    except Exception as e:
        logger.error(f"Error calculating stats: {str(e)}")
        return jsonify({
            'total_scans': 0,
            'total_vulnerabilities': 0,
            'success_rate': 0,
            'average_scan_time': 0,
            'recent_scans': []
        })

@app.route('/dashboard_data')
@login_required
def dashboard_data():
    try:
        # Get all scans for the user
        scans_response = supabase_admin.table('scans')\
            .select('*')\
            .eq('user_id', session['user_id'])\
            .order('created_at', desc=True)\
            .execute()

        if not scans_response.data:
            return jsonify({
                'scans': []
            })

        # Process scans data
        scans = []
        for scan in scans_response.data:
            try:
                scan_data = {
                    'created_at': scan.get('created_at'),
                    'target_url': scan.get('target_url'),
                    'scan_duration': scan.get('scan_duration', 0),
                    'vulnerabilities': scan.get('vulnerabilities', '[]'),
                    'status': 'success' if scan.get('scan_duration', 0) > 0 else 'failed'
                }
                scans.append(scan_data)
            except Exception as e:
                logger.error(f"Error processing scan {scan.get('id')}: {str(e)}")
                continue

        return jsonify({
            'scans': scans
        })

    except Exception as e:
        logger.error(f"Error fetching dashboard data: {str(e)}")
        return jsonify({
            'scans': [],
            'error': str(e)
        })

@app.route('/recent_scans')
@login_required
def recent_scans():
    try:
        # Get recent scans for the current user
        scans_response = supabase_admin.table('scans')\
            .select('*')\
            .eq('user_id', session['user_id'])\
            .order('created_at', desc=True)\
            .limit(10)\
            .execute()

        if not scans_response.data:
            return jsonify({'scans': []})

        return jsonify({'scans': scans_response.data})

    except Exception as e:
        logger.error(f"Error fetching recent scans: {str(e)}")
        return jsonify({'scans': [], 'error': str(e)})

@app.route('/scan_details/<scan_id>')
@login_required
def scan_details(scan_id):
    try:
        # Get scan details
        scan_response = supabase_admin.table('scans')\
            .select('*')\
            .eq('id', scan_id)\
            .eq('user_id', session['user_id'])\
            .execute()

        if not scan_response.data:
            return jsonify({'error': 'Scan not found'}), 404

        return jsonify(scan_response.data[0])

    except Exception as e:
        logger.error(f"Error fetching scan details: {str(e)}")
        return jsonify({'error': str(e)}), 500

def notify_scan_complete(scan_data):
    """Notify connected clients about completed scan"""
    try:
        socketio.emit('scan_complete', {
            'type': 'scan_complete',
            'data': scan_data
        })
    except Exception as e:
        logger.error(f"Error sending WebSocket notification: {str(e)}")

# Update the scan completion handler
def handle_scan_completion(scan_result):
    try:
        # Existing scan completion logic
        scan_data = {
            'target_url': scan_result['target_url'],
            'vulnerabilities': scan_result['vulnerabilities'],
            'scan_duration': scan_result['scan_duration'],
            'created_at': datetime.utcnow().isoformat(),
            'user_id': session['user_id']
        }
        
        # Save to database
        response = supabase_admin.table('scans').insert(scan_data).execute()
        
        if response.data:
            # Notify connected clients about the new scan
            notify_scan_complete(scan_data)
            return jsonify({'status': 'success', 'data': response.data[0]})
        else:
            return jsonify({'status': 'error', 'message': 'Failed to save scan results'})
            
    except Exception as e:
        logger.error(f"Error handling scan completion: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/documentation')
@login_required
def documentation():
    return render_template('documentation.html')

if __name__ == '__main__':
    try:
        port = int(os.getenv('PORT', 5000))
        host = '0.0.0.0'
        
        # Check if we should use ngrok
        use_ngrok = os.getenv('USE_NGROK', 'false').lower() == 'true'
        
        if use_ngrok:
            from pyngrok import ngrok, conf
            auth_token = os.getenv('NGROK_AUTHTOKEN')
            if auth_token:
                conf.get_default().auth_token = auth_token
                # Kill any existing ngrok processes
                ngrok.kill()
                # Create tunnel
                tunnel = ngrok.connect(port)
                print(f' * ngrok tunnel URL: {tunnel.public_url}')
        
        # Start the app
        print(f' * Running on http://{host}:{port}/')
        socketio.run(app, host=host, port=port, debug=True)
    except Exception as e:
        print(f' * Error: {str(e)}')
        socketio.run(app, debug=True)
