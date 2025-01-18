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
import re
import uuid
import secrets
import socket
from urllib.parse import urlparse
import whois
import dns.resolver
import win32evtlog

# Import scanner manager
from scan_tools.scanner_manager import ScannerManager

# Add these imports at the top with other imports
from AI_GUI.Ai import ChatBot

# Import SIEM blueprint
from SiemTool.Siem import siem_bp

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

# Initialize ChatBot
chatbot = ChatBot()

# Register SIEM blueprint
app.register_blueprint(siem_bp, url_prefix='/siem')

# Add datetime filter to Jinja
@app.template_filter('datetime')
def format_datetime(value, format='%Y-%m-%d %H:%M:%S'):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            return value
    return value.strftime(format)

@app.template_filter('progress_width')
def progress_width(value, total):
    """Calculate the width percentage for progress bars"""
    if not total:
        return "0%"
    percentage = (value / total) * 100
    return f"{percentage}%"

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
                    # Get vulnerabilities count
                    vulnerabilities = scan.get('vulnerabilities', [])
                    if isinstance(vulnerabilities, str):
                        vulnerabilities = json.loads(vulnerabilities)
                    vuln_count = len(vulnerabilities)

                    processed_scan = {
                        'id': scan.get('id'),
                        'target_url': scan.get('target_url'),
                        'created_at': scan.get('created_at'),
                        'scan_duration': scan.get('scan_duration', 0),
                        'vulnerability_count': vuln_count,
                        'status': scan.get('status', 'completed')
                    }
                    recent_scans.append(processed_scan)
                except Exception as e:
                    logger.error(f"Error processing scan {scan.get('id')}: {str(e)}")
                    continue

        return render_template('index.html', recent_scans=recent_scans)
    except Exception as e:
        logger.error(f"Error in vulnscan route: {str(e)}")
        return render_template('index.html', recent_scans=[])

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('vulnscan'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'regular_user')
        
        if not all([username, email, password]):
            flash('All fields are required', 'danger')
            return render_template('register.html')

        # Create user with Supabase Auth
        try:
            auth_response = supabase.auth.sign_up({
                "email": email,
                "password": password,
                "options": {
                    "data": {
                        "username": username,
                        "role": role
                    }
                }
            })

            if auth_response and auth_response.user:
                # Get user ID from the response
                user_id = auth_response.user.id
                
                if not user_id:
                    logger.error("Could not get user ID from auth response")
                    flash('Registration failed. Please try again.', 'danger')
                    return render_template('register.html')
                
                # Create user record in the public.users table
                user_data = {
                    'id': user_id,
                    'email': email,
                    'username': username,
                    'role': role,
                    'created_at': datetime.utcnow().isoformat()
                }
                
                try:
                    supabase.table('users').insert(user_data).execute()
                except Exception as db_error:
                    logger.warning(f"Error creating user record (continuing anyway): {str(db_error)}")
                
                # Store verification data in session
                session['pending_verification_email'] = email
                session['verification_resend_count'] = 0
                session['last_verification_resend'] = time.time()
                session['temp_user_id'] = user_id
                
                flash('Registration successful! Please check your email for verification.', 'success')
                return redirect(url_for('verify_email_page'))
            else:
                flash('Registration failed. Please try again.', 'danger')
                return render_template('register.html')
                
        except Exception as e:
            error_message = str(e).lower()
            if 'user already registered' in error_message:
                flash('Email already registered. Please use a different email.', 'danger')
            else:
                logger.error(f"Registration error: {str(e)}")
                flash('Registration failed. Please try again.', 'danger')
            return render_template('register.html')
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Redirect to vulnscan if already logged in
    if 'user_id' in session:
        return redirect(url_for('vulnscan'))
        
    if request.method == 'POST':
        try:
            # Handle both JSON and form data
            if request.is_json:
                data = request.get_json()
                email = data.get('email')
                password = data.get('password')
            else:
                email = request.form.get('login')  # Form uses 'login' field
                password = request.form.get('password')
                remember_me = request.form.get('remember_me')

            if not email or not password:
                if request.is_json:
                    return jsonify({'error': 'Email and password are required'}), 400
                flash('Please provide both email and password', 'danger')
                return render_template('login.html')

            # Sign in user with Supabase Auth
            auth_response = supabase_admin.auth.sign_in_with_password({
                "email": email,
                "password": password
            })

            if auth_response.user:
                user_id = auth_response.user.id
                session['user_id'] = user_id
                session['email'] = email
                
                if not request.is_json and remember_me:
                    session.permanent = True

                # Get user data including role
                try:
                    user_data = supabase_admin.table('users')\
                        .select('username, role')\
                        .eq('id', user_id)\
                        .single()\
                        .execute()

                    # Print user data for debugging
                    print("\n=== User Login Data ===")
                    print(f"User ID: {user_id}")
                    print(f"Email: {email}")
                    print(f"Auth Response: {auth_response.user}")
                    print(f"User Data from DB: {user_data.data}")
                    print("=====================\n")

                    if user_data.data:
                        session['username'] = user_data.data.get('username')
                        session['role'] = user_data.data.get('role', 'regular_user')
                        
                        # Print session data
                        print("\n=== Session Data ===")
                        print(f"Username: {session.get('username')}")
                        print(f"Role: {session.get('role')}")
                        print("==================\n")
                    else:
                        # Create user record if it doesn't exist
                        user_data = {
                            'id': user_id,
                            'email': email,
                            'username': email.split('@')[0],
                            'role': 'regular_user',
                            'created_at': datetime.utcnow().isoformat()
                        }
                        supabase_admin.table('users').insert(user_data).execute()
                        session['username'] = user_data['username']
                        session['role'] = user_data['role']
                        
                        # Print new user data
                        print("\n=== New User Created ===")
                        print(f"User Data: {user_data}")
                        print("======================\n")

                    # Initialize user stats if needed
                    try:
                        stats_check = supabase_admin.table('user_stats')\
                            .select('user_id')\
                            .eq('user_id', user_id)\
                            .execute()
                            
                        if not stats_check.data:
                            supabase_admin.table('user_stats').insert({
                                'user_id': user_id
                            }).execute()
                    except Exception as stats_error:
                        logger.error(f"Error checking/creating user stats: {str(stats_error)}")

                except Exception as user_error:
                    logger.error(f"Error getting user data: {str(user_error)}")
                    session['username'] = email.split('@')[0]
                    session['role'] = 'regular_user'
                    print(f"\n=== Error Getting User Data ===\nError: {str(user_error)}\n==========================\n")

                if request.is_json:
                    return jsonify({
                        'success': True,
                        'session': auth_response.session,
                        'user': {
                            'id': user_id,
                            'email': email,
                            'username': session.get('username'),
                            'role': session.get('role')
                        }
                    })
                else:
                    flash('Login successful!', 'success')
                    return redirect(url_for('vulnscan'))
            else:
                if request.is_json:
                    return jsonify({'error': 'Invalid credentials'}), 401
                flash('Invalid login credentials', 'danger')
                return render_template('login.html')

        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            error_message = str(e).lower()
            print(f"\n=== Login Error ===\nError: {str(e)}\n==================\n")
            
            if 'invalid login' in error_message:
                flash('Invalid email or password', 'danger')
            elif 'rate limit' in error_message:
                flash('Too many login attempts. Please try again later.', 'danger')
            else:
                flash('An error occurred during login. Please try again.', 'danger')
                
            if request.is_json:
                return jsonify({'error': str(e)}), 500
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
                                total_scan_time=0,
                                success_rate=0,
                                scan_history=[])

        # Calculate stats
        total_scans = len(scans.data)
        total_vulnerabilities = 0
        total_scan_time = 0
        successful_scans = 0
        scan_history = []

        for scan in scans.data:
            try:
                # Handle vulnerabilities field
                vulnerabilities = scan.get('vulnerabilities', [])
                if isinstance(vulnerabilities, str):
                    vulnerabilities = json.loads(vulnerabilities)
                
                total_vulnerabilities += len(vulnerabilities)
                scan_duration = scan.get('scan_duration', 0)
                total_scan_time += scan_duration
                
                if scan_duration > 0:
                    successful_scans += 1
                
                # Format scan data for display
                scan_data = {
                    'target_url': scan.get('target_url'),
                    'created_at': scan.get('created_at'),
                    'scan_duration': scan_duration,
                    'vulnerabilities': vulnerabilities
                }
                scan_history.append(scan_data)
                
            except Exception as e:
                logger.error(f"Error processing scan stats: {e}")
                continue

        # Sort scan history by created_at in descending order
        scan_history.sort(key=lambda x: x['created_at'], reverse=True)
        
        # Calculate success rate
        success_rate = (successful_scans / total_scans * 100) if total_scans > 0 else 0

        return render_template('dashboard.html',
                            total_scans=total_scans,
                            total_vulnerabilities=total_vulnerabilities,
                            total_scan_time=total_scan_time,
                            success_rate=success_rate,
                            scan_history=scan_history)

    except Exception as e:
        logger.error(f"Error loading dashboard: {str(e)}")
        flash('Error loading dashboard data', 'error')
        return redirect(url_for('index'))

@app.route('/scan', methods=['POST'])
@login_required
def scan():
    try:
        # First, verify user exists in database
        user_id = session.get('user_id')
        
        data = request.get_json()
        if not data or 'url' not in data:
            logger.error("No URL provided in scan request")
            return jsonify({'error': 'No URL provided'}), 400

        url = data['url']
        selected_modules = data.get('modules', [])
        logger.info(f"Starting scan for URL: {url} with modules: {selected_modules}")

        try:
            # Initialize scanner if needed
            if not hasattr(app, 'scanner_manager'):
                app.scanner_manager = ScannerManager()

            # Perform scan with error handling
            try:
                scan_results = app.scanner_manager.scan_url(url, selected_modules)
                if scan_results is None:
                    logger.error("Scan returned None results")
                    return jsonify({'error': 'Scan failed - no results returned'}), 500
            except ConnectionError as ce:
                logger.error(f"Connection error during scan: {str(ce)}")
                return jsonify({'error': 'Failed to connect to target. Please check the URL and try again.'}), 500
            except TimeoutError as te:
                logger.error(f"Timeout error during scan: {str(te)}")
                return jsonify({'error': 'Scan timed out. Please try again.'}), 500
            except Exception as scan_error:
                logger.error(f"Scan execution error: {str(scan_error)}")
                return jsonify({'error': f'Scan failed: {str(scan_error)}'}), 500

            # Process vulnerabilities with error handling
            try:
                # Ensure vulnerabilities is a list
                vulnerabilities = scan_results.get('vulnerabilities', [])
                if not isinstance(vulnerabilities, list):
                    vulnerabilities = [vulnerabilities] if vulnerabilities else []
                
                # Track unique vulnerability types for stats
                vuln_types = set()
                stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                processed_vulnerabilities = []

                # Process each vulnerability
                for vuln in vulnerabilities:
                    if isinstance(vuln, dict):
                        # Create processed vulnerability with all details
                        processed_vuln = {
                            'type': str(vuln.get('type', 'Unknown')),
                            'severity': str(vuln.get('severity', 'low')).lower(),
                            'description': str(vuln.get('description', '')),
                            'location': str(vuln.get('location', url)),
                            'method': vuln.get('method'),
                            'parameter': vuln.get('parameter'),
                            'payload': vuln.get('payload'),
                            'evidence': vuln.get('evidence'),
                            'details': vuln.get('details')
                        }
                        processed_vulnerabilities.append(processed_vuln)

                        # Only count for stats if it's a new vulnerability type
                        vuln_key = f"{processed_vuln['type']}:{processed_vuln['severity']}"
                        if vuln_key not in vuln_types:
                            vuln_types.add(vuln_key)
                            severity = processed_vuln['severity']
                            if severity in stats:
                                stats[severity] += 1

                    elif isinstance(vuln, str):
                        processed_vuln = {
                            'type': 'Unknown',
                            'severity': 'low',
                            'description': str(vuln),
                            'location': str(url)
                        }
                        processed_vulnerabilities.append(processed_vuln)

                # Convert all values to strings for JSON serialization
                scan_data = {
                    'user_id': str(user_id),
                    'target_url': str(url),
                    'vulnerabilities': processed_vulnerabilities,  # Remove json.dumps() here
                    'stats': stats,  # Remove json.dumps() here
                    'scan_duration': float(scan_results.get('scan_duration', 0)),
                    'created_at': datetime.utcnow().isoformat(),
                    'status': 'completed'
                }

                # Save to database if user exists
                if user_id:
                    try:
                        result = supabase_admin.table('scans').insert(scan_data).execute()
                        if result.data:
                            logger.info("Successfully saved scan results to database")
                        else:
                            logger.error("No data returned from database insert")
                    except Exception as db_error:
                        logger.error(f"Database error (continuing anyway): {str(db_error)}")

                # Return processed results
                return jsonify({
                    'vulnerabilities': processed_vulnerabilities,
                    'stats': stats,
                    'scan_duration': scan_results.get('scan_duration', 0),
                    'status': 'completed'
                })

            except Exception as process_error:
                logger.error(f"Error processing scan results: {str(process_error)}")
                return jsonify({'error': f'Error processing scan results: {str(process_error)}'}), 500

        except Exception as scanner_error:
            logger.error(f"Scanner error: {str(scanner_error)}")
            return jsonify({'error': f'Scanner error: {str(scanner_error)}'}), 500

    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/scan_results')
def scan_results():
    try:
        # Get results from session
        results = session.get('latest_scan_results')
        if not results:
            return render_template('results.html', vulnerabilities=[])
            
        # Get vulnerabilities from results
        vulnerabilities = results.get('vulnerabilities', [])
        
        # Render the template with the vulnerabilities
        return render_template('results.html', 
                             vulnerabilities=vulnerabilities,
                             scan_duration=results.get('scan_duration', 0),
                             target_url=results.get('target_url', ''))
        
    except Exception as e:
        logger.error(f"Error displaying scan results: {str(e)}")
        return render_template('results.html', vulnerabilities=[], error=str(e))

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
    type = request.args.get('type', 'signup')
    
    if not token:
        flash('No verification token provided.', 'error')
        return redirect(url_for('verify_email_page'))
    
    try:
        if type == 'signup':
            result = supabase.auth.verify_signup({
                "token": token
            })
            
            if result.user:
                # Clear verification session
                session.pop('pending_verification_email', None)
                session.pop('verification_resend_count', None)
                session.pop('last_verification_resend', None)
                
                # Set login session
                session['user_id'] = result.user.id
                session['email'] = result.user.email
                
                flash('Email verified successfully! Welcome to VulnScan.', 'success')
                return redirect(url_for('vulnscan'))
        
        flash('Invalid or expired verification token. Please try again.', 'error')
        return redirect(url_for('verify_email_page'))
        
    except Exception as e:
        error_message = str(e).lower()
        if 'expired' in error_message:
            flash('Verification link has expired. Please request a new one.', 'error')
        elif 'invalid' in error_message:
            flash('Invalid verification link. Please try again or request a new one.', 'error')
        else:
            logger.error(f'Link verification error: {str(e)}')
            flash('An error occurred during verification. Please try again.', 'error')
        return redirect(url_for('verify_email_page'))

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
        flash('No pending verification. Please register or login.', 'warning')
        return redirect(url_for('login'))
    
    email = session.get('pending_verification_email')
    temp_user_id = session.get('temp_user_id')
    
    # Check if user is already verified
    try:
        user_response = supabase_admin.auth.admin.get_user_by_id(temp_user_id)
        if user_response and hasattr(user_response, 'email_confirmed_at') and user_response.email_confirmed_at:
            logger.info("User is already verified")
            # Clear all verification session data
            for key in ['pending_verification_email', 'verification_resend_count', 
                      'last_verification_resend', 'temp_user_id', 'verification_in_progress']:
                session.pop(key, None)
            
            # Set login session if not set
            if 'user_id' not in session:
                session['user_id'] = user_response.id
                session['email'] = user_response.email
            
            flash('Your email is already verified. Welcome to VulnScan!', 'success')
            return redirect(url_for('vulnscan'))
    except Exception as user_error:
        logger.warning(f"Could not verify user account status: {str(user_error)}")
    
    resend_count = session.get('verification_resend_count', 0)
    last_resend = session.get('last_verification_resend', 0)
    
    # Calculate cooldown
    cooldown = 0
    if last_resend:
        time_since_last = time.time() - float(last_resend)
        if time_since_last < 60:
            cooldown = int(60 - time_since_last)
    
    return render_template('verify_email.html', 
                         email=email,
                         resend_count=resend_count,
                         cooldown=cooldown)

@app.route('/verify-email/code', methods=['POST'])
def verify_email_code():
    """Handle OTP code verification"""
    if 'pending_verification_email' not in session:
        logger.warning("No pending verification session")
        flash('No pending verification. Please try logging in.', 'warning')
        return redirect(url_for('login'))
    
    # Check if verification is in progress
    if session.get('verification_in_progress'):
        logger.warning("Verification already in progress")
        flash('Verification in progress. Please wait...', 'warning')
        return redirect(url_for('verify_email_page'))
    
    try:
        # Set verification in progress
        session['verification_in_progress'] = True
        
        code = request.form.get('code')
        email = session.get('pending_verification_email')
        
        logger.info(f"Attempting to verify code for email: {email}")
        
        # Check if user is already verified
        try:
            user_response = supabase_admin.auth.admin.get_user_by_id(session.get('temp_user_id'))
            if user_response and hasattr(user_response, 'email_confirmed_at') and user_response.email_confirmed_at:
                logger.info("User is already verified")
                # Clear all verification session data
                for key in ['pending_verification_email', 'verification_resend_count', 
                          'last_verification_resend', 'temp_user_id', 'verification_in_progress']:
                    session.pop(key, None)
                
                # Set login session if not set
                if 'user_id' not in session:
                    session['user_id'] = user_response.id
                    session['email'] = user_response.email
                
                flash('Your email is already verified. Redirecting to dashboard...', 'success')
                return redirect(url_for('vulnscan'))
        except Exception as user_error:
            logger.warning(f"Could not verify user account status: {str(user_error)}")
        
        if not code:
            logger.warning("No verification code provided")
            flash('Please enter the verification code.', 'warning')
            return redirect(url_for('verify_email_page'))
            
        if not code.isdigit() or len(code) != 6:
            logger.warning(f"Invalid code format: {code}")
            flash('Invalid verification code format. Please enter a 6-digit code.', 'warning')
            return redirect(url_for('verify_email_page'))
        
        try:
            # Verify OTP with Supabase
            logger.info(f"Sending verification request to Supabase for code: {code}")
            result = supabase_admin.auth.verify_otp({
                "email": email,
                "token": code,
                "type": "email",  # Use 'email' type for email verification
                "options": {
                    "redirectTo": url_for('vulnscan', _external=True)
                }
            })
            
            if result and result.user:
                logger.info("Verification successful")
                
                # Clear all verification session data immediately
                for key in ['pending_verification_email', 'verification_resend_count', 
                          'last_verification_resend', 'temp_user_id', 'verification_in_progress']:
                    session.pop(key, None)
                
                # Set login session
                session['user_id'] = result.user.id
                session['email'] = result.user.email
                
                # Double check user exists in users table
                try:
                    user_check = supabase_admin.table('users').select('*').eq('id', result.user.id).execute()
                    if not user_check.data:
                        # Create user record if it doesn't exist
                        user_data = {
                            'id': result.user.id,
                            'email': result.user.email,
                            'username': result.user.email.split('@')[0],
                            'created_at': datetime.utcnow().isoformat()
                        }
                        supabase_admin.table('users').insert(user_data).execute()
                        logger.info(f"Created user record for {result.user.id}")
                except Exception as db_error:
                    logger.error(f"Database error (continuing anyway): {str(db_error)}")
                
                flash('Email verified successfully! Welcome to VulnScan.', 'success')
                return redirect(url_for('vulnscan'))
                
        except Exception as e:
            error_message = str(e).lower()
            logger.error(f"Verification error: {str(e)}")
            
            if hasattr(e, 'response'):
                status_code = getattr(e.response, 'status_code', None)
                response_text = getattr(e.response, 'text', '')
                logger.error(f"Response status: {status_code}")
                logger.error(f"Response content: {response_text}")
                
                if status_code == 401 or 'expired' in error_message or 'invalid' in error_message:
                    flash('This verification code has already been used or has expired. Please request a new code.', 'error')
                    return redirect(url_for('verify_email_page'))
            
            if 'too many' in error_message:
                flash('Too many attempts. Please wait a few minutes and try again.', 'error')
            else:
                flash('Invalid verification code. Please try again or request a new code.', 'error')
                
    finally:
        # Always clear verification in progress flag
        session.pop('verification_in_progress', None)
        
    return redirect(url_for('verify_email_page'))

@app.route('/resend-verification', methods=['POST'])
def resend_verification():
    """Resend verification email"""
    if 'pending_verification_email' not in session:
        logger.info("No pending verification email in session")
        flash('Please register or login first.', 'warning')
        return redirect(url_for('login'))
    
    email = session['pending_verification_email']
    temp_user_id = session.get('temp_user_id')
    
    logger.info(f"Attempting to resend verification email to: {email}")
    
    try:
        # Check if we've exceeded resend limit
        resend_count = session.get('verification_resend_count', 0)
        logger.info(f"Current resend count: {resend_count}")
        if resend_count >= 3:
            logger.warning(f"Resend limit exceeded for email: {email}")
            flash('Maximum resend limit reached. Please try registering again.', 'error')
            # Clear session data since we've hit the limit
            session.pop('pending_verification_email', None)
            session.pop('verification_resend_count', None)
            session.pop('last_verification_resend', None)
            session.pop('temp_user_id', None)
            return redirect(url_for('register'))
            
        # Check cooldown period
        last_resend = session.get('last_verification_resend')
        if last_resend:
            time_since_last = time.time() - float(last_resend)
            logger.info(f"Time since last resend: {time_since_last} seconds")
            if time_since_last < 60:  # 60 seconds cooldown
                remaining = int(60 - time_since_last)
                logger.info(f"Cooldown period active. {remaining} seconds remaining")
                flash(f'Please wait {remaining} seconds before requesting another code.', 'warning')
                return redirect(url_for('verify_email_page'))
        
        # First check if user exists and isn't already verified
        try:
            user_response = supabase_admin.auth.admin.get_user_by_id(temp_user_id)
            if user_response and hasattr(user_response, 'email_confirmed_at') and user_response.email_confirmed_at:
                logger.info("User is already verified")
                flash('Your email is already verified. Please login.', 'success')
                return redirect(url_for('login'))
        except Exception as user_error:
            logger.warning(f"Could not verify user status: {str(user_error)}")
        
        # Try to send verification email using admin auth client
        try:
            logger.info("Attempting to send verification email...")
            result = supabase_admin.auth.admin.invite_user_by_email(
                email,
                {
                    "redirectTo": url_for('verify_email', _external=True)
                }
            )
            
            if result:
                logger.info("Verification email sent successfully")
                # Update session tracking
                session['verification_resend_count'] = resend_count + 1
                session['last_verification_resend'] = time.time()
                logger.info(f"Updated resend count to {resend_count + 1}")
                
                flash('New verification email sent! Please check your inbox and spam folder.', 'success')
                return redirect(url_for('verify_email_page'))
                
        except Exception as invite_error:
            logger.error(f"Error sending invite: {str(invite_error)}")
            # Fall back to resend method if invite fails
            
        # Try resend as fallback
        try:
            logger.info("Attempting resend as fallback...")
            result = supabase_admin.auth.resend({
                "type": "signup",
                "email": email,
                "options": {
                    "redirectTo": url_for('verify_email', _external=True)
                }
            })
            
            if result:
                logger.info("Resend successful")
                # Update session tracking
                session['verification_resend_count'] = resend_count + 1
                session['last_verification_resend'] = time.time()
                logger.info(f"Updated resend count to {resend_count + 1}")
                
                flash('New verification email sent! Please check your inbox and spam folder.', 'success')
            else:
                logger.error("Resend returned no result")
                flash('Failed to send verification email. Please try again.', 'error')
                
        except Exception as resend_error:
            logger.error(f"Resend failed: {str(resend_error)}")
            flash('Failed to send verification email. Please try again.', 'error')
            
    except Exception as e:
        error_message = str(e).lower()
        logger.error(f"Resend verification error: {str(e)}")
        
        if 'rate limit' in error_message:
            flash('Too many attempts. Please wait a few minutes.', 'error')
        elif 'not found' in error_message:
            flash('Email not found. Please register again.', 'error')
            return redirect(url_for('register'))
        else:
            flash('Failed to send verification email. Please try again.', 'error')
    
    return redirect(url_for('verify_email_page'))

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
        # First, verify user exists in database
        user_id = session.get('user_id')
        user_check = supabase_admin.table('users').select('*').eq('id', user_id).execute()
        
        if not user_check.data:
            # Create user record if it doesn't exist
            user_data = {
                'id': user_id,
                'email': session.get('email'),
                'username': session.get('email', '').split('@')[0],
                'created_at': datetime.utcnow().isoformat()
            }
            try:
                supabase_admin.table('users').insert(user_data).execute()
                logger.info(f"Created missing user record for {user_id}")
            except Exception as e:
                logger.error(f"Error creating user record: {str(e)}")
                return jsonify({'success': False, 'error': 'Failed to create user record'}), 500

        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        # Process vulnerabilities
        vulnerabilities = data.get('vulnerabilities', [])
        if not isinstance(vulnerabilities, list):
            vulnerabilities = [vulnerabilities] if vulnerabilities else []

        # Process each vulnerability
        processed_vulnerabilities = []
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):
                processed_vuln = {
                    'type': vuln.get('type', 'Unknown'),
                    'severity': vuln.get('severity', 'low').lower(),
                    'description': vuln.get('description', ''),
                    'location': vuln.get('location', data.get('target_url', ''))
                }
                processed_vulnerabilities.append(processed_vuln)
            elif isinstance(vuln, str):
                processed_vulnerabilities.append({
                    'type': 'Unknown',
                    'severity': 'low',
                    'description': vuln,
                    'location': data.get('target_url', '')
                })

        # Calculate stats
        stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in processed_vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            if severity in stats:
                stats[severity] += 1

        # Save scan to database
        scan_data = {
            'id': str(uuid.uuid4()),
            'user_id': user_id,
            'target_url': data.get('target_url'),
            'vulnerabilities': processed_vulnerabilities,  # Supabase will handle JSONB conversion
            'stats': stats,  # Supabase will handle JSONB conversion
            'scan_duration': float(data.get('scan_duration', 0)),
            'status': 'completed',
            'created_at': datetime.utcnow().isoformat()
        }

        # Log the data for debugging
        logger.info(f"Saving scan with {len(processed_vulnerabilities)} vulnerabilities")
        logger.debug(f"Scan data: {json.dumps(scan_data)}")
        
        result = supabase_admin.table('scans').insert(scan_data).execute()
        if result.data:
            logger.info("Successfully saved scan results to database")
            return jsonify({'success': True})
        else:
            logger.error("No data returned from database insert")
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

        # Get recent scans for trend chart (last 24 hours)
        recent_scans = []
        twenty_four_hours_ago = datetime.utcnow() - timedelta(hours=24)
        
        for scan in scans_response.data:
            try:
                # Parse ISO format timestamp
                created_at = scan.get('created_at')
                # Remove timezone info and parse
                scan_date = datetime.fromisoformat(created_at.split('+')[0])
                
                # Process vulnerabilities for total count
                vulnerabilities = scan.get('vulnerabilities', [])
                if isinstance(vulnerabilities, str):
                    try:
                        vulnerabilities = json.loads(vulnerabilities)
                    except json.JSONDecodeError:
                        vulnerabilities = []
                elif not isinstance(vulnerabilities, list):
                    vulnerabilities = []

                vuln_count = len(vulnerabilities)
                total_vulnerabilities += vuln_count
                scan_duration = scan.get('scan_duration', 0)
                if scan_duration > 0:
                    total_scan_time += scan_duration
                    successful_scans += 1
                
                # Add to recent scans if within last 24 hours
                if scan_date >= twenty_four_hours_ago:
                    recent_scans.append({
                        'timestamp': scan_date.strftime('%H:%M'),
                        'full_timestamp': scan_date.strftime('%Y-%m-%d %H:%M'),
                        'vulnerabilities': vuln_count,  # Send the count directly
                        'scan_duration': scan_duration
                    })
            except Exception as e:
                logger.error(f"Error processing scan {scan.get('id')}: {str(e)}")
                continue

        # Sort scans by full timestamp
        recent_scans.sort(key=lambda x: datetime.strptime(x['full_timestamp'], '%Y-%m-%d %H:%M'))

        # Calculate statistics
        success_rate = round((successful_scans / total_scans) * 100, 1) if total_scans > 0 else 0
        average_scan_time = round(total_scan_time / successful_scans, 1) if successful_scans > 0 else 0

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

        # Process scans data
        processed_scans = []
        for scan in scans_response.data:
            try:
                # Get vulnerabilities count
                vulnerabilities = scan.get('vulnerabilities', [])
                if isinstance(vulnerabilities, str):
                    try:
                        vulnerabilities = json.loads(vulnerabilities)
                    except json.JSONDecodeError:
                        vulnerabilities = []
                elif not isinstance(vulnerabilities, list):
                    vulnerabilities = [vulnerabilities] if vulnerabilities else []

                vuln_count = len(vulnerabilities)

                processed_scan = {
                    'id': scan.get('id'),
                    'target_url': scan.get('target_url'),
                    'created_at': scan.get('created_at'),
                    'scan_duration': scan.get('scan_duration', 0),
                    'vulnerability_count': vuln_count,
                    'status': scan.get('status', 'completed')
                }
                processed_scans.append(processed_scan)
            except Exception as e:
                logger.error(f"Error processing scan {scan.get('id')}: {str(e)}")
                continue

        return jsonify({'scans': processed_scans})

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

# Role-based access control decorators
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please login to access this page', 'warning')
                return redirect(url_for('login'))
            
            user_role = session.get('role', 'regular_user')
            if user_role not in roles:
                flash('You do not have permission to access this page', 'danger')
                return redirect(url_for('vulnscan'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login'))
        
        user_role = session.get('role')
        if user_role != 'admin':
            flash('Admin access required', 'danger')
            return redirect(url_for('vulnscan'))
        
        return f(*args, **kwargs)
    return decorated_function

# Admin routes
@app.route('/admin')
@admin_required
def admin_panel():
    try:
        # Get all users with their roles
        users = supabase_admin.table('users')\
            .select('id, username, email, role, created_at')\
            .order('created_at', desc=True)\
            .execute()
            
        # Get all scans with full data
        scans = supabase_admin.table('scans')\
            .select('*')\
            .order('created_at', desc=True)\
            .limit(100)\
            .execute()
            
        # Calculate totals
        total_users = len(users.data) if users.data else 0
        total_scans = len(scans.data) if scans.data else 0
        total_vulnerabilities = 0
        total_scan_time = 0
        successful_scans = 0
        
        # Calculate totals and scan time
        for scan in scans.data or []:
            try:
                # Calculate vulnerabilities
                vulnerabilities = scan.get('vulnerabilities', [])
                if isinstance(vulnerabilities, str):
                    vulnerabilities = json.loads(vulnerabilities)
                total_vulnerabilities += len(vulnerabilities)
                
                # Calculate scan time
                scan_duration = scan.get('scan_duration', 0)
                if scan_duration > 0:
                    total_scan_time += scan_duration
                    successful_scans += 1
            except Exception as e:
                logger.error(f"Error processing scan vulnerabilities: {str(e)}")
                continue
        
        # Calculate average scan time
        avg_scan_time = round(total_scan_time / successful_scans, 2) if successful_scans > 0 else 0
            
        return render_template('admin.html', 
                             users=users.data if users.data else [], 
                             scans=scans.data if scans.data else [],
                             total_users=total_users,
                             total_scans=total_scans,
                             total_vulnerabilities=total_vulnerabilities,
                             avg_scan_time=avg_scan_time)
                             
    except Exception as e:
        logger.error(f"Error in admin panel: {str(e)}")
        flash('Error loading admin panel', 'danger')
        return redirect(url_for('vulnscan'))

@app.route('/admin/users/<user_id>', methods=['GET', 'PUT', 'DELETE'])
@admin_required
def admin_manage_user(user_id):
    try:
        if request.method == 'GET':
            # Get user details
            user = supabase_admin.table('users')\
                .select('*')\
                .eq('id', user_id)\
                .single()\
                .execute()
                
            if not user.data:
                return jsonify({'error': 'User not found'}), 404
                
            return jsonify(user.data)
            
        elif request.method == 'PUT':
            data = request.get_json()
            
            # Update user role
            if 'role' in data:
                result = supabase_admin.table('users')\
                    .update({'role': data['role']})\
                    .eq('id', user_id)\
                    .execute()
                    
                if result.data:
                    return jsonify({'message': 'User role updated successfully'})
                else:
                    return jsonify({'error': 'Failed to update user role'}), 500
                    
        elif request.method == 'DELETE':
            try:
                # First, delete user's scans
                supabase_admin.table('scans')\
                    .delete()\
                    .eq('user_id', user_id)\
                    .execute()
                
                # Delete user's stats
                supabase_admin.table('user_stats')\
                    .delete()\
                    .eq('user_id', user_id)\
                    .execute()
                
                # Delete user from public.users table
                supabase_admin.table('users')\
                    .delete()\
                    .eq('id', user_id)\
                    .execute()
                
                # Finally, delete from auth.users
                supabase_admin.auth.admin.delete_user(user_id)
                
                return jsonify({'success': True, 'message': 'User deleted successfully'})
            except Exception as e:
                logger.error(f"Error deleting user: {str(e)}")
                return jsonify({'success': False, 'error': 'Failed to delete user: ' + str(e)}), 500
                
    except Exception as e:
        logger.error(f"Error managing user: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/edit_user', methods=['POST'])
@admin_required
def admin_edit_user():
    try:
        user_id = request.form.get('user_id')
        username = request.form.get('username')
        email = request.form.get('email')
        role = request.form.get('role')
        
        if not all([user_id, username, email, role]):
            flash('All fields are required', 'danger')
            return redirect(url_for('admin_panel'))
            
        # Update user in database
        result = supabase_admin.table('users')\
            .update({
                'username': username,
                'email': email,
                'role': role
            })\
            .eq('id', user_id)\
            .execute()
            
        if result.data:
            flash('User updated successfully', 'success')
        else:
            flash('Failed to update user', 'danger')
            
        return redirect(url_for('admin_panel'))
        
    except Exception as e:
        logger.error(f"Error editing user: {str(e)}")
        flash('Error updating user', 'danger')
        return redirect(url_for('admin_panel'))

@app.route('/admin/add_user', methods=['POST'])
@admin_required
def admin_add_user():
    try:
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'regular_user')
        
        if not all([username, email, password]):
            flash('All fields are required', 'danger')
            return redirect(url_for('admin_panel'))
            
        # Create user in Supabase Auth
        auth_response = supabase_admin.auth.admin.create_user({
            'email': email,
            'password': password,
            'email_confirm': True,
            'user_metadata': {
                'username': username,
                'role': role
            }
        })
        
        if auth_response:
            user_id = auth_response.id
            
            # Create user record in public.users table
            user_data = {
                'id': user_id,
                'email': email,
                'username': username,
                'role': role,
                'created_at': datetime.utcnow().isoformat()
            }
            
            result = supabase_admin.table('users').insert(user_data).execute()
            
            if result.data:
                flash('User created successfully', 'success')
            else:
                flash('User created but failed to add to database', 'warning')
                
        else:
            flash('Failed to create user', 'danger')
            
        return redirect(url_for('admin_panel'))
        
    except Exception as e:
        logger.error(f"Error adding user: {str(e)}")
        flash(f'Error creating user: {str(e)}', 'danger')
        return redirect(url_for('admin_panel'))

@app.route('/admin/update_role/<user_id>', methods=['POST'])
@admin_required
def admin_update_role(user_id):
    try:
        data = request.get_json()
        new_role = data.get('role')
        
        if not new_role:
            return jsonify({'success': False, 'message': 'No role specified'}), 400
            
        # Update user role in database
        result = supabase_admin.table('users')\
            .update({'role': new_role})\
            .eq('id', user_id)\
            .execute()
            
        if result.data:
            return jsonify({'success': True, 'message': 'Role updated successfully'})
        else:
            return jsonify({'success': False, 'message': 'Failed to update role'}), 500
            
    except Exception as e:
        logger.error(f"Error updating role: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/admin/roles/request', methods=['POST'])
@login_required
def request_role_change():
    try:
        data = request.get_json()
        requested_role = data.get('role')
        
        if not requested_role:
            return jsonify({'error': 'No role specified'}), 400
            
        user_id = session['user_id']
        current_role = session.get('role', 'regular_user')
        
        # Don't allow requesting admin role
        if requested_role == 'admin':
            return jsonify({'error': 'Cannot request admin role'}), 403
            
        # Update user's role (in a real application, this would create a role request for admin approval)
        result = supabase_admin.table('users')\
            .update({'role': requested_role})\
            .eq('id', user_id)\
            .execute()
            
        if result.data:
            session['role'] = requested_role
            return jsonify({
                'message': 'Role updated successfully',
                'new_role': requested_role
            })
        else:
            return jsonify({'error': 'Failed to update role'}), 500
            
    except Exception as e:
        logger.error(f"Error requesting role change: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/analytics')
@login_required
def analytics():
    return render_template('analytics.html')

@app.route('/api/analytics')
@login_required
def get_analytics():
    try:
        time_range = request.args.get('timeRange', 'all')
        user_id = session.get('user_id')
        
        # Calculate the date range
        now = datetime.utcnow()
        if time_range == '24h':
            start_date = (now - timedelta(days=1)).isoformat()
        elif time_range == '7d':
            start_date = (now - timedelta(days=7)).isoformat()
        elif time_range == '30d':
            start_date = (now - timedelta(days=30)).isoformat()
        else:  # 'all'
            start_date = None

        # Get scans from Supabase
        scans_query = supabase_admin.table('scans').select('*').eq('user_id', user_id)
        if start_date:
            scans_query = scans_query.gte('created_at', start_date)
        scans_response = scans_query.execute()
        
        scans = scans_response.data if scans_response.data else []

        # Calculate basic stats
        total_scans = len(scans)
        total_vulns = 0
        total_scan_time = 0
        vuln_distribution = [0, 0, 0, 0]  # Critical, High, Medium, Low
        vuln_types = {}
        
        for scan in scans:
            # Get vulnerabilities
            try:
                vulnerabilities = scan.get('vulnerabilities', [])
                # Handle both string and list formats
                if isinstance(vulnerabilities, str):
                    try:
                        vulnerabilities = json.loads(vulnerabilities)
                    except json.JSONDecodeError:
                        vulnerabilities = []
                elif not isinstance(vulnerabilities, list):
                    vulnerabilities = []
                
                total_vulns += len(vulnerabilities)
                total_scan_time += scan.get('scan_duration', 0)
                
                # Process vulnerabilities
                for vuln in vulnerabilities:
                    severity = vuln.get('severity', '').lower()
                    if severity == 'critical':
                        vuln_distribution[0] += 1
                    elif severity == 'high':
                        vuln_distribution[1] += 1
                    elif severity == 'medium':
                        vuln_distribution[2] += 1
                    else:
                        vuln_distribution[3] += 1
                    
                    # Update vulnerability types
                    vuln_type = vuln.get('type', 'Unknown')
                    if vuln_type in vuln_types:
                        vuln_types[vuln_type]['count'] += 1
                    else:
                        vuln_types[vuln_type] = {
                            'count': 1,
                            'severity': severity
                        }
            except Exception as e:
                logger.error(f"Error processing vulnerabilities for scan {scan.get('id')}: {str(e)}")
                continue

        # Calculate averages
        avg_vulns_per_scan = round(total_vulns / total_scans, 2) if total_scans > 0 else 0
        avg_scan_time = round(total_scan_time / total_scans, 2) if total_scans > 0 else 0

        # Calculate scan activity over time
        if time_range == '24h':
            interval = timedelta(hours=1)
            format_str = '%H:00'
            periods = 24
        elif time_range == '7d':
            interval = timedelta(days=1)
            format_str = '%Y-%m-%d'
            periods = 7
        elif time_range == '30d':
            interval = timedelta(days=1)
            format_str = '%Y-%m-%d'
            periods = 30
        else:
            interval = timedelta(days=7)
            format_str = '%Y-%m-%d'
            periods = 12

        activity_data = {
            'labels': [],
            'scans': [],
            'vulnerabilities': []
        }

        for i in range(periods):
            end_date = now - (i * interval)
            start_date = end_date - interval
            
            # Convert timestamps to naive UTC for comparison
            def to_naive_utc(dt_str):
                try:
                    # Parse ISO format and convert to naive UTC
                    dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
                    if dt.tzinfo:
                        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
                    return dt
                except Exception:
                    return None
            
            # Filter scans for this period
            period_scans = [
                s for s in scans 
                if s.get('created_at') and start_date <= to_naive_utc(s['created_at']) <= end_date
            ]
            
            # Calculate vulnerabilities for this period
            period_vulns = sum(
                len(s.get('vulnerabilities', [])) if isinstance(s.get('vulnerabilities'), list)
                else len(json.loads(s.get('vulnerabilities', '[]'))) if isinstance(s.get('vulnerabilities'), str)
                else 0
                for s in period_scans
            )
            
            activity_data['labels'].insert(0, end_date.strftime(format_str))
            activity_data['scans'].insert(0, len(period_scans))
            activity_data['vulnerabilities'].insert(0, period_vulns)

        # Get top vulnerabilities
        top_vulns = sorted(
            [{'type': k, **v} for k, v in vuln_types.items()],
            key=lambda x: x['count'],
            reverse=True
        )[:10]

        # Get recent activity
        recent_activity = []
        for scan in sorted(scans, key=lambda x: x.get('created_at', ''), reverse=True)[:10]:
            try:
                vulnerabilities = scan.get('vulnerabilities', [])
                if isinstance(vulnerabilities, str):
                    vulnerabilities = json.loads(vulnerabilities)
                
                recent_activity.append({
                    'url': scan.get('target_url'),
                    'timestamp': scan.get('created_at'),
                    'vulnerabilities': len(vulnerabilities),
                    'duration': scan.get('scan_duration', 0)
                })
            except Exception as e:
                logger.error(f"Error processing recent activity for scan {scan.get('id')}: {str(e)}")
                continue

        return jsonify({
            'stats': {
                'totalScans': total_scans,
                'totalVulnerabilities': total_vulns,
                'avgVulnerabilitiesPerScan': avg_vulns_per_scan,
                'avgScanTime': avg_scan_time
            },
            'charts': {
                'vulnerabilityDistribution': vuln_distribution,
                'scanActivity': activity_data
            },
            'topVulnerabilities': top_vulns,
            'recentActivity': recent_activity
        })

    except Exception as e:
        logger.error(f"Error in analytics endpoint: {str(e)}")
        return jsonify({
            'error': str(e),
            'stats': {
                'totalScans': 0,
                'totalVulnerabilities': 0,
                'avgVulnerabilitiesPerScan': 0,
                'avgScanTime': 0
            },
            'charts': {
                'vulnerabilityDistribution': [0, 0, 0, 0],
                'scanActivity': {'labels': [], 'scans': [], 'vulnerabilities': []}
            },
            'topVulnerabilities': [],
            'recentActivity': []
        }), 500

@app.route('/profile')
@login_required
def profile():
    try:
        # Get user data from Supabase
        user_id = session.get('user_id')
        user_data = supabase_admin.table('users')\
            .select('*')\
            .eq('id', user_id)\
            .single()\
            .execute()

        if not user_data.data:
            flash('User data not found', 'danger')
            return redirect(url_for('vulnscan'))

        # Get user's scan statistics
        scans_response = supabase_admin.table('scans')\
            .select('*')\
            .eq('user_id', user_id)\
            .execute()

        scans = scans_response.data if scans_response.data else []
        
        # Calculate user statistics
        total_scans = len(scans)
        total_vulnerabilities = 0
        total_scan_time = 0
        vulnerability_severity = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }

        for scan in scans:
            try:
                vulnerabilities = scan.get('vulnerabilities', [])
                if isinstance(vulnerabilities, str):
                    vulnerabilities = json.loads(vulnerabilities)
                
                total_vulnerabilities += len(vulnerabilities)
                total_scan_time += scan.get('scan_duration', 0)

                # Count vulnerabilities by severity
                for vuln in vulnerabilities:
                    severity = vuln.get('severity', '').lower()
                    if severity in vulnerability_severity:
                        vulnerability_severity[severity] += 1
            except Exception as e:
                logger.error(f"Error processing scan {scan.get('id')}: {str(e)}")
                continue

        # Calculate averages
        avg_vulnerabilities = round(total_vulnerabilities / total_scans, 2) if total_scans > 0 else 0
        avg_scan_time = round(total_scan_time / total_scans, 2) if total_scans > 0 else 0

        # Get recent activity
        recent_scans = sorted(scans, key=lambda x: x.get('created_at', ''), reverse=True)[:5]
        recent_activity = []

        for scan in recent_scans:
            try:
                vulnerabilities = scan.get('vulnerabilities', [])
                if isinstance(vulnerabilities, str):
                    vulnerabilities = json.loads(vulnerabilities)

                recent_activity.append({
                    'target_url': scan.get('target_url'),
                    'created_at': scan.get('created_at'),
                    'vulnerabilities': len(vulnerabilities),
                    'scan_duration': scan.get('scan_duration', 0)
                })
            except Exception as e:
                logger.error(f"Error processing recent activity: {str(e)}")
                continue

        return render_template('profile.html',
                             user=user_data.data,
                             stats={
                                 'total_scans': total_scans,
                                 'total_vulnerabilities': total_vulnerabilities,
                                 'avg_vulnerabilities': avg_vulnerabilities,
                                 'avg_scan_time': avg_scan_time,
                                 'vulnerability_severity': vulnerability_severity
                             },
                             recent_activity=recent_activity)

    except Exception as e:
        logger.error(f"Error in profile route: {str(e)}")
        flash('Error loading profile data', 'danger')
        return redirect(url_for('vulnscan'))

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    try:
        user_id = session.get('user_id')
        data = request.form.to_dict()
        
        # Validate username
        if 'username' in data:
            username = data['username'].strip()
            if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', username):
                flash('Username must be 3-20 characters long and contain only letters, numbers, underscores, and hyphens.', 'danger')
                return redirect(url_for('profile'))

        # Update user data
        update_data = {
            'username': data.get('username')
        }

        result = supabase_admin.table('users')\
            .update(update_data)\
            .eq('id', user_id)\
            .execute()

        if result.data:
            session['username'] = data.get('username')
            flash('Profile updated successfully', 'success')
        else:
            flash('Failed to update profile', 'danger')

        return redirect(url_for('profile'))

    except Exception as e:
        logger.error(f"Error updating profile: {str(e)}")
        flash('Error updating profile', 'danger')
        return redirect(url_for('profile'))

@app.route('/profile/change-password', methods=['POST'])
@login_required
def change_password():
    try:
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not all([current_password, new_password, confirm_password]):
            flash('All password fields are required', 'danger')
            return redirect(url_for('profile'))

        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('profile'))

        # Validate password strength
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long', 'danger')
            return redirect(url_for('profile'))

        if not any(c.isupper() for c in new_password):
            flash('Password must contain at least one uppercase letter', 'danger')
            return redirect(url_for('profile'))

        if not any(c.islower() for c in new_password):
            flash('Password must contain at least one lowercase letter', 'danger')
            return redirect(url_for('profile'))

        if not any(c.isdigit() for c in new_password):
            flash('Password must contain at least one number', 'danger')
            return redirect(url_for('profile'))

        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in new_password):
            flash('Password must contain at least one special character', 'danger')
            return redirect(url_for('profile'))

        # Update password in Supabase Auth
        user_id = session.get('user_id')
        supabase_admin.auth.admin.update_user_by_id(
            user_id,
            {"password": new_password}
        )

        flash('Password updated successfully', 'success')
        return redirect(url_for('profile'))

    except Exception as e:
        logger.error(f"Error changing password: {str(e)}")
        flash('Error updating password', 'danger')
        return redirect(url_for('profile'))

@app.route('/history')
@login_required
def history():
    try:
        # Get all scans for the user
        user_id = session.get('user_id')
        scans_response = supabase_admin.table('scans')\
            .select('*')\
            .eq('user_id', user_id)\
            .order('created_at', desc=True)\
            .execute()

        if not scans_response.data:
            return render_template('history.html', scans=[])

        # Process scans
        processed_scans = []
        for scan in scans_response.data:
            try:
                # Get vulnerabilities
                vulnerabilities = scan.get('vulnerabilities', [])
                if isinstance(vulnerabilities, str):
                    vulnerabilities = json.loads(vulnerabilities)
                elif not isinstance(vulnerabilities, list):
                    vulnerabilities = []

                # Calculate severity counts
                severity_counts = {
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0
                }

                for vuln in vulnerabilities:
                    severity = vuln.get('severity', '').lower()
                    if severity in severity_counts:
                        severity_counts[severity] += 1

                # Process scan data
                processed_scan = {
                    'id': scan.get('id'),
                    'target_url': scan.get('target_url'),
                    'created_at': scan.get('created_at'),
                    'scan_duration': scan.get('scan_duration', 0),
                    'total_vulnerabilities': len(vulnerabilities),
                    'severity_counts': severity_counts,
                    'vulnerabilities': vulnerabilities,
                    'status': scan.get('status', 'completed')
                }
                processed_scans.append(processed_scan)

            except Exception as e:
                logger.error(f"Error processing scan {scan.get('id')}: {str(e)}")
                continue

        return render_template('history.html', scans=processed_scans)

    except Exception as e:
        logger.error(f"Error in history route: {str(e)}")
        flash('Error loading scan history', 'danger')
        return render_template('history.html', scans=[])

# Settings Helper Functions
def get_user_settings(user_id):
    """Get user settings from Supabase."""
    try:
        # Get settings using admin client
        settings = supabase_admin.table('user_settings')\
            .select('*')\
            .eq('user_id', user_id)\
            .execute()
            
        # Check if settings exist
        if settings.data and len(settings.data) > 0:
            return settings.data[0]
            
        # If no settings found, create default settings
        return create_default_settings(user_id)
    except Exception as e:
        logger.error(f"Error getting user settings: {str(e)}")
        return get_default_settings()

def create_default_settings(user_id):
    """Create default settings for a new user."""
    try:
        # Get default settings with user_id and API key
        default_settings = get_default_settings()
        default_settings['user_id'] = user_id
        default_settings['api_key'] = secrets.token_urlsafe(32)
        
        # Insert settings using admin client
        result = supabase_admin.table('user_settings')\
            .insert(default_settings)\
            .execute()
            
        # Return created settings or defaults
        if result.data and len(result.data) > 0:
            return result.data[0]
        return default_settings
    except Exception as e:
        logger.error(f"Error creating default settings: {str(e)}")
        return get_default_settings()

def get_default_settings():
    """Get default settings dictionary."""
    return {
        'scan_depth': 2,
        'concurrent_scans': 3,
        'scan_timeout': 30,
        'auto_scan': False,
        'email_notifications': True,
        'critical_alerts': True,
        'scan_completion': True,
        'report_format': 'pdf',
        'include_details': True,
        'auto_export': False,
        'api_key': secrets.token_urlsafe(32)
    }

def update_settings(user_id, settings_type, **settings):
    """Update user settings in Supabase."""
    try:
        # Validate settings based on type
        if settings_type == 'scan':
            if not (1 <= settings.get('scan_depth', 2) <= 3):
                raise ValueError('Invalid scan depth value')
            if not (1 <= settings.get('concurrent_scans', 3) <= 5):
                raise ValueError('Invalid concurrent scans value')
            if not (5 <= settings.get('scan_timeout', 30) <= 120):
                raise ValueError('Invalid scan timeout value')
        elif settings_type == 'report':
            if settings.get('report_format') not in ['pdf', 'html', 'json']:
                raise ValueError('Invalid report format')
                
        # Update settings using admin client
        result = supabase_admin.table('user_settings')\
            .update(settings)\
            .eq('user_id', user_id)\
            .execute()
            
        # Check update result
        if result.data and len(result.data) > 0:
            return True, "Settings updated successfully"
        return False, "Failed to update settings"
        
    except ValueError as ve:
        return False, str(ve)
    except Exception as e:
        logger.error(f"Error updating settings: {str(e)}")
        return False, f"Error updating settings: {str(e)}"

@app.route('/settings/general', methods=['GET'])
@login_required
def settings_general():
    """Render the general settings page."""
    try:
        # Get user settings
        settings = get_user_settings(session['user_id'])
        if not settings:
            # If no settings returned, use defaults
            settings = get_default_settings()
            settings['user_id'] = session['user_id']
            
        return render_template('settings_general.html', settings=settings)
    except Exception as e:
        logger.error(f"Error loading settings page: {str(e)}")
        flash('Error loading settings', 'danger')
        return redirect(url_for('vulnscan'))

@app.route('/settings/update_scan_settings', methods=['POST'])
@login_required
def update_scan_settings():
    """Update scan settings."""
    try:
        scan_settings = {
            'scan_depth': int(request.form.get('scan_depth', 2)),
            'concurrent_scans': int(request.form.get('concurrent_scans', 3)),
            'scan_timeout': int(request.form.get('scan_timeout', 30)),
            'auto_scan': request.form.get('auto_scan') == 'on'
        }
        
        success, message = update_settings(session['user_id'], 'scan', **scan_settings)
        
        if success:
            flash('Scan settings updated successfully', 'success')
        else:
            flash(message, 'danger')
            
    except Exception as e:
        flash(f'Error updating scan settings: {str(e)}', 'danger')
        
    return redirect(url_for('settings_general'))

@app.route('/settings/update_notification_settings', methods=['POST'])
@login_required
def update_notification_settings():
    """Update notification settings."""
    try:
        notification_settings = {
            'email_notifications': request.form.get('email_notifications') == 'on',
            'critical_alerts': request.form.get('critical_alerts') == 'on',
            'scan_completion': request.form.get('scan_completion') == 'on'
        }
        
        success, message = update_settings(session['user_id'], 'notification', **notification_settings)
        
        if success:
            flash('Notification settings updated successfully', 'success')
        else:
            flash(message, 'danger')
            
    except Exception as e:
        flash(f'Error updating notification settings: {str(e)}', 'danger')
        
    return redirect(url_for('settings_general'))

@app.route('/settings/update_report_settings', methods=['POST'])
@login_required
def update_report_settings():
    """Update report settings."""
    try:
        report_settings = {
            'report_format': request.form.get('report_format', 'pdf'),
            'include_details': request.form.get('include_details') == 'on',
            'auto_export': request.form.get('auto_export') == 'on'
        }
        
        success, message = update_settings(session['user_id'], 'report', **report_settings)
        
        if success:
            flash('Report settings updated successfully', 'success')
        else:
            flash(message, 'danger')
            
    except Exception as e:
        flash(f'Error updating report settings: {str(e)}', 'danger')
        
    return redirect(url_for('settings_general'))

@app.route('/api/regenerate-key', methods=['POST'])
@login_required
def regenerate_api_key():
    """Regenerate API key."""
    try:
        new_api_key = secrets.token_urlsafe(32)
        success, message = update_settings(session['user_id'], 'api', api_key=new_api_key)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'API key regenerated successfully',
                'api_key': new_api_key
            })
        return jsonify({
            'success': False,
            'message': message
        }), 500
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

# Reports Helper Functions
def generate_report(scan_id, report_format='pdf', include_details=True):
    """Generate a report for a scan."""
    try:
        # Get scan data
        scan = supabase_admin.table('scans')\
            .select('*')\
            .eq('id', scan_id)\
            .single()\
            .execute()
            
        if not scan.data:
            raise ValueError('Scan not found')
            
        # Process vulnerabilities
        vulnerabilities = json.loads(scan.data.get('vulnerabilities', '[]'))
        stats = json.loads(scan.data.get('stats', '{}'))
        
        # Create report data
        report_data = {
            'scan_info': {
                'target_url': scan.data.get('target_url'),
                'scan_date': scan.data.get('created_at'),
                'scan_duration': scan.data.get('scan_duration'),
                'status': scan.data.get('status')
            },
            'vulnerabilities': vulnerabilities if include_details else len(vulnerabilities),
            'statistics': stats,
            'summary': generate_report_summary(vulnerabilities, stats)
        }
        
        # Create report record
        report = {
            'user_id': scan.data.get('user_id'),
            'scan_id': scan_id,
            'report_format': report_format,
            'report_data': json.dumps(report_data),
            'summary': report_data['summary'],
            'total_vulnerabilities': len(vulnerabilities),
            'severity_counts': json.dumps(stats),
            'status': 'generating'
        }
        
        # Insert report
        result = supabase_admin.table('reports')\
            .insert(report)\
            .execute()
            
        if not result.data:
            raise ValueError('Failed to create report')
            
        # Generate report file
        report_file = generate_report_file(result.data[0], report_data, report_format)
        
        # Update report with download URL
        supabase_admin.table('reports')\
            .update({'status': 'completed', 'download_url': report_file})\
            .eq('id', result.data[0].get('id'))\
            .execute()
            
        return result.data[0]
        
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        raise

def generate_report_summary(vulnerabilities, stats):
    """Generate a summary for the report."""
    critical = stats.get('critical', 0)
    high = stats.get('high', 0)
    medium = stats.get('medium', 0)
    low = stats.get('low', 0)
    
    risk_level = 'Critical' if critical > 0 else 'High' if high > 0 else 'Medium' if medium > 0 else 'Low' if low > 0 else 'Safe'
    
    return f"Security scan found {len(vulnerabilities)} vulnerabilities ({critical} Critical, {high} High, {medium} Medium, {low} Low). Overall risk level: {risk_level}"

def generate_report_file(report, report_data, report_format):
    """Generate the actual report file in the specified format."""
    try:
        if report_format == 'json':
            return generate_json_report(report, report_data)
        elif report_format == 'html':
            return generate_html_report(report, report_data)
        else:  # pdf
            return generate_pdf_report(report, report_data)
    except Exception as e:
        logger.error(f"Error generating report file: {str(e)}")
        raise

def generate_json_report(report, report_data):
    """Generate a JSON report."""
    # Implementation for JSON report generation
    pass

def generate_html_report(report, report_data):
    """Generate an HTML report."""
    # Implementation for HTML report generation
    pass

def generate_pdf_report(report, report_data):
    """Generate a PDF report."""
    # Implementation for PDF report generation
    pass

@app.route('/reports')
@login_required
def reports():
    """Display the reports page."""
    try:
        # Get user's reports
        reports_response = supabase_admin.table('reports')\
            .select('*')\
            .eq('user_id', session['user_id'])\
            .order('created_at', desc=True)\
            .execute()
            
        reports = []
        if reports_response.data:
            for report in reports_response.data:
                try:
                    severity_counts = json.loads(report.get('severity_counts', '{}'))
                    reports.append({
                        'id': report.get('id'),
                        'scan_id': report.get('scan_id'),
                        'format': report.get('report_format'),
                        'summary': report.get('summary'),
                        'total_vulnerabilities': report.get('total_vulnerabilities', 0),
                        'severity_counts': severity_counts,
                        'status': report.get('status'),
                        'download_url': report.get('download_url'),
                        'created_at': report.get('created_at')
                    })
                except Exception as e:
                    logger.error(f"Error processing report {report.get('id')}: {str(e)}")
                    continue
                    
        return render_template('reports.html', reports=reports)
        
    except Exception as e:
        logger.error(f"Error in reports route: {str(e)}")
        flash('Error loading reports', 'danger')
        return render_template('reports.html', reports=[])

@app.route('/api/reports/generate/<scan_id>', methods=['POST'])
@login_required
def generate_report_api(scan_id):
    """API endpoint to generate a report."""
    try:
        # Get user settings
        settings = get_user_settings(session['user_id'])
        
        # Generate report
        report = generate_report(
            scan_id,
            report_format=settings.get('report_format', 'pdf'),
            include_details=settings.get('include_details', True)
        )
        
        return jsonify({
            'success': True,
            'message': 'Report generated successfully',
            'report': report
        })
        
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/reports/download/<report_id>')
@login_required
def download_report(report_id):
    """Download a report."""
    try:
        # Get report
        report = supabase_admin.table('reports')\
            .select('*')\
            .eq('id', report_id)\
            .eq('user_id', session['user_id'])\
            .single()\
            .execute()
            
        if not report.data:
            flash('Report not found', 'danger')
            return redirect(url_for('reports'))
            
        if not report.data.get('download_url'):
            flash('Report file not available', 'danger')
            return redirect(url_for('reports'))
            
        # Return the file
        return redirect(report.data.get('download_url'))
        
    except Exception as e:
        logger.error(f"Error downloading report: {str(e)}")
        flash('Error downloading report', 'danger')
        return redirect(url_for('reports'))

@app.route('/ids')
@login_required
def ids():
    """Render the IDS page with AI integration."""
    try:
        settings = get_user_settings(session['user_id'])
        return render_template('Ai.html',  # Template should be in main templates directory
                             settings=settings,
                             user_role=session.get('role', 'regular_user'))
    except Exception as e:
        logger.error(f"Error loading IDS page: {str(e)}")
        flash('Error loading IDS interface', 'danger')
        return redirect(url_for('vulnscan'))

@app.route('/api/ids/upload', methods=['POST'])
@login_required
def ids_upload():
    """Handle file uploads for AI analysis."""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        result = chatbot.handle_upload(file)
        
        if isinstance(result, tuple):
            return jsonify(result[0]), result[1]
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in file upload: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/ids/chat', methods=['POST'])
@login_required
def ids_chat():
    """Handle IDS chat interactions."""
    try:
        data = request.get_json()
        user_message = data.get('message', '')
        
        if not user_message:
            return jsonify({
                'success': False,
                'message': 'No message provided'
            }), 400
            
        # Get response from ChatBot
        response = chatbot.get_response(user_message)
        
        return jsonify({
            'success': True,
            'response': response,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in IDS chat: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@socketio.on('ids_message')
def handle_ids_message(message):
    """Handle real-time IDS chat messages via WebSocket."""
    try:
        response = chatbot.get_response(message['data'])
        emit('ids_response', {
            'response': response,
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Error in IDS WebSocket handler: {str(e)}")
        emit('ids_error', {'message': str(e)})

# Update TRUSTED_DOMAINS with more legitimate domains
TRUSTED_DOMAINS = {
    # Social Media & Video Platforms
    'youtube.com', 'www.youtube.com', 'youtu.be',
    'facebook.com', 'www.facebook.com', 'fb.com',
    'twitter.com', 'www.twitter.com', 'x.com',
    'linkedin.com', 'www.linkedin.com',
    'instagram.com', 'www.instagram.com',
    
    # Google Services
    'google.com', 'www.google.com',
    'gmail.com', 'www.gmail.com',
    'drive.google.com', 'docs.google.com',
    'meet.google.com', 'play.google.com',
    'chrome.google.com', 'store.google.com',
    
    # Microsoft Services
    'microsoft.com', 'www.microsoft.com',
    'outlook.com', 'www.outlook.com',
    'live.com', 'www.live.com',
    'office.com', 'www.office.com',
    'windows.com', 'xbox.com',
    
    # Cloud Services
    'github.com', 'www.github.com', 'raw.githubusercontent.com',
    'gitlab.com', 'www.gitlab.com',
    'amazonaws.com', 'amazon.com', 'aws.amazon.com',
    'azure.com', 'azure.microsoft.com',
    'cloudflare.com', 'www.cloudflare.com',
    'digitalocean.com', 'www.digitalocean.com',
    
    # Popular Services
    'apple.com', 'www.apple.com', 'icloud.com',
    'amazon.com', 'www.amazon.com',
    'netflix.com', 'www.netflix.com',
    'spotify.com', 'www.spotify.com',
    'dropbox.com', 'www.dropbox.com',
    'wordpress.com', 'www.wordpress.com',
    'shopify.com', 'www.shopify.com',
    'zoom.us', 'www.zoom.us',
    
    # Popular CDNs
    'cloudfront.net',
    'akamai.net',
    'fastly.net',
    'jsdelivr.net',
    'unpkg.com',
    'cdnjs.cloudflare.com',
    
    # Educational
    'edu', '.edu',
    'ac.uk', '.ac.uk',
    'edu.au', '.edu.au',
    
    # Government
    'gov', '.gov',
    'mil', '.mil',
    
    # Common TLDs (for better domain validation)
    'com', 'org', 'net', 'io', 'co'
}

# Add these lists at the top with TRUSTED_DOMAINS
SUSPICIOUS_KEYWORDS = {
    'login', 'signin', 'verify', 'account', 'secure', 'banking', 'security',
    'payment', 'wallet', 'crypto', 'bitcoin', 'authenticate', 'password',
    'credential', 'token', 'reset', 'update', 'confirm'
}

SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.club', '.online', '.site', '.icu', '.live', '.click',
    '.loan', '.work', '.beauty', '.support', '.loan', '.download', '.country',
    '.stream', '.racing', '.xin', '.win', '.bid', '.gq', '.tk', '.ml', '.ga', '.cf'
}

MALICIOUS_PATTERNS = {
    # URL patterns
    r'(paypal|apple|google|microsoft|amazon|facebook).*\..*\.(com|net|org)',  # Fake domains
    r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses in URL
    
    # Path patterns
    r'/wp-admin.*\.php',
    r'/includes.*\.php',
    r'/admin.*\.php',
    r'/shell.*\.php',
    r'/upload.*\.php',
    r'/thumb.*\.php',
    r'/image.*\.php',
    r'/download.*\.exe'
}

@app.route('/url-checker')
@login_required
def url_checker():
    """Render the URL Checker page."""
    try:
        return render_template('url_checker.html')
    except Exception as e:
        logger.error(f"Error loading URL checker: {str(e)}")
        flash('Error loading URL checker', 'danger')
        return redirect(url_for('vulnscan'))

@app.route('/api/check-url', methods=['POST'])
@login_required
def check_url():
    """API endpoint for URL security checking."""
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
            
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()
        
        # Check if domain or its parent domain is trusted
        is_trusted = any(
            domain.endswith(f".{trusted}") or domain == trusted 
            for trusted in TRUSTED_DOMAINS
        )
        
        # Additional security checks
        def has_suspicious_patterns():
            # Check for IP address as domain
            if re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', domain):
                return True
                
            # Check for suspicious TLDs
            if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
                return True
                
            # Check for malicious patterns in full URL
            if any(re.search(pattern, url.lower()) for pattern in MALICIOUS_PATTERNS):
                return True
                
            # Check for brand impersonation
            if any(brand in domain and not domain.endswith(f".{brand}.com") 
                  for brand in ['paypal', 'apple', 'google', 'microsoft', 'amazon', 'facebook']):
                return True
                
            return False
        
        # Initialize checks dictionary
        checks = {
            'trusted_domain': {
                'passed': is_trusted,
                'message': 'Trusted Domain Check: ' + ('Domain is trusted' if is_trusted else 'Domain not in trusted list')
            },
            'suspicious_patterns': {
                'passed': not has_suspicious_patterns(),
                'message': 'Malicious Pattern Check: ' + ('No suspicious patterns detected' if not has_suspicious_patterns() else 'Suspicious patterns detected')
            },
            'https': {
                'passed': url.startswith('https://'),
                'message': 'HTTPS Protocol Check: ' + ('URL uses secure HTTPS protocol' if url.startswith('https://') else 'URL does not use HTTPS')
            },
            'dns': {
                'passed': False,
                'message': 'DNS Check: Checking domain DNS records...'
            },
            'domain_age': {
                'passed': False,
                'message': 'Domain Age Check: Verifying domain age...'
            },
            'suspicious_ip': {
                'passed': False,
                'message': 'IP Check: Analyzing IP address...'
            },
            'response': {
                'passed': False,
                'message': 'Response Check: Verifying URL response...'
            },
            'content': {
                'passed': False,
                'message': 'Content Check: Analyzing page content...'
            }
        }
        
        # If domain is trusted, some checks are automatically passed
        if checks['trusted_domain']['passed']:
            for check in ['suspicious_ip', 'domain_age', 'dns', 'content']:
                checks[check]['passed'] = True
                checks[check]['message'] = f'{check.replace("_", " ").title()} Check: Domain is trusted'
        else:
            # DNS check
            try:
                dns.resolver.resolve(domain, 'A')
                checks['dns']['passed'] = True
                checks['dns']['message'] = 'DNS Check: Domain has valid DNS records'
            except:
                checks['dns']['message'] = 'DNS Check: Domain has invalid or missing DNS records'
            
            # Domain age check
            try:
                domain_info = whois.whois(domain)
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                if creation_date:
                    age_days = (datetime.now() - creation_date).days
                    checks['domain_age']['passed'] = age_days > 30  # Reduced from 90 to 30 days
                    checks['domain_age']['message'] = f'Domain Age Check: Domain is {age_days} days old'
            except:
                # Don't automatically fail if we can't verify age
                checks['domain_age']['passed'] = True
                checks['domain_age']['message'] = 'Domain Age Check: Unable to verify domain age'
            
            # IP check
            try:
                ip_address = socket.gethostbyname(domain)
                private_ip_patterns = [
                    "192.168.",
                    "10.",
                    "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.",
                    "172.24.", "172.25.", "172.26.", "172.27.",
                    "172.28.", "172.29.", "172.30.", "172.31.",
                    "127.",
                    "169.254."
                ]
                is_private = any(ip_address.startswith(pattern) for pattern in private_ip_patterns)
                checks['suspicious_ip']['passed'] = not is_private
                checks['suspicious_ip']['message'] = f'IP Check: Domain IP ({ip_address}) ' + ('appears safe' if not is_private else 'uses private IP range')
            except:
                checks['suspicious_ip']['message'] = 'IP Check: Unable to resolve domain IP'
            
            # Content check with improved patterns
            try:
                response = requests.get(url, timeout=5)
                suspicious_patterns = [
                    "<script>eval(",
                    "javascript:void(",
                    "onclick=alert",
                    "onload=eval",
                    "onerror=eval"
                ]
                content_lower = response.text.lower()
                has_suspicious = any(pattern.lower() in content_lower for pattern in suspicious_patterns)
                
                # Don't mark as suspicious for common legitimate uses
                legitimate_patterns = [
                    "google-analytics.com",
                    "googletagmanager.com",
                    "jquery",
                    "bootstrap",
                    "cloudflare",
                    "cdn"
                ]
                has_legitimate = any(pattern.lower() in content_lower for pattern in legitimate_patterns)
                
                checks['content']['passed'] = not has_suspicious or has_legitimate
                checks['content']['message'] = 'Content Check: ' + ('No suspicious content detected' if checks['content']['passed'] else 'Contains potentially suspicious scripts')
            except:
                # Don't fail if content check fails
                checks['content']['passed'] = True
                checks['content']['message'] = 'Content Check: Unable to analyze page content'

        # Response check (always performed)
        try:
            response = requests.head(url, timeout=5, allow_redirects=True)
            checks['response']['passed'] = response.status_code < 400
            checks['response']['message'] = f'Response Check: URL returns status code {response.status_code}'
        except requests.exceptions.SSLError:
            checks['response']['message'] = 'Response Check: SSL certificate validation failed'
        except requests.exceptions.ConnectionError:
            checks['response']['message'] = 'Response Check: Unable to connect to URL'
        except requests.exceptions.Timeout:
            checks['response']['message'] = 'Response Check: Connection timed out'
        except:
            checks['response']['message'] = 'Response Check: Unable to connect to URL'
        
        # Calculate safety based on critical checks only
        critical_checks = {
            'https': checks['https']['passed'],          # Must use HTTPS
            'dns': checks['dns']['passed'],              # Must have valid DNS
            'suspicious_patterns': checks['suspicious_patterns']['passed'],  # Must not have malicious patterns
            'suspicious_ip': checks['suspicious_ip']['passed']  # Must not use suspicious IP
        }

        # Website is considered safe if:
        # 1. It's a trusted domain, OR
        # 2. It passes all critical checks and has no major red flags
        is_safe = (
            checks['trusted_domain']['passed'] or
            (all(critical_checks.values()) and
             checks['response']['passed'] and  # Should return valid response
             not any(check['message'].startswith('Error:') for check in checks.values()))  # No major errors
        )

        return jsonify({
            'is_safe': is_safe,
            'checks': checks
        })
        
    except Exception as e:
        logger.error(f"Error checking URL: {str(e)}")
        return jsonify({
            'error': str(e)
        }), 500

# SIEM Tool Global Variables
events = []
alerts = []
is_monitoring = False
monitor_thread = None

def monitor_events():
    global events, alerts, is_monitoring
    
    while is_monitoring:
        try:
            for log_type in ["Security", "System", "Application"]:
                hand = win32evtlog.OpenEventLog(None, log_type)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                
                while is_monitoring:
                    events_list = win32evtlog.ReadEventLog(hand, flags, 0)
                    if not events_list:
                        break
                        
                    for event in events_list:
                        formatted_event = format_event(event, log_type)
                        events.append(formatted_event)
                        
                        if 'alert_message' in formatted_event:
                            alerts.append({
                                'message': formatted_event['alert_message'],
                                'event': formatted_event
                            })
                
                win32evtlog.CloseEventLog(hand)
                
        except Exception as e:
            logger.error(f"Error monitoring events: {e}")
            is_monitoring = False
            break
            
        time.sleep(1)

def format_event(event, log_type):
    description_data = {}
    if event.StringInserts:
        raw_description = "\n".join(event.StringInserts)
        lines = raw_description.split('\n')
        
        if log_type == "Security" and event.SourceName == "Microsoft-Windows-Security-Auditing":
            for i, line in enumerate(lines):
                line = line.strip()
                if not line:
                    continue
                
                if line.startswith('C:') or '\\' in line:
                    description_data['process_path'] = line
                elif line.endswith('$'):
                    description_data['machine_account'] = line
                elif line.startswith('S-1-5-'):
                    if 'user_sid' not in description_data:
                        description_data['user_sid'] = line
                    else:
                        description_data['target_sid'] = line
                elif line.startswith('0x'):
                    if 'process_id' not in description_data:
                        description_data['process_id'] = line
                    else:
                        description_data['thread_id'] = line
                elif line == 'WORKGROUP':
                    description_data['domain'] = line
                elif line.startswith('DESKTOP-') or line.startswith('LENOVO'):
                    if 'computer_name' not in description_data:
                        description_data['computer_name'] = line
                    else:
                        description_data['workstation_name'] = line
        
        elif log_type == "System":
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                parts = None
                for separator in [':\t', ':\n', ':', '\t', '=']:
                    if separator in line:
                        parts = line.split(separator, 1)
                        break
                
                if parts and len(parts) == 2:
                    key = parts[0].strip().lower()
                    value = parts[1].strip()
                    if 'service' in key:
                        key = 'service_name'
                    elif 'state' in key:
                        key = 'service_state'
                    description_data[key] = value
                else:
                    description_data[f'detail_{len(description_data)}'] = line
        
        elif log_type == "Application":
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                parts = None
                for separator in [':\t', ':\n', ':', '\t', '=']:
                    if separator in line:
                        parts = line.split(separator, 1)
                        break
                
                if parts and len(parts) == 2:
                    key = parts[0].strip().lower()
                    value = parts[1].strip()
                    if 'application' in key:
                        key = 'app_name'
                    elif 'version' in key:
                        key = 'app_version'
                    elif 'error' in key:
                        key = 'error_details'
                    description_data[key] = value
                else:
                    description_data[f'message_{len(description_data)}'] = line
    
    event_data = {
        'timestamp': event.TimeGenerated.Format(),
        'log_type': log_type,
        'event_id': event.EventID,
        'source': event.SourceName,
        'category': event.EventCategory,
        'description': description_data
    }
    
    alert_message = get_alert_message(event, log_type)
    if alert_message:
        logger.info(f"Alert generated: {alert_message} for event ID: {event.EventID}")
        event_data['alert_message'] = alert_message
        
    return event_data

def get_alert_message(event, log_type):
    event_id = event.EventID
    source = event.SourceName
    logger.debug(f"Checking alert for event ID: {event_id} in log type: {log_type}, Source: {source}")
    
    # Security Events
    if log_type == "Security":
        if event_id == 4625:
            return "Failed Login Attempt Detected!"
        elif event_id == 4720:
            return "New User Account Created!"
        elif event_id == 4723:
            return "Password Change Attempt Detected!"
        elif event_id == 4688:  # Process Creation
            if event.StringInserts:
                process_info = "\n".join(event.StringInserts).lower()
                suspicious_commands = [
                    'cmd.exe', 'whoami', 'net user', 'net localgroup', 'netstat',
                    'ipconfig', 'systeminfo', 'tasklist', 'reg query', 'dir ',
                    'type ', 'ping ', 'tracert', 'nslookup'
                ]
                for command in suspicious_commands:
                    if command in process_info:
                        return f"Command Execution Detected: {command}!"
    
    # System Events
    elif log_type == "System":
        if event_id == 7036 and event.StringInserts and len(event.StringInserts) >= 2:
            service_name = event.StringInserts[0]
            service_state = event.StringInserts[1].lower()
            return f"Service '{service_name}' {service_state}!"
        elif event_id == 1074:
            return "System Shutdown/Restart Initiated!"
        elif event_id == 6005:
            return "System Startup Complete!"
        elif event_id == 6006:
            return "System Shutdown Complete!"
        elif event_id == 6008:
            return "System Unexpected Shutdown!"
        elif event_id == 1:
            return "System Error Detected!"
    
    # Application Events
    elif log_type == "Application":
        if source == "Windows PowerShell":
            return "PowerShell Activity Detected!"
        elif source in ["MsiInstaller", "Windows Installer"]:
            if event_id == 11707:
                return "Application Installation Success!"
            elif event_id == 11708:
                return "Application Installation Failed!"
            elif event_id == 11724:
                return "Application Installation Started!"
        elif source == "Application Error":
            return f"Application Error Detected in {event.StringInserts[0] if event.StringInserts else 'Unknown App'}!"
        elif source == "Application Hang":
            return f"Application Hang Detected in {event.StringInserts[0] if event.StringInserts else 'Unknown App'}!"
        elif source == "Windows Error Reporting":
            return "Application Crash Report Generated!"
        elif source == "TestApplication":
            return "Test Application Event Detected!"
    
    return None

@app.route('/api/siem/start', methods=['POST'])
@login_required
def start_monitoring():
    global is_monitoring, monitor_thread
    
    if not is_monitoring:
        is_monitoring = True
        monitor_thread = threading.Thread(target=monitor_events)
        monitor_thread.daemon = True
        monitor_thread.start()
        return jsonify({'status': 'success', 'message': 'Monitoring started'})
    
    return jsonify({'status': 'error', 'message': 'Monitoring already active'})

@app.route('/api/siem/stop', methods=['POST'])
@login_required
def stop_monitoring():
    global is_monitoring
    is_monitoring = False
    return jsonify({'status': 'success', 'message': 'Monitoring stopped'})

@app.route('/api/siem/events')
@login_required
def get_events():
    return jsonify(events)

@app.route('/api/siem/alerts')
@login_required
def get_alerts():
    return jsonify(alerts)

@app.route('/api/siem/clear', methods=['POST'])
@login_required
def clear_data():
    global events, alerts
    events = []
    alerts = []
    return jsonify({'status': 'success', 'message': 'Data cleared'})

# Add this route after other routes
@app.route('/report/<scan_id>')
@login_required
def report(scan_id):
    try:
        # Get scan details
        result = supabase_admin.table('scans').select('*').eq('id', scan_id).execute()
        if not result.data:
            return "Scan not found", 404

        scan = result.data[0]
        
        # Process vulnerabilities
        vulnerabilities = {}
        stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        # Parse vulnerabilities
        vuln_list = scan.get('vulnerabilities', [])
        if isinstance(vuln_list, str):
            try:
                vuln_list = json.loads(vuln_list)
            except:
                vuln_list = []
        
        # Group vulnerabilities by type
        for vuln in vuln_list:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in vulnerabilities:
                vulnerabilities[vuln_type] = []
            vulnerabilities[vuln_type].append(vuln)
            
            # Update stats
            severity = vuln.get('severity', 'low').lower()
            if severity in stats:
                stats[severity] += 1

        # Sort vulnerabilities by severity and then by type
        for vuln_type in vulnerabilities:
            vulnerabilities[vuln_type].sort(
                key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(x.get('severity', 'low').lower(), 4)
            )

        return render_template('report.html', 
                            scan=scan,
                            vulnerabilities=vulnerabilities,
                            stats=stats)
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/scans')
@login_required
def scans_page():
    return render_template('scans.html')

if __name__ == '__main__':
    try:
        port = int(os.getenv('PORT', 5000))
        host = '0.0.0.0'
        
     
        # Start the app
        print(f' * Running on http://{host}:{port}/')
        socketio.run(app, host=host, port=port, debug=True)
    except Exception as e:
        print(f' * Error: {str(e)}')
        socketio.run(app, debug=True)
