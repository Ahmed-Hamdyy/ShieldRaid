from flask import Blueprint, render_template, jsonify, request, url_for, abort
import win32evtlog
from datetime import datetime
import threading
import queue
from collections import deque
import json
import logging
import os
from functools import wraps
from flask import session, redirect, url_for

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create blueprint instead of Flask app
siem_bp = Blueprint('siem', __name__, 
    template_folder='templates',
    static_folder=None  # Use main app's static folder
)

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# CSRF protection decorator
def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == "POST":
            # Check if request is AJAX
            if not request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                logger.error('CSRF check failed: Not an AJAX request')
                abort(403)
        return f(*args, **kwargs)
    return decorated_function

# Global storage
events = []
alerts = []
is_monitoring = False
monitor_thread = None

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
            # Check if StringInserts contains process information
            if event.StringInserts:
                process_info = "\n".join(event.StringInserts).lower()
                # List of suspicious commands to monitor
                suspicious_commands = [
                    'cmd.exe',
                    'whoami',
                    'net user',
                    'net localgroup',
                    'netstat',
                    'ipconfig',
                    'systeminfo',
                    'tasklist',
                    'reg query',
                    'dir ',
                    'type ',
                    'ping ',
                    'tracert',
                    'nslookup'
                ]
                
                for command in suspicious_commands:
                    if command in process_info:
                        return f"Command Execution Detected: {command}!"
    
    # System Events
    elif log_type == "System":
        if event_id == 7036:  # Service Control Manager
            if event.StringInserts and len(event.StringInserts) >= 2:
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
        # PowerShell events
        if source == "Windows PowerShell":
            return "PowerShell Activity Detected!"
        # Windows Installer events
        elif source in ["MsiInstaller", "Windows Installer"]:
            if event_id == 11707:
                return "Application Installation Success!"
            elif event_id == 11708:
                return "Application Installation Failed!"
            elif event_id == 11724:
                return "Application Installation Started!"
        # Application Error events
        elif source == "Application Error":
            return f"Application Error Detected in {event.StringInserts[0] if event.StringInserts else 'Unknown App'}!"
        # Application Hang events
        elif source == "Application Hang":
            return f"Application Hang Detected in {event.StringInserts[0] if event.StringInserts else 'Unknown App'}!"
        # Windows Error Reporting
        elif source == "Windows Error Reporting":
            return "Application Crash Report Generated!"
        # Custom Application events
        elif source == "TestApplication":
            return "Test Application Event Detected!"
    
    return None

def format_event(event, log_type):
    logger.debug(f"Formatting event - ID: {event.EventID}, Type: {log_type}, Source: {event.SourceName}")
    
    # Parse the description into key-value pairs
    description_data = {}
    if event.StringInserts:
        raw_description = "\n".join(event.StringInserts)
        lines = raw_description.split('\n')
        
        # Handle different log types
        if log_type == "Security" and event.SourceName == "Microsoft-Windows-Security-Auditing":
            # Process the lines based on their position and content
            for i, line in enumerate(lines):
                line = line.strip()
                if not line:
                    continue
                
                # Try to identify the type of value based on its format and position
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
            # System log specific parsing
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Try to split on common separators
                parts = None
                for separator in [':\t', ':\n', ':', '\t', '=']:
                    if separator in line:
                        parts = line.split(separator, 1)
                        break
                
                if parts and len(parts) == 2:
                    key = parts[0].strip().lower()
                    value = parts[1].strip()
                    # Clean up common system event keys
                    if 'service' in key:
                        key = 'service_name'
                    elif 'state' in key:
                        key = 'service_state'
                    description_data[key] = value
                else:
                    description_data[f'detail_{len(description_data)}'] = line
        
        elif log_type == "Application":
            # Application log specific parsing
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Try to split on common separators
                parts = None
                for separator in [':\t', ':\n', ':', '\t', '=']:
                    if separator in line:
                        parts = line.split(separator, 1)
                        break
                
                if parts and len(parts) == 2:
                    key = parts[0].strip().lower()
                    value = parts[1].strip()
                    # Clean up common application event keys
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
    
    # Add alert message if this is an alert-worthy event
    alert_message = get_alert_message(event, log_type)
    if alert_message:
        logger.info(f"Alert generated: {alert_message} for event ID: {event.EventID}")
        event_data['alert_message'] = alert_message
        
    return event_data

def correlate_events(events, time_window_minutes=5):
    """Correlate events to detect potential security incidents"""
    correlated_alerts = []
    
    # Convert time window to seconds
    time_window = time_window_minutes * 60
    
    # Group events by timestamp and track processed events
    events_by_time = {}
    processed_events = set()
    
    for event in events:
        try:
            timestamp = datetime.strptime(event['timestamp'], '%a %b %d %H:%M:%S %Y')
            event_key = (event['event_id'], event['timestamp'])
            
            if event_key in processed_events:
                continue
                
            if timestamp not in events_by_time:
                events_by_time[timestamp] = []
            
            # Format event data in a structured way
            formatted_event = {
                'event_id': event.get('event_id', 'N/A'),
                'log_type': event.get('log_type', 'Unknown'),
                'source': event.get('source', 'Unknown'),
                'timestamp': event['timestamp'],
                'details': event.get('description', {}),
                'alert_message': event.get('alert_message', '')
            }
            
            events_by_time[timestamp].append(formatted_event)
            processed_events.add(event_key)
            
        except Exception as e:
            logger.error(f"Error parsing timestamp: {e}")
            continue
    
    # Sort timestamps
    sorted_times = sorted(events_by_time.keys())
    
    # Pattern 1: Multiple Failed Logins
    failed_logins = []
    for time in sorted_times:
        for event in events_by_time[time]:
            if "Failed Login Attempt" in str(event.get('alert_message', '')):
                failed_logins.append((time, event))
    
    if len(failed_logins) >= 2:
        time_diff = (failed_logins[-1][0] - failed_logins[0][0]).total_seconds()
        if time_diff <= time_window:
            correlated_alerts.append({
                'type': 'Potential Brute Force Attack',
                'events': [e[1] for e in failed_logins],
                'timestamp': datetime.now().strftime('%a %b %d %H:%M:%S %Y'),
                'details': f'Multiple failed login attempts detected within {time_window_minutes} minutes',
                'summary': {
                    'total_attempts': len(failed_logins),
                    'time_span': f'{time_diff:.1f} seconds',
                    'target_accounts': list(set(e[1].get('details', {}).get('machine_account', 'Unknown') for e in failed_logins))
                }
            })

    # Pattern 2: Suspicious Command Sequence
    suspicious_commands = []
    for time in sorted_times:
        for event in events_by_time[time]:
            if "Command Execution" in str(event.get('alert_message', '')):
                suspicious_commands.append((time, event))
    
    if len(suspicious_commands) >= 2:
        time_diff = (suspicious_commands[-1][0] - suspicious_commands[0][0]).total_seconds()
        if time_diff <= time_window:
            correlated_alerts.append({
                'type': 'Potential Reconnaissance Activity',
                'events': [e[1] for e in suspicious_commands],
                'timestamp': datetime.now().strftime('%a %b %d %H:%M:%S %Y'),
                'details': 'Multiple system commands executed in sequence',
                'summary': {
                    'total_commands': len(suspicious_commands),
                    'time_span': f'{time_diff:.1f} seconds',
                    'command_sources': list(set(e[1].get('details', {}).get('process_path', 'Unknown') for e in suspicious_commands))
                }
            })
    
    # Pattern 3: PowerShell Activity
    powershell_events = []
    for time in sorted_times:
        for event in events_by_time[time]:
            if "PowerShell" in str(event.get('source', '')):
                powershell_events.append((time, event))
    
    if powershell_events:  # Even single PowerShell events are interesting
        time_diff = 0
        if len(powershell_events) > 1:
            time_diff = (powershell_events[-1][0] - powershell_events[0][0]).total_seconds()
        
        correlated_alerts.append({
            'type': 'PowerShell Activity',
            'events': [e[1] for e in powershell_events],
            'timestamp': datetime.now().strftime('%a %b %d %H:%M:%S %Y'),
            'details': 'PowerShell activity detected',
            'summary': {
                'total_events': len(powershell_events),
                'time_span': f'{time_diff:.1f} seconds' if time_diff > 0 else 'Single event',
                'execution_context': list(set(e[1].get('details', {}).get('process_path', 'Unknown') for e in powershell_events))
            }
        })
    
    return correlated_alerts

def monitor_event_logs():
    global is_monitoring, events, alerts
    log_types = ["Application", "System", "Security"]
    logger.info(f"Starting event log monitoring for types: {log_types}")
    
    log_handles = {log_type: win32evtlog.OpenEventLog(None, log_type) for log_type in log_types}
    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    start_time = datetime.now()
    displayed_events = set()
    
    # Add baseline system info
    system_baseline = {
        'users': set(),
        'services': set(),
        'scheduled_tasks': set(),
        'network_connections': set()
    }

    try:
        while is_monitoring:
            for log_type, log_handle in log_handles.items():
                try:
                    windows_events = win32evtlog.ReadEventLog(log_handle, flags, 0)
                    for event in windows_events:
                        if event.EventID < 0:
                            continue
                            
                        event_time = event.TimeGenerated.Format()
                        event_datetime = datetime.strptime(event_time, '%a %b %d %H:%M:%S %Y')
                        
                        if event_datetime < start_time:
                            continue

                        event_key = (event.EventID, event_time)
                        if event_key in displayed_events:
                            continue
                            
                        displayed_events.add(event_key)
                        event_data = format_event(event, log_type)
                        
                        # Update baseline for specific events
                        if log_type == "Security":
                            if event.EventID == 4720:  # New user created
                                if event.StringInserts:
                                    system_baseline['users'].add(event.StringInserts[0])
                            elif event.EventID == 4697:  # Service installed
                                if event.StringInserts:
                                    system_baseline['services'].add(event.StringInserts[0])
                        
                        # Add baseline info to event data
                        event_data['system_baseline'] = {
                            'total_users': len(system_baseline['users']),
                            'total_services': len(system_baseline['services']),
                            'total_tasks': len(system_baseline['scheduled_tasks']),
                            'total_connections': len(system_baseline['network_connections'])
                        }
                        
                        if 'alert_message' in event_data:
                            logger.info(f"New alert: {event_data['alert_message']} (Event ID: {event_data['event_id']})")
                            alerts.append(event_data)
                        
                        logger.debug(f"New event: Type={log_type}, ID={event.EventID}, Source={event.SourceName}")
                        events.append(event_data)
                        
                except Exception as e:
                    logger.error(f"Error reading {log_type} log: {str(e)}")
                    continue
    finally:
        logger.info("Stopping event log monitoring")
        for handle in log_handles.values():
            win32evtlog.CloseEventLog(handle)

@siem_bp.route('/')
@login_required
def index():
    logger.info("Main page accessed")
    return render_template('Siem.html')

@siem_bp.route('/start_monitoring')
@login_required
def start_monitoring():
    """Start monitoring Windows event logs"""
    global is_monitoring, monitor_thread
    logger.info("Received start monitoring request")
    
    if not is_monitoring:
        is_monitoring = True
        monitor_thread = threading.Thread(target=monitor_event_logs)
        monitor_thread.daemon = True
        monitor_thread.start()
        logger.info("Monitoring thread started")
        return jsonify({'status': 'success', 'message': 'Monitoring started'})
    
    logger.info("Monitoring already active")
    return jsonify({'status': 'info', 'message': 'Already monitoring'})

@siem_bp.route('/stop_monitoring')
@login_required
def stop_monitoring():
    """Stop monitoring Windows event logs"""
    global is_monitoring
    logger.info("Received stop monitoring request")
    
    if is_monitoring:
        is_monitoring = False
        logger.info("Monitoring stopped")
        return jsonify({'status': 'success', 'message': 'Monitoring stopped'})
    
    logger.info("Monitoring already stopped")
    return jsonify({'status': 'info', 'message': 'Already stopped'})

@siem_bp.route('/events', methods=['GET', 'POST'])
@login_required
@csrf_protect
def handle_events():
    global events
    if request.method == 'POST':
        try:
            event_data = request.json
            event_data['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            events.append(event_data)
            logger.info(f"New event added: {event_data}")
            return jsonify({"status": "success", "message": "Event added successfully"})
        except Exception as e:
            logger.error(f"Error adding event: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500
    else:  # GET
        try:
            return jsonify(events)
        except Exception as e:
            logger.error(f"Error getting events: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500

@siem_bp.route('/alerts', methods=['GET', 'POST'])
@login_required
@csrf_protect
def handle_alerts():
    global alerts
    if request.method == 'POST':
        try:
            alert_data = request.json
            alert_data['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            alerts.append(alert_data)
            logger.info(f"New alert added: {alert_data}")
            return jsonify({"status": "success", "message": "Alert added successfully"})
        except Exception as e:
            logger.error(f"Error adding alert: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500
    else:  # GET
        try:
            return jsonify(alerts)
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500

@siem_bp.route('/clear_all', methods=['POST'])
@login_required
@csrf_protect
def clear_all():
    """Clear all events and alerts from memory"""
    global events, alerts
    try:
        events.clear()
        alerts.clear()
        logger.info("All events and alerts cleared")
        return jsonify({"status": "success", "message": "All events and alerts cleared"})
    except Exception as e:
        logger.error(f"Error clearing data: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@siem_bp.route('/analytics')
@login_required
def analytics():
    """Analytics dashboard page"""
    return render_template('SiemAnalytics.html')

@siem_bp.route('/get_analytics_data')
@login_required
def get_analytics_data():
    """Get data for analytics charts"""
    try:
        # Event type distribution
        event_distribution = {
            'Security': len([e for e in events if e['log_type'] == 'Security']),
            'System': len([e for e in events if e['log_type'] == 'System']),
            'Application': len([e for e in events if e['log_type'] == 'Application'])
        }
        
        # Alert type distribution
        alert_types = {}
        for alert in alerts:
            alert_type = alert.get('alert_message', 'Unknown')
            alert_types[alert_type] = alert_types.get(alert_type, 0) + 1
        
        # Command execution statistics
        command_stats = {}
        for alert in alerts:
            if 'Command Execution Detected' in alert.get('alert_message', ''):
                command = alert['alert_message'].split(': ')[1].replace('!', '')
                command_stats[command] = command_stats.get(command, 0) + 1
        
        return jsonify({
            'event_distribution': event_distribution,
            'alert_types': alert_types,
            'command_stats': command_stats,
            'total_events': len(events),
            'total_alerts': len(alerts)
        })
    except Exception as e:
        logger.error(f"Error getting analytics data: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@siem_bp.route('/correlations.html')
@login_required
def correlations_page():
    """Correlations visualization page"""
    return render_template('SiemCorrelations.html')

@siem_bp.route('/correlations')
@login_required
def get_correlations():
    """Get correlated security events"""
    try:
        correlated_alerts = correlate_events(events)
        return jsonify({
            'status': 'success',
            'correlations': correlated_alerts
        })
    except Exception as e:
        logger.error(f"Error getting correlations: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500