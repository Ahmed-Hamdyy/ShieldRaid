# app.py

from flask import Flask, render_template, request, jsonify
import requests
import logging

# Import vulnerability checks from scan_tools
from scan_tools.check_sql_injection import check_sql_injection
from scan_tools.check_xss import check_xss
from scan_tools.check_broken_authentication import check_broken_authentication
from scan_tools.check_sensitive_data_exposure import check_sensitive_data_exposure
from scan_tools.check_security_misconfiguration import check_security_misconfiguration
from scan_tools.check_vulnerable_components import check_vulnerable_components
from scan_tools.check_csrf import check_csrf
from scan_tools.check_remote_code_execution import check_remote_code_execution
from scan_tools.check_directory_traversal import check_directory_traversal
from scan_tools.check_insecure_deserialization import check_insecure_deserialization
from scan_tools.check_xxe import check_xxe
from scan_tools.check_clickjacking import check_clickjacking
from scan_tools.check_content_security_policy import check_content_security_policy
from scan_tools.check_open_redirect import check_open_redirect
from scan_tools.check_information_disclosure import check_information_disclosure
from scan_tools.check_session_fixation import check_session_fixation
from scan_tools.check_missing_security_headers import check_missing_security_headers
from scan_tools.check_weak_password_policies import check_weak_password_policies
from scan_tools.check_unvalidated_redirects import check_unvalidated_redirects
from scan_tools.check_path_traversal import check_path_traversal
from scan_tools.check_mass_assignment import check_mass_assignment
from scan_tools.check_idor import check_idor
from scan_tools.check_unencrypted_sensitive_cookies import check_unencrypted_sensitive_cookies
from scan_tools.check_no_rate_limiting import check_no_rate_limiting
from scan_tools.check_insecure_file_upload import check_insecure_file_upload

app = Flask(__name__)

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s'
)
logger = logging.getLogger(__name__)

# Main Scan Function
def perform_scan(target_url):
    vulnerabilities = []
    logger.info(f"Starting scan for {target_url}")
    try:
        response = requests.get(target_url, timeout=10, verify=True)
    except requests.exceptions.RequestException as e:
        vulnerabilities.append({
            "type": "Connection Error",
            "description": f"Error accessing {target_url}: {str(e)}",
            "location": "Network Request",
            "severity": "No Internet Connection"
        })
        logger.error(f"Error accessing {target_url}: {e}")
        return vulnerabilities

    # Perform all checks
    vulnerabilities.extend(check_sql_injection(target_url))
    vulnerabilities.extend(check_xss(target_url))
    vulnerabilities.extend(check_broken_authentication(target_url, response))
    vulnerabilities.extend(check_sensitive_data_exposure(target_url, response))
    vulnerabilities.extend(check_security_misconfiguration(target_url))
    vulnerabilities.extend(check_vulnerable_components(target_url, response))
    vulnerabilities.extend(check_csrf(target_url))
    vulnerabilities.extend(check_remote_code_execution(target_url))
    vulnerabilities.extend(check_directory_traversal(target_url))
    vulnerabilities.extend(check_insecure_deserialization(target_url))
    vulnerabilities.extend(check_xxe(target_url))
    vulnerabilities.extend(check_clickjacking(target_url))
    vulnerabilities.extend(check_content_security_policy(target_url, response))
    vulnerabilities.extend(check_open_redirect(target_url))
    vulnerabilities.extend(check_information_disclosure(target_url))
    vulnerabilities.extend(check_session_fixation(target_url, response))
    vulnerabilities.extend(check_missing_security_headers(target_url, response))
    vulnerabilities.extend(check_weak_password_policies(target_url))
    vulnerabilities.extend(check_unvalidated_redirects(target_url))
    vulnerabilities.extend(check_path_traversal(target_url))
    vulnerabilities.extend(check_mass_assignment(target_url))
    vulnerabilities.extend(check_idor(target_url))
    vulnerabilities.extend(check_unencrypted_sensitive_cookies(target_url, response))
    vulnerabilities.extend(check_no_rate_limiting(target_url))
    vulnerabilities.extend(check_insecure_file_upload(target_url))
    
    logger.info(f"Scan completed for {target_url}")
    return vulnerabilities

@app.route('/')
def index():
    logger.info("Rendering index page")
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    logger.info("Received scan request")
    data = request.get_json()
    target_url = data.get('url')

    if not target_url:
        logger.warning("No URL provided in scan request")
        return jsonify({'error': 'No URL provided'}), 400

    vulnerabilities = perform_scan(target_url)
    return jsonify({'vulnerabilities': vulnerabilities}), 200

if __name__ == '__main__':
    logger.info("Starting Flask application")
    app.run(debug=True, host='0.0.0.0', port=8000)
