# scan_tools/check_mass_assignment.py

import requests
from urllib.parse import urljoin
import logging

logger = logging.getLogger(__name__)

def check_mass_assignment(target_url):
    vulnerabilities = []
    logger.info("Checking for Mass Assignment vulnerabilities")
    registration_url = urljoin(target_url, '/register')
    payload = {
        'username': 'testuser',
        'password': 'SecurePass123',
        'role': 'admin'  # Attempt to assign elevated privileges
    }
    try:
        response = requests.post(registration_url, data=payload, timeout=10, verify=True)
        if "registration successful" in response.text.lower():
            user_dashboard = urljoin(target_url, '/dashboard')
            dashboard_response = requests.get(user_dashboard, timeout=10, verify=True)
            if "admin panel" in dashboard_response.text.lower():
                vulnerabilities.append({
                    "type": "Mass Assignment",
                    "description": "Mass Assignment vulnerability detected by assigning elevated privileges during registration.",
                    "location": "Registration Endpoint: /register",
                    "severity": "Critical"
                })
                logger.warning("Mass Assignment vulnerability detected.")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during Mass Assignment check: {e}")
    return vulnerabilities
