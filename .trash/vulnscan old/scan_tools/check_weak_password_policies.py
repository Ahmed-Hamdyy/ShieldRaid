# scan_tools/check_weak_password_policies.py

import requests
from urllib.parse import urljoin
import logging

logger = logging.getLogger(__name__)

def check_weak_password_policies(target_url):
    vulnerabilities = []
    logger.info("Checking for Weak Password Policies")
    registration_url = urljoin(target_url, '/register')
    weak_passwords = ['12345', 'password', 'admin', 'qwerty']
    for weak_password in weak_passwords:
        payload = {'username': 'testuser', 'password': weak_password}
        try:
            response = requests.post(registration_url, data=payload, timeout=10, verify=True)
            if "registration successful" in response.text.lower():
                vulnerabilities.append({
                    "type": "Weak Password Policies",
                    "description": f"Accepted weak password: {weak_password}",
                    "location": "Registration Endpoint: /register",
                    "severity": "Medium"
                })
                logger.warning(f"Weak Password Policies vulnerability detected with password: {weak_password}")
                break
        except requests.exceptions.RequestException as e:
            logger.error(f"Error during Weak Password Policies check: {e}")
    return vulnerabilities
