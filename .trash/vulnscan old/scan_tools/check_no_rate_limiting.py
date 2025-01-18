# scan_tools/check_no_rate_limiting.py

import requests
from urllib.parse import urljoin
import logging
import time

logger = logging.getLogger(__name__)

def check_no_rate_limiting(target_url):
    vulnerabilities = []
    logger.info("Checking for No Rate Limiting vulnerabilities")
    
    login_url = urljoin(target_url, '/login')
    payload = {'username': 'testuser', 'password': 'wrongpassword'}
    failed_attempts = 10
    blocked = False
    for i in range(failed_attempts):
        try:
            response = requests.post(login_url, data=payload, timeout=5, verify=True)
            if response.status_code == 429:
                blocked = True
                logger.info("Rate limiting is enforced.")
                break
            time.sleep(1)  # Wait a bit between attempts
        except requests.exceptions.RequestException as e:
            logger.error(f"Error during Rate Limiting check: {e}")
            break
    if not blocked:
        vulnerabilities.append({
            "type": "No Rate Limiting",
            "description": "No rate limiting detected on the login endpoint, allowing brute-force attacks.",
            "location": login_url,
            "severity": "High"
        })
        logger.warning("No Rate Limiting vulnerability detected.")
    return vulnerabilities
