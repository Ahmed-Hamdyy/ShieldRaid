# scan_tools/check_unvalidated_redirects.py

import requests
from urllib.parse import urljoin
import logging

logger = logging.getLogger(__name__)

def check_unvalidated_redirects(target_url):
    vulnerabilities = []
    logger.info("Checking for Unvalidated Redirects vulnerabilities")
    redirect_payload = "https://malicious.com"
    scan_url = urljoin(target_url, f"/redirect?next={redirect_payload}")
    try:
        redirect_response = requests.get(scan_url, allow_redirects=False, timeout=10, verify=True)
        if redirect_response.status_code in [301, 302, 303, 307, 308]:
            location = redirect_response.headers.get('Location', '')
            if redirect_payload in location:
                vulnerabilities.append({
                    "type": "Unvalidated Redirects",
                    "description": "Unvalidated redirects detected, allowing redirection to malicious sites.",
                    "location": scan_url,
                    "severity": "High"
                })
                logger.warning("Unvalidated Redirects vulnerability detected.")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during Unvalidated Redirects check: {e}")
    return vulnerabilities
