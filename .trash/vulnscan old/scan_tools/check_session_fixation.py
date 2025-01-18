# scan_tools/check_session_fixation.py

import requests
from urllib.parse import urljoin
import logging

logger = logging.getLogger(__name__)

def check_session_fixation(target_url, response):
    vulnerabilities = []
    logger.info("Checking for Session Fixation vulnerabilities")
    session_cookie_name = None
    for cookie in response.cookies:
        if 'session' in cookie.name.lower() or 'php' in cookie.name.lower():
            session_cookie_name = cookie.name
            break

    if session_cookie_name:
        logger.info(f"Found session cookie: {session_cookie_name}")
        try:
            fixed_session_id = "fixedsessionid12345"
            cookies = {session_cookie_name: fixed_session_id}
            protected_url = urljoin(target_url, '/dashboard')
            protected_response = requests.get(protected_url, cookies=cookies, timeout=10, verify=True)
            if protected_response.status_code == 200 and "welcome" in protected_response.text.lower():
                vulnerabilities.append({
                    "type": "Session Fixation",
                    "description": "Session fixation vulnerability detected. Session ID remains unchanged after login.",
                    "location": f"Cookie: {session_cookie_name}",
                    "severity": "High"
                })
                logger.warning("Session Fixation vulnerability detected.")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error during Session Fixation check: {e}")
    return vulnerabilities
