# scan_tools/check_unencrypted_sensitive_cookies.py

import logging

logger = logging.getLogger(__name__)

def check_unencrypted_sensitive_cookies(target_url, response):
    vulnerabilities = []
    logger.info("Checking for Unencrypted Sensitive Cookies")
    for cookie in response.cookies:
        if 'session' in cookie.name.lower() or 'auth' in cookie.name.lower():
            if not cookie.secure:
                vulnerabilities.append({
                    "type": "Unencrypted Sensitive Cookies",
                    "description": f"Sensitive cookie '{cookie.name}' is not marked as Secure.",
                    "location": f"Cookie: {cookie.name}",
                    "severity": "Medium"
                })
                logger.warning(f"Unencrypted Sensitive Cookie detected: {cookie.name}")
    return vulnerabilities
