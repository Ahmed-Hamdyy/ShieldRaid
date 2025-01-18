# scan_tools/check_broken_authentication.py

import logging
from .utils import *

logger = logging.getLogger(__name__)

def check_broken_authentication(target_url, response):
    vulnerabilities = []
    logger.info("Checking for Broken Authentication vulnerabilities")
    cookies = response.cookies
    for cookie in cookies:
        issues = []
        if not cookie.secure:
            issues.append("Secure flag not set")
        if not cookie.has_nonstandard_attr('HttpOnly') and not cookie.has_nonstandard_attr('httponly'):
            issues.append("HttpOnly flag not set")
        if issues:
            vulnerability_detail = {
                "type": "Broken Authentication",
                "description": f"Cookie '{cookie.name}' is missing: {', '.join(issues)}.",
                "location": f"Cookie: {cookie.name}",
                "severity": "Medium"
            }
            vulnerabilities.append(vulnerability_detail)
            logger.warning(f"Broken Authentication issue detected: {vulnerability_detail['description']}")
    return vulnerabilities
