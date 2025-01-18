# scan_tools/check_security_misconfiguration.py

import logging
from .utils import get_allowed_methods

logger = logging.getLogger(__name__)

def check_security_misconfiguration(target_url):
    vulnerabilities = []
    logger.info("Checking for Security Misconfiguration vulnerabilities")
    allowed_methods = get_allowed_methods(target_url)
    insecure_methods = ['PUT', 'DELETE', 'TRACE', 'OPTIONS']
    for method in insecure_methods:
        if method in allowed_methods:
            vulnerabilities.append({
                "type": "Security Misconfiguration",
                "description": f"HTTP method '{method}' is allowed and may be insecure.",
                "location": "Allowed HTTP Methods",
                "severity": "Medium"
            })
            logger.warning(f"Security Misconfiguration issue detected: HTTP method '{method}' is allowed.")
    return vulnerabilities
