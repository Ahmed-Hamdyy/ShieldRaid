# scan_tools/check_security_misconfiguration.py

import aiohttp
import logging
from .utils import get_allowed_methods

logger = logging.getLogger(__name__)

async def check_security_misconfiguration(target_url):
    vulnerabilities = []
    logger.info("Checking for Security Misconfiguration vulnerabilities")
    allowed_methods = await get_allowed_methods(target_url)
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

async def scan(target_url):
    """
    Main scan function that wraps the check_security_misconfiguration functionality.
    """
    return await check_security_misconfiguration(target_url)
