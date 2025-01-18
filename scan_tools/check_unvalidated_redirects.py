# scan_tools/check_unvalidated_redirects.py

import aiohttp
from urllib.parse import urljoin
import logging

logger = logging.getLogger(__name__)

async def check_unvalidated_redirects(target_url):
    vulnerabilities = []
    logger.info("Checking for Unvalidated Redirects vulnerabilities")
    redirect_payload = "https://malicious.com"
    scan_url = urljoin(target_url, f"/redirect?next={redirect_payload}")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(scan_url, allow_redirects=False, timeout=10, ssl=False) as response:
                if response.status in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if redirect_payload in location:
                        vulnerabilities.append({
                            "type": "Unvalidated Redirects",
                            "description": "Unvalidated redirects detected, allowing redirection to malicious sites.",
                            "location": scan_url,
                            "severity": "High"
                        })
                        logger.warning("Unvalidated Redirects vulnerability detected.")
    except Exception as e:
        logger.error(f"Error during Unvalidated Redirects check: {e}")
    return vulnerabilities


async def scan(target_url):
    """
    Main scan function that wraps the check_unvalidated_redirects functionality.
    """
    return await check_unvalidated_redirects(target_url)
