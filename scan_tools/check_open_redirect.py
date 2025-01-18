# scan_tools/check_open_redirect.py

import aiohttp
from urllib.parse import urljoin
import logging

logger = logging.getLogger(__name__)

async def check_open_redirect(target_url):
    vulnerabilities = []
    logger.info("Checking for Open Redirect vulnerabilities")
    redirect_payload = "https://malicious.com"
    scan_url = urljoin(target_url, f"/redirect?url={redirect_payload}")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(scan_url, allow_redirects=False, timeout=10, ssl=False) as response:
                if response.status in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if redirect_payload in location:
                        vulnerabilities.append({
                            "type": "Open Redirect",
                            "description": "Open Redirect vulnerability detected by redirecting to an external URL.",
                            "location": f"Endpoint: /redirect?url={redirect_payload}",
                            "severity": "High"
                        })
                        logger.warning("Open Redirect vulnerability detected.")
    except Exception as e:
        logger.error(f"Error during Open Redirect check: {e}")
    return vulnerabilities


async def scan(target_url):
    """
    Main scan function that wraps the check_open_redirect functionality.
    """
    return await check_open_redirect(target_url)
