# scan_tools/check_unencrypted_sensitive_cookies.py

import aiohttp
import logging

logger = logging.getLogger(__name__)

async def check_unencrypted_sensitive_cookies(target_url):
    vulnerabilities = []
    logger.info("Checking for Unencrypted Sensitive Cookies")
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(target_url, timeout=10, ssl=False) as response:
                if response.status != 200:
                    logger.error(f"Failed to fetch {target_url}. Status code: {response.status}")
                    return vulnerabilities
                    
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
    except Exception as e:
        logger.error(f"Error during Unencrypted Sensitive Cookies check: {e}")
    return vulnerabilities


async def scan(target_url):
    """
    Main scan function that wraps the check_unencrypted_sensitive_cookies functionality.
    """
    return await check_unencrypted_sensitive_cookies(target_url)
