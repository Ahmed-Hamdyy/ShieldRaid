# scan_tools/check_session_fixation.py

import aiohttp
from urllib.parse import urljoin
import logging

logger = logging.getLogger(__name__)

async def check_session_fixation(target_url):
    vulnerabilities = []
    logger.info("Checking for Session Fixation vulnerabilities")
    session_cookie_name = None
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(target_url, timeout=10, ssl=False) as response:
                if response.status != 200:
                    logger.error(f"Failed to fetch {target_url}. Status code: {response.status}")
                    return vulnerabilities
                    
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
                        
                        async with session.get(protected_url, cookies=cookies, timeout=10, ssl=False) as protected_response:
                            if protected_response.status == 200:
                                text = await protected_response.text()
                                if "welcome" in text.lower():
                                    vulnerabilities.append({
                                        "type": "Session Fixation",
                                        "description": "Session fixation vulnerability detected. Session ID remains unchanged after login.",
                                        "location": f"Cookie: {session_cookie_name}",
                                        "severity": "High"
                                    })
                                    logger.warning("Session Fixation vulnerability detected.")
                    except Exception as e:
                        logger.error(f"Error during Session Fixation check: {e}")
    except Exception as e:
        logger.error(f"Error during Session Fixation check: {e}")
    return vulnerabilities

async def scan(target_url):
    """
    Main scan function that wraps the check_session_fixation functionality.
    """
    return await check_session_fixation(target_url)
