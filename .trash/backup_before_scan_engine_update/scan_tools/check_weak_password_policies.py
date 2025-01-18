# scan_tools/check_weak_password_policies.py

import aiohttp
from urllib.parse import urljoin
import logging

logger = logging.getLogger(__name__)

async def check_weak_password_policies(target_url):
    vulnerabilities = []
    logger.info("Checking for Weak Password Policies")
    registration_url = urljoin(target_url, '/register')
    weak_passwords = ['12345', 'password', 'admin', 'qwerty']
    
    async with aiohttp.ClientSession() as session:
        for weak_password in weak_passwords:
            payload = {'username': 'testuser', 'password': weak_password}
            try:
                async with session.post(registration_url, data=payload, timeout=10, ssl=False) as response:
                    if response.status != 200:
                        continue
                        
                    text = await response.text()
                    if "registration successful" in text.lower():
                        vulnerabilities.append({
                            "type": "Weak Password Policies",
                            "description": f"Accepted weak password: {weak_password}",
                            "location": "Registration Endpoint: /register",
                            "severity": "Medium"
                        })
                        logger.warning(f"Weak Password Policies vulnerability detected with password: {weak_password}")
                        break
            except Exception as e:
                logger.error(f"Error during Weak Password Policies check: {e}")
    return vulnerabilities


async def scan(target_url):
    """
    Main scan function that wraps the check_weak_password_policies functionality.
    """
    return await check_weak_password_policies(target_url)
