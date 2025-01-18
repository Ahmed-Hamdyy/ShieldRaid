# scan_tools/check_mass_assignment.py

import aiohttp
from urllib.parse import urljoin
import logging

logger = logging.getLogger(__name__)

async def check_mass_assignment(target_url):
    vulnerabilities = []
    logger.info("Checking for Mass Assignment vulnerabilities")
    registration_url = urljoin(target_url, '/register')
    payload = {
        'username': 'testuser',
        'password': 'SecurePass123',
        'role': 'admin'  # Attempt to assign elevated privileges
    }
    try:
        async with aiohttp.ClientSession() as session:
            # Try registration
            async with session.post(registration_url, data=payload, timeout=10, ssl=False) as response:
                if response.status != 200:
                    logger.error(f"Failed to send POST request to {registration_url}. Status code: {response.status}")
                    return vulnerabilities
                    
                response_text = (await response.text()).lower()
                if "registration successful" in response_text:
                    # Check dashboard access
                    user_dashboard = urljoin(target_url, '/dashboard')
                    async with session.get(user_dashboard, timeout=10, ssl=False) as dashboard_response:
                        if dashboard_response.status == 200:
                            dashboard_text = (await dashboard_response.text()).lower()
                            if "admin panel" in dashboard_text:
                                vulnerabilities.append({
                                    "type": "Mass Assignment",
                                    "description": "Mass Assignment vulnerability detected by assigning elevated privileges during registration.",
                                    "location": "Registration Endpoint: /register",
                                    "severity": "Critical"
                                })
                                logger.warning("Mass Assignment vulnerability detected.")
    except Exception as e:
        logger.error(f"Error during Mass Assignment check: {e}")
    return vulnerabilities


async def scan(target_url):
    """
    Main scan function that wraps the check_mass_assignment functionality.
    """
    return await check_mass_assignment(target_url)
