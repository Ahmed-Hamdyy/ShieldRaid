import aiohttp
from urllib.parse import urljoin
import logging

logger = logging.getLogger(__name__)

async def check_idor(target_url):
    vulnerabilities = []
    logger.info("Checking for Insecure Direct Object References (IDOR) vulnerabilities")

    # User profile and potential IDOR paths
    id_patterns = [1, 5]
    endpoints = ["/user", "/profile", "/account"]

    try:
        async with aiohttp.ClientSession() as session:
            for endpoint in endpoints:
                logger.info(f"Testing endpoint: {endpoint} for IDOR vulnerabilities")
                for user_id in id_patterns:
                    user_profile_url = urljoin(target_url, f"{endpoint}/{user_id}")
                    logger.info(f"Attempting to access profile with ID {user_id} at {user_profile_url}")
                    
                    async with session.get(user_profile_url, timeout=10, ssl=False) as response:
                        if response.status != 200:
                            if response.status in [401, 403]:
                                logger.info(f"Access denied for profile with ID {user_id} at {user_profile_url}, likely secure.")
                            continue
                            
                        text = await response.text()
                        if "username" in text.lower() or "email" in text.lower():
                            vulnerabilities.append({
                                "type": "Insecure Direct Object References (IDOR)",
                                "description": f"IDOR vulnerability detected by accessing unauthorized profile with ID {user_id}.",
                                "location": user_profile_url,
                                "severity": "High"
                            })
                            logger.warning(f"IDOR vulnerability detected: Accessed profile with ID {user_id} at {user_profile_url}")
                            break  # Stop further checks once a vulnerability is found
                        else:
                            logger.info(f"No sensitive data found at {user_profile_url}")

    except Exception as e:
        logger.error(f"Error during IDOR check: {e}")
    
    logger.info("IDOR check completed.")
    return vulnerabilities


async def scan(target_url):
    """
    Main scan function that wraps the check_idor functionality.
    """
    return await check_idor(target_url)
