# scan_tools/check_sensitive_data_exposure.py

import aiohttp
import logging

logger = logging.getLogger(__name__)

async def check_sensitive_data_exposure(target_url):
    vulnerabilities = []
    logger.info("Checking for Sensitive Data Exposure")
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(target_url, timeout=10, ssl=False) as response:
                if response.status != 200:
                    logger.error(f"Failed to fetch {target_url}. Status code: {response.status}")
                    return vulnerabilities
                    
                if not target_url.startswith('https://'):
                    vulnerabilities.append({
                        "type": "Sensitive Data Exposure",
                        "description": "Connection is not secure (HTTPS not used). Data transmitted may be intercepted.",
                        "location": "URL Scheme",
                        "severity": "Low"
                    })
                    logger.warning("Sensitive Data Exposure: HTTPS not enforced.")
                else:
                    hsts = response.headers.get('Strict-Transport-Security')
                    if not hsts:
                        vulnerabilities.append({
                            "type": "Sensitive Data Exposure",
                            "description": "Strict-Transport-Security header is not set, exposing the application to downgrade attacks.",
                            "location": "HTTP Header: Strict-Transport-Security",
                            "severity": "Medium"
                        })
                        logger.warning("Sensitive Data Exposure: HSTS header not set.")
    except Exception as e:
        logger.error(f"Error during Sensitive Data Exposure check: {e}")
    return vulnerabilities


async def scan(target_url):
    """
    Main scan function that wraps the check_sensitive_data_exposure functionality.
    """
    return await check_sensitive_data_exposure(target_url)
