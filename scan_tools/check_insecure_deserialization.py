# scan_tools/check_insecure_deserialization.py

import aiohttp
import logging

logger = logging.getLogger(__name__)

async def check_insecure_deserialization(target_url):
    vulnerabilities = []
    logger.info("Checking for Insecure Deserialization vulnerabilities")
    insecure_payload = '{"__class__": "os.system", "__args__": ["echo vulnerable"]}'
    headers = {'Content-Type': 'application/json'}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(target_url, data=insecure_payload, headers=headers, timeout=10, ssl=False) as response:
                if response.status != 200:
                    logger.error(f"Failed to send POST request to {target_url}. Status code: {response.status}")
                    return vulnerabilities
                    
                response_text = (await response.text()).lower()
                if 'vulnerable' in response_text:
                    vulnerabilities.append({
                        "type": "Insecure Deserialization",
                        "description": "Possible insecure deserialization vulnerability detected by injecting malicious JSON payload.",
                        "location": "POST Request Body",
                        "severity": "High"
                    })
                    logger.warning("Insecure Deserialization vulnerability detected.")
    except Exception as e:
        logger.error(f"Error during Insecure Deserialization check: {e}")
    return vulnerabilities


async def scan(target_url):
    """
    Main scan function that wraps the check_insecure_deserialization functionality.
    """
    return await check_insecure_deserialization(target_url)
