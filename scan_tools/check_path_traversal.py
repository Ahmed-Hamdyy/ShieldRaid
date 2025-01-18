# scan_tools/check_path_traversal.py

import aiohttp
import logging
from .utils import inject_payload

logger = logging.getLogger(__name__)

async def check_path_traversal(target_url):
    vulnerabilities = []
    logger.info("Checking for Path Traversal vulnerabilities")
    traversal_payload = "../../../../../../etc/passwd"
    scan_url = inject_payload(target_url, traversal_payload)
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(scan_url, timeout=10, ssl=False) as response:
                if response.status != 200:
                    logger.error(f"Failed to fetch {scan_url}. Status code: {response.status}")
                    return vulnerabilities
                    
                text = await response.text()
                if "root:" in text:
                    vulnerabilities.append({
                        "type": "Path Traversal",
                        "description": "Path Traversal vulnerability detected by accessing system files.",
                        "location": scan_url,
                        "severity": "High"
                    })
                    logger.warning("Path Traversal vulnerability detected.")
    except Exception as e:
        logger.error(f"Error during Path Traversal check: {e}")
    return vulnerabilities


async def scan(target_url):
    """
    Main scan function that wraps the check_path_traversal functionality.
    """
    return await check_path_traversal(target_url)
