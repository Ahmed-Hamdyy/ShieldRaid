# scan_tools/check_path_traversal.py

import requests
import logging
from .utils import inject_payload

logger = logging.getLogger(__name__)

def check_path_traversal(target_url):
    vulnerabilities = []
    logger.info("Checking for Path Traversal vulnerabilities")
    traversal_payload = "../../../../../../etc/passwd"
    scan_url = inject_payload(target_url, traversal_payload)
    try:
        traversal_response = requests.get(scan_url, timeout=10, verify=True)
        if "root:" in traversal_response.text:
            vulnerabilities.append({
                "type": "Path Traversal",
                "description": "Path Traversal vulnerability detected by accessing system files.",
                "location": scan_url,
                "severity": "High"
            })
            logger.warning("Path Traversal vulnerability detected.")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during Path Traversal check: {e}")
    return vulnerabilities
