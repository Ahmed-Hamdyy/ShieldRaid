# scan_tools/check_remote_code_execution.py

import requests
import logging
from .utils import inject_payload

logger = logging.getLogger(__name__)

def check_remote_code_execution(target_url):
    vulnerabilities = []
    logger.info("Checking for Remote Code Execution (RCE) vulnerabilities")

    rce_payloads = [
        "$(whoami)",
        "`whoami`",
        "${@print(md5(1))}",
        ";echo RCEVulnerable",
        "|echo RCEVulnerable"
    ]

    for payload in rce_payloads:
        test_url = inject_payload(target_url, payload)
        try:
            response = requests.get(test_url, timeout=10)
            if "RCEVulnerable" in response.text:
                vulnerabilities.append({
                    "type": "Remote Code Execution (RCE)",
                    "description": f"Possible RCE detected with payload: {payload}",
                    "location": test_url,
                    "severity": "Critical"
                })
                logger.warning(f"RCE vulnerability detected with payload: {payload}")
                return vulnerabilities  # Stop after detection
        except requests.exceptions.RequestException as e:
            logger.error(f"Error during RCE check with payload '{payload}': {e}")
    return vulnerabilities
