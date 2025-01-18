# scan_tools/check_insecure_file_upload.py

import requests
from urllib.parse import urljoin
import logging

logger = logging.getLogger(__name__)

def check_insecure_file_upload(target_url):
    vulnerabilities = []
    logger.info("Checking for Insecure File Upload vulnerabilities")
    upload_url = urljoin(target_url, '/upload')
    malicious_file = {
        'file': ('shell.php', '<?php echo "Vulnerable"; ?>', 'application/php')
    }
    try:
        upload_response = requests.post(upload_url, files=malicious_file, timeout=10, verify=True)
        if 'Vulnerable' in upload_response.text:
            vulnerabilities.append({
                "type": "Insecure File Upload",
                "description": "Insecure File Upload vulnerability detected by uploading a PHP shell.",
                "location": upload_url,
                "severity": "Critical"
            })
            logger.warning("Insecure File Upload vulnerability detected.")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during Insecure File Upload check: {e}")
    return vulnerabilities
