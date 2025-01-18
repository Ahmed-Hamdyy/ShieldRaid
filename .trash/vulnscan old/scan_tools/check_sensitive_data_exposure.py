# scan_tools/check_sensitive_data_exposure.py

import requests
import logging

logger = logging.getLogger(__name__)

def check_sensitive_data_exposure(target_url, response):
    vulnerabilities = []
    logger.info("Checking for Sensitive Data Exposure")
    if not target_url.startswith('https://'):
        vulnerabilities.append({
            "type": "Sensitive Data Exposure",
            "description": "Connection is not secure (HTTPS not used). Data transmitted may be intercepted.",
            "location": "URL Scheme",
            "severity": "High"
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
    return vulnerabilities
