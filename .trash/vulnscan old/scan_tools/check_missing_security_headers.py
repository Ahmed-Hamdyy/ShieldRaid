# scan_tools/check_missing_security_headers.py

import logging

logger = logging.getLogger(__name__)

def check_missing_security_headers(target_url, response):
    vulnerabilities = []
    logger.info("Checking for Missing or Misconfigured Security Headers")
    headers_to_check = {
        'Content-Security-Policy': 'Content-Security-Policy header is missing or misconfigured.',
        'X-Frame-Options': 'X-Frame-Options header is missing or misconfigured.',
        'X-Content-Type-Options': 'X-Content-Type-Options header is missing.',
        'Referrer-Policy': 'Referrer-Policy header is missing.',
        'X-XSS-Protection': 'X-XSS-Protection header is missing or disabled.',
        'Permissions-Policy': 'Permissions-Policy header is missing.',
        'Strict-Transport-Security': 'Strict-Transport-Security header is missing.'
    }
    
    for header, description in headers_to_check.items():
        header_value = response.headers.get(header)
        if not header_value:
            vulnerabilities.append({
                "type": "Missing Security Header",
                "description": description,
                "location": "HTTP Headers",
                "severity": "Medium"
            })
            logger.warning(f"{header} is missing.")
    return vulnerabilities
