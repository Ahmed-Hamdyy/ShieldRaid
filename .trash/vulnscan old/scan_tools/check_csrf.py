import requests
from bs4 import BeautifulSoup
import re
import logging

logger = logging.getLogger(__name__)

def check_csrf(target_url):
    vulnerabilities = []
    logger.info("Checking for Cross-Site Request Forgery (CSRF) vulnerabilities")
    
    try:
        response = requests.get(target_url, timeout=10, verify=True)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        if not forms:
            logger.info("No forms found on the page. Skipping CSRF check.")
            return vulnerabilities
        
        logger.info(f"Found {len(forms)} forms on {target_url} to check for CSRF tokens.")
        
        csrf_found = False
        csrf_patterns = re.compile(r'csrf|token|authenticity', re.I)
        
        for form in forms:
            tokens = form.find_all('input', {'name': csrf_patterns})
            if tokens:
                csrf_found = True
                logger.info("CSRF token found in form.")
                break
        
        if not csrf_found:
            vulnerabilities.append({
                "type": "Cross-Site Request Forgery (CSRF)",
                "description": "No CSRF tokens found in forms, making the application susceptible to CSRF attacks.",
                "location": "Forms on the page",
                "severity": "High"
            })
            logger.warning("Cross-Site Request Forgery (CSRF) vulnerability detected. No CSRF tokens found.")
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during CSRF check: {e}")
    
    return vulnerabilities
