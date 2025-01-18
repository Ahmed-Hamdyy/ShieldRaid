import logging
import requests

logger = logging.getLogger(__name__)

def scan(url):
    """Check for security headers in the response"""
    try:
        logger.info(f"Checking security headers for {url}")
        vulnerabilities = []
        
        # Send request
        response = requests.get(url, verify=False)
        headers = response.headers
        
        # List of important security headers
        security_headers = {
            'Strict-Transport-Security': 'Missing HSTS header',
            'X-Frame-Options': 'Missing X-Frame-Options header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'Content-Security-Policy': 'Missing Content Security Policy',
            'X-XSS-Protection': 'Missing XSS Protection header',
            'Referrer-Policy': 'Missing Referrer Policy',
            'Permissions-Policy': 'Missing Permissions Policy'
        }
        
        # Check each security header
        for header, message in security_headers.items():
            if header not in headers:
                vulnerabilities.append({
                    'type': 'Missing Security Header',
                    'severity': 'medium',
                    'description': message,
                    'location': f"Header: {header}",
                    'recommendation': f'Add the {header} header to improve security'
                })
                logger.warning(f"Missing security header: {header}")
        
        return vulnerabilities
        
    except Exception as e:
        logger.error(f"Error checking security headers: {str(e)}")
        return [{
            'type': 'Error',
            'severity': 'error',
            'description': f'Error checking security headers: {str(e)}',
            'location': url
        }] 

async def scan(target_url):
    """
    Main scan function that wraps the check_security_headers functionality.
    """
    return await check_security_headers(target_url)
