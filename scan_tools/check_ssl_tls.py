import logging
import ssl
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

def check_ssl_tls(url):
    """Check SSL/TLS configuration"""
    try:
        logger.info(f"Checking SSL/TLS configuration for {url}")
        vulnerabilities = []
        
        # Parse URL
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443
        
        # Create SSL context
        context = ssl.create_default_context()
        
        try:
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Check SSL/TLS version
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        vulnerabilities.append({
                            'type': 'weak_protocol',
                            'severity': 'high',
                            'description': f'Weak SSL/TLS protocol version detected: {version}',
                            'recommendation': 'Upgrade to TLS 1.2 or higher'
                        })
                    
                    # Check cipher strength
                    if cipher[2] < 128:
                        vulnerabilities.append({
                            'type': 'weak_cipher',
                            'severity': 'high',
                            'description': f'Weak cipher detected: {cipher[0]}',
                            'recommendation': 'Use strong ciphers with at least 128-bit key length'
                        })
        
        except ssl.SSLError as e:
            vulnerabilities.append({
                'type': 'ssl_error',
                'severity': 'high',
                'description': f'SSL/TLS error: {str(e)}',
                'recommendation': 'Check SSL/TLS configuration'
            })
        
        return vulnerabilities
        
    except Exception as e:
        logger.error(f"Error checking SSL/TLS: {str(e)}")
        return [{
            'type': 'error',
            'severity': 'error',
            'description': f'Error checking SSL/TLS: {str(e)}'
        }] 

async def scan(target_url):
    """
    Main scan function that wraps the check_ssl_tls functionality.
    """
    return await check_ssl_tls(target_url)
