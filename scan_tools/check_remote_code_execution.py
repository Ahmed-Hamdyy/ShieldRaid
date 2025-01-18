import aiohttp
import logging
import time
import re
import html
import hashlib
from typing import List, Dict, Set
import random
import string
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import asyncio

logger = logging.getLogger(__name__)

class RCEScanner:
    def __init__(self):
        self.seen_vulnerabilities = set()  # Track unique vulnerabilities
        self.successful_payloads = set()
        self.max_workers = 3
        
    def generate_random_string(self, length: int = 8) -> str:
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def generate_payloads(self) -> Dict[str, List[Dict]]:
        """Generate smart RCE detection payloads with validation"""
        canary = self.generate_random_string()
        
        return {
            'timing': [
                {
                    'payload': f'sleep 5',
                    'validation': {
                        'type': 'timing',
                        'min_time': 4.5,
                        'max_time': 5.5
                    }
                },
                {
                    'payload': f'ping -n 3 127.0.0.1',  # Windows
                    'validation': {
                        'type': 'timing',
                        'min_time': 2.5,
                        'max_time': 3.5
                    }
                }
            ],
            'output': [
                {
                    'payload': 'id',
                    'validation': {
                        'type': 'pattern',
                        'patterns': [
                            r'uid=\d+\(.*?\)\s+gid=\d+\(.*?\)',
                            r'groups=\d+\(.*?\)'
                        ],
                        'require_all': False
                    }
                },
                {
                    'payload': 'whoami',
                    'validation': {
                        'type': 'pattern',
                        'patterns': [
                            r'^[a-zA-Z0-9\-_]+$',  # Username pattern
                            r'\\[a-zA-Z0-9\-_]+$'  # Windows domain\user pattern
                        ],
                        'require_all': False
                    }
                }
            ],
            'error': [
                {
                    'payload': f'cat /nonexistent_{canary}',
                    'validation': {
                        'type': 'error',
                        'patterns': [
                            'No such file',
                            'cannot find',
                            'not found'
                        ]
                    }
                }
            ]
        }

    def generate_vulnerability_hash(self, url: str, param: str, payload_type: str) -> str:
        """Generate a unique hash for a vulnerability to prevent duplicates"""
        # Create a unique string combining the key elements of the vulnerability
        vuln_key = f"{url}:{param}:{payload_type}".lower()
        return hashlib.md5(vuln_key.encode()).hexdigest()

    async def find_injectable_params(self, session: aiohttp.ClientSession, url: str) -> List[Dict]:
        """Find potentially injectable parameters"""
        injectable_params = []
        try:
            # Check URL parameters
            parsed_url = urlparse(url)
            if parsed_url.query:
                params = parse_qs(parsed_url.query)
                for param in params:
                    injectable_params.append({
                        'url': url,
                        'method': 'GET',
                        'param': param,
                        'type': 'url'
                    })

            # Check forms
            async with session.get(url, ssl=False, timeout=10) as response:
                text = await response.text()
                soup = BeautifulSoup(text, 'html.parser')

                # Find forms
                for form in soup.find_all('form'):
                    form_url = urljoin(url, form.get('action', ''))
                    method = form.get('method', 'GET').upper()
                    
                    # Find potentially dangerous input fields
                    for input_tag in form.find_all(['input', 'textarea']):
                        input_name = input_tag.get('name', '')
                        input_type = input_tag.get('type', '').lower()
                        
                        # Check for suspicious parameter names
                        if any(keyword in input_name.lower() for keyword in SUSPICIOUS_PARAM_NAMES):
                            injectable_params.append({
                                'url': form_url,
                                'method': method,
                                'param': input_name,
                                'type': 'form'
                            })

        except Exception as e:
            logger.error(f"Error finding injectable parameters: {str(e)}")

        return injectable_params

    async def validate_execution(self, response_text: str, response_time: float, validation: Dict) -> Tuple[bool, str]:
        """Smart validation of potential RCE"""
        if validation['type'] == 'timing':
            if validation['min_time'] <= response_time <= validation['max_time']:
                return True, f"Command execution time matches expected range ({response_time:.2f}s)"
            return False, ""

        elif validation['type'] == 'pattern':
            patterns = validation['patterns']
            matches = []
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    matches.append(pattern)
            
            if matches:
                if validation.get('require_all', False):
                    if len(matches) == len(patterns):
                        return True, f"All expected patterns found in output"
                    return False, ""
                return True, f"Pattern match found in output"
            return False, ""

        elif validation['type'] == 'error':
            if any(pattern.lower() in response_text.lower() for pattern in validation['patterns']):
                return True, f"Expected error pattern found in response"
            return False, ""

        return False, ""

    async def test_parameter(self, session: aiohttp.ClientSession, injectable: Dict, payloads: Dict[str, List[Dict]]) -> List[Dict]:
        """Test a parameter for RCE vulnerabilities"""
        vulnerabilities = []
        url = injectable['url']
        method = injectable['method']
        param = injectable['param']

        try:
            # Get baseline response time
            start_time = time.time()
            async with session.request(method, url, ssl=False, timeout=10) as response:
                baseline_response = await response.text()
                baseline_time = time.time() - start_time

            # Test each payload category
            for category, category_payloads in payloads.items():
                # Generate a unique hash for this vulnerability check
                vuln_hash = self.generate_vulnerability_hash(url, param, category)
                
                # Skip if we've already found this vulnerability
                if vuln_hash in self.seen_vulnerabilities:
                                continue
                                
                for payload_info in category_payloads:
                    payload = payload_info['payload']
                    validation = payload_info['validation']

                    try:
                        # Prepare the request
                        if method == 'GET':
                            test_url = url.replace(f"{param}=", f"{param}={payload}")
                            start_time = time.time()
                            async with session.get(test_url, ssl=False, timeout=15) as response:
                                response_text = await response.text()
                                response_time = time.time() - start_time
                        else:
                            data = {param: payload}
                            start_time = time.time()
                            async with session.post(url, data=data, ssl=False, timeout=15) as response:
                                response_text = await response.text()
                                response_time = time.time() - start_time

                        # Smart validation
                        is_vulnerable, evidence = await self.validate_execution(
                            response_text, 
                            response_time - baseline_time,
                            validation
                        )

                        if is_vulnerable:
                            # Additional validation to reduce false positives
                            if await self.confirm_vulnerability(session, injectable, payload):
                                # Only add if we haven't seen this vulnerability before
                                if vuln_hash not in self.seen_vulnerabilities:
                                    self.seen_vulnerabilities.add(vuln_hash)
                                vulnerabilities.append({
                                    "type": "Remote Code Execution (RCE)",
                                        "description": f"RCE vulnerability detected using {category} technique",
                                        "url": url,
                                        "method": method,
                                        "param": param,
                                        "evidence": evidence,
                                        "payload": html.escape(payload),
                                        "response_time": f"{response_time:.2f}s",
                                        "severity": "Critical",
                                        "vuln_hash": vuln_hash  # Add hash for reference
                                    })
                                    # Break the payload loop once we've confirmed a vulnerability for this category
                                    break

                    except asyncio.TimeoutError:
                        if category == 'timing':
                            logger.info(f"Timeout detected for timing-based test on {url}")
                    except Exception as e:
                        logger.debug(f"Error testing payload: {str(e)}")
                        continue

            except Exception as e:
            logger.error(f"Error testing parameter {param} on {url}: {str(e)}")
    
    return vulnerabilities

    async def confirm_vulnerability(self, session: aiohttp.ClientSession, injectable: Dict, payload: str) -> bool:
        """Additional validation to reduce false positives"""
        try:
            # Test with a different delay to confirm timing-based vulnerabilities
            if 'sleep' in payload or 'ping' in payload:
                different_delay = 'sleep 2' if 'sleep' in payload else 'ping -n 2 127.0.0.1'
                
                start_time = time.time()
                if injectable['method'] == 'GET':
                    test_url = injectable['url'].replace(f"{injectable['param']}=", f"{injectable['param']}={different_delay}")
                    async with session.get(test_url, ssl=False, timeout=5) as response:
                        await response.text()
                else:
                    data = {injectable['param']: different_delay}
                    async with session.post(injectable['url'], data=data, ssl=False, timeout=5) as response:
                        await response.text()
                
                execution_time = time.time() - start_time
                
                # Verify if the execution time matches the expected delay
                return 1.5 <= execution_time <= 2.5

            return True  # For non-timing based vulnerabilities, trust the initial detection

        except Exception:
            return False

    async def scan_url(self, url: str) -> List[Dict]:
        """Main scanning function"""
        all_vulnerabilities = []
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            connector = aiohttp.TCPConnector(limit=3)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                # Find injectable parameters
                injectables = await self.find_injectable_params(session, url)
                if not injectables:
                    logger.info("No potentially injectable parameters found")
                    return []

                # Generate payloads
                payloads = self.generate_payloads()

                # Test parameters sequentially to avoid overwhelming the target
                for injectable in injectables:
                    vulnerabilities = await self.test_parameter(session, injectable, payloads)
                    # No need for deduplication here as it's handled in test_parameter
                    all_vulnerabilities.extend(vulnerabilities)

                logger.info(f"Found {len(self.seen_vulnerabilities)} unique RCE vulnerabilities")

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
    scanner = RCEScanner()
    return await scanner.scan_url(target_url)

# Constants
SUSPICIOUS_PARAM_NAMES = [
    'cmd', 'exec', 'command', 'execute', 'ping', 'query', 'jump', 'code', 'reg',
    'do', 'func', 'function', 'option', 'load', 'process', 'run', 'shell', 'system',
    'proc', 'action'
]
