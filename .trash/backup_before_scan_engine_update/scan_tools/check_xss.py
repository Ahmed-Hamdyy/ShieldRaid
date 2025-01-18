import aiohttp
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from .utils import inject_payload

logger = logging.getLogger(__name__)

async def scan(target_url):
    vulnerabilities = []
    logger.info("Checking for Cross-Site Scripting (XSS) vulnerabilities")

    # XSS payloads
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
        async with aiohttp.ClientSession() as session:
            async with session.get(target_url, timeout=10, ssl=False) as response:
                if response.status != 200:
                    logger.error(f"Failed to fetch {target_url}. Status code: {response.status}")
                    return vulnerabilities
                    
                text = await response.text()
                soup = BeautifulSoup(text, 'html.parser')
                forms = soup.find_all("form")
                logger.info(f"Found {len(forms)} forms on {target_url}")

                # Process each form
                for form in forms:
                    action = form.get("action")
                    method = form.get("method", "get").lower()
                    form_url = urljoin(target_url, action) if action else target_url
                    logger.info(f"Processing form with action: {action} and method: {method}")

                    inputs = form.find_all("input")
                    form_data = {input_tag.get("name"): "test" if input_tag.get("type", "text") in ["text", "search"] else input_tag.get("value", "")
                                for input_tag in inputs}

                    # Test each payload on each input
                    for payload in xss_payloads:
                        for input_name in form_data.keys():
                            test_data = form_data.copy()
                            test_data[input_name] = payload

                            try:
                                logger.info(f"Testing XSS payload: '{payload}' in input: '{input_name}' on form: {form_url}")
                                if method == "post":
                                    async with session.post(form_url, data=test_data) as response:
                                        response_text = await response.text()
                                else:
                                    async with session.get(form_url, params=test_data) as response:
                                        response_text = await response.text()

                                if payload in response_text:
                                    vulnerabilities.append({
                                        "type": "Cross-Site Scripting (XSS)",
                                        "description": f"Reflected XSS detected with payload: {payload}",
                                        "location": f"Form: {form_url}, Input: {input_name}",
                                        "severity": "High"
                                    })
                                    logger.warning(f"XSS vulnerability detected with payload: {payload} in form {form_url}")
                                    break
                            except Exception as e:
                                logger.error(f"Error during XSS test on form {form_url} with payload '{payload}': {e}")

    except Exception as e:
        logger.error(f"Error during XSS check: {e}")
        return vulnerabilities

    return vulnerabilities
