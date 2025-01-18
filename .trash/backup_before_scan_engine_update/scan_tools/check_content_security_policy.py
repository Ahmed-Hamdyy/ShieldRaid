import logging
import aiohttp

logger = logging.getLogger(__name__)

async def check_content_security_policy(target_url):
    vulnerabilities = []
    logger.info("Checking for Content Security Policy (CSP) vulnerabilities on %s", target_url)
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(target_url, timeout=10, ssl=False) as response:
                if response.status != 200:
                    logger.error(f"Failed to fetch {target_url}. Status code: {response.status}")
                    return vulnerabilities
                    
                # استخراج سياسات CSP من الرأس
                csp = response.headers.get('Content-Security-Policy')
                if not csp:
                    vulnerabilities.append({
                        "type": "Content Security Policy (CSP) Violation",
                        "description": "Content-Security-Policy header is missing, increasing risk of XSS and other attacks.",
                        "location": "HTTP Header: Content-Security-Policy",
                        "severity": "High"
                    })
                    logger.warning("Content-Security-Policy header not set for %s", target_url)
                else:
                    logger.info("Content-Security-Policy header is present.")
                    
                    # توجيهات ضعيفة شائعة
                    insecure_directives = ["'unsafe-inline'", "'unsafe-eval'", "*", "data:", "blob:"]
                    directives = csp.split(";")
                    
                    # فحص التوجيهات الضعيفة
                    for directive in directives:
                        if any(insecure in directive for insecure in insecure_directives):
                            vulnerabilities.append({
                                "type": "Content Security Policy (CSP) Violation",
                                "description": f"Insecure CSP directive found: {directive.strip()}",
                                "location": "HTTP Header: Content-Security-Policy",
                                "severity": "Medium"
                            })
                            logger.warning("Insecure CSP directive detected: %s", directive.strip())

                    # التحقق من توجيهات CSP الأساسية الموصى بها
                    recommended_directives = ["default-src", "script-src", "object-src", "frame-ancestors"]
                    missing_directives = [d for d in recommended_directives if d not in csp]
                    if missing_directives:
                        vulnerabilities.append({
                            "type": "Content Security Policy (CSP) Violation",
                            "description": f"Missing essential CSP directives: {', '.join(missing_directives)}.",
                            "location": "HTTP Header: Content-Security-Policy",
                            "severity": "Low"
                        })
                        logger.warning("Missing essential CSP directives: %s", ', '.join(missing_directives))

                    # اقتراح لتقييد المزيد من السياسات
                    if "default-src" in csp and "* " in csp:
                        vulnerabilities.append({
                            "type": "Content Security Policy (CSP) Recommendation",
                            "description": "Consider using more restrictive sources instead of '*'.",
                            "location": "HTTP Header: Content-Security-Policy",
                            "severity": "Low"
                        })
                        logger.info("Consider replacing '*' in CSP with more specific domains or 'self'.")
    except Exception as e:
        logger.error(f"Error during Content Security Policy check: {e}")
    return vulnerabilities


async def scan(target_url):
    """
    Main scan function that wraps the check_content_security_policy functionality.
    """
    return await check_content_security_policy(target_url)
