import logging
import aiohttp

logger = logging.getLogger(__name__)

async def check_missing_security_headers(target_url):
    vulnerabilities = []
    missing_headers = []  # قائمة لتخزين الرؤوس المفقودة
    logger.info("Checking for Missing or Misconfigured Security Headers")
    
    headers_to_check = {
        'Content-Security-Policy': 'Content-Security-Policy header is missing or misconfigured.',
        'X-Frame-Options': 'X-Frame-Options header is missing or misconfigured.',
        'X-Content-Type-Options': 'X-Content-Type-Options header is missing or misconfigured.',
        'Referrer-Policy': 'Referrer-Policy header is missing or misconfigured.',
        'X-XSS-Protection': 'X-XSS-Protection header is missing or disabled.',
        'Permissions-Policy': 'Permissions-Policy header is missing or misconfigured.',
        'Strict-Transport-Security': 'Strict-Transport-Security header is missing or misconfigured.',
        'Expect-CT': 'Expect-CT header is missing or misconfigured.',
        'X-Permitted-Cross-Domain-Policies': 'X-Permitted-Cross-Domain-Policies header is missing or misconfigured.'
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(target_url, timeout=10, ssl=False) as response:
                if response.status != 200:
                    logger.error(f"Failed to fetch {target_url}. Status code: {response.status}")
                    return vulnerabilities
                    
                for header, description in headers_to_check.items():
                    header_value = response.headers.get(header)
                    
                    # التحقق من وجود الرأس
                    if not header_value:
                        missing_headers.append(header)  # إضافة الرأس المفقود للقائمة
                
                # إذا كانت هناك رؤوس مفقودة، يتم إضافة تقرير واحد
                if missing_headers:
                    vulnerabilities.append({
                        "type": "Missing Security Header",
                        "description": f"Missing the following security headers: {', '.join(missing_headers)}.",
                        "location": "HTTP Headers",
                        "severity": "Info"
                    })
                    logger.warning(f"Missing security headers: {', '.join(missing_headers)}.")
    except Exception as e:
        logger.error(f"Error during Missing Security Headers check: {e}")
    return vulnerabilities

async def scan(target_url):
    """
    Main scan function that wraps the check_missing_security_headers functionality.
    """
    return await check_missing_security_headers(target_url)
