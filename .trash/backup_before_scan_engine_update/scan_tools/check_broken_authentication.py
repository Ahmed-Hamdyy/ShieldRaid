import logging
from .utils import *
import aiohttp

logger = logging.getLogger(__name__)

async def check_broken_authentication(target_url):
    """
    Checks for Broken Authentication vulnerabilities related to cookie security.
    """
    vulnerabilities = []
    logger.info("Checking for Broken Authentication vulnerabilities related to cookies")
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(target_url, timeout=10, ssl=False) as response:
                if response.status != 200:
                    logger.error(f"Failed to fetch {target_url}. Status code: {response.status}")
                    return vulnerabilities
                    
                # استخراج الكوكيز من الاستجابة
                cookies = response.cookies
                for cookie in cookies:
                    issues = []
                    
                    # التحقق من غياب خاصية Secure
                    if not cookie.secure:
                        issues.append("Secure flag not set")
                    
                    # التحقق من غياب خاصية HttpOnly
                    if not cookie.has_nonstandard_attr('HttpOnly') and not cookie.has_nonstandard_attr('httponly'):
                        issues.append("HttpOnly flag not set")
                    
                    # التحقق من غياب خاصية SameSite
                    if not cookie.has_nonstandard_attr('SameSite'):
                        issues.append("SameSite flag not set")
                    
                    # التحقق من كوكيز تنتهي بعد مدة طويلة أو لا تنتهي أبداً
                    if cookie.expires is None:
                        issues.append("Session cookie with no expiry")
                    elif cookie.expires - response.elapsed.total_seconds() > 86400 * 30:
                        issues.append("Long-lived cookie (expires > 30 days)")

                    # تحليل حساسية المعلومات في الكوكيز
                    if any(keyword in cookie.name.lower() for keyword in ['session', 'auth', 'token']):
                        issues.append("Sensitive information in cookie name")
                    
                    # التحقق من كوكيز قابلة للنقل بين المواقع (في حال غياب SameSite و Secure)
                    if not cookie.secure and not cookie.has_nonstandard_attr('SameSite'):
                        issues.append("Potential CSRF risk without SameSite and Secure flags")

                    # إضافة النتيجة النهائية إذا وجدت أي قضايا
                    if issues:
                        severity = "High" if "Secure flag not set" in issues or "HttpOnly flag not set" in issues else "Medium"
                        vulnerability_detail = {
                            "type": "Broken Authentication",
                            "description": f"Cookie '{cookie.name}' has issues: {', '.join(issues)}.",
                            "location": f"Cookie: {cookie.name}",
                            "severity": severity
                        }
                        vulnerabilities.append(vulnerability_detail)
                        logger.warning(f"Broken Authentication issue detected in cookie '{cookie.name}': {', '.join(issues)}")

    except Exception as e:
        logger.error(f"Error during Broken Authentication check: {e}")
    
    if not vulnerabilities:
        logger.info("No Broken Authentication vulnerabilities related to cookies were found.")
    
    return vulnerabilities

async def scan(target_url):
    """
    Main scan function that wraps the check_broken_authentication functionality.
    """
    return await check_broken_authentication(target_url)
