import aiohttp
from bs4 import BeautifulSoup
import re
import logging

logger = logging.getLogger(__name__)

async def check_csrf(target_url):
    """
    Checks for CSRF vulnerabilities by analyzing forms and headers on the target page.
    """
    vulnerabilities = []
    logger.info("Checking for Cross-Site Request Forgery (CSRF) vulnerabilities")
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(target_url, timeout=10, ssl=False) as response:
                if response.status != 200:
                    logger.error(f"Failed to fetch {target_url}. Status code: {response.status}")
                    return vulnerabilities
                
                text = await response.text()
                # استخدام BeautifulSoup لتحليل الصفحة
                soup = BeautifulSoup(text, 'html.parser')
                forms = soup.find_all('form')

                if not forms:
                    logger.info("No forms found on the page. Skipping CSRF check.")
                    return vulnerabilities

                logger.info(f"Found {len(forms)} forms on {target_url} to check for CSRF tokens.")
                
                csrf_token_found = False
                csrf_token_names = re.compile(r'csrf|token|xsrf|authenticity', re.I)  # RegEx للبحث عن أسماء محتملة للتوكنات
                
                for form in forms:
                    form_method = form.get('method', 'get').lower()
                    
                    if form_method != 'post':
                        logger.info("Skipping form with method %s, as CSRF tokens are only needed for POST forms.", form_method)
                        continue  # Skip GET forms

                    tokens = form.find_all('input', {'type': 'hidden', 'name': csrf_token_names})

                    if tokens:
                        csrf_token_found = True
                        logger.info("CSRF token found in form with action: %s", form.get('action'))
                        break  # Stop after finding the first valid CSRF token

                # التحقق من وجود رأسيات CSRF
                csrf_header_found = 'x-csrf-token' in response.headers or 'x-xsrf-token' in response.headers
                if csrf_header_found:
                    logger.info("CSRF header found in response headers.")

                # إذا لم يتم العثور على أي توكن أو رأسية، تُسجل كضعف محتمل
                if not csrf_token_found and not csrf_header_found:
                    vulnerabilities.append({
                        "type": "Cross-Site Request Forgery (CSRF)",
                        "description": "No CSRF tokens or headers found in forms, making the application susceptible to CSRF attacks.",
                        "location": "Forms and headers on the page",
                        "severity": "High"
                    })
                    logger.warning("CSRF vulnerability detected: No CSRF tokens or headers found.")
        
    except Exception as e:
        logger.error(f"Error during CSRF check: {e}")

    return vulnerabilities


async def scan(target_url):
    """
    Main scan function that wraps the check_csrf functionality.
    """
    return await check_csrf(target_url)
