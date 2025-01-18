import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import logging
import asyncio

logger = logging.getLogger(__name__)

async def check_no_rate_limiting(target_url):
    """
    Checks if rate limiting is enforced on the login page.
    If the login page is not specified, attempts to locate it.
    """
    vulnerabilities = []
    logger.info("Starting Rate Limiting check for target URL: %s", target_url)

    # البحث تلقائيًا عن صفحة تسجيل الدخول إذا لم يتم تحديدها
    login_url = await find_login_page(target_url)
    if not login_url:
        logger.warning("No login page found on the target site.")
        return vulnerabilities

    logger.info(f"Login page found: {login_url}")

    # البحث عن أسماء حقول الإدخال للـ username و password
    login_form_data = await find_login_form_fields(login_url)
    if not login_form_data:
        logger.warning("Unable to detect username and password fields on the login page.")
        return vulnerabilities

    logger.info(f"Login form fields detected: {login_form_data}")

    failed_attempts = 15
    blocked = False
    async with aiohttp.ClientSession() as session:
        for i in range(failed_attempts):
            try:
                async with session.post(login_url, data=login_form_data, timeout=5, ssl=False) as response:
                    # تحليل كود الاستجابة والرأسيات للتحقق من التقييد
                    if response.status == 429 or 'retry-after' in response.headers:
                        blocked = True
                        logger.info("Rate limiting is enforced with status code 429 or Retry-After header.")
                        break

                    # تحليل الرأسيات المتعلقة بالتقييد
                    rate_limit = response.headers.get('X-RateLimit-Limit')
                    rate_remaining = response.headers.get('X-RateLimit-Remaining')
                    if rate_limit and rate_remaining and int(rate_remaining) == 0:
                        blocked = True
                        logger.info("Rate limiting detected using X-RateLimit headers.")
                        break

                    await asyncio.sleep(0.5)

            except Exception as e:
                logger.error(f"Error during Rate Limiting check: {e}")
                break

    if not blocked:
        vulnerabilities.append({
            "type": "No Rate Limiting",
            "description": "No rate limiting detected on the login endpoint, allowing brute-force attacks.",
            "location": login_url,
            "severity": "High"
        })
        logger.warning("No Rate Limiting vulnerability detected.")

    return vulnerabilities

async def find_login_page(target_url):
    """
    Attempts to find a login page by analyzing links in the target URL's home page.
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(target_url, timeout=5, ssl=False) as response:
                if response.status != 200:
                    logger.error(f"Failed to fetch {target_url}. Status code: {response.status}")
                    return None
                    
                text = await response.text()
                soup = BeautifulSoup(text, 'html.parser')

                # البحث عن روابط تحتوي على كلمات مثل "login" أو "signin"
                for link in soup.find_all('a', href=True):
                    href = link['href'].lower()
                    if 'login' in href or 'signin' in href:
                        login_url = urljoin(target_url, href)
                        logger.info(f"Login page located: {login_url}")
                        return login_url
    except Exception as e:
        logger.error(f"Error while searching for login page: {e}")

    return None

async def find_login_form_fields(login_url):
    """
    Detects the username and password fields in the login form.
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(login_url, timeout=5, ssl=False) as response:
                if response.status != 200:
                    logger.error(f"Failed to fetch {login_url}. Status code: {response.status}")
                    return None
                    
                text = await response.text()
                soup = BeautifulSoup(text, 'html.parser')

                form = soup.find('form')
                if not form:
                    logger.warning("No form found on the login page.")
                    return None

                # التعرف على حقول username و password في النموذج
                username_field = None
                password_field = None
                for input_tag in form.find_all('input'):
                    input_name = input_tag.get('name', '').lower()
                    if 'user' in input_name or 'email' in input_name:
                        username_field = input_tag.get('name')
                    elif 'pass' in input_name:
                        password_field = input_tag.get('name')

                if username_field and password_field:
                    # تحضير البيانات لتجربة الدخول
                    return {username_field: 'testuser', password_field: 'wrongpassword'}

    except Exception as e:
        logger.error(f"Error while detecting form fields: {e}")

    return None


async def scan(target_url):
    """
    Main scan function that wraps the check_no_rate_limiting functionality.
    """
    return await check_no_rate_limiting(target_url)
