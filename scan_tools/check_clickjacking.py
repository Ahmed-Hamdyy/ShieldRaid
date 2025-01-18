import aiohttp
import logging

logger = logging.getLogger(__name__)

async def check_clickjacking(target_url):
    """
    Check if the target URL is vulnerable to clickjacking by analyzing HTTP headers.
    The function checks X-Frame-Options and Content-Security-Policy headers.
    """
    vulnerabilities = []
    logger.info("Starting Clickjacking check for target URL: %s", target_url)

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(target_url, timeout=10, ssl=False) as response:
                if response.status != 200:
                    logger.error(f"Failed to fetch {target_url}. Status code: {response.status}")
                    return vulnerabilities
                
                # استخراج الرؤوس
                x_frame_options = response.headers.get('X-Frame-Options', '').lower()
                csp = response.headers.get('Content-Security-Policy', '').lower()

                frame_allowed = True  # افتراض السماح بالإطار حتى يتبين العكس

                # تحليل X-Frame-Options
                logger.info("Analyzing X-Frame-Options and Content-Security-Policy headers")
                if 'deny' in x_frame_options:
                    frame_allowed = False
                    logger.info("X-Frame-Options header detected with 'DENY' policy.")
                elif 'sameorigin' in x_frame_options:
                    frame_allowed = False
                    logger.info("X-Frame-Options header detected with 'SAMEORIGIN' policy.")
                elif x_frame_options:
                    logger.warning("X-Frame-Options header has unrecognized value: %s", x_frame_options)
                else:
                    logger.warning("X-Frame-Options header is missing. Potential Clickjacking vulnerability.")

                # تحليل Content-Security-Policy للـ frame-ancestors
                if 'frame-ancestors' in csp:
                    # التأكد من أن frame-ancestors تقتصر على self أو none
                    if 'none' in csp or 'self' in csp:
                        frame_allowed = False
                        logger.info("Content-Security-Policy frame-ancestors directive restricts framing.")
                    else:
                        logger.warning("Content-Security-Policy allows framing from external sources: %s", csp)
                elif not csp:
                    logger.warning("Content-Security-Policy header is missing. Potential Clickjacking vulnerability.")

                # إذا كان التأطير مسموحًا، أضف الثغرة إلى القائمة
                if frame_allowed:
                    vulnerabilities.append({
                        "type": "Clickjacking",
                        "description": "The application can be framed, making it vulnerable to clickjacking attacks.",
                        "location": target_url,
                        "severity": "Medium"
                    })
                    logger.warning("Clickjacking vulnerability detected for %s", target_url)
                else:
                    logger.info("No Clickjacking vulnerability detected; framing is restricted.")

    except Exception as e:
        logger.error(f"Error during Clickjacking check for {target_url}: {e}")
        vulnerabilities.append({
            "type": "Error",
            "description": f"Failed to check for Clickjacking due to network error: {e}",
            "location": target_url,
            "severity": "High"
        })

    return vulnerabilities

async def scan(target_url):
    """
    Main scan function that wraps the check_clickjacking functionality.
    """
    return await check_clickjacking(target_url)
