import aiohttp
import logging

logger = logging.getLogger(__name__)

async def check_information_disclosure(target_url):
    vulnerabilities = []
    logger.info("Checking for Information Disclosure vulnerabilities")

    # قائمة موسعة من التواقيع التي تشير إلى كشف محتمل لمعلومات حساسة
    error_signatures = [
        "error on line",
        "stack trace",
        "exception occurred",
        "server at",
        "application error",
        "null pointer",
        "database error",
        "sql syntax",
        "path disclosure",
        "file not found",
        "fatal error",
        "runtime error",
        "traceback",
        "invalid query",
    ]

    try:
        logger.info(f"Sending GET request to {target_url}")
        async with aiohttp.ClientSession() as session:
            async with session.get(target_url, timeout=10, ssl=False) as response:
                if response.status != 200:
                    logger.error(f"Failed to fetch {target_url}. Status code: {response.status}")
                    return vulnerabilities
                    
                response_text = (await response.text()).lower()

                # التحقق من وجود أي توقيع يكشف عن معلومات حساسة في الاستجابة
                if any(sig in response_text for sig in error_signatures):
                    matching_signatures = [sig for sig in error_signatures if sig in response_text]
                    vulnerabilities.append({
                        "type": "Information Disclosure",
                        "description": f"Detailed error messages or sensitive information exposed: {', '.join(matching_signatures)}",
                        "location": "Response Body",
                        "severity": "Medium"
                    })
                    logger.warning("Information Disclosure vulnerability detected with signatures: " + ', '.join(matching_signatures))
                else:
                    logger.info("No information disclosure vulnerabilities detected in response.")

    except Exception as e:
        logger.error(f"Error during Information Disclosure check: {e}")

    return vulnerabilities


async def scan(target_url):
    """
    Main scan function that wraps the check_information_disclosure functionality.
    """
    return await check_information_disclosure(target_url)
