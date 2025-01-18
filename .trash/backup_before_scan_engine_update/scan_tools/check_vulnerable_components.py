import requests
from bs4 import BeautifulSoup
import logging
from .utils import extract_version, is_vulnerable_version

logger = logging.getLogger(__name__)

def check_vulnerable_components(target_url, response):
    vulnerabilities = []
    logger.info("Checking for Vulnerable and Outdated Components")

    try:
        # تأكد من أن الرد يحتوي على HTML
        if "text/html" not in response.headers.get("Content-Type", ""):
            logger.warning("Response does not contain HTML content. Skipping component checks.")
            return vulnerabilities

        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = soup.find_all('script', src=True)

        # Define libraries of interest
        libraries = ["jquery", "bootstrap", "angular", "vue"]

        for script in scripts:
            src = script['src'].lower()
            for library in libraries:
                if library in src:
                    version = extract_version(src, library)
                    if version:
                        if is_vulnerable_version(version, library):
                            vulnerabilities.append({
                                "type": "Vulnerable and Outdated Component",
                                "description": f"{library.capitalize()} version {version} is outdated and may contain vulnerabilities.",
                                "location": f"Script Source: {src}",
                                "severity": "Medium"
                            })
                            logger.warning(f"Vulnerable and Outdated Component detected: {library.capitalize()} {version}")
                        else:
                            logger.info(f"{library.capitalize()} version {version} found and is up-to-date.")
                    else:
                        logger.warning(f"Could not extract version for {library} from {src}")
                else:
                    logger.info(f"{library} not found in {src}")
    except Exception as e:
        logger.error(f"Error during component check: {e}")

    if not vulnerabilities:
        logger.info("No vulnerable components found.")
    return vulnerabilities


async def scan(target_url):
    """
    Main scan function that wraps the check_vulnerable_components functionality.
    """
    return await check_vulnerable_components(target_url)
