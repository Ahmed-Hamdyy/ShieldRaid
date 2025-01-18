import requests
from bs4 import BeautifulSoup
import logging
from .utils import extract_version, is_vulnerable_version

logger = logging.getLogger(__name__)

def check_vulnerable_components(target_url, response):
    vulnerabilities = []
    logger.info("Checking for Vulnerable and Outdated Components")
    
    soup = BeautifulSoup(response.text, 'html.parser')
    scripts = soup.find_all('script', src=True)

    # Define libraries of interest
    libraries = ["jquery", "bootstrap", "angular", "vue"]

    for script in scripts:
        src = script['src'].lower()
        for library in libraries:
            if library in src:
                version = extract_version(src, library)
                if version and is_vulnerable_version(version, library):
                    vulnerabilities.append({
                        "type": "Vulnerable and Outdated Component",
                        "description": f"{library.capitalize()} version {version} is outdated and may contain vulnerabilities.",
                        "location": f"Script Source: {src}",
                        "severity": "Medium"
                    })
                    logger.warning(f"Vulnerable and Outdated Component detected: {library.capitalize()} {version}")
                else:
                    logger.info(f"{library.capitalize()} version {version} found and is up-to-date.")
    return vulnerabilities
