import re
from urllib.parse import urlparse, urljoin, urlencode, parse_qs
import requests
import logging

logger = logging.getLogger(__name__)

def inject_payload(url, payload, param_name='input'):
    """
    Injects a payload into a specified query parameter of the URL.
    """
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    query_params[param_name] = payload  # Set or overwrite the parameter with the payload
    new_query = urlencode(query_params, doseq=True)
    new_url = parsed_url._replace(query=new_query).geturl()
    logger.info(f"Payload '{payload}' injected into URL: {new_url}")
    return new_url

def extract_version(src, library="jquery"):
    """
    Extracts the version number from a script source URL based on library type.
    Example: 'https://code.jquery.com/jquery-3.5.1.min.js' -> '3.5.1'
    """
    version_patterns = {
        "jquery": r'jquery-(\d+\.\d+\.\d+)',
        "bootstrap": r'bootstrap-(\d+\.\d+\.\d+)',
        "angular": r'angular-(\d+\.\d+\.\d+)',
        "vue": r'vue\.(\d+\.\d+\.\d+)',
    }
    pattern = version_patterns.get(library.lower())
    match = re.search(pattern, src) if pattern else None
    if match:
        version = match.group(1)
        logger.info(f"Version {version} extracted from {src} for {library}")
        return version
    logger.warning(f"No version found in {src} for {library}")
    return None

def is_vulnerable_version(version, library="jquery"):
    """
    Checks if the specified version of a library is known to be vulnerable.
    """
    known_vulnerabilities = {
        "jquery": ['1.12.4', '2.2.4', '3.5.0'],
        "bootstrap": ['4.3.1', '3.4.0'],
        "angular": ['1.5.8', '1.6.1'],
        "vue": ['2.5.17', '2.6.10']
    }
    vulnerable_versions = known_vulnerabilities.get(library.lower(), [])
    is_vulnerable = version in vulnerable_versions
    if is_vulnerable:
        logger.warning(f"Detected vulnerable version {version} for {library}")
    else:
        logger.info(f"Version {version} for {library} is not listed as vulnerable")
    return is_vulnerable

def get_allowed_methods(url):
    """
    Retrieves the allowed HTTP methods for a given URL using the OPTIONS method.
    """
    try:
        response = requests.options(url, timeout=5, verify=False)
        allow = response.headers.get('Allow', '')
        methods = [method.strip().upper() for method in allow.split(',') if method.strip()]
        logger.info(f"Allowed HTTP methods for {url}: {methods}")
        return methods
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching allowed methods for {url}: {e}")
        return []
