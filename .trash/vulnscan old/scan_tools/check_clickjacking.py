import requests
import logging

logger = logging.getLogger(__name__)

def check_clickjacking(target_url):
    """
    Check if the target URL is vulnerable to clickjacking by analyzing the HTTP headers
    such as X-Frame-Options and Content-Security-Policy.
    """
    vulnerabilities = []
    logger.info("Starting Clickjacking check for target URL: %s", target_url)

    try:
        # Send a request to the target URL
        response = requests.get(target_url, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        logger.error("Error connecting to %s: %s", target_url, e)
        vulnerabilities.append({
            "type": "Connection Error",
            "description": f"Failed to connect to {target_url}",
            "location": "Network Request",
            "severity": "Critical"
        })
        return vulnerabilities

    # Extract headers
    x_frame_options = response.headers.get('X-Frame-Options', '').lower()
    csp = response.headers.get('Content-Security-Policy', '').lower()

    # Determine framing policy
    logger.info("Checking X-Frame-Options and Content-Security-Policy headers")
    frame_allowed = True
    if 'deny' in x_frame_options or 'sameorigin' in x_frame_options:
        frame_allowed = False
        logger.info("X-Frame-Options header detected with secure value: %s", x_frame_options)
    elif 'frame-ancestors' in csp:
        if 'none' in csp or 'self' in csp:
            frame_allowed = False
            logger.info("Content-Security-Policy header detected with frame-ancestors directive: %s", csp)

    # Log and add vulnerability if framing is allowed
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

    return vulnerabilities
