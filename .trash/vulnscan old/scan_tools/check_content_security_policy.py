import logging

logger = logging.getLogger(__name__)

def check_content_security_policy(target_url, response):
    vulnerabilities = []
    logger.info("Checking for Content Security Policy (CSP) vulnerabilities")
    
    csp = response.headers.get('Content-Security-Policy')
    if not csp:
        vulnerabilities.append({
            "type": "Content Security Policy (CSP) Violation",
            "description": "Content-Security-Policy header is not set, increasing risk of XSS attacks.",
            "location": "HTTP Header: Content-Security-Policy",
            "severity": "Medium"
        })
        logger.warning("Content-Security-Policy header not set.")
    else:
        logger.info("Content-Security-Policy header is present.")
        
        # Common insecure directives
        insecure_directives = ["'unsafe-inline'", "'unsafe-eval'", "*", "data:", "blob:"]
        directives = csp.split(";")
        
        for directive in directives:
            if any(insecure in directive for insecure in insecure_directives):
                vulnerabilities.append({
                    "type": "Content Security Policy (CSP) Violation",
                    "description": f"Insecure CSP directive detected: {directive.strip()}",
                    "location": "HTTP Header: Content-Security-Policy",
                    "severity": "Medium"
                })
                logger.warning(f"Insecure CSP directive detected: {directive.strip()}")

        # Recommended directives check
        recommended_directives = ["default-src", "script-src", "object-src"]
        missing_directives = [d for d in recommended_directives if d not in csp]
        if missing_directives:
            vulnerabilities.append({
                "type": "Content Security Policy (CSP) Violation",
                "description": f"Missing recommended CSP directives: {', '.join(missing_directives)}.",
                "location": "HTTP Header: Content-Security-Policy",
                "severity": "Low"
            })
            logger.warning(f"Missing recommended CSP directives: {', '.join(missing_directives)}")

    return vulnerabilities
