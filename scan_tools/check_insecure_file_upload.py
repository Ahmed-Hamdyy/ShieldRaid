# scan_tools/check_insecure_file_upload.py

import aiohttp
from urllib.parse import urljoin
import logging
import io

logger = logging.getLogger(__name__)

async def check_insecure_file_upload(target_url):
    vulnerabilities = []
    logger.info("Checking for Insecure File Upload vulnerabilities")
    upload_url = urljoin(target_url, '/upload')
    
    # Create form data
    form_data = aiohttp.FormData()
    form_data.add_field('file',
                       io.BytesIO('<?php echo "Vulnerable"; ?>'.encode()),
                       filename='shell.php',
                       content_type='application/php')
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(upload_url, data=form_data, timeout=10, ssl=False) as response:
                if response.status != 200:
                    logger.error(f"Failed to send POST request to {upload_url}. Status code: {response.status}")
                    return vulnerabilities
                    
                response_text = await response.text()
                if 'Vulnerable' in response_text:
                    vulnerabilities.append({
                        "type": "Insecure File Upload",
                        "description": "Insecure File Upload vulnerability detected by uploading a PHP shell.",
                        "location": upload_url,
                        "severity": "Critical"
                    })
                    logger.warning("Insecure File Upload vulnerability detected.")
    except Exception as e:
        logger.error(f"Error during Insecure File Upload check: {e}")
    return vulnerabilities


async def scan(target_url):
    """
    Main scan function that wraps the check_insecure_file_upload functionality.
    """
    return await check_insecure_file_upload(target_url)
