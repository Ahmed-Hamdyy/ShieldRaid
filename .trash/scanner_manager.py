import time
from logger import logger

class ScannerManager:
    def __init__(self, available_modules, module_mapping):
        self.available_modules = available_modules
        self.module_mapping = module_mapping

    def scan_url(self, url, selected_modules=None):
        """Scan a URL with selected modules."""
        try:
            start_time = time.time()
            vulnerabilities = []
            
            # Run selected modules
            for module_name in (selected_modules or self.available_modules):
                if module_name in self.module_mapping:
                    module_vulns = self.module_mapping[module_name](url)
                    if module_vulns:
                        vulnerabilities.extend(module_vulns)
            
            # Calculate scan duration
            scan_duration = round(time.time() - start_time, 2)
            
            # Calculate stats
            stats = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
            
            # Count vulnerabilities by severity
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'low').lower()
                if severity in stats:
                    stats[severity] += 1
            
            return {
                'vulnerabilities': vulnerabilities,
                'stats': stats,
                'scan_duration': scan_duration,
                'status': 'completed'
            }
            
        except Exception as e:
            logger.error(f"Error scanning URL {url}: {str(e)}")
            return None 