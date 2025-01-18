import logging
import importlib
import os
import time
import requests
import asyncio
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class ScannerManager:
    def __init__(self):
        self.module_map = {}
        self.load_modules()

    def load_modules(self):
        """Load all scanning modules"""
        try:
            module_dir = os.path.dirname(__file__)
            
            # Find all Python files that start with 'check_'
            module_files = [f[:-3] for f in os.listdir(module_dir) 
                          if f.startswith('check_') and f.endswith('.py')]
            
            # Create mapping from module name to file name
            name_mapping = {}
            for module_file in module_files:
                # Convert check_sql_injection.py to sql_injection
                module_key = module_file[6:]  # Remove 'check_' prefix
                name_mapping[module_key] = module_file

            # Load each module
            for module_key, module_file in name_mapping.items():
                try:
                    if os.path.exists(os.path.join(module_dir, f"{module_file}.py")):
                        module = importlib.import_module(f'.{module_file}', package='scan_tools')
                        if hasattr(module, 'scan'):
                            self.module_map[module_key] = module
                            logger.info(f"Loaded scanning module: {module_key}")
                        else:
                            logger.warning(f"Module {module_file} does not have a scan function")
                    else:
                        logger.warning(f"Module file {module_file}.py not found")
                except Exception as e:
                    logger.error(f"Error loading module {module_file}: {str(e)}")
                    continue

            if not self.module_map:
                logger.error("No scanning modules were loaded successfully")
            else:
                logger.info(f"Successfully loaded {len(self.module_map)} scanning modules")

        except Exception as e:
            logger.error(f"Error loading modules: {str(e)}")

    def scan_url(self, url, selected_modules=None):
        """Scan a URL with selected modules."""
        try:
            start_time = time.time()
            vulnerabilities = []
            stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            
            # Initial connection test
            try:
                response = requests.get(url, verify=False, timeout=10)
                logger.info("Initial connection successful")
            except Exception as e:
                logger.error(f"Failed to connect to {url}: {str(e)}")
                return {
                    'vulnerabilities': [{
                        'type': 'Connection Error',
                        'severity': 'error',
                        'description': f'Failed to connect to {url}: {str(e)}',
                        'location': url
                    }],
                    'stats': stats,
                    'scan_duration': 0,
                    'status': 'error'
                }
            
            # If no modules selected, return empty results
            if not selected_modules:
                logger.warning("No modules selected for scanning")
                return {
                    'vulnerabilities': [],
                    'stats': stats,
                    'scan_duration': 0,
                    'status': 'completed'
                }
            
            # Run selected modules
            for module_name in selected_modules:
                if module_name in self.module_map:
                    module = self.module_map[module_name]
                    try:
                        logger.info(f"Running module: {module_name}")
                        scan_func = getattr(module, 'scan')
                        
                        if asyncio.iscoroutinefunction(scan_func):
                            # Create event loop for async functions
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)
                            try:
                                results = loop.run_until_complete(scan_func(url))
                            finally:
                                loop.close()
                        else:
                            # Call sync function directly
                            results = scan_func(url)
                            
                        if results:
                            vulnerabilities.extend(results)
                            # Update stats based on findings
                            for vuln in results:
                                severity = vuln.get('severity', '').lower()
                                if severity in stats:
                                    stats[severity] += 1
                            logger.info(f"Module {module_name} found {len(results)} vulnerabilities")
                    except Exception as e:
                        logger.error(f"Error in module {module_name}: {str(e)}")
                        continue
                else:
                    logger.warning(f"Module {module_name} not found in available modules")
            
            scan_duration = time.time() - start_time
            logger.info(f"Scan completed in {scan_duration:.2f} seconds")

            return {
                'vulnerabilities': vulnerabilities,
                'stats': stats,
                'scan_duration': round(scan_duration, 2),
                'status': 'completed'
            }
            
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            return {
                'vulnerabilities': [{
                    'type': 'Scan Error',
                    'severity': 'error',
                    'description': f'Error during scan: {str(e)}',
                    'location': url
                }],
                'stats': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                'scan_duration': 0,
                'status': 'error'
            }