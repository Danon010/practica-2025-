from zapv2 import ZAPv2
import time
import logging
from typing import Dict, Any
from .base import BaseScanner, ScannerError, ScannerTimeoutError

logger = logging.getLogger(__name__)

class ZapScanner(BaseScanner):
    
    def __init__(self, api_key: str, proxy: str = 'http://localhost:8080', timeout: int = 7200):
        super().__init__(timeout)
        self.api_key = api_key
        self.proxy = proxy
        self.zap = ZAPv2(apikey=api_key, proxies={'http': proxy, 'https': proxy})
    
    def scan(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        try:
            self.check_ready()
            self.validate_target(target)
            self._log_scan_start(target)
            
            options = options or {}

            session_name = f"scan_{int(time.time())}"
            self.zap.core.new_session(session_name)

            self.zap.urlopen(target)

            spider_id = self._start_spider(target, options)
            self._wait_for_complete(spider_id, 'spider')

            ascan_id = self._start_active_scan(target, options)
            self._wait_for_complete(ascan_id, 'ascan')

            return self._get_results(target)
        
        except Exception as e:
            self.zap.core.shutdown()
            logger.error(f"ZAP scan failed: {str(e)}", exc_info=True)
            raise ScannerError(f"ZAP error: {str(e)}")
    
    def _start_spider(self, target: str, options: Dict[str, Any]) -> str:
        spider_options = {
            'maxChildren': options.get('spider_max_children', 10),
            'recurse': True,
            'contextName': None
        }
        return self.zap.spider.scan(target, **spider_options)
    
    def _start_active_scan(self, target: str, options: Dict[str, Any]) -> str:
        scan_options = {
            'recurse': True,
            'scanPolicyName': options.get('scan_policy', 'Default Policy'),
            'method': 'GET',
            'postData': ''
        }
        return self.zap.ascan.scan(target, **scan_options)
    
    def _wait_for_complete(self, scan_id: str, scan_type: str):
        start_time = time.time()
        status = 0
        
        while status < 100:
            if time.time() - start_time > self.timeout:
                raise ScannerTimeoutError(f"{scan_type} scan timed out")
            
            time.sleep(10)
            status = getattr(self.zap, scan_type).status(scan_id)
    
    def _get_results(self, target: str) -> Dict[str, Any]:
        alerts = self.zap.core.alerts(baseurl=target)
        
        vulns = []
        for alert in alerts:
            if alert['risk'] == 'Informational':
                continue

            vuln_data = {
                'type': 'web',
                'cve_id': alert.get('cweid', 'N/A'),
                'name': alert['name'],
                'description': alert['description'],
                'severity': alert['risk'].lower(),
                'cvss_score': self._risk_to_cvss(alert['risk']),
                'solution': alert['solution'],
                'references': alert.get('reference', '').split('\n')
            }

            if 'url' in alert:
                vuln_data['url'] = alert['url']
            else:
                vuln_data['url'] = target
                
            vulns.append(vuln_data)
        
        return {
            'target': target,
            'vulnerabilities': vulns
        }
    
    def _risk_to_cvss(self, risk: str) -> float:
        risk_map = {
            'High': 9.0,
            'Medium': 6.0,
            'Low': 3.0
        }
        return risk_map.get(risk, 0.0)
