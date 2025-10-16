from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from datetime import datetime
import time
import logging
from typing import Dict, Any
from .base import BaseScanner, ScannerError

logger = logging.getLogger(__name__)

class OpenVASScanner(BaseScanner):
    
    def __init__(self, username: str, password: str, host: str = 'localhost', port: int = 9390, timeout: int = 14400):
        super().__init__(timeout)
        self.username = username
        self.password = password
        self.host = host
        self.port = port
        self.transform = EtreeTransform()
    
    def scan(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        connection = None
        try:
            self.check_ready()
            self.validate_target(target)
            self._log_scan_start(target)
            
            options = options or {}

            connection = Gmp(
                hostname=self.host,
                port=self.port,
                transform=self.transform
            )
            connection.authenticate(self.username, self.password)

            target_id = self._create_target(connection, target, options)

            task_id = self._create_task(connection, target_id, options)

            report_id = self._start_scan(connection, task_id)

            return self._get_results(connection, report_id, target)
            
        except Exception as e:
            logger.error(f"OpenVAS scan failed: {str(e)}", exc_info=True)
            raise ScannerError(f"OpenVAS error: {str(e)}")
        finally:
            if connection:
                connection.disconnect()
    
    def _create_target(self, gmp: Gmp, target: str, options: Dict[str, Any]) -> str:
        port_list_id = options.get('port_list_id', '33d0cd82-57c6-11e1-8ed1-406186ea4fc5')  # Default порты
        alive_test = options.get('alive_test', 'ICMP, TCP-ACK Service & ARP Ping')
        
        response = gmp.create_target(
            name=f"Scan {datetime.now().isoformat()}",
            hosts=[target],
            port_list_id=port_list_id,
            alive_test=alive_test
        )
        return response.xpath('@id')[0]
    
    def _create_task(self, gmp: Gmp, target_id: str, options: Dict[str, Any]) -> str:
        scan_config_id = options.get('scan_config_id', 'daba56c8-73ec-11df-a475-002264764cea')  # Full and fast
        scanner_id = options.get('scanner_id', '08b69003-5fc2-4037-a479-93b440211c73')  # Default scanner
        
        response = gmp.create_task(
            name=f"Task {datetime.now().isoformat()}",
            config_id=scan_config_id,
            target_id=target_id,
            scanner_id=scanner_id,
            preferences={
                'max_checks': options.get('max_checks', 10),
                'max_hosts': options.get('max_hosts', 5)
            }
        )
        return response.xpath('@id')[0]
    
    def _start_scan(self, gmp: Gmp, task_id: str) -> str:
        response = gmp.start_task(task_id)
        report_id = response.xpath('//report_id/text()')[0]
        
        start_time = time.time()
        while True:
            if time.time() - start_time > self.timeout:
                raise ScannerError("OpenVAS scan timed out")
                
            task = gmp.get_task(task_id)
            status = task.xpath('//status/text()')[0]
            
            if status == 'Done':
                break
            elif status == 'Stopped':
                raise ScannerError("Scan was stopped")
            
            time.sleep(60)
        
        return report_id
    
    def _get_results(self, gmp: Gmp, report_id: str, target: str) -> Dict[str, Any]:
        report = gmp.get_report(report_id, report_format_id='a994b278-1f62-11e1-96ac-406186ea4fc5')  # XML формат
        
        vulns = []
        for result in report.xpath('//result'):
            severity_elem = result.xpath('severity/text()')
            if not severity_elem:
                continue
                
            severity = float(severity_elem[0])
            if severity <= 0:
                continue

            name_elem = result.xpath('nvt/name/text()')
            description_elem = result.xpath('description/text()')
            cve_elem = result.xpath('nvt/cve/text()')
            solution_elem = result.xpath('nvt/solution/text()')
            port_elem = result.xpath('port/text()')
            
            vulns.append({
                'type': 'openvas',
                'cve_id': cve_elem[0] if cve_elem else 'N/A',
                'name': name_elem[0] if name_elem else 'Unknown',
                'description': description_elem[0] if description_elem else 'No description',
                'severity': self._cvss_to_severity(severity),
                'cvss_score': severity,
                'port': port_elem[0] if port_elem else 'general',
                'solution': solution_elem[0] if solution_elem else 'No solution provided',
                'references': [
                    ref.text for ref in result.xpath('nvt/refs/ref') if ref.text
                ]
            })
        
        return {
            'target': target,
            'vulnerabilities': vulns
        }
    
    def _cvss_to_severity(self, cvss: float) -> str:
        if cvss >= 9.0:
            return 'critical'
        elif cvss >= 7.0:
            return 'high'
        elif cvss >= 4.0:
            return 'medium'
        else:
            return 'low'
