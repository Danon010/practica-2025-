import nmap
import re
import logging
from typing import List, Dict, Any
from .base import BaseScanner, ScannerError

logger = logging.getLogger(__name__)

class NmapScanner(BaseScanner):
    
    def __init__(self, timeout: int = 1800):
        super().__init__(timeout)
        self.nm = nmap.PortScanner()
        self.nmap_args = "-sV -T4 --script=vulners"
    
    def scan(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        try:
            self.check_ready()
            self.validate_target(target)
            self._log_scan_start(target)
            
            options = options or {}
            scan_args = self._build_scan_args(options)
            
            logger.info(f"Starting Nmap scan for {target} with args: {scan_args}")
            
            scan_result = self.nm.scan(
                hosts=target,
                arguments=scan_args,
                timeout=self.timeout
            )
            
            return self._parse_results(scan_result)
        
        except nmap.PortScannerError as e:
            raise ScannerError(f"Nmap error: {str(e)}")
        except Exception as e:
            logger.error(f"Nmap scan failed: {str(e)}", exc_info=True)
            raise ScannerError(f"Unexpected error: {str(e)}")
    
    def _build_scan_args(self, options: Dict[str, Any]) -> str:
        args = [self.nmap_args]
        
        if options.get('os_detection', False):
            args.append("-O")
        if ports := options.get('ports'):
            if self._validate_ports(ports):
                args.append(f"-p {ports}")
        if scripts := options.get('scripts'):
            args.append(f"--script={scripts}")
        
        if options.get('script_scan'):
            args.append("--script=vulners")
        
        return ' '.join(args)
    
    def _validate_ports(self, ports: str) -> bool:
        if not re.match(r'^[\d,\- ]+$', ports):
            raise ScannerError("Invalid ports format")
        return True
    
    def _parse_results(self, scan_data: Dict) -> Dict[str, Any]:
        if not scan_data['nmap']['scanstats']['uphosts']:
            return {'target': '', 'vulnerabilities': []}
        
        results = {
            'target': next(iter(scan_data['scan'])),
            'vulnerabilities': []
        }
        
        for host, host_data in scan_data['scan'].items():
            for proto in ['tcp', 'udp']:
                if proto not in host_data:
                    continue
                
                for port, port_data in host_data[proto].items():
                    if 'script' not in port_data:
                        continue

                    for vuln in self._parse_scripts(port_data['script'], port, proto):
                        results['vulnerabilities'].append(vuln)
        
        return results
    
    def _parse_scripts(self, scripts: Dict, port: int, proto: str) -> List[Dict]:
        vulns = []
        
        if 'vulners' in scripts:
            for line in scripts['vulners'].split('\n'):
                if not line.strip() or line.startswith('cpe:'):
                    continue
                
                parts = line.split()
                if len(parts) >= 3:
                    vulns.append({
                        'port': port,
                        'protocol': proto,
                        'cve_id': parts[0],
                        'severity': self._map_severity(parts[1]),
                        'cvss_score': float(parts[2]),
                        'service': parts[3] if len(parts) > 3 else 'unknown',
                        'name': f"Nmap NSE vulners: {parts[0]}",
                        'description': f"Vulnerability found by Nmap vulners script: {parts[0]}",
                        'solution': "Update affected software"
                    })
        
        return vulns
    
    def _map_severity(self, nmap_severity: str) -> str:
        severity_map = {
            '10.0': 'critical', '9.0': 'critical',
            '8.0': 'high', '7.0': 'high',
            '6.0': 'medium', '5.0': 'medium',
            '4.0': 'low', '3.0': 'low',
            '0.0': 'info'
        }
        return severity_map.get(nmap_severity, 'medium')
