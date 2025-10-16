from typing import Optional
from .nmap_scanner import NmapScanner
from .zap_scanner import ZapScanner
from .openvas_scanner import OpenVASScanner
from .base import BaseScanner
from app.config import settings

class ScannerFactory:
    
    @staticmethod
    def create_scanner(scanner_type: str) -> BaseScanner:
        scanner_type = scanner_type.lower()
        
        if scanner_type == 'nmap':
            return NmapScanner(timeout=settings.NMAP_TIMEOUT)
        
        elif scanner_type == 'zap':
            if not settings.ZAP_API_KEY:
                raise ValueError("ZAP_API_KEY not configured")
            return ZapScanner(
                api_key=settings.ZAP_API_KEY,
                proxy=settings.ZAP_PROXY,
                timeout=settings.ZAP_TIMEOUT
            )
        
        elif scanner_type == 'openvas':
            return OpenVASScanner(
                username=settings.OPENVAS_USERNAME,
                password=settings.OPENVAS_PASSWORD,
                host=settings.OPENVAS_HOST,
                port=settings.OPENVAS_PORT,
                timeout=settings.OPENVAS_TIMEOUT
            )
        
        raise ValueError(f"Unknown scanner type: {scanner_type}")

    @staticmethod
    def get_available_scanners():
        available = ['nmap']

        try:
            import requests
            response = requests.get('http://localhost:8080/JSON/core/view/version/', timeout=5)
            if response.status_code == 200:
                available.append('zap')
        except:
            pass
            
        return available
            
    @staticmethod
    def is_scanner_available(scanner_type: str) -> bool:
        try:
            scanner = ScannerFactory.create_scanner(scanner_type)
            return True
        except (ValueError, Exception):
            return False
