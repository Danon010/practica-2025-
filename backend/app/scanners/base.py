import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class ScannerError(Exception):
    pass

class ScannerTimeoutError(ScannerError):
    pass

class ScannerNotReadyError(ScannerError):
    pass

class BaseScanner(ABC):
    
    def __init__(self, timeout: int = 3600):
        self.timeout = timeout
        self.last_scan_time: Optional[datetime] = None
    
    @abstractmethod
    def scan(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        pass
    
    def check_ready(self) -> bool:
        if self.last_scan_time and (datetime.now() - self.last_scan_time) < timedelta(seconds=60):
            raise ScannerNotReadyError("Scanner is in cooldown period")
        return True
    
    def validate_target(self, target: str) -> bool:
        if not target:
            raise ScannerError("Target cannot be empty")
        return True
    
    def _log_scan_start(self, target: str):
        logger.info(f"Starting {self.__class__.__name__} scan for target: {target}")
        self.last_scan_time = datetime.now()
