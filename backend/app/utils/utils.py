import re
from typing import Union, Dict, Any
import logging
from sqlalchemy.orm import Session
from app.database.models import ScanTask, Vulnerability
from app.scanners.factory import ScannerFactory

logger = logging.getLogger(__name__)

def validate_scan_target(target: str, is_web: bool = False) -> bool:
    if not target or not isinstance(target, str):
        return False
        
    if is_web:
        pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        return re.match(pattern, target) is not None
    else:
        pattern = r'^[\w\.\-/:,\[\] ]+$'
        return re.match(pattern, target) is not None

def check_scan_limits(user_id: int, db: Session) -> bool:
    try:
        active_scans = db.query(ScanTask).filter(
            ScanTask.user_id == user_id,
            ScanTask.status.in_(['pending', 'running'])
        ).count()
        
        max_concurrent_scans = 3
        return active_scans < max_concurrent_scans
        
    except Exception as e:
        logger.error(f"Error checking scan limits for user {user_id}: {str(e)}")
        return False

def generate_scan_report(scan_id: int, report_type: str, db: Session) -> Dict[str, Any]:
    try:
        scan = db.query(ScanTask).filter(ScanTask.id == scan_id).first()
        if not scan:
            return {"error": "Scan not found"}
        
        vulnerabilities = db.query(Vulnerability).filter(
            Vulnerability.scan_id == scan_id
        ).all()

        severity_counts = {}
        for vuln in vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
        
        report_data = {
            "scan_id": scan.id,
            "target": scan.target,
            "scan_type": scan.scan_type,
            "status": scan.status,
            "created_at": scan.created_at.isoformat(),
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            "duration": scan.duration,
            "total_vulnerabilities": len(vulnerabilities),
            "severity_counts": severity_counts,
            "vulnerabilities": [
                {
                    "id": vuln.id,
                    "cve_id": vuln.cve_id,
                    "name": vuln.name,
                    "severity": vuln.severity,
                    "cvss_score": vuln.cvss_score,
                    "description": vuln.description,
                    "solution": vuln.solution,
                    "port": vuln.port,
                    "protocol": vuln.protocol
                }
                for vuln in vulnerabilities
            ]
        }
        
        return report_data
        
    except Exception as e:
        logger.error(f"Error generating report for scan {scan_id}: {str(e)}")
        return {"error": f"Failed to generate report: {str(e)}"}

def format_scan_duration(seconds: float) -> str:
    if seconds is None:
        return "N/A"
    
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    
    if hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    elif minutes > 0:
        return f"{minutes}m {secs}s"
    else:
        return f"{secs}s"

def is_scanner_available(scanner_type: str) -> bool:
    return ScannerFactory.is_scanner_available(scanner_type)

def send_scan_notification(scan: ScanTask, message: str):

    logger.info(f"Scan {scan.id} ({scan.target}): {message}")
