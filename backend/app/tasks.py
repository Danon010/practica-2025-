import time
import logging
from celery import Celery
from celery.exceptions import Reject
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Dict, Any

from app.database import SessionLocal
from app.database.models import ScanTask, Vulnerability, ScanStatus
from app.config import settings
from app.scanners.factory import ScannerFactory
from app.utils import send_scan_notification
from app.exceptions import ScanAlreadyRunningError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

celery = Celery(
    'tasks',
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)

celery.conf.update(
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_track_started=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
    task_routes={
        'scan.network': {'queue': 'scans'},
        'scan.web': {'queue': 'scans'},
        'scan.full': {'queue': 'scans'},
        'scan.cancel': {'queue': 'control'},
    }
)

class ScanTaskBase(celery.Task):
    autoretry_for = (Exception,)
    retry_backoff = True
    retry_backoff_max = 700
    retry_kwargs = {'max_retries': 3}
    max_retries = 3

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        scan_id = args[0] if args else kwargs.get('scan_id')
        db = SessionLocal()
        try:
            scan = db.query(ScanTask).filter(ScanTask.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.FAILED
                scan.finished_at = datetime.utcnow()
                db.commit()
                logger.error(f"Scan {scan_id} failed: {str(exc)}")
                send_scan_notification(scan, f"Scan failed: {str(exc)}")
        except Exception as e:
            logger.error(f"Error updating failed scan {scan_id}: {str(e)}")
        finally:
            db.close()

    def on_success(self, retval, task_id, args, kwargs):
        scan_id = args[0] if args else kwargs.get('scan_id')
        db = SessionLocal()
        try:
            scan = db.query(ScanTask).filter(ScanTask.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.finished_at = datetime.utcnow()
                db.commit()
                logger.info(f"Scan {scan_id} completed successfully")
                send_scan_notification(scan, "Scan completed successfully")
        except Exception as e:
            logger.error(f"Error updating completed scan {scan_id}: {str(e)}")
        finally:
            db.close()

@celery.task(base=ScanTaskBase, bind=True, name='scan.network')
def network_scan_task(self, scan_id: int, target: str, options: Dict[str, Any] = None, user_id: int = None):
    db = SessionLocal()
    scan = None
    try:
        options = options or {}
        scan = db.query(ScanTask).filter(ScanTask.id == scan_id).first()
        
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            raise Reject(f"Scan {scan_id} not found", requeue=False)
        
        if scan.status != ScanStatus.PENDING:
            raise ScanAlreadyRunningError(f"Scan {scan_id} is already running")

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.utcnow()
        db.commit()
        
        logger.info(f"Starting network scan for target: {target}")

        scanner = ScannerFactory.create_scanner('nmap')
        results = scanner.scan(target, options)

        for vuln in results.get('vulnerabilities', []):
            db_vuln = Vulnerability(
                scan_id=scan.id,
                cve_id=vuln.get('cve_id', 'N/A'),
                name=vuln.get('name', 'Unknown'),
                description=vuln.get('description', 'No description'),
                severity=vuln.get('severity', 'info'),
                cvss_score=vuln.get('cvss_score', 0.0),
                cvss_vector=vuln.get('cvss_vector', ''),
                port=vuln.get('port'),
                protocol=vuln.get('protocol', 'tcp'),
                solution=vuln.get('solution', 'No solution provided'),
                references=vuln.get('references', [])
            )
            db.add(db_vuln)
        
        db.commit()
        return {
            "status": "completed", 
            "found_vulnerabilities": len(results.get('vulnerabilities', [])),
            "scan_id": scan_id
        }
    
    except Exception as e:
        logger.error(f"Error during network scan: {str(e)}", exc_info=True)
        if scan:
            scan.status = ScanStatus.FAILED
            scan.finished_at = datetime.utcnow()
            db.commit()
        raise
    
    finally:
        db.close()

@celery.task(base=ScanTaskBase, bind=True, name='scan.web')
def web_scan_task(self, scan_id: int, target: str, options: Dict[str, Any] = None, user_id: int = None):
    db = SessionLocal()
    scan = None
    try:
        options = options or {}
        scan = db.query(ScanTask).filter(ScanTask.id == scan_id).first()
        
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            raise Reject(f"Scan {scan_id} not found", requeue=False)

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.utcnow()
        db.commit()
        
        logger.info(f"Starting web scan for target: {target}")

        scanner = ScannerFactory.create_scanner('zap')
        results = scanner.scan(target, options)

        for vuln in results.get('vulnerabilities', []):
            db_vuln = Vulnerability(
                scan_id=scan.id,
                cve_id=vuln.get('cve_id', 'N/A'),
                name=vuln.get('name', 'Unknown'),
                description=vuln.get('description', 'No description'),
                severity=vuln.get('severity', 'info'),
                cvss_score=vuln.get('cvss_score', 0.0),
                solution=vuln.get('solution', 'No solution provided'),
                references=vuln.get('references', [])
            )
            db.add(db_vuln)
        
        db.commit()
        return {
            "status": "completed", 
            "found_vulnerabilities": len(results.get('vulnerabilities', [])),
            "scan_id": scan_id
        }
    
    except Exception as e:
        logger.error(f"Error during web scan: {str(e)}", exc_info=True)
        if scan:
            scan.status = ScanStatus.FAILED
            scan.finished_at = datetime.utcnow()
            db.commit()
        raise
    
    finally:
        db.close()

@celery.task(base=ScanTaskBase, bind=True, name='scan.full')
def full_scan_task(self, scan_id: int, target: str, options: Dict[str, Any] = None, user_id: int = None):
    db = SessionLocal()
    scan = None
    try:
        options = options or {}
        scan = db.query(ScanTask).filter(ScanTask.id == scan_id).first()
        
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            raise Reject(f"Scan {scan_id} not found", requeue=False)

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.utcnow()
        db.commit()
        
        logger.info(f"Starting full scan for target: {target}")

        scanner = ScannerFactory.create_scanner('openvas')
        results = scanner.scan(target, options)

        for vuln in results.get('vulnerabilities', []):
            db_vuln = Vulnerability(
                scan_id=scan.id,
                cve_id=vuln.get('cve_id', 'N/A'),
                name=vuln.get('name', 'Unknown'),
                description=vuln.get('description', 'No description'),
                severity=vuln.get('severity', 'info'),
                cvss_score=vuln.get('cvss_score', 0.0),
                cvss_vector=vuln.get('cvss_vector', ''),
                port=vuln.get('port', 'general'),
                solution=vuln.get('solution', 'No solution provided'),
                references=vuln.get('references', [])
            )
            db.add(db_vuln)
        
        db.commit()
        return {
            "status": "completed", 
            "found_vulnerabilities": len(results.get('vulnerabilities', [])),
            "scan_id": scan_id
        }
    
    except Exception as e:
        logger.error(f"Error during full scan: {str(e)}", exc_info=True)
        if scan:
            scan.status = ScanStatus.FAILED
            scan.finished_at = datetime.utcnow()
            db.commit()
        raise
    
    finally:
        db.close()

@celery.task(name='scan.cancel')
def cancel_scan_task(scan_task_id: str):
    """Отмена сканирования"""
    try:
        logger.info(f"Cancelling scan task: {scan_task_id}")

        celery.control.revoke(scan_task_id, terminate=True)
        
        return {"status": "cancelled", "task_id": scan_task_id}
    except Exception as e:
        logger.error(f"Error cancelling scan task: {str(e)}")
        raise

@celery.task(name='scans.monitor')
def monitor_scans():
    """Мониторинг зависших сканирований"""
    db = SessionLocal()
    try:
        timeout = datetime.utcnow() - timedelta(hours=2)
        stuck_scans = db.query(ScanTask).filter(
            ScanTask.status == ScanStatus.RUNNING,
            ScanTask.started_at < timeout
        ).all()
        
        for scan in stuck_scans:
            logger.warning(f"Found stuck scan: {scan.id}")
            scan.status = ScanStatus.FAILED
            scan.finished_at = datetime.utcnow()
            db.commit()
            send_scan_notification(scan, "Scan was stuck and marked as failed")
        
        return {"checked_scans": len(stuck_scans), "stuck_scans": [s.id for s in stuck_scans]}
    except Exception as e:
        logger.error(f"Error monitoring scans: {str(e)}")
        return {"error": str(e)}
    finally:
        db.close()

@celery.task(name='scans.cleanup')
def cleanup_old_scans(days: int = 30):
    db = SessionLocal()
    try:
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        old_scans = db.query(ScanTask).filter(
            ScanTask.status.in_([ScanStatus.COMPLETED, ScanStatus.FAILED]),
            ScanTask.finished_at < cutoff_date
        ).all()
        
        deleted = 0
        for scan in old_scans:
            db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).delete()
            db.delete(scan)
            deleted += 1
        
        db.commit()
        return {"deleted_scans": deleted}
    except Exception as e:
        logger.error(f"Error cleaning up old scans: {str(e)}")
        return {"error": str(e)}
    finally:
        db.close()

@celery.task(name='scanners.health_check')
def scanners_health_check():
    try:
        available_scanners = ScannerFactory.get_available_scanners()
        health_status = {}
        
        for scanner_type in ['nmap', 'zap', 'openvas']:
            health_status[scanner_type] = ScannerFactory.is_scanner_available(scanner_type)
        
        return {
            "status": "healthy" if any(health_status.values()) else "degraded",
            "available_scanners": available_scanners,
            "health_status": health_status
        }
    except Exception as e:
        logger.error(f"Error in scanners health check: {str(e)}")
        return {"status": "error", "error": str(e)}
