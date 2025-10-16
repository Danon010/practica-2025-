from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database import get_db
from app.database.models import ScanTask, User, ScanStatus, ScanType, Vulnerability
from app.schemas.schemas import (
    ScanCreate, ScanOut, ScanScheduleCreate, VulnerabilityOut, ScanStats
)
from app.auth.dependencies import get_current_active_user
from app.tasks import (
    network_scan_task, web_scan_task, full_scan_task, cancel_scan_task
)
from app.utils import (
    check_scan_limits, validate_scan_target, generate_scan_report
)
from app.exceptions import (
    ScanAlreadyRunningError, InvalidTargetError, ScanLimitExceededError
)

router = APIRouter(prefix="/scans", tags=["scans"])

@router.post("/network", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
async def create_network_scan(
    scan: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    try:
        if not validate_scan_target(scan.target):
            raise InvalidTargetError("Invalid scan target")

        if not check_scan_limits(current_user.id, db):
            raise ScanLimitExceededError("Scan limit exceeded")

        db_scan = ScanTask(
            target=scan.target,
            scan_type=ScanType.NETWORK,
            status=ScanStatus.PENDING,
            options=scan.options,
            user_id=current_user.id
        )
        db.add(db_scan)
        db.commit()
        db.refresh(db_scan)

        background_tasks.add_task(
            network_scan_task,
            scan_id=db_scan.id,
            target=scan.target,
            options=scan.options,
            user_id=current_user.id
        )
        
        return db_scan
    
    except InvalidTargetError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    except ScanLimitExceededError as e:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e)
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error starting scan: {str(e)}"
        )

@router.post("/web", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
async def create_web_scan(
    scan: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    try:
        if not validate_scan_target(scan.target, is_web=True):
            raise InvalidTargetError("Invalid web target")
        
        if not check_scan_limits(current_user.id, db):
            raise ScanLimitExceededError("Scan limit exceeded")
        
        db_scan = ScanTask(
            target=scan.target,
            scan_type=ScanType.WEB,
            status=ScanStatus.PENDING,
            options=scan.options,
            user_id=current_user.id
        )
        db.add(db_scan)
        db.commit()
        db.refresh(db_scan)
        
        background_tasks.add_task(
            web_scan_task,
            scan_id=db_scan.id,
            target=scan.target,
            options=scan.options,
            user_id=current_user.id
        )
        
        return db_scan
    
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error starting web scan: {str(e)}"
        )

@router.post("/full", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
async def create_full_scan(
    scan: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    try:
        if not validate_scan_target(scan.target):
            raise InvalidTargetError("Invalid target")
        
        if not check_scan_limits(current_user.id, db):
            raise ScanLimitExceededError("Scan limit exceeded")
        
        db_scan = ScanTask(
            target=scan.target,
            scan_type=ScanType.FULL,
            status=ScanStatus.PENDING,
            options=scan.options,
            user_id=current_user.id
        )
        db.add(db_scan)
        db.commit()
        db.refresh(db_scan)
        
        background_tasks.add_task(
            full_scan_task,
            scan_id=db_scan.id,
            target=scan.target,
            options=scan.options,
            user_id=current_user.id
        )
        
        return db_scan
    
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error starting full scan: {str(e)}"
        )

@router.get("/", response_model=List[ScanOut])
async def list_scans(
    skip: int = 0,
    limit: int = 100,
    scan_type: Optional[ScanType] = None,
    status: Optional[ScanStatus] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    query = db.query(ScanTask).filter(ScanTask.user_id == current_user.id)
    
    if scan_type:
        query = query.filter(ScanTask.scan_type == scan_type)
    
    if status:
        query = query.filter(ScanTask.status == status)
    
    scans = query.order_by(ScanTask.created_at.desc()).offset(skip).limit(limit).all()
    return scans

@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    scan = db.query(ScanTask).filter(
        ScanTask.id == scan_id,
        ScanTask.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    return scan

@router.get("/{scan_id}/vulnerabilities", response_model=List[VulnerabilityOut])
async def get_scan_vulnerabilities(
    scan_id: int,
    severity: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    scan = db.query(ScanTask).filter(
        ScanTask.id == scan_id,
        ScanTask.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    query = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id)
    
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    
    vulnerabilities = query.order_by(
        Vulnerability.cvss_score.desc()
    ).offset(skip).limit(limit).all()
    
    return vulnerabilities

@router.post("/{scan_id}/cancel", response_model=ScanOut)
async def cancel_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    scan = db.query(ScanTask).filter(
        ScanTask.id == scan_id,
        ScanTask.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.status not in [ScanStatus.PENDING, ScanStatus.RUNNING]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot cancel scan in current status"
        )
    
    try:
        cancel_scan_task.delay(scan.task_id)

        scan.status = ScanStatus.CANCELLED
        scan.finished_at = datetime.utcnow()
        db.commit()
        db.refresh(scan)
        
        return scan
    
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error cancelling scan: {str(e)}"
        )

@router.get("/{scan_id}/stats", response_model=ScanStats)
async def get_scan_stats(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    scan = db.query(ScanTask).filter(
        ScanTask.id == scan_id,
        ScanTask.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    severity_counts = db.query(
        Vulnerability.severity,
        db.func.count(Vulnerability.id)
    ).filter(
        Vulnerability.scan_id == scan_id
    ).group_by(Vulnerability.severity).all()
    
    stats = {
        "scan_id": scan.id,
        "total_vulnerabilities": db.query(Vulnerability).filter(
            Vulnerability.scan_id == scan_id
        ).count(),
        "severity_counts": dict(severity_counts),
        "duration": scan.duration,
        "status": scan.status.value
    }
    
    return stats

@router.post("/schedules", response_model=ScanOut)
async def create_scan_schedule(
    schedule: ScanScheduleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    try:
        if not validate_scan_target(schedule.target, is_web=(schedule.scan_type == ScanType.WEB)):
            raise InvalidTargetError("Invalid target")
        
        db_schedule = ScanTask(
            target=schedule.target,
            scan_type=schedule.scan_type,
            status=ScanStatus.PENDING,
            user_id=current_user.id
        )
        db.add(db_schedule)
        db.commit()
        db.refresh(db_schedule)
        
        return db_schedule
    
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating schedule: {str(e)}"
        )

@router.get("/{scan_id}/report")
async def generate_scan_report_endpoint(
    scan_id: int,
    report_type: str = "json",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    scan = db.query(ScanTask).filter(
        ScanTask.id == scan_id,
        ScanTask.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    try:
        report_content = generate_scan_report(scan_id, report_type, db)
        
        return JSONResponse(
            content={
                "scan_id": scan_id,
                "report_type": report_type,
                "content": report_content
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error generating report: {str(e)}"
        )
