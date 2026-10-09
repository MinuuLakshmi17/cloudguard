import os, uuid
from datetime import datetime, timezone
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from .db import Base, engine, get_db
from .models import Scan, FindingRecord, AuditEvent
from .schemas import ScanRequest, FindingStatusUpdate, ExplainResponse
from .jobs import enqueue_scan, redis_client, safe_plan_path

Base.metadata.create_all(bind=engine)
app = FastAPI(title="CloudGuard API", version="1.0.0", description="Terraform plan JSON static analysis and finding management.")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])

@app.get("/health")
def health():
    return {"status": "ok"}

def scan_out(s: Scan):
    return {"id": s.id, "name": s.name, "status": s.status, "created_at": s.created_at,
            "completed_at": s.completed_at, "error": s.error}

def finding_out(f: FindingRecord):
    return {"id": f.id, "scan_id": f.scan_id, "rule_id": f.rule_id, "title": f.title,
            "severity": f.severity, "resource_address": f.resource_address, "resource_type": f.resource_type,
            "evidence": f.evidence, "remediation": f.remediation, "status": f.status, "created_at": f.created_at}

@app.post("/api/scans", status_code=202)
def create_scan(payload: ScanRequest, db: Session = Depends(get_db)):
    try:
        safe_plan_path(payload.plan_path)
        scan_id = enqueue_scan(payload.name, payload.plan_path)
        return {"scan_id": scan_id, "status": "queued"}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Unable to enqueue scan: {type(exc).__name__}")

@app.get("/api/scans")
def list_scans(limit: int = Query(20, ge=1, le=100), db: Session = Depends(get_db)):
    scans = db.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(limit)).all()
    return [scan_out(s) for s in scans]

@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    count = db.scalar(select(func.count()).select_from(FindingRecord).where(FindingRecord.scan_id == scan_id)) or 0
    return {**scan_out(scan), "finding_count": count}

@app.get("/api/findings")
def list_findings(severity: str | None = None, status: str | None = None, resource_type: str | None = None,
                  q: str | None = None, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                  db: Session = Depends(get_db)):
    stmt = select(FindingRecord)
    if severity:
        stmt = stmt.where(FindingRecord.severity == severity.lower())
    if status:
        stmt = stmt.where(FindingRecord.status == status.lower())
    if resource_type:
        stmt = stmt.where(FindingRecord.resource_type == resource_type)
    if q:
        pattern = f"%{q}%"
        stmt = stmt.where((FindingRecord.title.ilike(pattern)) | (FindingRecord.resource_address.ilike(pattern)) | (FindingRecord.evidence.ilike(pattern)))
    rows = db.scalars(stmt.order_by(FindingRecord.created_at.desc()).offset(offset).limit(limit)).all()
    return [finding_out(f) for f in rows]

@app.patch("/api/findings/{finding_id}")
def update_finding(finding_id: str, payload: FindingStatusUpdate, db: Session = Depends(get_db)):
    finding = db.get(FindingRecord, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    old = finding.status
    finding.status = payload.status
    db.add(AuditEvent(finding_id=finding_id, action="status_changed", details={"from": old, "to": payload.status}))
    db.commit()
    db.refresh(finding)
    return finding_out(finding)

@app.post("/api/findings/{finding_id}/explain", response_model=ExplainResponse)
def explain_finding(finding_id: str, db: Session = Depends(get_db)):
    finding = db.get(FindingRecord, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    return ExplainResponse(finding_id=finding.id,
        explanation=f"{finding.title}. This assessment is based on the Terraform plan evidence recorded for resource {finding.resource_address}. Review the planned configuration and confirm whether the exposure is required.",
        evidence=finding.evidence, proposed_fix=finding.remediation, requires_approval=True)

@app.get("/api/summary")
def summary(db: Session = Depends(get_db)):
    total = db.scalar(select(func.count()).select_from(FindingRecord)) or 0
    severities = {s: db.scalar(select(func.count()).select_from(FindingRecord).where(FindingRecord.severity == s)) or 0 for s in ["critical","high","medium","low"]}
    statuses = {s: db.scalar(select(func.count()).select_from(FindingRecord).where(FindingRecord.status == s)) or 0 for s in ["open","in_progress","accepted_risk","resolved"]}
    return {"total_findings": total, "by_severity": severities, "by_status": statuses}
