import json, os, uuid
import redis
from .db import SessionLocal
from .models import Scan, FindingRecord
from scanner.terraform_plan import scan_file

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
PLAN_ROOT = os.path.realpath(os.getenv("PLAN_ROOT", "examples"))
QUEUE_KEY = "cloudguard:scan-queue"

def redis_client():
    return redis.Redis.from_url(REDIS_URL, decode_responses=True)

def safe_plan_path(path: str) -> str:
    real = os.path.realpath(path)
    if os.path.commonpath([PLAN_ROOT, real]) != PLAN_ROOT:
        raise ValueError("plan_path must point inside the configured PLAN_ROOT")
    if not os.path.isfile(real) or not real.lower().endswith(".json"):
        raise ValueError("plan_path must be an existing JSON file inside PLAN_ROOT")
    return real

def enqueue_scan(name: str, plan_path: str) -> str:
    plan_path = safe_plan_path(plan_path)
    scan_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Scan(id=scan_id, name=name, status="queued"))
        db.commit()
    redis_client().lpush(QUEUE_KEY, json.dumps({"scan_id": scan_id, "plan_path": plan_path}))
    return scan_id

def process_job(job: dict) -> None:
    with SessionLocal() as db:
        scan = db.get(Scan, job["scan_id"])
        if not scan:
            return
        scan.status = "running"
        db.commit()
        try:
            findings = scan_file(safe_plan_path(job["plan_path"]))
            for f in findings:
                db.add(FindingRecord(id=f.fingerprint, scan_id=scan.id, rule_id=f.rule_id,
                    title=f.title, severity=f.severity, resource_address=f.resource_address,
                    resource_type=f.resource_type, evidence=f.evidence, remediation=f.remediation,
                    status="open"))
            scan.status = "completed"
            from .models import now_utc
            scan.completed_at = now_utc()
            db.commit()
        except Exception as exc:
            db.rollback()
            scan = db.get(Scan, job["scan_id"])
            if scan:
                scan.status = "failed"
                scan.error = str(exc)[:1000]
                db.commit()

def work_once(block: int = 2) -> bool:
    client = redis_client()
    item = client.brpop(QUEUE_KEY, timeout=block)
    if not item:
        return False
    _, raw = item
    process_job(json.loads(raw))
    return True
