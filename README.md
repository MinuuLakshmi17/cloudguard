# CloudGuard — Infrastructure-as-Code Security Posture Scanner

CloudGuard is an educational CSPM-style project that statically analyzes **Terraform plan JSON** without connecting to AWS. It produces actionable findings for risky S3, security-group, EBS/RDS, and IAM configurations, stores scan results in PostgreSQL, tracks asynchronous scan jobs in Redis, and exposes a React UI.

## Architecture
- `scanner/`: deterministic policy checks against Terraform plan JSON (`resource_changes` format).
- `backend/`: FastAPI REST API, SQLAlchemy/PostgreSQL persistence, Redis job coordination.
- `frontend/`: React + TypeScript + Vite findings dashboard.
- `examples/`: synthetic Terraform plan JSON containing intentionally vulnerable resources.
- `.github/workflows/security.yml`: CI checks for Python tests and frontend build on changes.
- `docker-compose.yml`: API, worker, PostgreSQL, Redis, and frontend.

## What it checks
- S3 bucket missing explicit server-side encryption configuration.
- S3 bucket with public ACL or public-access-block settings that allow public access.
- Security-group ingress from `0.0.0.0/0` or `::/0` on sensitive ports (SSH/RDP and broad all-port ranges).
- EBS volumes and RDS instances without encryption enabled.
- IAM policies with wildcard actions (`*`) or wildcard resources (`*`).

Severity is policy-driven: critical/high/medium/low. Findings include stable IDs, resource addresses, evidence, and a suggested remediation. Rules are intentionally small and inspect Terraform plan JSON's `planned_values` and `resource_changes` representations. Terraform plan JSON can contain secrets; do not commit real plan files or upload them to untrusted services.

## Quick start
Requirements: Docker Engine/Desktop and Docker Compose v2.

```bash
cp .env.example .env
docker compose up --build
```
- UI: http://localhost:5173
- API docs: http://localhost:8000/docs
- API health: http://localhost:8000/health

Seed and scan the sample plan:
```bash
curl -X POST http://localhost:8000/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"name":"example-vulnerable-plan","plan_path":"/app/examples/vulnerable-plan.json"}'
```
The worker reads `plan_path` inside the API/worker container. The response returns a scan ID; poll `GET /api/scans/{scan_id}`. In this demo the API and worker share the project mount.

## Local tests
```bash
python -m venv .venv
. .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt
PYTHONPATH=. pytest -q
```
The scanner tests require no cloud account, Docker, network, or credentials.

## API
- `POST /api/scans` — enqueue a scan using a local Terraform plan JSON path.
- `GET /api/scans` — list recent scans.
- `GET /api/scans/{scan_id}` — scan status and summary.
- `GET /api/findings` — filter findings by severity, status, resource type, and text query.
- `PATCH /api/findings/{finding_id}` — update remediation status.
- `POST /api/findings/{finding_id}/explain` — produce a deterministic evidence-linked explanation and Terraform remediation draft. Optional LLM provider integration is deliberately not enabled by default.
- `GET /api/summary` — counts by severity/status and recent scan activity.

## Security and scope
This is a static-analysis demo, not an AWS scanner and not a substitute for Terraform validate/plan or a commercial CSPM product. It does not assume a Terraform plan is safe to parse: run only trusted plan files in an isolated environment. The demo accepts paths under the configured plan root only. The AI endpoint currently provides deterministic, evidence-linked explanations/remediation drafts (no external LLM calls) to keep behavior reproducible and avoid sending infrastructure details to third parties.

Before production use, add authentication/authorization, tenant isolation, request rate limits, durable queue semantics, artifact retention controls, secret redaction, signed builds, and broader Terraform-provider coverage.
