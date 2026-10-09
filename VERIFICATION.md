# Verification report

## Checks run in this environment (2026-10-09)

- **Scanner tests: 5 passed** (`pytest -q backend/tests`). Cover expected-risk
  detection, the `resource_changes` fallback path, fingerprint stability,
  no-flag on encrypted storage, and non-object rejection.
- **Adversarial scan test:** `examples/vulnerable-plan.json` → 7 findings
  (CG-IAM-001, CG-S3-002, CG-NET-001, CG-STO-002, CG-STO-001, CG-IAM-002,
  CG-S3-001 across IAM, S3, network, storage). `examples/safe-plan.json` →
  0 findings. No false positives; fingerprints byte-stable across runs.
- **Worker path (SQLite):** simulated a scan job through `process_job` —
  scan reached `completed`, all 7 findings persisted, a remediation status
  update (`open` → `in_progress`) wrote exactly one audit event.
- **Path traversal:** `safe_plan_path` rejected `/etc/passwd` and an
  `examples/../../etc/passwd` escape. Both blocked with `ValueError`.
- **Frontend production build: verified** after fixing two real defects:
  1. `@types/react` and `@types/react-dom` were missing from
     `devDependencies`, so `tsc -b` failed on every JSX file.
  2. `tsconfig.json` targeted ES2020, but the code uses `String.replaceAll`
     (ES2021). Target and lib raised to ES2021.
  `npm run build` (`tsc -b && vite build`) now succeeds.
- **Frontend/backend contract:** API base (`/api`), nginx `/api/` →
  `api:8000/api/` proxy, scan/finding/explain endpoints, and the demo
  `plan_path` (`/app/examples/vulnerable-plan.json` under `PLAN_ROOT`)
  all agree across `App.tsx`, `nginx.conf`, `main.py`, and
  `docker-compose.yml`.

## Not verified here

- **Docker Compose run:** no container runtime is available in this
  environment. Dockerfiles and `docker-compose.yml` were reviewed by
  inspection only.
- **Redis-backed queue:** the enqueue → worker handoff through Redis was
  not exercised (no Redis server here); `process_job` was verified
  directly. The queue code path (`lpush`/`brpop`) is standard redis-py.
- **In-browser pass:** no browser test suite exists yet.
- **PostgreSQL:** the backend was exercised against SQLite via the
  `DATABASE_URL` override; the SQLAlchemy models are dialect-neutral,
  but Postgres-specific behavior was not run.

## CI

`.github/workflows/security.yml` runs the scanner tests and the frontend
production build on changes to `scanner/`, `backend/`, `frontend/`, and
`examples/`. It must be added through the GitHub web UI (the API cannot
push workflow files).
