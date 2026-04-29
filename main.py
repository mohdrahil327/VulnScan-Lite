import os
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, validator
from celery.result import AsyncResult
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from scanner.utils import normalize_url
from worker import celery_app, run_scan

API_PREFIX = "/api"
DEFAULT_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

frontend_origins = os.getenv("FRONTEND_ORIGINS", ",".join(DEFAULT_ALLOWED_ORIGINS))
allow_origins = [origin.strip() for origin in frontend_origins.split(",") if origin.strip()]
allow_credentials = "*" not in allow_origins

app = FastAPI(title="VulnScan Lite API")

BASE_DIR = Path(__file__).resolve().parent
frontend_build = BASE_DIR / "frontend_build"
if frontend_build.exists():
    app.mount("/", StaticFiles(directory=str(frontend_build), html=True), name="frontend")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str

    @validator("url")
    def validate_url(cls, value: str) -> str:
        return normalize_url(value)

@app.exception_handler(RateLimitExceeded)
def rate_limit_exceeded(_: Request, exc: RateLimitExceeded):
    return PlainTextResponse(
        "Rate limit exceeded. Please wait a moment and try again.",
        status_code=429,
    )

@app.get(f"{API_PREFIX}/health")
def health_check():
    return {"status": "ok", "message": "VulnScan Lite API is running."}

@app.post(f"{API_PREFIX}/scan")
@limiter.limit("5/minute")
def start_scan(request: ScanRequest):
    try:
        task = run_scan.delay(request.url)
        return {"scan_id": task.id, "status": "QUEUED"}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Unable to enqueue scan task: {exc}")

@app.get(f"{API_PREFIX}/scan/{{scan_id}}/status")
def scan_status(scan_id: str):
    task = AsyncResult(scan_id, app=celery_app)
    state = task.state

    if state == "PENDING":
        return {"status": "QUEUED"}
    if state == "STARTED":
        return {"status": "SCANNING"}
    if state == "SUCCESS":
        return {"status": "COMPLETED"}
    if state == "FAILURE":
        return {"status": "FAILED", "error": str(task.result)}

    return {"status": state}

@app.get(f"{API_PREFIX}/result/{{scan_id}}")
def get_result(scan_id: str):
    task = AsyncResult(scan_id, app=celery_app)
    if task.state != "SUCCESS":
        raise HTTPException(status_code=404, detail="Scan result not ready")
    return task.result
