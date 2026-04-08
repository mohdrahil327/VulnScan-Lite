from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
import uuid
from scanner.scan import scan_website

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
results = {}

class ScanRequest(BaseModel):
    url: str

def perform_scan(scan_id: str, url: str):
    try:
        payload = scan_website(url)
        results[scan_id] = {"status": "COMPLETED", "result": payload}
    except Exception as e:
        results[scan_id] = {"status": "FAILED", "error": str(e)}

@app.post("/scan")
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    results[scan_id] = {"status": "SCANNING", "created_at": uuid.uuid1().hex}
    background_tasks.add_task(perform_scan, scan_id, request.url)

    return {"scan_id": scan_id, "status": "SCANNING"}

@app.get("/scan/{scan_id}/status")
def scan_status(scan_id: str):
    item = results.get(scan_id)
    if not item:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    return item

@app.get("/result/{scan_id}")
def get_result(scan_id: str):
    item = results.get(scan_id)
    if not item:
        raise HTTPException(status_code=404, detail="Scan ID not found")

    if item.get("status") != "COMPLETED":
        return {"status": item.get("status"), "message": "Scan not finished yet"}

    return item.get("result")