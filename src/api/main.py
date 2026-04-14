import json
import os
import uuid
import asyncio
import time
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import tempfile
import shutil
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

app = FastAPI(title="CryptoGuard API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory scan store — replace with SQLite for production
SCANS = {}
RESULTS_DIR = Path(__file__).parent.parent.parent / "results" / "scans"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


class ScanStatus:
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETE  = "complete"
    FAILED    = "failed"


def save_scan(scan_id: str, data: dict):
    SCANS[scan_id] = data
    with open(RESULTS_DIR / f"{scan_id}.json", "w") as f:
        json.dump(data, f, indent=2)


def load_scans():
    """Load persisted scans from disk on startup."""
    for f in sorted(RESULTS_DIR.glob("*.json"), key=os.path.getmtime, reverse=True)[:50]:
        try:
            with open(f) as fp:
                data = json.load(fp)
                SCANS[data["id"]] = data
        except Exception:
            pass


def run_analysis(scan_id: str, target_path: str, hybrid: bool = True):
    """Run CryptoGuard analysis in background."""
    try:
        SCANS[scan_id]["status"] = ScanStatus.RUNNING
        SCANS[scan_id]["started_at"] = time.time()
        save_scan(scan_id, SCANS[scan_id])

        from src.parser.code_parser import (
            extract_snippets_from_file,
            extract_snippets_from_dir,
        )
        from src.analyzer.llm_engine import analyze_snippet, set_hybrid

        set_hybrid(hybrid)

        # Extract snippets
        if os.path.isfile(target_path):
            snippets = extract_snippets_from_file(target_path)
        else:
            snippets = extract_snippets_from_dir(target_path)

        total = len(snippets)
        SCANS[scan_id]["total_snippets"] = total
        SCANS[scan_id]["analyzed"]       = 0
        save_scan(scan_id, SCANS[scan_id])

        all_findings = []
        for i, snippet in enumerate(snippets, 1):
            findings = analyze_snippet(snippet)
            all_findings.extend(findings)
            SCANS[scan_id]["analyzed"] = i
            SCANS[scan_id]["findings"] = all_findings
            save_scan(scan_id, SCANS[scan_id])

        SCANS[scan_id]["status"]       = ScanStatus.COMPLETE
        SCANS[scan_id]["completed_at"] = time.time()
        SCANS[scan_id]["findings"]     = all_findings
        save_scan(scan_id, SCANS[scan_id])

    except Exception as e:
        SCANS[scan_id]["status"] = ScanStatus.FAILED
        SCANS[scan_id]["error"]  = str(e)
        save_scan(scan_id, SCANS[scan_id])


# ── API routes ────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    load_scans()


@app.post("/api/scan")
async def create_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    hybrid: bool = True,
):
    """Upload a .java, .kt, or .zip file and start a scan."""
    scan_id  = str(uuid.uuid4())[:8]
    filename = file.filename or "upload"
    ext      = Path(filename).suffix.lower()

    if ext not in (".java", ".kt", ".zip"):
        raise HTTPException(400, "Only .java, .kt, or .zip files are supported")

    # Save uploaded file to temp directory
    tmp_dir  = Path(tempfile.mkdtemp())
    tmp_file = tmp_dir / filename
    with open(tmp_file, "wb") as f:
        shutil.copyfileobj(file.file, f)

    # Unzip if needed
    if ext == ".zip":
        import zipfile
        extract_dir = tmp_dir / "extracted"
        extract_dir.mkdir()
        with zipfile.ZipFile(tmp_file) as zf:
            zf.extractall(extract_dir)
        target = str(extract_dir)
    else:
        target = str(tmp_file)

    # Create scan record
    scan = {
        "id":             scan_id,
        "filename":       filename,
        "status":         ScanStatus.PENDING,
        "hybrid":         hybrid,
        "created_at":     time.time(),
        "total_snippets": 0,
        "analyzed":       0,
        "findings":       [],
        "error":          None,
    }
    save_scan(scan_id, scan)

    # Run in background
    background_tasks.add_task(run_analysis, scan_id, target, hybrid)

    return {"scan_id": scan_id, "status": ScanStatus.PENDING}


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    """Get scan status and results."""
    if scan_id not in SCANS:
        raise HTTPException(404, "Scan not found")
    return SCANS[scan_id]


@app.get("/api/scan/{scan_id}/stream")
async def stream_scan(scan_id: str):
    """Server-Sent Events stream for real-time progress."""
    async def event_generator():
        while True:
            if scan_id not in SCANS:
                yield "data: {\"error\": \"not found\"}\n\n"
                break
            scan = SCANS[scan_id]
            data = json.dumps({
                "status":         scan["status"],
                "analyzed":       scan.get("analyzed", 0),
                "total_snippets": scan.get("total_snippets", 0),
                "findings_count": len(scan.get("findings", [])),
            })
            yield f"data: {data}\n\n"
            if scan["status"] in (ScanStatus.COMPLETE, ScanStatus.FAILED):
                break
            await asyncio.sleep(1)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/scans")
async def list_scans():
    """List recent scans."""
    scans = sorted(SCANS.values(), key=lambda s: s.get("created_at", 0), reverse=True)
    return [
        {
            "id":             s["id"],
            "filename":       s.get("filename", ""),
            "status":         s["status"],
            "created_at":     s.get("created_at", 0),
            "findings_count": len(s.get("findings", [])),
            "critical":       sum(1 for f in s.get("findings", []) if f.get("severity") == "CRITICAL"),
        }
        for s in scans[:20]
    ]


@app.post("/api/results")
async def receive_results(payload: dict):
    """
    Receive scan results from GitLab CI or external sources.
    GitLab CI job POSTs results here after running cryptoguard CLI.
    """
    scan_id = payload.get("scan_id", str(uuid.uuid4())[:8])
    scan = {
        "id":             scan_id,
        "filename":       payload.get("filename", "ci-scan"),
        "status":         ScanStatus.COMPLETE,
        "hybrid":         payload.get("hybrid", True),
        "created_at":     payload.get("timestamp", time.time()),
        "total_snippets": payload.get("total_snippets", 0),
        "analyzed":       payload.get("total_snippets", 0),
        "findings":       payload.get("findings", []),
        "source":         payload.get("source", "api"),
        "gitlab_project": payload.get("gitlab_project", ""),
        "gitlab_branch":  payload.get("gitlab_branch", ""),
        "gitlab_commit":  payload.get("gitlab_commit", ""),
        "error":          None,
    }
    save_scan(scan_id, scan)
    return {"scan_id": scan_id, "status": "received"}


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


# Serve dashboard
@app.get("/", response_class=HTMLResponse)
async def dashboard():
    index = Path(__file__).parent / "static" / "index.html"
    if index.exists():
        return HTMLResponse(index.read_text())
    return HTMLResponse("<h1>Dashboard not found</h1>")


app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")