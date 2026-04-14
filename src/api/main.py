import json
import os
import uuid
import asyncio
import time
import sqlite3
from pathlib import Path
from contextlib import contextmanager
from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
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

# ── DATABASE ──────────────────────────────────────────────────────────────────

DB_PATH = Path(__file__).parent.parent.parent / "results" / "cryptoguard.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# In-memory cache for running scans (SSE needs fast access)
SCANS_CACHE = {}


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id            TEXT PRIMARY KEY,
                filename      TEXT NOT NULL,
                status        TEXT NOT NULL DEFAULT 'pending',
                hybrid        INTEGER NOT NULL DEFAULT 1,
                source        TEXT DEFAULT 'upload',
                gitlab_project TEXT DEFAULT '',
                gitlab_branch  TEXT DEFAULT '',
                gitlab_commit  TEXT DEFAULT '',
                total_snippets INTEGER DEFAULT 0,
                analyzed       INTEGER DEFAULT 0,
                error          TEXT,
                created_at     REAL NOT NULL,
                started_at     REAL,
                completed_at   REAL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                cwe_id      TEXT NOT NULL,
                severity    TEXT NOT NULL,
                confidence  TEXT,
                explanation TEXT,
                fix_code    TEXT,
                file        TEXT,
                method      TEXT,
                start_line  INTEGER,
                line_hint   INTEGER,
                model       TEXT,
                created_at  REAL NOT NULL
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan  ON findings(scan_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_findings_sev   ON findings(severity)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_findings_cwe   ON findings(cwe_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_scans_created  ON scans(created_at DESC)")
        # Clean up scans left running/pending from a previous server crash
        db.execute("""
            UPDATE scans SET status='failed', error='Server restarted during scan'
            WHERE status IN ('running', 'pending')
        """)


class ScanStatus:
    PENDING  = "pending"
    RUNNING  = "running"
    COMPLETE = "complete"
    FAILED   = "failed"


# ── DB HELPERS ────────────────────────────────────────────────────────────────

def db_insert_scan(scan: dict):
    with get_db() as db:
        db.execute("""
            INSERT OR REPLACE INTO scans
              (id, filename, status, hybrid, source, gitlab_project,
               gitlab_branch, gitlab_commit, total_snippets, analyzed,
               error, created_at, started_at, completed_at)
            VALUES
              (:id, :filename, :status, :hybrid, :source, :gitlab_project,
               :gitlab_branch, :gitlab_commit, :total_snippets, :analyzed,
               :error, :created_at, :started_at, :completed_at)
        """, {
            "id":             scan["id"],
            "filename":       scan.get("filename", ""),
            "status":         scan.get("status", ScanStatus.PENDING),
            "hybrid":         int(scan.get("hybrid", True)),
            "source":         scan.get("source", "upload"),
            "gitlab_project": scan.get("gitlab_project", ""),
            "gitlab_branch":  scan.get("gitlab_branch", ""),
            "gitlab_commit":  scan.get("gitlab_commit", ""),
            "total_snippets": scan.get("total_snippets", 0),
            "analyzed":       scan.get("analyzed", 0),
            "error":          scan.get("error"),
            "created_at":     scan.get("created_at", time.time()),
            "started_at":     scan.get("started_at"),
            "completed_at":   scan.get("completed_at"),
        })


def db_update_scan(scan_id: str, **kwargs):
    if not kwargs:
        return
    sets = ", ".join(f"{k} = :{k}" for k in kwargs)
    kwargs["scan_id"] = scan_id
    with get_db() as db:
        db.execute(f"UPDATE scans SET {sets} WHERE id = :scan_id", kwargs)


def db_insert_findings(scan_id: str, findings: list):
    if not findings:
        return
    rows = []
    now = time.time()
    for f in findings:
        rows.append((
            scan_id,
            f.get("cwe_id", ""),
            f.get("severity", ""),
            f.get("confidence", ""),
            f.get("explanation", ""),
            f.get("fix_code", ""),
            f.get("file", ""),
            f.get("method", ""),
            f.get("start_line"),
            f.get("line_hint"),
            f.get("model", ""),
            now,
        ))
    with get_db() as db:
        db.executemany("""
            INSERT INTO findings
              (scan_id, cwe_id, severity, confidence, explanation,
               fix_code, file, method, start_line, line_hint, model, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, rows)


def db_get_scan(scan_id: str) -> dict | None:
    with get_db() as db:
        row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        scan = dict(row)
        scan["hybrid"] = bool(scan["hybrid"])
        findings = db.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY severity, cwe_id",
            (scan_id,)
        ).fetchall()
        scan["findings"] = [dict(f) for f in findings]
        return scan


def db_list_scans(limit: int = 20) -> list:
    with get_db() as db:
        rows = db.execute("""
            SELECT s.*,
              COUNT(f.id)                                          AS findings_count,
              SUM(CASE WHEN f.severity='CRITICAL' THEN 1 ELSE 0 END) AS critical,
              SUM(CASE WHEN f.severity='HIGH'     THEN 1 ELSE 0 END) AS high
            FROM scans s
            LEFT JOIN findings f ON f.scan_id = s.id
            GROUP BY s.id
            ORDER BY s.created_at DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]


def db_delete_findings(scan_id: str):
    with get_db() as db:
        db.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))


# ── ANALYSIS ──────────────────────────────────────────────────────────────────

def run_analysis(scan_id: str, target_path: str, hybrid: bool = True):
    try:
        SCANS_CACHE[scan_id]["status"]     = ScanStatus.RUNNING
        SCANS_CACHE[scan_id]["started_at"] = time.time()
        db_update_scan(scan_id, status=ScanStatus.RUNNING, started_at=time.time())

        from src.parser.code_parser import (
            extract_snippets_from_file,
            extract_snippets_from_dir,
        )
        from src.analyzer.llm_engine import analyze_snippet, set_hybrid

        set_hybrid(hybrid)

        snippets = (
            extract_snippets_from_file(target_path)
            if os.path.isfile(target_path)
            else extract_snippets_from_dir(target_path)
        )

        total = len(snippets)
        SCANS_CACHE[scan_id]["total_snippets"] = total
        SCANS_CACHE[scan_id]["analyzed"]       = 0
        db_update_scan(scan_id, total_snippets=total, analyzed=0)

        all_findings = []
        for i, snippet in enumerate(snippets, 1):
            findings = analyze_snippet(snippet)
            all_findings.extend(findings)
            SCANS_CACHE[scan_id]["analyzed"]       = i
            SCANS_CACHE[scan_id]["findings_count"] = len(all_findings)

        # Persist findings to DB
        db_delete_findings(scan_id)
        db_insert_findings(scan_id, all_findings)
        db_update_scan(
            scan_id,
            status=ScanStatus.COMPLETE,
            analyzed=total,
            completed_at=time.time(),
        )
        SCANS_CACHE[scan_id]["status"] = ScanStatus.COMPLETE

    except Exception as e:
        SCANS_CACHE[scan_id]["status"] = ScanStatus.FAILED
        SCANS_CACHE[scan_id]["error"]  = str(e)
        db_update_scan(scan_id, status=ScanStatus.FAILED, error=str(e))


# ── API ROUTES ────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    init_db()


@app.post("/api/scan")
async def create_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    hybrid: bool = True,
):
    scan_id  = str(uuid.uuid4())[:8]
    filename = file.filename or "upload"
    ext      = Path(filename).suffix.lower()

    if ext not in (".java", ".kt", ".zip"):
        raise HTTPException(400, "Only .java, .kt, or .zip files are supported")

    tmp_dir  = Path(tempfile.mkdtemp())
    tmp_file = tmp_dir / filename
    with open(tmp_file, "wb") as f:
        shutil.copyfileobj(file.file, f)

    if ext == ".zip":
        import zipfile
        extract_dir = tmp_dir / "extracted"
        extract_dir.mkdir()
        with zipfile.ZipFile(tmp_file) as zf:
            zf.extractall(extract_dir)
        target = str(extract_dir)
    else:
        target = str(tmp_file)

    scan = {
        "id":             scan_id,
        "filename":       filename,
        "status":         ScanStatus.PENDING,
        "hybrid":         hybrid,
        "source":         "upload",
        "created_at":     time.time(),
        "total_snippets": 0,
        "analyzed":       0,
        "findings_count": 0,
        "error":          None,
    }
    SCANS_CACHE[scan_id] = scan
    db_insert_scan(scan)

    background_tasks.add_task(run_analysis, scan_id, target, hybrid)
    return {"scan_id": scan_id, "status": ScanStatus.PENDING}


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    scan = db_get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@app.get("/api/scan/{scan_id}/stream")
async def stream_scan(scan_id: str):
    async def event_generator():
        while True:
            cache = SCANS_CACHE.get(scan_id)
            if not cache:
                # Scan not in cache — load status from DB
                with get_db() as db:
                    row = db.execute(
                        "SELECT status, total_snippets, analyzed FROM scans WHERE id=?",
                        (scan_id,)
                    ).fetchone()
                if not row:
                    yield 'data: {"error":"not found"}\n\n'
                    break
                count = db.execute(
                    "SELECT COUNT(*) FROM findings WHERE scan_id=?", (scan_id,)
                ).fetchone()[0] if row else 0
                data = json.dumps({
                    "status":         row["status"],
                    "analyzed":       row["analyzed"],
                    "total_snippets": row["total_snippets"],
                    "findings_count": count,
                })
                yield f"data: {data}\n\n"
                break

            data = json.dumps({
                "status":         cache["status"],
                "analyzed":       cache.get("analyzed", 0),
                "total_snippets": cache.get("total_snippets", 0),
                "findings_count": cache.get("findings_count", 0),
            })
            yield f"data: {data}\n\n"

            if cache["status"] in (ScanStatus.COMPLETE, ScanStatus.FAILED):
                SCANS_CACHE.pop(scan_id, None)
                break
            await asyncio.sleep(1)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/scans")
async def list_scans():
    return db_list_scans(limit=20)


@app.post("/api/results")
async def receive_results(payload: dict):
    scan_id = payload.get("scan_id", str(uuid.uuid4())[:8])
    scan = {
        "id":             scan_id,
        "filename":       payload.get("filename", "ci-scan"),
        "status":         ScanStatus.COMPLETE,
        "hybrid":         payload.get("hybrid", True),
        "source":         payload.get("source", "api"),
        "gitlab_project": payload.get("gitlab_project", ""),
        "gitlab_branch":  payload.get("gitlab_branch", ""),
        "gitlab_commit":  payload.get("gitlab_commit", ""),
        "total_snippets": payload.get("total_snippets", 0),
        "analyzed":       payload.get("total_snippets", 0),
        "created_at":     payload.get("timestamp", time.time()),
        "completed_at":   time.time(),
        "error":          None,
    }
    db_insert_scan(scan)
    db_delete_findings(scan_id)
    db_insert_findings(scan_id, payload.get("findings", []))
    return {"scan_id": scan_id, "status": "received"}


@app.get("/api/findings")
async def search_findings(
    cwe_id:   str | None = None,
    severity: str | None = None,
    project:  str | None = None,
    limit:    int = 100,
):
    """Search findings across all scans — useful for cross-project analysis."""
    conditions = ["1=1"]
    params: list = []
    if cwe_id:
        conditions.append("f.cwe_id = ?")
        params.append(cwe_id)
    if severity:
        conditions.append("f.severity = ?")
        params.append(severity.upper())
    if project:
        conditions.append("s.gitlab_project LIKE ?")
        params.append(f"%{project}%")
    params.append(limit)

    with get_db() as db:
        rows = db.execute(f"""
            SELECT f.*, s.filename, s.gitlab_project, s.gitlab_branch,
                   s.gitlab_commit, s.created_at AS scan_date
            FROM findings f
            JOIN scans s ON s.id = f.scan_id
            WHERE {' AND '.join(conditions)}
            ORDER BY f.created_at DESC
            LIMIT ?
        """, params).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/health")
async def health():
    with get_db() as db:
        scan_count    = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        finding_count = db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    return {
        "status":   "ok",
        "version":  "1.0.0",
        "db":       str(DB_PATH),
        "scans":    scan_count,
        "findings": finding_count,
    }


# Serve dashboard
@app.get("/", response_class=HTMLResponse)
async def dashboard():
    index = Path(__file__).parent / "static" / "index.html"
    if index.exists():
        return HTMLResponse(index.read_text())
    return HTMLResponse("<h1>Dashboard not found</h1>")


app.mount(
    "/static",
    StaticFiles(directory=Path(__file__).parent / "static"),
    name="static",
)
