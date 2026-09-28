from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, FileResponse
import json
import os
from pathlib import Path
from typing import List, Dict, Any

app = FastAPI()

# Setup absolute paths
BASE_DIR = Path(__file__).resolve().parent.parent 
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
REPORTS_BASE = BASE_DIR / "reports" / "poc_demo"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

def get_all_runs() -> List[Dict[str, Any]]:
    """Discover all run directories and their metadata."""
    runs = []
    if not REPORTS_BASE.exists():
        return []
    
    # Sort by timestamp (run_YYYYMMDD_HHMMSS)
    dir_names = sorted([d for d in os.listdir(REPORTS_BASE) if d.startswith("run_")], reverse=True)
    
    for d in dir_names:
        run_path = REPORTS_BASE / d
        json_report = run_path / "security_report.json"
        has_html = (run_path / "security_report.html").exists()
        
        status = "Unknown"
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        target = "N/A"
        
        if json_report.exists():
            try:
                with open(json_report) as f:
                    rdata = json.load(f)
                    summary = rdata.get("summary", {})
                    status = summary.get("overall_status", "Completed")
                    severity_counts = summary.get("severity_counts", severity_counts)
                    target = summary.get("target_id", rdata.get("target", "N/A"))
            except:
                pass
        
        runs.append({
            "id": d,
            "status": status,
            "has_html": has_html,
            "timestamp": d.replace("run_", "").replace("_", " "),
            "severity_counts": severity_counts,
            "target": target
        })
    return runs

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    runs = get_all_runs()
    latest_data = {}
    trend_data = {
        "labels": [],
        "critical": [],
        "high": [],
        "medium": []
    }
    
    if runs:
        # Load latest run data
        latest_run_id = runs[0]["id"]
        latest_json = REPORTS_BASE / latest_run_id / "security_report.json"
        if latest_json.exists():
            with open(latest_json) as f:
                latest_data = json.load(f)
        
        # Aggregate last 10 runs for trend chart
        for run in reversed(runs[:10]):
            trend_data["labels"].append(run["timestamp"].split(" ")[1]) # Just the time or short date
            trend_data["critical"].append(run["severity_counts"].get("critical", 0))
            trend_data["high"].append(run["severity_counts"].get("high", 0))
            trend_data["medium"].append(run["severity_counts"].get("medium", 0))

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "report": latest_data,
            "runs": runs,
            "trend_data": trend_data
        },
    )

@app.get("/report/{run_id}")
async def view_html_report(run_id: str):
    """Serve the static HTML report for a specific run."""
    report_path = REPORTS_BASE / run_id / "security_report.html"
    if report_path.exists():
        return FileResponse(report_path)
    return {"error": "Report not found"}