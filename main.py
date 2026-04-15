
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from pathlib import Path
from uuid import uuid4
import shutil
import json
import re
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

BASE_DIR = Path(__file__).resolve().parent
PRIVATE_DIR = BASE_DIR / "private"
SESSIONS_DIR = BASE_DIR / "sessions"
SESSIONS_DIR.mkdir(parents=True, exist_ok=True)

APP_FILES = {
    "aaw": PRIVATE_DIR / "aaw.html",
    "aws": PRIVATE_DIR / "aws.html",
    "xmin": PRIVATE_DIR / "xmin.html",
}

app = FastAPI(title="WTG Secure Backend")
app.mount("/sessions", StaticFiles(directory=str(SESSIONS_DIR)), name="sessions")


class FilterPayload(BaseModel):
    session_id: str
    start_date: str = ""
    end_date: str = ""
    start_time: str = ""
    end_time: str = ""
    turbines: List[str] = []
    turbine_search: str = ""
    aws_event_search: str = ""
    xmin_variable_search: str = ""
    xmin_interval: str = "10"
    show_emergency_sequence: bool = False


def empty_html(title: str, message: str) -> str:
    return f"""<!doctype html>
<html><head><meta charset="utf-8">
<style>
body{{margin:0;font:14px/1.6 system-ui,Segoe UI,Arial,sans-serif;background:#f8fbff;color:#0f172a}}
.wrap{{display:grid;place-items:center;min-height:920px;padding:28px}}
.card{{max-width:800px;background:#fff;border:1px solid #dbe4f0;border-radius:22px;padding:24px;box-shadow:0 10px 24px rgba(15,23,42,.06)}}
h3{{margin:0 0 8px;font-size:22px}} p{{margin:0;color:#5b6472}}
</style></head><body><div class="wrap"><div class="card"><h3>{title}</h3><p>{message}</p></div></div></body></html>"""


def sanitize_filename(name: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]+", "_", name or "file")
    return clean[:200] or "file"


def save_upload(upload: Optional[UploadFile], target_dir: Path, target_name: str) -> Optional[str]:
    if upload is None:
        return None
    suffix = Path(upload.filename or "").suffix or ""
    target = target_dir / f"{target_name}{suffix}"
    with target.open("wb") as f:
        shutil.copyfileobj(upload.file, f)
    return str(target)


def load_manifest(session_dir: Path) -> Dict[str, Any]:
    manifest_path = session_dir / "manifest.json"
    if not manifest_path.exists():
        raise HTTPException(status_code=404, detail="Session not found.")
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def save_manifest(session_dir: Path, data: Dict[str, Any]) -> None:
    (session_dir / "manifest.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def dispatch_change(page, selector: str, value: str):
    page.eval_on_selector(selector, """(el, value) => {
        el.value = value || '';
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
    }""", value)


def safe_wait_for(page, script: str, timeout: int = 4000):
    try:
        page.wait_for_function(script, timeout=timeout)
    except Exception:
        pass


def sanitize_static_page(page) -> str:
    return page.evaluate("""
    () => {
      const replaceCanvas = () => {
        document.querySelectorAll('canvas').forEach((cv, idx) => {
          try {
            const img = document.createElement('img');
            img.src = cv.toDataURL('image/png');
            img.alt = 'Rendered chart ' + (idx + 1);
            img.style.maxWidth = '100%';
            img.style.height = 'auto';
            img.style.display = 'block';
            img.style.background = '#fff';
            img.style.border = '1px solid #e5edf8';
            img.style.borderRadius = '12px';
            cv.replaceWith(img);
          } catch (err) {}
        });
      };
      replaceCanvas();
      document.querySelectorAll('script').forEach(el => el.remove());
      document.querySelectorAll('input[type="file"], button[onclick], [data-export], .btn-reset-file').forEach(el => {
        if (el && el.remove) el.remove();
      });
      return '<!doctype html>\\n' + document.documentElement.outerHTML;
    }
    """)


def extract_meta_aaw(page) -> Dict[str, Any]:
    return page.evaluate("""
    () => {
      const uniq = arr => Array.from(new Set((arr || []).filter(Boolean))).sort();
      const pillText = selector => Array.from(document.querySelectorAll(selector)).map(el => (el.textContent || '').trim());
      const tables = ['#tbl-repeated','#tbl-new','#tbl-cleared','#tbl-repeated-3days','#tbl-lubrication'];
      const turbines = uniq([
        ...pillText('.turbine-pill'),
        ...Array.from(document.querySelectorAll('#turbine-filter-list input[data-turbine]')).map(el => el.getAttribute('data-turbine'))
      ]);
      const counts = {};
      tables.forEach(sel => {
        const body = document.querySelector(sel + ' tbody');
        counts[sel] = body ? Array.from(body.querySelectorAll('tr')).length : 0;
      });
      return { turbines, counts };
    }
    """)


def extract_meta_aws(page) -> Dict[str, Any]:
    return page.evaluate("""
    () => {
      const uniq = arr => Array.from(new Set((arr || []).filter(Boolean))).sort();
      const texts = selector => Array.from(document.querySelectorAll(selector)).map(el => (el.textContent || '').trim()).filter(Boolean);
      const devices = texts('.device-item, .turbine-item, [data-device]');
      const events = texts('.event-item, .alarm-item, [data-event], #event-list button, #event-list .item');
      const categories = texts('.category-item, .cat-item, [data-category], #category-list button, #category-list .item');
      return { turbines: uniq(devices), events: uniq(events), categories: uniq(categories) };
    }
    """)


def extract_meta_xmin(page) -> Dict[str, Any]:
    return page.evaluate("""
    () => {
      const uniq = arr => Array.from(new Set((arr || []).filter(Boolean))).sort();
      let turbines = [];
      let variables = [];
      try {
        turbines = uniq((window.rawData || []).map(r => r && r['Device']).filter(Boolean));
        variables = uniq(Object.keys((window.rawData || [])[0] || {}).filter(k => k !== 'Device' && k !== 'Date'));
      } catch (err) {}
      return { turbines, variables, categories: [] };
    }
    """)


def apply_common_client_filters_aaw(page, filters: Dict[str, Any]):
    turbines = filters.get("turbines") or []
    if turbines and "__ALL__" not in turbines:
        page.evaluate("""
        (wanted) => {
          const list = document.getElementById('turbine-filter-list');
          if (!list) return;
          const set = new Set(wanted.map(v => String(v)));
          list.querySelectorAll('input[data-turbine]').forEach(cb => {
            cb.checked = set.has(cb.getAttribute('data-turbine') || '');
          });
          if (typeof renderAllTables === 'function') renderAllTables();
        }
        """, turbines)
    search_text = filters.get("turbine_search") or ""
    if search_text:
        dispatch_change(page, "#global-search", search_text)
    safe_wait_for(page, "document.querySelector('#tbl-repeated tbody tr') || document.querySelector('#tbl-new tbody tr')", 2000)


def apply_common_client_filters_aws(page, filters: Dict[str, Any]):
    start_date = filters.get("start_date") or ""
    end_date = filters.get("end_date") or ""
    start_time = filters.get("start_time") or ""
    end_time = filters.get("end_time") or ""
    if start_date:
        dispatch_change(page, "#start-date", start_date)
    if end_date:
        dispatch_change(page, "#end-date", end_date)
    if start_time:
        dispatch_change(page, "#start-time", start_time)
    if end_time:
        dispatch_change(page, "#end-time", end_time)
    if filters.get("turbine_search"):
        dispatch_change(page, "#device-filter", filters["turbine_search"])
    if filters.get("aws_event_search"):
        dispatch_change(page, "#event-search", filters["aws_event_search"])
    if filters.get("show_emergency_sequence"):
        try:
            page.click("#btn-emergency-seq")
        except Exception:
            pass
    page.wait_for_timeout(500)


def apply_common_client_filters_xmin(page, filters: Dict[str, Any]):
    start_date = filters.get("start_date") or ""
    end_date = filters.get("end_date") or ""
    start_time = filters.get("start_time") or ""
    end_time = filters.get("end_time") or ""
    if start_date:
        dispatch_change(page, "#startDate", start_date)
    if end_date:
        dispatch_change(page, "#endDate", end_date)
    if start_time:
        dispatch_change(page, "#startTime", start_time)
    if end_time:
        dispatch_change(page, "#endTime", end_time)
    if filters.get("turbine_search"):
        dispatch_change(page, "#turbineSearch", filters["turbine_search"])
    if filters.get("xmin_variable_search"):
        dispatch_change(page, "#variableSearch", filters["xmin_variable_search"])
    if filters.get("xmin_interval"):
        try:
            page.select_option("#intervalSelect", str(filters["xmin_interval"]))
        except Exception:
            pass
    page.wait_for_timeout(500)


def process_aaw(context, session_dir: Path, files: Dict[str, str], filters: Dict[str, Any]) -> Dict[str, Any]:
    result_path = session_dir / "aaw.html"
    if not files.get("aaw_today") or not files.get("aaw_yesterday"):
        html = empty_html("AAW Analysis", "AAW needs at least the today file and the yesterday file.")
        result_path.write_text(html, encoding="utf-8")
        return {
            "status": {"state": "waiting", "label": "Waiting", "meta": "AAW needs at least the today file and the yesterday file."},
            "meta": {"turbines": [], "counts": {}}
        }
    page = context.new_page(viewport={"width": 1600, "height": 2400})
    try:
        page.set_content(APP_FILES["aaw"].read_text(encoding="utf-8"), wait_until="load")
        page.set_input_files("#file-today", files["aaw_today"])
        page.set_input_files("#file-yesterday", files["aaw_yesterday"])
        if files.get("aaw_daybefore"):
            try:
                page.set_input_files("#file-daybefore", files["aaw_daybefore"])
            except Exception:
                pass
        page.wait_for_timeout(300)
        page.click("#btn-compare")
        safe_wait_for(page, "document.querySelector('#tbl-repeated tbody tr') || document.querySelector('#tbl-new tbody tr') || document.querySelector('#tbl-cleared tbody tr')", 7000)
        apply_common_client_filters_aaw(page, filters)
        meta = extract_meta_aaw(page)
        html = sanitize_static_page(page)
        result_path.write_text(html, encoding="utf-8")
        return {
            "status": {"state": "ready", "label": "Ready", "meta": "AAW comparison was processed on the server."},
            "meta": meta
        }
    except Exception as exc:
        result_path.write_text(empty_html("AAW Analysis", f"AAW processing failed: {exc}"), encoding="utf-8")
        return {
            "status": {"state": "error", "label": "Needs check", "meta": f"AAW processing failed: {exc}"},
            "meta": {"turbines": [], "counts": {}}
        }
    finally:
        page.close()


def process_aws(context, session_dir: Path, files: Dict[str, str], filters: Dict[str, Any]) -> Dict[str, Any]:
    result_path = session_dir / "aws.html"
    if not files.get("aws_file"):
        html = empty_html("AWS Dashboard", "No AWS file was uploaded for this session.")
        result_path.write_text(html, encoding="utf-8")
        return {
            "status": {"state": "waiting", "label": "Waiting", "meta": "No AWS file has been selected yet."},
            "meta": {"turbines": [], "events": [], "categories": []}
        }
    page = context.new_page(viewport={"width": 1600, "height": 2600})
    try:
        page.set_content(APP_FILES["aws"].read_text(encoding="utf-8"), wait_until="load")
        page.set_input_files("#file-input", files["aws_file"])
        safe_wait_for(page, "document.querySelector('table tbody tr') || document.querySelector('#event-list')", 10000)
        page.wait_for_timeout(1000)
        apply_common_client_filters_aws(page, filters)
        meta = extract_meta_aws(page)
        html = sanitize_static_page(page)
        result_path.write_text(html, encoding="utf-8")
        return {
            "status": {"state": "ready", "label": "Ready", "meta": "AWS dashboard was processed on the server."},
            "meta": meta
        }
    except Exception as exc:
        result_path.write_text(empty_html("AWS Dashboard", f"AWS processing failed: {exc}"), encoding="utf-8")
        return {
            "status": {"state": "error", "label": "Needs check", "meta": f"AWS processing failed: {exc}"},
            "meta": {"turbines": [], "events": [], "categories": []}
        }
    finally:
        page.close()


def process_xmin(context, session_dir: Path, files: Dict[str, str], filters: Dict[str, Any]) -> Dict[str, Any]:
    result_path = session_dir / "xmin.html"
    if not files.get("xmin_file"):
        html = empty_html("X‑Minutal Analysis", "No X‑Minutal file was uploaded for this session.")
        result_path.write_text(html, encoding="utf-8")
        return {
            "status": {"state": "waiting", "label": "Waiting", "meta": "No X‑Minutal file has been selected yet."},
            "meta": {"turbines": [], "variables": [], "categories": []}
        }
    page = context.new_page(viewport={"width": 1700, "height": 3200})
    try:
        page.set_content(APP_FILES["xmin"].read_text(encoding="utf-8"), wait_until="load")
        page.set_input_files("#csvInput", files["xmin_file"])
        safe_wait_for(page, "window.rawData && window.rawData.length > 0", 10000)
        page.wait_for_timeout(1000)
        try:
            page.wait_for_selector("#awsInput", timeout=1200)
            if files.get("aws_file"):
                page.set_input_files("#awsInput", files["aws_file"])
                page.wait_for_timeout(500)
        except Exception:
            pass
        apply_common_client_filters_xmin(page, filters)
        meta = extract_meta_xmin(page)
        html = sanitize_static_page(page)
        result_path.write_text(html, encoding="utf-8")
        return {
            "status": {"state": "ready", "label": "Ready", "meta": "X‑Minutal analysis was processed on the server."},
            "meta": meta
        }
    except Exception as exc:
        result_path.write_text(empty_html("X‑Minutal Analysis", f"X‑Minutal processing failed: {exc}"), encoding="utf-8")
        return {
            "status": {"state": "error", "label": "Needs check", "meta": f"X‑Minutal processing failed: {exc}"},
            "meta": {"turbines": [], "variables": [], "categories": []}
        }
    finally:
        page.close()


def build_urls(session_id: str) -> Dict[str, str]:
    return {
        "aaw": f"/sessions/{session_id}/aaw.html",
        "aws": f"/sessions/{session_id}/aws.html",
        "xmin": f"/sessions/{session_id}/xmin.html",
    }


def process_session(session_dir: Path, files: Dict[str, str], filters: Dict[str, Any]) -> Dict[str, Any]:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, executable_path='/usr/bin/chromium', args=['--no-sandbox','--disable-dev-shm-usage'])
        context = browser.new_context(locale="en-US")
        try:
            aaw = process_aaw(context, session_dir, files, filters)
            aws = process_aws(context, session_dir, files, filters)
            xmin = process_xmin(context, session_dir, files, filters)
        finally:
            context.close()
            browser.close()

    turbines = sorted(set((aaw["meta"].get("turbines") or []) + (aws["meta"].get("turbines") or []) + (xmin["meta"].get("turbines") or [])))
    meta = {
        "session_id": session_dir.name,
        "subtitle": "Server-side secure mode is active. Files are processed in the backend and only rendered results are sent back to the browser.",
        "status": {
            "aaw": aaw["status"],
            "aws": aws["status"],
            "xmin": xmin["status"],
        },
        "turbines": turbines,
        "aws_categories": aws["meta"].get("categories") or [],
        "aws_events": aws["meta"].get("events") or [],
        "xmin_categories": xmin["meta"].get("categories") or [],
        "xmin_variables": xmin["meta"].get("variables") or [],
    }
    return {
        "urls": build_urls(session_dir.name),
        "meta": meta,
    }


@app.get("/api/health")
def health():
    return {"ok": True}


@app.post("/api/process")
async def api_process(
    aaw_today: Optional[UploadFile] = File(default=None),
    aaw_yesterday: Optional[UploadFile] = File(default=None),
    aaw_daybefore: Optional[UploadFile] = File(default=None),
    aws_file: Optional[UploadFile] = File(default=None),
    xmin_file: Optional[UploadFile] = File(default=None),
):
    session_id = uuid4().hex[:12]
    session_dir = SESSIONS_DIR / session_id
    uploads_dir = session_dir / "uploads"
    uploads_dir.mkdir(parents=True, exist_ok=True)

    files = {
        "aaw_today": save_upload(aaw_today, uploads_dir, "aaw_today"),
        "aaw_yesterday": save_upload(aaw_yesterday, uploads_dir, "aaw_yesterday"),
        "aaw_daybefore": save_upload(aaw_daybefore, uploads_dir, "aaw_daybefore"),
        "aws_file": save_upload(aws_file, uploads_dir, "aws_file"),
        "xmin_file": save_upload(xmin_file, uploads_dir, "xmin_file"),
    }
    result = process_session(session_dir, files, {})
    manifest = {"session_id": session_id, "files": files, "filters": {}, "meta": result["meta"]}
    save_manifest(session_dir, manifest)
    return {"session_id": session_id, **result}


@app.post("/api/filter")
async def api_filter(payload: FilterPayload):
    session_dir = SESSIONS_DIR / payload.session_id
    manifest = load_manifest(session_dir)
    filters = payload.dict()
    result = process_session(session_dir, manifest["files"], filters)
    manifest["filters"] = filters
    manifest["meta"] = result["meta"]
    save_manifest(session_dir, manifest)
    return {"session_id": payload.session_id, **result}
