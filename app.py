
import os
import logging
import shutil
import asyncio
from fastapi import FastAPI, UploadFile, Form, File
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from starlette.staticfiles import StaticFiles
from utilities.file_utils import detect_file_type, extract_files, zip_directory
from scanners.clamav import run_clamav_fs_scan
from scanners.yara import run_yara_scan, clone_yara_rules
from scanners.trivy import run_trivy_fs_scan, run_trivy_image_scan
from scanners.grype import run_grype_image_scan
from repo_scanner.repo_scan import clone_and_scan_repo

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
UPLOAD_FOLDER = '/app/uploads'
SCAN_RESULTS_FOLDER = '/app/scan-results'
YARA_RULES_FOLDER = '/app/yara-rules'
YARA_RULES_REPO_URL = 'https://github.com/Yara-Rules/rules.git'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SCAN_RESULTS_FOLDER, exist_ok=True)

# FastAPI app instance
app = FastAPI()

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Setup Jinja2 templates
templates = Jinja2Templates(directory="templates")

# Startup event to clone YARA rules
@app.on_event("startup")
async def startup_event():
    clone_result = clone_yara_rules(YARA_RULES_REPO_URL, YARA_RULES_FOLDER)
    if 'error' in clone_result:
        logger.error(f"Failed to clone YARA rules: {clone_result['error']}")


# Routes
@app.get("/", response_class=HTMLResponse)
async def get_index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Scanning route
@app.post("/scan/", response_class=HTMLResponse)
async def scan_file(
    request: Request,
    scan_type: str = Form(...),
    file: UploadFile = File(None),
    image_name: str = Form(None),
    repo_url: str = Form(None)
):
    scan_results = []

    logger.info(f"Received scan request with type: {scan_type}, file: {file.filename if file else None}, image_name: {image_name}, repo_url: {repo_url}")

    if scan_type == 'filesystem' and file:
        filename = file.filename
        if not filename:
            logger.error("No filename provided for file upload.")
            return {"error": "No valid filename provided."}

        file_path = os.path.join(UPLOAD_FOLDER, filename)
        content = await file.read()
        with open(file_path, "wb") as f:
            f.write(content)

        file_type = await detect_file_type(file_path)
        extract_path = os.path.join(UPLOAD_FOLDER, 'extracted')
        os.makedirs(extract_path, exist_ok=True)

        if file_type in ['application/gzip', 'application/x-tar', 'application/zip']:
            if extract_files(file_path, extract_path):
                scan_results.append(await run_trivy_fs_scan(extract_path))
                scan_results.append(run_clamav_fs_scan(extract_path))
                scan_results.append(run_yara_scan(extract_path, YARA_RULES_FOLDER))
                zip_file_path = os.path.join(UPLOAD_FOLDER, f"{filename}_scanned.zip")
                zip_directory(extract_path, zip_file_path)
                scan_results.append({"path": zip_file_path, "scan_type": "Zip", "severity": "info", "details": "Files re-zipped after scanning."})
                shutil.rmtree(extract_path)
            else:
                return {"error": f"Failed to extract {filename}"}
        else:
            scan_results.append(await run_trivy_fs_scan(file_path))
            scan_results.append(run_clamav_fs_scan(file_path))
            scan_results.append(run_yara_scan(file_path, YARA_RULES_FOLDER))

        os.remove(file_path)

    elif scan_type == 'image' and image_name:
        scan_results.append(await run_trivy_image_scan(image_name))
        scan_results.append(await run_grype_image_scan(image_name))

    elif scan_type == 'repo' and repo_url:
        scan_results.extend(await clone_and_scan_repo(repo_url))

    else:
        return {"error": "Invalid scan type or missing parameters."}

    return templates.TemplateResponse("scan.html", {"request": request, "scan_results": scan_results})

if __name__ == "__main__":
    import uvicorn
    logger.info("Starting FastAPI application")
    uvicorn.run(app, host="0.0.0.0", port=8000)