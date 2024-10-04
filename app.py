import os
import subprocess
import logging
import magic
import tarfile
import shutil
import zipfile
from fastapi import FastAPI, File, UploadFile, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from starlette.staticfiles import StaticFiles

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configurations
UPLOAD_FOLDER = '/app/uploads'
SCAN_RESULTS_FOLDER = '/app/scan-results'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SCAN_RESULTS_FOLDER, exist_ok=True)

# Create FastAPI instance
app = FastAPI()

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Setup Jinja2 templates
templates = Jinja2Templates(directory="templates")

# Route to render the main HTML page
@app.get("/", response_class=HTMLResponse)
async def get_index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Initialize file type detector
try:
    mime = magic.Magic(mime=True)
except Exception as e:
    logger.error(f"Failed to initialize magic: {e}")
    mime = None

def detect_file_type(file_path):
    """Detect the type of a file using libmagic."""
    if mime:
        try:
            file_type = mime.from_file(file_path)
            logger.info(f"Detected file type: {file_type}")
            return file_type
        except Exception as e:
            logger.error(f"Failed to detect file type: {e}")
            return "Unknown file type"
    else:
        logger.error("libmagic not initialized.")
        return "libmagic not available"

def extract_files(filepath, dest):
    """Extract .tar, .tgz, .tar.gz, and .zip files."""
    try:
        if tarfile.is_tarfile(filepath):
            with tarfile.open(filepath, 'r:*') as tar:
                tar.extractall(path=dest)
                logger.info(f"Extracted {filepath} to {dest}")
            return True
        elif zipfile.is_zipfile(filepath):
            with zipfile.ZipFile(filepath, 'r') as zip_ref:
                zip_ref.extractall(dest)
                logger.info(f"Extracted {filepath} to {dest}")
            return True
        else:
            logger.warning(f"{filepath} is not a valid archive.")
            return False
    except Exception as e:
        logger.error(f"Failed to extract {filepath}: {e}")
        return False

def zip_directory(src_dir, zip_file_path):
    """Zip the contents of the source directory."""
    logger.info(f"Zipping the directory {src_dir} to {zip_file_path}")
    try:
        with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for root, dirs, files in os.walk(src_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, start=src_dir)
                    zip_file.write(file_path, arcname)
        logger.info(f"Zipping completed: {zip_file_path}")
    except Exception as e:
        logger.error(f"Failed to zip directory {src_dir}: {e}")

def run_trivy_fs_scan(target_path):
    """Run Trivy filesystem scan."""
    scan_output_path = os.path.join(SCAN_RESULTS_FOLDER, 'trivy_fs_scan.log')
    logger.info(f"Running Trivy filesystem scan on: {target_path}")
    command = ['trivy', 'fs', target_path, '--format', 'table']

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        if result.returncode == 0:
            with open(scan_output_path, 'w') as f:
                f.write(result.stdout)
            logger.info("Trivy filesystem scan completed successfully.")
            return {'path': target_path, 'scan_type': 'Trivy FS', 'severity': 'info', 'details': result.stdout}
        else:
            logger.error(f"Trivy filesystem scan failed: {result.stderr}")
            return {'error': f"Trivy scan failed: {result.stderr}"}
    except Exception as e:
        logger.error(f"Exception during Trivy scan: {e}")
        return {'error': f"Exception during Trivy scan: {e}"}

def run_trivy_image_scan(image_name):
    """Run Trivy image scan."""
    scan_output_path = os.path.join(SCAN_RESULTS_FOLDER, 'trivy_image_scan.log')
    logger.info(f"Running Trivy image scan on: {image_name}")
    command = ['trivy', 'image', image_name, '--format', 'table']

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        if result.returncode == 0:
            with open(scan_output_path, 'w') as f:
                f.write(result.stdout)
            logger.info("Trivy image scan completed successfully.")
            return {'path': image_name, 'scan_type': 'Trivy Image', 'severity': 'info', 'details': result.stdout}
        else:
            logger.error(f"Trivy image scan failed: {result.stderr}")
            return {'error': f"Trivy image scan failed: {result.stderr}"}
    except Exception as e:
        logger.error(f"Exception during Trivy image scan: {e}")
        return {'error': f"Exception during Trivy image scan: {e}"}

def run_trivy_repo_scan(repo_url):
    """Run Trivy repo scan."""
    scan_output_path = os.path.join(SCAN_RESULTS_FOLDER, 'trivy_repo_scan.log')
    logger.info(f"Running Trivy repo scan on: {repo_url}")
    command = ['trivy', 'repo', repo_url, '--format', 'table']

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        if result.returncode == 0:
            with open(scan_output_path, 'w') as f:
                f.write(result.stdout)
            logger.info("Trivy repo scan completed successfully.")
            return {'path': repo_url, 'scan_type': 'Trivy Repo', 'severity': 'info', 'details': result.stdout}
        else:
            logger.error(f"Trivy repo scan failed: {result.stderr}")
            return {'error': f"Trivy repo scan failed: {result.stderr}"}
    except Exception as e:
        logger.error(f"Exception during Trivy repo scan: {e}")
        return {'error': f"Exception during Trivy repo scan: {e}"}

@app.post("/scan/")
async def scan_file(scan_type: str = Form(...), file: UploadFile = File(None), image_name: str = Form(None), repo_url: str = Form(None)):
    scan_results = []

    if scan_type == 'filesystem':
        if file:
            filename = file.filename
            if not filename:
                logger.error("No filename provided for file upload.")
                return {"error": "No valid filename provided."}

            file_path = os.path.join(UPLOAD_FOLDER, filename)
            with open(file_path, "wb") as f:
                shutil.copyfileobj(file.file, f)
            
            file_type = detect_file_type(file_path)
            extract_path = os.path.join(UPLOAD_FOLDER, 'extracted')
            os.makedirs(extract_path, exist_ok=True)

            if file_type in ['application/gzip', 'application/x-tar', 'application/zip']:
                if extract_files(file_path, extract_path):
                    scan_results.append(run_trivy_fs_scan(extract_path))
                    zip_file_path = os.path.join(UPLOAD_FOLDER, f"{filename}_scanned.zip")
                    zip_directory(extract_path, zip_file_path)
                    scan_results.append({"path": zip_file_path, "scan_type": "Zip", "severity": "info", "details": "Files re-zipped after scanning."})
                    shutil.rmtree(extract_path)  # Clean up extracted files
                else:
                    return {"error": f"Failed to extract {filename}"}
            else:
                scan_results.append(run_trivy_fs_scan(file_path))

    elif scan_type == 'image' and image_name:
        scan_results.append(run_trivy_image_scan(image_name))

    elif scan_type == 'git' and repo_url:
        scan_results.append(run_trivy_repo_scan(repo_url))

    return scan_results

if __name__ == "__main__":
    import uvicorn
    logger.info("Starting FastAPI application on http://0.0.0.0:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
