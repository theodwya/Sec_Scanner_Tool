import os
import logging
import magic
import tarfile
import shutil
import zipfile
import clamd
import git
import yara
import asyncio
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
YARA_RULES_REPO = 'https://github.com/Yara-Rules/rules.git'
YARA_RULES_FOLDER = '/app/yara_rules'
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

async def detect_file_type(file_path):
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

async def run_trivy_fs_scan(target_path):
    """Run Trivy filesystem scan."""
    scan_output_path = os.path.join(SCAN_RESULTS_FOLDER, 'trivy_fs_scan.log')
    logger.info(f"Running Trivy filesystem scan on: {target_path}")
    command = ['trivy', 'fs', target_path, '--format', 'table']

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

        if process.returncode == 0:
            with open(scan_output_path, 'w') as f:
                f.write(stdout.decode())
            logger.info("Trivy filesystem scan completed successfully.")
            return {'path': target_path, 'scan_type': 'Trivy FS', 'severity': 'info', 'details': stdout.decode()}
        else:
            logger.error(f"Trivy filesystem scan failed: {stderr.decode()}")
            return {'error': f"Trivy scan failed: {stderr.decode()}"}
    except Exception as e:
        logger.error(f"Exception during Trivy scan: {e}")
        return {'error': f"Exception during Trivy scan: {e}"}

async def run_trivy_image_scan(image_name):
    """Run Trivy image scan."""
    scan_output_path = os.path.join(SCAN_RESULTS_FOLDER, 'trivy_image_scan.log')
    logger.info(f"Running Trivy image scan on: {image_name}")
    command = ['trivy', 'image', image_name, '--format', 'table']

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

        if process.returncode == 0:
            with open(scan_output_path, 'w') as f:
                f.write(stdout.decode())
            logger.info("Trivy image scan completed successfully.")
            return {'path': image_name, 'scan_type': 'Trivy Image', 'severity': 'info', 'details': stdout.decode()}
        else:
            logger.error(f"Trivy image scan failed: {stderr.decode()}")
            return {'error': f"Trivy image scan failed: {stderr.decode()}"}
    except Exception as e:
        logger.error(f"Exception during Trivy image scan: {e}")
        return {'error': f"Exception during Trivy image scan: {e}"}

async def run_grype_image_scan(image_name):
    """Run Grype image scan."""
    scan_output_path = os.path.join(SCAN_RESULTS_FOLDER, 'grype_image_scan.log')
    logger.info(f"Running Grype image scan on: {image_name}")
    command = ['grype', image_name, '--output', 'table']

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

        if process.returncode == 0:
            with open(scan_output_path, 'w') as f:
                f.write(stdout.decode())
            logger.info("Grype image scan completed successfully.")
            return {'path': image_name, 'scan_type': 'Grype Image', 'severity': 'info', 'details': stdout.decode()}
        else:
            logger.error(f"Grype image scan failed: {stderr.decode()}")
            return {'error': f"Grype image scan failed: {stderr.decode()}"}
    except Exception as e:
        logger.error(f"Exception during Grype image scan: {e}")
        return {'error': f"Exception during Grype image scan: {e}"}

async def run_trivy_repo_scan(repo_url):
    """Run Trivy repo scan."""
    scan_output_path = os.path.join(SCAN_RESULTS_FOLDER, 'trivy_repo_scan.log')
    logger.info(f"Running Trivy repo scan on: {repo_url}")
    command = ['trivy', 'repo', repo_url, '--format', 'table']

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

        if process.returncode == 0:
            with open(scan_output_path, 'w') as f:
                f.write(stdout.decode())
            logger.info("Trivy repo scan completed successfully.")
            return {'path': repo_url, 'scan_type': 'Trivy Repo', 'severity': 'info', 'details': stdout.decode()}
        else:
            logger.error(f"Trivy repo scan failed: {stderr.decode()}")
            return {'error': f"Trivy repo scan failed: {stderr.decode()}"}
    except Exception as e:
        logger.error(f"Exception during Trivy repo scan: {e}")
        return {'error': f"Exception during Trivy repo scan: {e}"}

async def clone_and_scan_repo(repo_url):
    """Clone the Git repository locally and run a filesystem scan."""
    repo_name = os.path.basename(repo_url).replace('.git', '')
    repo_path = os.path.join(UPLOAD_FOLDER, repo_name)

    # Step 1: Run Trivy remote repo scan on the URL
    remote_repo_scan_result = await run_trivy_repo_scan(repo_url)

    # Remove the directory if it already exists
    if os.path.exists(repo_path):
        shutil.rmtree(repo_path)

    # Step 2: Clone the repository locally
    logger.info(f"Cloning repository from {repo_url} to {repo_path}")
    try:
        git.Repo.clone_from(repo_url, repo_path)
        logger.info(f"Cloned repository successfully: {repo_path}")
    except Exception as e:
        logger.error(f"Failed to clone repository: {e}")
        return [{'error': f"Failed to clone repository: {e}"}]

    # Step 3: Run local Trivy filesystem, ClamAV, and Trivy local repo scans
    local_trivy_fs_scan_result = await run_trivy_fs_scan(repo_path)
    local_clamav_fs_scan_result = await run_clamav_fs_scan(repo_path)
    local_trivy_repo_scan_result = await run_trivy_repo_scan(repo_path)

    # Collect all scan results
    return [
        remote_repo_scan_result,
        local_trivy_fs_scan_result,
        local_clamav_fs_scan_result,
        local_trivy_repo_scan_result
    ]

async def clone_yara_rules():
    """Clone YARA rules from the official YARA-Rules GitHub repository."""
    # Remove the directory if it already exists
    if os.path.exists(YARA_RULES_FOLDER):
        shutil.rmtree(YARA_RULES_FOLDER)

    # Clone the YARA rules
    logger.info(f"Cloning YARA rules from {YARA_RULES_REPO}")
    try:
        git.Repo.clone_from(YARA_RULES_REPO, YARA_RULES_FOLDER)
        logger.info(f"Cloned YARA rules successfully into: {YARA_RULES_FOLDER}")
    except Exception as e:
        logger.error(f"Failed to clone YARA rules: {e}")
        return {'error': f"Failed to clone YARA rules: {e}"}

async def run_yara_scan(target_path):
    """Run YARA scan on a file or directory."""
    logger.info(f"Running YARA scan on: {target_path}")
    yara_rules_path = os.path.join(YARA_RULES_FOLDER, "malware")  # Adjust path based on YARA rules in the repo

    try:
        # Compile YARA rules
        rules = yara.compile(filepath=yara_rules_path)

        # Initialize results
        results = []
        
        # Apply YARA rules to the target path
        if os.path.isfile(target_path):
            matches = rules.match(target_path)
            if matches:
                results.append({'path': target_path, 'matches': str(matches)})
        else:
            for root, dirs, files in os.walk(target_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    matches = rules.match(file_path)
                    if matches:
                        results.append({'path': file_path, 'matches': str(matches)})
                        
        return results if results else {'status': 'No matches found'}
    except Exception as e:
        logger.error(f"Exception during YARA scan: {e}")
        return {'error': f"Exception during YARA scan: {e}"}

async def run_clamav_fs_scan(file_path):
    """Run ClamAV scan on the file using clamd."""
    logger.info(f"Running ClamAV FS scan on: {file_path}")
    try:
        cd = clamd.ClamdUnixSocket()  # Or ClamdNetworkSocket() depending on configuration
        
        # Perform the scan and collect results
        scan_result = cd.multiscan(file_path)  # `multiscan` scans directories recursively
        logger.info(f"ClamAV scan completed: {scan_result}")
        
        # Initialize counters
        total_files = len(scan_result)
        infected_files = sum(1 for result in scan_result.values() if result[0] == 'FOUND')

        # Build the results output
        details = "\n".join([f"{path}: {status}" for path, status in scan_result.items()])
        summary = f"Total files scanned: {total_files}, Infected files: {infected_files}"

        return {
            'path': file_path,
            'scan_type': 'ClamAV FS',
            'severity': 'info' if infected_files == 0 else 'warning',
            'details': f"{summary}\n\nDetails:\n{details}"
        }
    except Exception as e:
        logger.error(f"Exception during ClamAV FS scan: {e}")
        return {'error': f"Exception during ClamAV FS scan: {e}"}

# Update the scan route to render `scan.html`
@app.post("/scan/")
async def scan_file(request: Request, scan_type: str = Form(...), file: UploadFile = File(None), image_name: str = Form(None), repo_url: str = Form(None)):
    scan_results = []

    # Log the incoming scan type and parameters
    logger.info(f"Received scan request with type: {scan_type}, file: {file.filename if file else None}, image_name: {image_name}, repo_url: {repo_url}")

    if scan_type == 'filesystem' and file:
        # Filesystem scan
        filename = file.filename
        if not filename:
            logger.error("No filename provided for file upload.")
            return {"error": "No valid filename provided."}

        file_path = os.path.join(UPLOAD_FOLDER, filename)
        # Read file asynchronously and write synchronously to handle file uploads
        content = await file.read()
        with open(file_path, "wb") as f:
            f.write(content)

        file_type = await detect_file_type(file_path)
        extract_path = os.path.join(UPLOAD_FOLDER, 'extracted')
        os.makedirs(extract_path, exist_ok=True)

        if file_type in ['application/gzip', 'application/x-tar', 'application/zip']:
            if extract_files(file_path, extract_path):
                scan_results.append(await run_trivy_fs_scan(extract_path))
                scan_results.append(await run_clamav_fs_scan(extract_path))
                scan_results.append(await run_yara_scan(extract_path))  # YARA scan
                zip_file_path = os.path.join(UPLOAD_FOLDER, f"{filename}_scanned.zip")
                zip_directory(extract_path, zip_file_path)
                scan_results.append({"path": zip_file_path, "scan_type": "Zip", "severity": "info", "details": "Files re-zipped after scanning."})
                shutil.rmtree(extract_path)  # Clean up extracted files
            else:
                return {"error": f"Failed to extract {filename}"}
        else:
            scan_results.append(await run_trivy_fs_scan(file_path))
            scan_results.append(await run_clamav_fs_scan(file_path))
            scan_results.append(await run_yara_scan(file_path))  # YARA scan

        # Clean up uploaded file after scan
        os.remove(file_path)

    elif scan_type == 'image' and image_name:
        # Image scan
        scan_results.append(await run_trivy_image_scan(image_name))
        scan_results.append(await run_grype_image_scan(image_name))  # Grype image scan

    elif scan_type == 'repo' and repo_url:
        # Clone and scan repo
        scan_results.extend(await clone_and_scan_repo(repo_url))

    else:
        return {"error": "Invalid scan type or missing parameters."}

    # Render the scan.html template and pass the scan results
    return templates.TemplateResponse("scan.html", {"request": request, "scan_results": scan_results})

# Entry point for running the application
if __name__ == "__main__":
    import uvicorn
    logger.info("Starting FastAPI application on http://0.0.0.0:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
