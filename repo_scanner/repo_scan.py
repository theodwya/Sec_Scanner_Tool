
import os
import shutil
import git
import logging
from scanners.clamav import run_clamav_fs_scan
from scanners.yara import run_yara_scan, clone_yara_rules
from scanners.trivy import run_trivy_fs_scan, run_trivy_repo_scan

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Configurations for Yara Rules
YARA_RULES_REPO_URL = 'https://github.com/Yara-Rules/rules.git'
YARA_RULES_FOLDER = '/app/yara-rules'

async def clone_and_scan_repo(repo_url):
    """Clone the repository and run all necessary scans."""
    try:
        # Define the directory to clone the repo into
        repo_dir = '/app/repo-scans'
        os.makedirs(repo_dir, exist_ok=True)
        repo_name = os.path.basename(repo_url).replace('.git', '')
        repo_path = os.path.join(repo_dir, repo_name)

        # Step 1: Run Trivy remote repo scan on the URL
        remote_repo_scan_result = await run_trivy_repo_scan(repo_url)

        # If the repo directory already exists, remove it
        if os.path.exists(repo_path):
            shutil.rmtree(repo_path)

        # Step 2: Clone the repository locally
        logger.info(f"Cloning repository from {repo_url} to {repo_path}")
        git.Repo.clone_from(repo_url, repo_path)
        logger.info(f"Repository cloned successfully to {repo_path}")

        # Clone YARA rules before running YARA scan
        clone_result = clone_yara_rules(YARA_RULES_REPO_URL, YARA_RULES_FOLDER)
        if 'error' in clone_result:
            logger.error(f"Failed to clone YARA rules: {clone_result['error']}")

        # Step 3: Run local Trivy filesystem scan, ClamAV, and YARA scans
        local_trivy_fs_scan_result = await run_trivy_fs_scan(repo_path)
        local_clamav_fs_scan_result = run_clamav_fs_scan(repo_path)
        local_yara_scan_result = run_yara_scan(repo_path, YARA_RULES_FOLDER)
        local_trivy_image_result = run_trivy_repo_scan(repo_path)

        # Collect all scan results
        return [
            remote_repo_scan_result,
            local_trivy_fs_scan_result,
            local_clamav_fs_scan_result,
            local_yara_scan_result,
            local_trivy_image_result
        ]

    except Exception as e:
        logger.error(f"Repository scan failed: {e}")
        return [{"scan_type": "Repo Clone", "error": str(e)}]