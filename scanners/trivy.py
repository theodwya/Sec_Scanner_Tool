
import os
import logging
import asyncio

logger = logging.getLogger(__name__)

async def run_trivy_fs_scan(target_path):
    """Run Trivy filesystem scan."""
    logger.info(f"Running Trivy filesystem scan on: {target_path}")
    scan_output_path = os.path.join('/app/scan-results', 'trivy_fs_scan.log')
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
    logger.info(f"Running Trivy image scan on: {image_name}")
    scan_output_path = os.path.join('/app/scan-results', 'trivy_image_scan.log')
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

async def run_trivy_repo_scan(repo_url):
    """Run Trivy repository scan."""
    logger.info(f"Running Trivy repo scan on: {repo_url}")
    scan_output_path = os.path.join('/app/scan-results', 'trivy_repo_scan.log')
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
