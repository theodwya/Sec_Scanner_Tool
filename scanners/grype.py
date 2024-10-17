
import os
import logging
import asyncio

logger = logging.getLogger(__name__)

async def run_grype_image_scan(image_name):
    """Run Grype image scan."""
    logger.info(f"Running Grype image scan on: {image_name}")
    scan_output_path = os.path.join('/app/scan-results', 'grype_image_scan.log')
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
