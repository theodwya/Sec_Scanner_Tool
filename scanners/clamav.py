import clamd
import logging

logger = logging.getLogger(__name__)

def run_clamav_fs_scan(file_path):
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