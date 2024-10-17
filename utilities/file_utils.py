
import os
import logging
import tarfile
import zipfile
import magic

logger = logging.getLogger(__name__)

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
