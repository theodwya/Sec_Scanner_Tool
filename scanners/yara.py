import os
import git
import yara
import logging

logger = logging.getLogger(__name__)

def clone_yara_rules(rules_repo_url, rules_folder):
    """Clone or update YARA rules from the official YARA-Rules GitHub repository."""
    if os.path.exists(rules_folder):
        logger.info(f"Updating YARA rules in {rules_folder}")
        repo = git.Repo(rules_folder)
        repo.remote().pull()
    else:
        logger.info(f"Cloning YARA rules from {rules_repo_url} into {rules_folder}")
        git.Repo.clone_from(rules_repo_url, rules_folder)

def run_yara_scan(target_path, rules_folder):
    """Run YARA scan on a file or directory."""
    logger.info(f"Running YARA scan on: {target_path}")
    yara_rules_path = os.path.join(rules_folder, "malware")  # Adjust path based on YARA rules in the repo

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