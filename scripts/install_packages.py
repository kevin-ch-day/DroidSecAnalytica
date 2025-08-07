import subprocess
import sys
import logging
import time
import os
from datetime import datetime

# Define log directory and file
log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "logs"))
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "install_packages.log")

# Configure logging
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# List of required packages
packages = [
    "cryptography",
    "matplotlib",
    "mysql-connector-python",
    "openpyxl",
    "pandas",
    "plotly",
    "pycountry",
    "reportlab",
    "requests",
    "scikit-learn",
    "seaborn",
    "tabulate"
]

def run_command(command, description=""):
    """Run a shell command and handle errors with logging."""
    try:
        result = subprocess.run(
            command, check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if description:
            logging.info(f"{description} - SUCCESS")
        return True, result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"{description} - FAILED\nSTDOUT: {e.stdout}\nSTDERR: {e.stderr}")
        return False, e.stderr.strip()

def install_packages():
    """Upgrade pip and install Python packages."""
    print("\n[INFO] Starting package installation...\n")
    logging.info("Starting installation script.")

    # Upgrade pip
    print("[INFO] Upgrading pip...")
    success, _ = run_command([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], "Upgrade pip")
    if not success:
        print("[ERROR] Failed to upgrade pip. See log for details.")
        return

    # Bulk install attempt
    print("\n[INFO] Installing packages in bulk...\n")
    start_time = time.time()
    success, _ = run_command([sys.executable, "-m", "pip", "install", "-U"] + packages, "Bulk package install")

    # Fallback: install one by one if bulk install fails
    if not success:
        print("[WARN] Bulk install failed. Installing packages individually...")
        for pkg in packages:
            print(f"[INFO] Installing: {pkg}")
            run_command([sys.executable, "-m", "pip", "install", "-U", pkg], f"Install {pkg}")

    elapsed = round(time.time() - start_time, 2)
    print(f"\n[SUCCESS] Package installation completed in {elapsed} seconds.\n")
    logging.info(f"Package installation completed in {elapsed} seconds.")

if __name__ == "__main__":
    print(f"\n--- Install Script Run: {datetime.now()} ---")
    install_packages()
