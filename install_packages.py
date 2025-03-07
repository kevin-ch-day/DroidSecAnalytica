import subprocess
import sys
import logging
import time

# Configure logging
log_file = "logs\install_packages.log"
logging.basicConfig(
    filename=log_file, level=logging.INFO,
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

def run_command(command):
    """Run a shell command and handle errors."""
    try:
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {e}")
        return False

def install_packages():
    """Upgrade pip and install packages."""
    print("\nUpgrading pip...\n")
    logging.info("Upgrading pip...")
    
    if not run_command([sys.executable, "-m", "pip", "install", "--upgrade", "pip"]):
        print("Failed to upgrade pip. Check the log file.")
        return

    print("\nInstalling required packages...\n")
    logging.info("Installing required packages...")

    start_time = time.time()
    
    # Install all packages at once (faster)
    command = [sys.executable, "-m", "pip", "install", "-U"] + packages
    success = run_command(command)

    elapsed_time = round(time.time() - start_time, 2)

    if success:
        print("\nAll packages installed successfully!")
        logging.info("All packages installed successfully.")
    else:
        print("\nSome packages may have failed to install. Check the log for details.")
        logging.warning("Some packages may have failed to install.")

    print(f"Installation completed in {elapsed_time} seconds.")
    logging.info(f"Installation completed in {elapsed_time} seconds.")

if __name__ == "__main__":
    install_packages()
