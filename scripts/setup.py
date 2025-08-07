"""Project setup script.

Installs dependencies from requirements.txt and verifies database connectivity.
"""
import argparse
import os
import subprocess
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

REQ_FILE = os.path.join(ROOT_DIR, "requirements.txt")


def install_requirements():
    """Install required Python packages using pip."""
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", REQ_FILE])


def check_database_connection():
    """Attempt to connect to the configured database."""
    try:
        from database.db_conn import test_connection
    except Exception as e:
        print(f"Unable to import database connector: {e}")
        raise SystemExit(1)
    try:
        test_connection()
    except Exception as e:
        print(f"Database connection failed: {e}")
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description="Set up DroidSecAnalytica")
    parser.add_argument(
        "--skip-install",
        action="store_true",
        help="Skip installing Python dependencies",
    )
    parser.add_argument(
        "--skip-db-check",
        action="store_true",
        help="Skip database connection test",
    )
    args = parser.parse_args()

    if not args.skip_install:
        print("Installing Python dependencies...")
        install_requirements()

    if not args.skip_db_check:
        print("Checking database connection...")
        check_database_connection()

    print("Setup routine complete.")


if __name__ == "__main__":
    main()
