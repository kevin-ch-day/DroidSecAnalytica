import os
import shutil

def delete_pycache_and_pyc_files(dry_run=False):
    """
    Recursively deletes all __pycache__ directories and .pyc files
    within the current project directory (DroidSecAnalytica).

    Args:
        dry_run (bool): If True, only prints what would be deleted (no actual deletion).
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))  # Get the script's directory
    print(f"\nScanning for '__pycache__' directories and .pyc files in: {current_dir}\n")

    pycache_count = 0
    pyc_file_count = 0

    # Walk through all directories
    for foldername, subfolders, filenames in os.walk(current_dir):

        # Delete __pycache__ directories
        for subfolder in subfolders:
            if subfolder == "__pycache__":
                pycache_path = os.path.join(foldername, subfolder)
                print(f"[DELETING] Removing directory: {pycache_path}")
                
                if not dry_run:
                    try:
                        shutil.rmtree(pycache_path, ignore_errors=True)
                        pycache_count += 1
                    except Exception as e:
                        print(f"[ERROR] Could not delete {pycache_path}: {e}")

        # Delete .pyc files
        for filename in filenames:
            if filename.endswith(".pyc"):
                pyc_file_path = os.path.join(foldername, filename)
                print(f"[DELETING] Removing file: {pyc_file_path}")

                if not dry_run:
                    try:
                        os.remove(pyc_file_path)
                        pyc_file_count += 1
                    except Exception as e:
                        print(f"[ERROR] Could not delete {pyc_file_path}: {e}")

    # Summary
    print("\n*** CLEANUP SUMMARY ***")
    print("===========================================")
    print(f" Removed {pycache_count} '__pycache__' directories.")
    print(f" Removed {pyc_file_count} '.pyc' files.")
    print("\n Cleanup Completed.")

# Run the cleanup script
if __name__ == "__main__":
    delete_pycache_and_pyc_files(dry_run=False)  # Set dry_run=True to preview deletions
