from . import db_conn
from datetime import datetime

# List of tables to check for orphaned analysis_id values
TABLES_TO_CHECK = [
    "vt_certificates",
    #"vt_intent_filters", # Skip
    #"vt_intent_filters_actions", # Skip
    #"vt_intent_filters_categories", # Skip
    "vt_permissions",
    "vt_providers",
    "vt_receivers",
    "vt_scan_analysis",
    "vt_services"
]


# Format section titles for readability
def format_title(title):
    return f"{'=' * 80}\n{title.center(80)}\n{'=' * 80}"


# Check if a column exists in a table before querying
def check_column_exists(table_name, column_name):
    query = f"""
        SELECT COUNT(*)
        FROM information_schema.columns
        WHERE table_name = '{table_name}' AND column_name = '{column_name}'
    """
    result = db_conn.execute_query(query, fetch=True)
    return result[0][0] > 0 if result else False


# Retrieve orphaned analysis IDs from database
def get_orphaned_analysis_ids():
    orphaned_analysis_ids = {}

    for table in TABLES_TO_CHECK:
        # Validate if `analysis_id` exists in the table
        if not check_column_exists(table, "analysis_id"):
            print(f"[WARNING] Skipping table '{table}' (No 'analysis_id' column detected).")
            continue

        query = f"""
            SELECT DISTINCT t.analysis_id
            FROM {table} t
            LEFT JOIN analysis_metadata a ON t.analysis_id = a.analysis_id
            WHERE a.analysis_id IS NULL
        """
        results = db_conn.execute_query(query, fetch=True)

        if results:
            orphaned_analysis_ids[table] = [row[0] for row in results]

    return orphaned_analysis_ids


# Display orphaned records before deletion
def display_orphaned_records(orphaned_ids):
    print(format_title("ORPHANED ANALYSIS RECORDS REPORT"))

    if not orphaned_ids:
        print("No orphaned analysis records detected. The database is consistent.\n")
        return

    total_orphans = sum(len(ids) for ids in orphaned_ids.values())
    print(f"Total orphaned analysis records found: {total_orphans}\n")

    for table, ids in orphaned_ids.items():
        print(f"Table: {table} | Orphaned Records: {len(ids)}")
        print(f"Example Analysis ID(s): {', '.join(map(str, ids[:5]))}...\n" if len(ids) > 5 else f"Analysis IDs: {', '.join(map(str, ids))}\n")


# Ask the user if they want to delete orphaned records
def prompt_for_deletion(orphaned_ids):
    if not orphaned_ids:
        return

    user_choice = input("Would you like to delete these orphaned records? (yes/no): ").strip().lower()

    if user_choice == "yes":
        delete_orphaned_records(orphaned_ids)
    else:
        print("\nNo records were deleted. Orphaned records remain in the database.")


# Delete orphaned analysis records from database
def delete_orphaned_records(orphaned_ids):
    print(format_title("DELETING ORPHANED ANALYSIS RECORDS"))

    for table, ids in orphaned_ids.items():
        delete_query = f"""
            DELETE FROM {table}
            WHERE analysis_id IN ({", ".join(map(str, ids))})
        """
        db_conn.execute_query(delete_query)
        print(f"Deleted {len(ids)} orphaned records from {table}.")

    print("\nDatabase cleanup completed. All orphaned records have been removed.")


# Run the full orphaned analysis audit and cleanup
def run_orphaned_analysis_cleanup():
    current_datetime = datetime.now().strftime("%B %d, %Y %I:%M %p")
    print(format_title("ORPHANED ANALYSIS RECORD CLEANUP"))
    print(f"Date: {current_datetime}\n")

    orphaned_ids = get_orphaned_analysis_ids()
    display_orphaned_records(orphaned_ids)
    prompt_for_deletion(orphaned_ids)
