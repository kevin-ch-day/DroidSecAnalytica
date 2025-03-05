from db_operations import malware_audit_queries
import pandas as pd
from datetime import datetime

def format_title(title):
    """Format section titles for better readability."""
    return f"\n{'='*100}\n{title.center(100)}\n{'='*100}"

def ensure_column_names(df, expected_columns):
    """Ensure DataFrame has correct column names."""
    if df is not None and not df.empty:
        df.columns = expected_columns
    return df

def display_section_results(title, description, df, empty_message, column_descriptions=None):
    """Display formatted results for a given section with column headers, descriptions, and explanations."""
    print(format_title(title))
    print(f"\n{description}\n")

    if df is not None and not df.empty:
        print("\nColumn Descriptions:")
        if column_descriptions:
            for col, desc in column_descriptions.items():
                print(f"   {col}: {desc}")

        print("\nResults:\n")
        print(df.to_markdown(index=False))  # Improved table format for better readability
    else:
        print(f"\n {empty_message}")

def display_analysis_summary():
    """Check and display analysis progress summary."""
    analyzed_samples, total_samples, pending_samples = malware_audit_queries.get_analysis_status()
    unanalyzed_count = malware_audit_queries.get_unanalyzed_samples()
    percentage_analyzed = (analyzed_samples / total_samples) * 100 if total_samples > 0 else 0

    print(format_title("ANALYSIS STATUS"))
    print("""
This section tracks the overall progress of the malware sample analysis.
Understanding how many samples have been processed, and how many remain unanalyzed,
helps in prioritizing security investigations and response efforts.
    """)

    print("\nAnalysis Progress Report\n")
    print(f"   Total Samples Collected: {total_samples:,}")
    print(f"   Analyzed Samples: {analyzed_samples:,} / {total_samples:,} ({percentage_analyzed:.2f}%)")
    print(f"   Pending Samples: {pending_samples:,} still require analysis.")
    print(f"   Unanalyzed Samples in Database: {unanalyzed_count:,}")

    if percentage_analyzed < 25:
        print("\nCritical Warning: Less than 25% of samples have been analyzed. Immediate action required.")
    elif percentage_analyzed < 50:
        print("\nWarning: Less than 50% of samples have been analyzed. Recommend prioritizing analysis tasks.")
    elif 50 <= percentage_analyzed < 80:
        print("\nModerate Progress: Over half of the samples have been analyzed, but further work is needed.")
    else:
        print("\nGood Progress: A significant portion of malware samples have been analyzed. Keep up the momentum.")

def run_audit():
    """Run all hash-related database checks sequentially."""
    
    # Get the current date and time
    current_datetime = datetime.now().strftime("%B %d, %Y %I:%M %p")

    print("\nHash Database Audit")
    print(f"Date: {current_datetime}")

    # Incomplete Hash Records
    df_incomplete_hashes = malware_audit_queries.get_incomplete_hash_records()
    df_incomplete_hashes = ensure_column_names(df_incomplete_hashes, ["Record_ID", "MD5", "SHA1", "SHA256", "Created_At"])
    
    display_section_results(
        "INCOMPLETE HASH RECORDS",
        """This section identifies hash records that are missing MD5, SHA1, or SHA256 values.
A complete record should have all three hash values. Missing values indicate potential issues
in data ingestion, collection, or corruption that should be reviewed.""",
        df_incomplete_hashes,
        "All records in `hash_data_ioc` have complete MD5, SHA1, and SHA256 hashes.",
        column_descriptions={
            "Record_ID": "Unique identifier for the hash record",
            "MD5": "MD5 hash of the sample",
            "SHA1": "SHA1 hash of the sample",
            "SHA256": "SHA256 hash of the sample",
            "Created_At": "Timestamp of when the record was added"
        }
    )

    # Hashes Missing from Malware Samples
    df_unlinked_hashes = malware_audit_queries.get_unlinked_hashes()
    df_unlinked_hashes = ensure_column_names(df_unlinked_hashes, ["Missing_Hash"])
    
    display_section_results(
        "UNLINKED HASHES IN DATABASE",
        """This section identifies SHA256 hashes that exist in `hash_data_ioc` but are not linked to
any malware samples in `malware_samples`. These unlinked hashes could be orphaned records,
indicating missing relationships between stored hash values and malware samples.""",
        df_unlinked_hashes,
        "No missing hashes found in `malware_samples`.",
        column_descriptions={"Missing_Hash": "SHA256 hash that is not linked to any malware sample"}
    )

    # Analysis Status Summary
    display_analysis_summary()

    # Most Common Malware Types
    df_malware_types = malware_audit_queries.get_most_common_malware()
    df_malware_types = ensure_column_names(df_malware_types, ["Malware_Type", "Occurrences"])
    
    display_section_results(
        "TOP DETECTED MALWARE TYPES",
        """This section provides an overview of the most frequently detected malware types based on
analysis results. This helps security analysts understand the prevalent threats in the dataset
and prioritize mitigation strategies accordingly.""",
        df_malware_types,
        "No malware classification data found.",
        column_descriptions={
            "Malware_Type": "Category or family of malware",
            "Occurrences": "Number of times this malware type has been detected"
        }
    )

    # Oldest Unanalyzed Samples
    df_oldest_unanalyzed = malware_audit_queries.get_oldest_unanalyzed_samples()
    df_oldest_unanalyzed = ensure_column_names(df_oldest_unanalyzed, ["SHA256", "VT_First_Submission"])
    
    display_section_results(
        "OLDEST UNANALYZED SAMPLES",
        """This section highlights the oldest malware samples that remain unanalyzed. Older samples
that are still pending investigation could indicate oversight or prioritization issues.
Analyzing these samples may uncover previously undetected threats.""",
        df_oldest_unanalyzed,
        "All collected samples have been analyzed.",
        column_descriptions={
            "SHA256": "Unique SHA256 hash of the malware sample",
            "VT_First_Submission": "Date when the sample was first submitted to VirusTotal"
        }
    )

    # Malware Submission Trends
    df_submission_trends = malware_audit_queries.get_sample_submission_trends()
    df_submission_trends = ensure_column_names(df_submission_trends, ["Year", "Month", "Submissions"])
    
    display_section_results(
        "MALWARE SUBMISSION TRENDS",
        """This section tracks the trends of malware sample submissions over time, categorized by year and month.
This helps in identifying seasonal trends in malware distribution, outbreak patterns, and
potential periods of increased cyber activity.""",
        df_submission_trends,
        "No submission trend data found.",
        column_descriptions={
            "Year": "Year of submission",
            "Month": "Month of submission",
            "Submissions": "Total number of submissions for that month"
        }
    )