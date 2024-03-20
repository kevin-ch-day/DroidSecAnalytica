# report_sections.py

from . import vt_report_utils

def print_summary_intro(report):
    vt_report_utils.format_section_title("Report Overview")

    malicious_count = report.get('Analysis Result', {}).get('summary_statistics', {}).get('Malicious', 0)
    undetected_count = report.get('Analysis Result', {}).get('summary_statistics', {}).get('Undetected', 0)
    
    status = 'Suspicious' if malicious_count else 'Clean'

    intro_message = "VirusTotal Analysis Report."
    status_message = f"Overall File Status: {status}."
    
    if status == 'Suspicious':
        status_detail = (f"The analysis flagged this file as suspicious based on detections from {malicious_count} antivirus engines. "
                         f"Conversely, {undetected_count} engines did not identify any threats.")
    else:
        status_detail = "No significant threats were detected by the antivirus engines, suggesting the file is generally considered safe."

    follow_up = "Below, there is a detailed breakdown of the findings, including insights into the antivirus engine results and any identified threats."

    # Combining and printing the constructed message parts for a smooth introduction.
    print("\n".join([intro_message, status_message, status_detail, "\n" + follow_up]))

def print_analysis_result(report):
    # Check for the presence of 'Analysis Result' in the report for safety.
    if "Analysis Result" in report:
        summary_stats = [["Statistic", "Count"]] + list(report['Analysis Result']['summary_statistics'].items())
        engine_detection = [["Engine", "Result"]] + report['Analysis Result']['engine_detection']
        
        # Using table format to display summary statistics and engine detection results for better readability.
        vt_report_utils.print_table_section("Summary Statistics", summary_stats)
        vt_report_utils.print_table_section("Engine Detection Results", engine_detection)
    else:
        print("No analysis results available.")

def print_other_sections(report):
    # Filtering out 'Analysis Result' to avoid duplication.
    excluded_keys = ["Analysis Result"]
    for key, value in report.items():
        if key not in excluded_keys:
            # Check if the value is a dictionary
            if isinstance(value, dict):
                print_nested_dictionary(key, value)
            # Check if the value is a list
            elif isinstance(value, list) and value:
                print_list_section(key, value)
            # Print individual key-value pairs
            else:
                print_key_value_pair(key, value)

def print_nested_dictionary(title, dictionary, level=1):
    """Recursively prints nested dictionaries with proper indentation."""
    vt_report_utils.format_section_title(title)
    for key, value in dictionary.items():
        # Add indentation based on the level of nesting
        indentation = "  " * level
        if isinstance(value, dict):
            print_nested_dictionary(f"{indentation}{key}", value, level + 1)
        else:
            print(f"{indentation}{key}: {value}")

def print_list_section(title, list_items):
    """Prints items of a list under a given title."""
    vt_report_utils.format_section_title(title)
    for item in list_items:
        print(f"- {item}")

def print_key_value_pair(key, value):
    """Prints a single key-value pair."""
    print(f"{key}: {value}")


def print_conclusion():
    # Further enhanced conclusion with more specific actionable insights and recommendations.
    vt_report_utils.format_section_title("Conclusion")
    
    print("Based on the findings, the following recommendations are provided:")
    if 'Suspicious' in globals().get('status', 'Clean'):
        print("- [Suspicions] The file has been marked as Suspicious by one or more antivirus engines. "
              "It's advised to not proceed with its execution or distribution. ")
    else:
        print("- [Clean] No significant threats detected by the antivirus engines. ")
    

