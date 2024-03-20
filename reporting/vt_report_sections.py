# report_sections.py

from . import vt_report_utils

def print_summary_intro(report):
    vt_report_utils.format_section_title("Report Overview")
    # Dynamically determining the overall status based on the report's findings.
    malicious_count = report.get('Analysis Result', {}).get('summary_statistics', {}).get('Malicious', 0)
    status = 'Suspicious' if malicious_count > 0 else 'Clean'

    # Crafting a detailed and engaging introduction to the report.
    intro_message = ("Welcome to the VirusTotal Analysis Report. This document provides a comprehensive "
                     "assessment of the analyzed file, employing the collective intelligence of numerous "
                     "antivirus engines and datasets to gauge the potential security risks.\n")
    
    # Elaborating on the significance of the overall status, with a focus on actionable insights.
    status_message = f"Overall File Status: {status}"
    if malicious_count > 0:
        status_detail = (f"This file has been flagged as Suspicious by {malicious_count} antivirus engines, "
                         "indicating potential harmful activities or characteristics commonly associated with malware.")
    else:
        status_detail = ("No significant threats have been detected, suggesting the file is generally considered Safe. "
                         "However, it's essential to remain cautious as new threats can emerge.")
    
    # Setting expectations for the detailed analysis that follows.
    follow_up = ("Detailed findings, including specific antivirus engine results and detected threats, are "
                 "presented in the subsequent sections to provide a thorough understanding of the file's security posture.")

    # Printing the compiled messages.
    print(intro_message)
    print(status_message)
    print(status_detail)
    print("\n" + follow_up)


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
            if isinstance(value, dict):
                vt_report_utils.print_dictionary_items(f"Details: {key}", value)
            elif isinstance(value, list) and value:
                vt_report_utils.print_list_items(f"List: {key}", value)
            else:
                # Improved formatting for individual key-value pairs.
                vt_report_utils.format_section_title(key)
                print(value)

def print_conclusion():
    # Further enhanced conclusion with more specific actionable insights and recommendations.
    vt_report_utils.format_section_title("Conclusion")
    
    # Detailed advice based on analysis status.
    print("The analysis has concluded, offering a detailed perspective on the security implications associated with the file in question. "
          "Based on the findings, the following recommendations are provided:")
    
    # Conditionally render advice based on the overall status, which could be extended with more conditions as needed.
    if 'Suspicious' in globals().get('status', 'Clean'):
        print("- The file has been marked as Suspicious by one or more antivirus engines. "
              "It's strongly advised to not proceed with its execution or distribution until further manual verification is conducted. ")
    else:
        print("- The file appears to be Clean with no significant threats detected by the antivirus engines. ")
    
    # General advice applicable in all scenarios.
    print("\nRegardless of the file's current assessment, maintaining an up-to-date cybersecurity posture is crucial. ")

