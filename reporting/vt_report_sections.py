from . import vt_report_utils

def write_summary_intro_to_file(report, file):
    """Writes the summary introduction section to the file."""
    summary_stats = report.get('Analysis Result', {}).get('summary_statistics', {})
    malicious_count = summary_stats.get('Malicious', 0)
    undetected_count = summary_stats.get('Undetected', 0)
    
    status = 'Suspicious' if malicious_count else 'Clean'
    status_message = f"Overall File Status: {status}."

    if status == 'Suspicious':
        status_detail = (
            f"The analysis flagged this file as suspicious based on detections from {malicious_count} antivirus engines. "
            f"Conversely, {undetected_count} engines did not identify any threats."
        )
    else:
        status_detail = "No significant threats were detected by the antivirus engines, suggesting the file is generally considered safe."

    file.write("\nReport Overview".center(60, "=") + "\n")
    file.write(status_message + "\n")
    file.write(status_detail + "\n")

def write_analysis_result_to_file(report, file):
    """Writes the analysis result section to the file."""
    if "Analysis Result" in report:
        summary_stats = [["Statistic", "Count"]] + list(report['Analysis Result']['summary_statistics'].items())
        engine_detection = [["Engine", "Result"]] + report['Analysis Result']['engine_detection']
        
        vt_report_utils.write_table_section_to_file("Summary Statistics", summary_stats, file)
        vt_report_utils.write_table_section_to_file("Engine Detection Results", engine_detection, file)
    else:
        file.write("No analysis results available.\n")

def write_other_sections_to_file(report, file):
    """Writes other sections of the report to the file."""
    excluded_keys = ["Analysis Result"]
    for key, value in report.items():
        if key not in excluded_keys:
            if isinstance(value, dict):
                write_nested_dictionary_to_file(key, value, file)
            elif isinstance(value, list) and value:
                vt_report_utils.write_list_section_to_file(key, value, file)
            else:
                vt_report_utils.write_key_value_pair_to_file(key, value, file)

def write_nested_dictionary_to_file(title, dictionary, file, level=1):
    """Recursively writes nested dictionaries to the file."""
    vt_report_utils.write_section_title_to_file(title, file)
    for key, value in dictionary.items():
        indentation = "  " * level
        if isinstance(value, dict):
            write_nested_dictionary_to_file(f"{indentation}{key}", value, file, level + 1)
        else:
            file.write(f"{indentation}{key}: {value}\n")

def write_conclusion_to_file(file):
    """Writes the conclusion section to the file."""
    vt_report_utils.write_section_title_to_file("Conclusion", file)
    
    file.write("Based on the findings, the following recommendations are provided:\n")
    if 'Suspicious' in globals().get('status', 'Clean'):
        file.write("- [Suspicions] The file has been marked as Suspicious by one or more antivirus engines. "
              "It's advised to not proceed with its execution or distribution.\n")
    else:
        file.write("- [Clean] No significant threats detected by the antivirus engines.\n")
