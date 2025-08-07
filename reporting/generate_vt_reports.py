# generate_vt_reports.py

def generate_report(andro_data, vt_data):
    """Generate and save the VirusTotal and Android data analysis report."""
    output_file = f"output\\virustotal_{vt_data.get('MD5', 'unknown')}_report.txt"
    try:
        print("Generating report...")
        with open(output_file, 'w') as f:
            write_summary_intro(vt_data, f)
            write_analysis_result(vt_data, f)
            write_andro_data_section(andro_data, f)
            write_other_sections(vt_data, f)
            write_conclusion(vt_data, f)
        print(f"Report saved to {output_file}")
    except Exception as e:
        print(f"Error generating report: {e}")

def write_summary_intro(vt_data, file):
    """Writes the summary introduction section to the file."""
    summary_stats = vt_data.get('Analysis Result', {}).get('summary_statistics', {})
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

    file.write("Report Overview\n" + "=" * 50 + "\n")
    file.write(status_message + "\n")
    file.write(status_detail + "\n")

def write_other_sections(vt_data, file):
    """Writes other sections of the report to the file."""
    file.write("\nOther Sections\n" + "=" * 50 + "\n")
    for key, value in vt_data.items():
        if key != 'Analysis Result':          
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    file.write(f"  {sub_key.capitalize()}: {sub_value}\n")
            
            elif isinstance(value, list):
                file.write(f"\n{key}\n")
                for idx, item in enumerate(value, start=1):
                    file.write(f"  - {item}\n")
            
            else:
                file.write(f"  {key.capitalize()}: {value}\n")

def write_conclusion(vt_data, file):
    """Writes the conclusion section to the file."""
    file.write("\nConclusion\n" + "=" * 50 + "\n")
    status = 'Suspicious' if 'Malicious' in vt_data.get('Analysis Result', {}).get('summary_statistics', {}) else 'Clean'
    if status == 'Suspicious':
        file.write("- [Suspicious] The file has been marked as suspicious by one or more antivirus engines.\n")
    else:
        file.write("- [Clean] No significant threats detected by the antivirus engines.\n")

def write_analysis_result(vt_data, file):
    """Writes the analysis result section to the file."""
    if "Analysis Result" in vt_data:
        try:
            summary_stats = vt_data['Analysis Result'].get('summary_statistics')
            engine_detection = vt_data['Analysis Result'].get('engine_detection')
            
            if summary_stats:
                write_summary_statistics_section(summary_stats, file)
                
            if engine_detection:
                write_engine_detection_section(engine_detection, file)
        except Exception as e:
            print(f"Error writing analysis result section to file: {e}")
    else:
        file.write("No analysis results available.\n")

def write_summary_statistics_section(summary_stats, file):
    """Writes the summary statistics section to the file."""
    file.write("\nSummary Statistics\n" + "=" * 50 + "\n")
    for key, value in summary_stats.items():
        file.write(f"{key:<20} | {value}\n")

def write_engine_detection_section(engine_detection, file):
    """Writes the engine detection results section to the file."""
    if not engine_detection:
        return
    
    # Sort the engine detection results alphabetically by engine name
    sorted_engine_detection = sorted(engine_detection, key=lambda x: x[0])

    file.write("\nEngine Detection Results\n" + "=" * 50 + "\n")
    file.write("-" * 50 + "\n")

    for engine, result in sorted_engine_detection:
        if result is not None:
            file.write("{:<20} | {}\n".format(engine, result))


def write_andro_data_section(andro_data, file):
    """Writes the Android application data section to the file."""
    file.write("\nAndroid Application Data\n" + "=" * 50 + "\n")
    if andro_data:
        file.write(f"Package Name: {andro_data.get('package', 'N/A')}\n")
        file.write(f"Main Activity: {andro_data.get('main_activity', 'N/A')}\n")
        file.write(f"Target SDK Version: {andro_data.get('target_sdk_version', 'N/A')}\n")
        file.write(f"Minimum SDK Version: {andro_data.get('min_sdk_version', 'N/A')}\n")
        file.write(f"MD5 Hash: {andro_data.get('md5', 'N/A')}\n")
        file.write(f"SHA1 Hash: {andro_data.get('sha1', 'N/A')}\n")
        file.write(f"SHA256 Hash: {andro_data.get('sha256', 'N/A')}\n")
    else:
        file.write("No Android application data available.\n")