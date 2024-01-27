from utils import logging_utils
from . import vt_utils

def generate_report(response):
    try:
        data = response.get('data', {})
        if not data:
            raise ValueError("No 'data' key in response.")

        attributes = data.get('attributes', {})
        if not attributes:
            raise ValueError("No valid attributes found in the data.")

        analysis_result = {}
        summary_statistics = attributes.get('last_analysis_stats', {})
        if summary_statistics:
            analysis_result['summary_statistics'] = {
                key.capitalize(): value
                for key, value in summary_statistics.items()
            }
        
        analysis_result['engine_detection'] = parse_engine_detection(attributes)

        report = {
            "Report URL": data['links']['self'],
            "VirusTotal Threat Label": attributes['popular_threat_classification']['suggested_threat_label'],
            "File Size": vt_utils.format_file_size(attributes['size']),
            "MD5": attributes['md5'],
            "SHA1": attributes['sha1'],
            "SHA256": attributes['sha256'],
            "Last Submission Date": vt_utils.format_timestamp(attributes['last_submission_date']),
            "First Seen": vt_utils.format_timestamp(attributes['first_seen_itw_date']),
            "Last Analysis Date": vt_utils.format_timestamp(attributes['last_analysis_date']),
            "Other Names": sorted(attributes['names']),
        }
        report["Analysis Result"] = analysis_result

        return report

    except Exception as e:
        logging_utils.log_error(f"Error in analyze_and_generate_report: {e}")
        return None

def display_report(report):

    # General Information
    print("\nGeneral Information:")
    print(f"Report URL:".ljust(25), report["Report URL"])
    print(f"VirusTotal Threat Label:".ljust(25), report["VirusTotal Threat Label"])
    print(f"File Size:".ljust(25), report["File Size"])
    print(f"MD5:".ljust(25), report["MD5"])
    print(f"SHA1:".ljust(25), report["SHA1"])
    print(f"SHA256:".ljust(25), report["SHA256"])
    print(f"Last Submission Date:".ljust(25), report["Last Submission Date"])
    print(f"First Seen:".ljust(25), report["First Seen"])
    print(f"Last Analysis Date:".ljust(25), report["Last Analysis Date"])

    # Other Names
    print("\nOther Names:")
    for item in report["Other Names"]:
        print(f"  - {item}")

    # Summary Statistics
    if "Analysis Result" in report:
        summary_statistics = report["Analysis Result"].get("summary_statistics", {})
        print("\nSummary Statistics:")
        for key, value in summary_statistics.items():
            print(f"{key}:".ljust(25), value)

    # Detection Breakdown Section
    if "Analysis Result" in report:
        detection_breakdown = report["Analysis Result"].get("engine_detection", [])
        if detection_breakdown:
            print("\nDetection Breakdown:")
            for item in detection_breakdown:
                engine_name, detection_label = item[0], item[1]
                print(f"{engine_name.ljust(30)}: {detection_label}")

    print()

def write_report_to_file(report):
    report["MD5"]
    report_filename = "output/" + report["MD5"] + "_virustotal_report.txt"

    with open(report_filename, "w") as file:
        file.write("\nVirusTotal Report:")

        # General Information
        file.write("\n\nGeneral Information:")
        file.write(f"\nReport URL:".ljust(25) + report["Report URL"])
        file.write(f"\nVirusTotal Threat Label:".ljust(25) + report["VirusTotal Threat Label"])
        file.write(f"\nFile Size:".ljust(25) + report["File Size"])
        file.write(f"\nMD5:".ljust(25) + report["MD5"])
        file.write(f"\nSHA1:".ljust(25) + report["SHA1"])
        file.write(f"\nSHA256:".ljust(25) + report["SHA256"])
        file.write(f"\nLast Submission Date:".ljust(25) + report["Last Submission Date"])
        file.write(f"\nFirst Seen:".ljust(25) + report["First Seen"])
        file.write(f"\nLast Analysis Date:".ljust(25) + report["Last Analysis Date"])

        # Other Names
        file.write("\n\nOther Names:")
        for item in report["Other Names"]:
            file.write(f"\n  - {item}")

        # Summary Statistics
        if "Analysis Result" in report:
            summary_statistics = report["Analysis Result"].get("summary_statistics", {})
            file.write("\n\nSummary Statistics:")
            for key, value in summary_statistics.items():
                file.write(f"\n{key}:".ljust(25) + str(value))

        # Detection Breakdown Section
        if "Analysis Result" in report:
            detection_breakdown = report["Analysis Result"].get("engine_detection", [])
            if detection_breakdown:
                file.write("\n\nDetection Breakdown:")
                for item in detection_breakdown:
                    engine_name, detection_label = item[0], item[1]
                    file.write(f"\n{engine_name.ljust(30)}: {detection_label}")

        file.write("\n")

    print(f"Report saved to: {report_filename}")

def parse_engine_detection(attributes):
    detailed_breakdown = []
    if 'last_analysis_results' in attributes:
        sorted_results = sorted(attributes['last_analysis_results'].items(), key=lambda engine_data: engine_data[0])
        for engine, label in sorted_results:
            result = label.get('result', 'N/A')
            if result:
                detailed_breakdown.append([engine, result])
    return detailed_breakdown