# generate_reports.py

def display_report(report):

    # General Information
    print("\nGeneral Information:")
    print(f"Report URL: {report['Report URL']}")
    print(f"VirusTotal Threat Label: {report['VirusTotal Threat Label']}")
    print(f"File Size: {report['File Size']}")
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