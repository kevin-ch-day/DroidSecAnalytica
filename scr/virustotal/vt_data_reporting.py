# vt_analysis.py

# Python Libraries
from typing import Any

# Custom Libraries
from reporting import generate_vt_reports

def generate_vt_report_if_applicable(andro_data, vt_data):
    if vt_data and andro_data:
        try:
            print("\n** Generating Virustotal.com Report **")
            generate_vt_reports.generate_report(andro_data, vt_data)
            print("VirusTotal analysis report generated successfully.")
        except Exception as e:
            print(f"[Error] Failed to generate VirusTotal analysis report: {e}")

def create_vt_report(andro_data, vt_data):
    if vt_data and andro_data:
        try:
            generate_vt_reports.generate_report(andro_data, vt_data)
            print("VirusTotal analysis report generated successfully.")
        except Exception as e:
            print(f"Error generating VirusTotal analysis report: {e}")
    else:
        print("No VirusTotal data available to generate the report.")