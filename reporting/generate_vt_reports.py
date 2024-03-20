# generate_vt_reports.py

from . import vt_report_sections
import logging

# Setup basic configuration for logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def ask_user_for_sections():
    print("\nSelect sections to include in your VirusTotal Analysis Report:")
    sections = ['summary_intro', 'analysis_result', 'other_sections', 'conclusion']
    for i, section in enumerate(sections, start=1):
        print(f"  {i}. {section.replace('_', ' ').title().replace('And', '&')}")
    
    selected = input("Enter section numbers separated by commas (e.g., 1,2,4), or type 'all' for the full report: ")
    if selected.lower() == 'all':
        return sections

    # Process user input, ensuring valid selections are returned
    selected_indices = [int(s.strip()) - 1 for s in selected.split(',') if s.strip().isdigit() and int(s.strip()) <= len(sections)]
    return [sections[i] for i in selected_indices if i < len(sections)]

def generate_selected_sections(report, selected_sections):
    section_functions = {
        'summary_intro': vt_report_sections.print_summary_intro,
        'analysis_result': vt_report_sections.print_analysis_result,
        'other_sections': vt_report_sections.print_other_sections,
        'conclusion': vt_report_sections.print_conclusion,
    }

    for section in selected_sections:
        if section in section_functions:
            logging.info(f"Generating section: {section}")
            section_functions[section](report)

def print_vt_report(vt_data):
    if not vt_data:
        logging.error("No report data available. Please ensure the VirusTotal analysis has been conducted.")
        return
    
    selected_sections = ask_user_for_sections()

    print("\nVirusTotal Analysis Report\n" + "=" * 50)
    generate_selected_sections(vt_data, selected_sections)
    print("=" * 50 + "\nReport generation complete.")

