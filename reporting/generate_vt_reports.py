import os
from . import vt_report_sections

def ask_user_for_sections():
    # Define available sections
    sections = ['summary_intro', 'analysis_result', 'other_sections', 'conclusion']
    
    # Print section options
    print("\nSelect sections to include in your VirusTotal Analysis Report:")
    for i, section in enumerate(sections, start=1):
        print(f"  {i}. {section.replace('_', ' ').title().replace('And', '&')}")

    # Get user input
    selected = input("Enter section numbers separated by commas (e.g., 1,2,4), or type 'all' for the full report: ")

    # Process user input
    if selected.lower() == 'all':
        return sections
    else:
        selected_indices = parse_selected_indices(selected, len(sections))
        return [sections[i] for i in selected_indices]

def parse_selected_indices(selected, max_index):
    # Parse selected indices from user input
    indices = []
    for s in selected.split(','):
        s = s.strip()
        if s.isdigit():
            index = int(s) - 1
            if 0 <= index < max_index:
                indices.append(index)
    return indices

def generate_selected_sections(report, selected_sections):
    section_functions = {
        'summary_intro': vt_report_sections.print_summary_intro,
        'analysis_result': vt_report_sections.print_analysis_result,
        'other_sections': vt_report_sections.print_other_sections,
        'conclusion': vt_report_sections.print_conclusion,
    }

    for section in selected_sections:
        if section in section_functions:
            print(f"Generating section: {section}")
            section_functions[section](report)

def print_vt_report(vt_data):
    if not vt_data:
        print("No report data available.")
        return
    
    selected_sections = ask_user_for_sections()

    output_dir = 'output'
    create_output_directory(output_dir)

    output_file = os.path.join(output_dir, f"virustotal_{vt_data['MD5']}_report.txt")

    try:
        with open(output_file, 'w') as f:
            f.write("VirusTotal Analysis Report\n" + "=" * 50 + "\n")
            for section in selected_sections:
                f.write("\n" + "=" * 50 + f"\n{section.replace('_', ' ').title()}\n" + "=" * 50 + "\n")
                generate_section_to_file(vt_data, section, f)
            f.write("=" * 50 + "\nReport generation complete.")

        print(f"Report generated and saved to {output_file}")
    except Exception as e:
        print(f"Error generating report: {e}")

def create_output_directory(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def generate_section_to_file(report, section, file):
    section_functions = {
        'summary_intro': vt_report_sections.print_summary_intro,
        'analysis_result': vt_report_sections.print_analysis_result,
        'other_sections': vt_report_sections.print_other_sections,
        'conclusion': vt_report_sections.print_conclusion,
    }

    if section in section_functions:
        file.write(section_functions[section](report))
