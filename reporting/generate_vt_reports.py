import os
from . import vt_report_sections

def parse_selected_sections(selected, max_index):
    """Parse the user-selected sections."""
    sections = []
    try:
        selected_indices = [int(s.strip()) - 1 for s in selected.split(',') if s.strip().isdigit()]
        sections = [index for index in selected_indices if 0 <= index < max_index]
    except ValueError:
        print("Invalid input format for selected sections.")
    print("Selected sections:", sections)
    return sections

def generate_report_sections(report, selected_sections, output_file):
    """Generate selected report sections and write them to the output file."""
    section_functions = {
        'summary_intro': vt_report_sections.write_summary_intro_to_file,
        'analysis_result': vt_report_sections.write_analysis_result_to_file,
        'other_sections': vt_report_sections.write_other_sections_to_file,
        'conclusion': vt_report_sections.write_conclusion_to_file,
    }

    with open(output_file, 'a') as f:
        for section_index in selected_sections:
            section_name = get_section_name_by_index(section_index)
            if section_name in section_functions:
                print(f"Generating section: {section_name}")
                write_section_header(section_name, f)
                try:
                    section_functions[section_name](report, f)  # Pass file object to write to file
                except Exception as e:
                    print(f"Error generating section '{section_name}': {e}")
            else:
                print(f"Warning: Section '{section_name}' not found in section functions.")

def get_section_name_by_index(index):
    """Get the section name based on its index."""
    sections = ['summary_intro', 'analysis_result', 'other_sections', 'conclusion']
    return sections[index]

def write_section_header(section_name, file):
    """Write section header to the file."""
    file.write("\n" + "=" * 50 + f"\n{section_name.replace('_', ' ').title()}\n" + "=" * 50 + "\n")

def generate_report(vt_data):
    """Generate and save the VirusTotal analysis report."""
    if not vt_data:
        print("No report data available.")
        return
    
    output_dir = 'output'
    output_file = os.path.join(output_dir, f"virustotal_{vt_data['MD5']}_report.txt")
    sections = ['summary_intro', 'analysis_result', 'other_sections', 'conclusion']

    try:
        print("Generating report...")
        with open(output_file, 'w') as f:
            f.write("VirusTotal Analysis Report\n" + "=" * 50 + "\n")
            selected_sections = parse_selected_sections("1, 2, 3, 4", len(sections))
            print("Selected sections:", selected_sections)
            generate_report_sections(vt_data, selected_sections, output_file)
            f.write("=" * 50 + "\nReport generation complete.")

        print(f"Report saved to {output_file}")
    except Exception as e:
        print(f"Error generating report: {e}")
