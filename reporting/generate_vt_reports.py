# generate_report.py

from . import vt_report_sections

def ask_user_for_sections():
    # Enhanced prompt with clearer instructions.
    print("\nSelect sections to include in your VirusTotal Analysis Report:")
    sections = ['summary_intro', 'analysis_result', 'other_sections', 'conclusion']
    for i, section in enumerate(sections, start=1):
        print(f"  {i}. {section.replace('_', ' ').capitalize().replace(' ', ' & ')}")
    
    # User input for section selection with additional instructions for clarity.
    selected = input("Enter the section numbers separated by commas (e.g., 1,2,4) or 'all' for the full report: ")
    if selected.lower() == 'all':  # Allow users to select all sections with 'all'.
        return sections

    selected_indices = [int(s.strip()) - 1 for s in selected.split(',') if s.strip().isdigit()]  # Process input.
    return [sections[i] for i in selected_indices if i < len(sections)]  # Return selected sections.

def generate_selected_sections(report, selected_sections):
    # Maps section names to functions for generating those sections.
    section_functions = {
        'summary_intro': vt_report_sections.print_summary_intro,
        'analysis_result': vt_report_sections.print_analysis_result,
        'other_sections': vt_report_sections.print_other_sections,
        'conclusion': vt_report_sections.print_conclusion,
    }
    
    # Execute functions for selected sections.
    for section in selected_sections:
        if section in section_functions:
            print("\n" + "=" * 20)  # Visual separator for each section.
            section_functions[section](report)

def print_vt_report(report):
    if not report:
        print("\n[Error] No report data available.")  # Error handling with clearer message.
        return
    selected_sections = ask_user_for_sections()  # User selects report sections.

    print("\nVirusTotal Analysis Report")  # Report title.
    print("=" * 50)  # Header separator for aesthetic purpose.

    generate_selected_sections(report, selected_sections)  # Generate user-selected sections.

    print("=" * 50)  # Footer separator for a neat conclusion.
    print("\nReport generation complete.")  # Inform the user that report generation is complete.

