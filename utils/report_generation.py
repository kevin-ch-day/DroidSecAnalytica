# report_generation.py

import os
from fpdf import FPDF

import datetime

# Function to add the title page to the PDF report with the current date
def add_title_page(pdf):
    pdf.set_title('Master of Science Graduate Project')
    pdf.set_author('Your Name')

    current_date = datetime.date.today().strftime('%Y-%m-%d')

    pdf.add_page()
    pdf.set_title('Master of Science Graduate Project')
    pdf.chapter_title('Title Page:')
    pdf.cell(0, 30, '', 0, 1)
    pdf.set_font('Arial', 'B', 24)
    pdf.cell(0, 20, 'VirusTotal Analysis Report', 0, 1, 'C')
    pdf.set_font('Arial', '', 14)
    pdf.cell(0, 10, 'Submitted in Partial Fulfillment of the Requirements', 0, 1, 'C')
    pdf.cell(0, 10, 'for the Degree of Master of Science', 0, 1, 'C')
    pdf.cell(0, 10, 'Department of Computer Science', 0, 1, 'C')
    pdf.cell(0, 10, 'University Name', 0, 1, 'C')
    pdf.cell(0, 10, f'Date: {current_date}', 0, 1, 'C')

# Function to generate a comprehensive report
def generate_report(analysis_df, pdf_filename, *hash_values):
    class PDF(FPDF):
        def header(self):
            self.set_font('Arial', 'B', 14)
            self.cell(0, 10, 'VirusTotal Analysis Report', 0, 1, 'C')
            self.ln(10)

        def chapter_title(self, title):
            self.set_font('Arial', 'B', 12)
            self.cell(0, 10, title, 0, 1, 'L')
            self.ln(10)

        def chapter_body(self, body):
            self.set_font('Arial', '', 12)
            self.multi_cell(0, 10, body)
            self.ln()

    pdf = PDF()
    pdf.add_page()

    add_title_page(pdf)

    pdf.add_page()
    pdf.set_title('Table of Contents')
    pdf.chapter_title('Table of Contents:')
    pdf.multi_cell(0, 10, '1. File Details', 0, 1, 'L')
    pdf.multi_cell(0, 10, '2. Vote Statistics', 0, 1, 'L')
    pdf.multi_cell(0, 10, '3. Classification', 0, 1, 'L')
    pdf.multi_cell(0, 10, '4. Detailed Scan Results', 0, 1, 'L')
    pdf.multi_cell(0, 10, '5. Malicious Votes Distribution', 0, 1, 'L')
    pdf.multi_cell(0, 10, '6. Conclusion', 0, 1, 'L')

    pdf.add_page()
    pdf.set_title('File Details')
    pdf.chapter_title('1. File Details:')
    
    # Create a dictionary with default values for hash values
    hash_details = {
        'MD5': 'N/A',
        'SHA1': 'N/A',
        'SHA256': 'N/A'
    }
    
    # Update the dictionary with provided hash values
    for hash_value in hash_values:
        hash_details[hash_value] = analysis_df[hash_value].iloc[0]
    
    file_details = [f"{key}: {value}" for key, value in hash_details.items()]
    pdf.chapter_body('\n'.join(file_details))

    pdf.add_page()
    pdf.set_title('Vote Statistics')
    pdf.chapter_title('2. Vote Statistics:')
    vote_statistics = [
        f"Malicious Votes: {analysis_df['Malicious Count'].iloc[0]}",
        f"Harmless Votes: {analysis_df['Benign Count'].iloc[0]}",
        f"Suspicious Votes: {analysis_df['Suspicious Count'].iloc[0]}",
        f"Undetected Votes: {analysis_df['Undetected Count'].iloc[0]}",
        f"Total Votes: {analysis_df['Total Scans'].iloc[0]}",
        f"Malicious Percentage: {analysis_df['Malicious Percentage'].iloc[0]}"
    ]
    pdf.chapter_body('\n'.join(vote_statistics))

    pdf.set_title('Classification')
    pdf.chapter_title('3. Classification:')
    classification = [f"Classification: {analysis_df['Classification'].iloc[0]}"]
    pdf.chapter_body('\n'.join(classification))

    pdf.add_page()
    pdf.set_title('Detailed Scan Results')
    pdf.chapter_title('3. Detailed Scan Results:')
    detailed_scan_results = analysis_df['Detailed Scan Results'].iloc[0]
    pdf.chapter_body('\n'.join(detailed_scan_results))

    pdf.add_page()
    pdf.set_title('Malicious Votes Distribution')
    pdf.chapter_title('4. Malicious Votes Distribution:')
    pdf.image('detection_ratio_histogram.png', x=10, w=190)

    pdf.add_page()
    pdf.set_title('Conclusion')
    pdf.chapter_title('5. Conclusion:')
    pdf.multi_cell(0, 10, 'This concludes the VirusTotal analysis report.')

    pdf.output(pdf_filename)

    analysis_df.to_html('analysis_report.html', index=False)
