# create_analysis_report.py

import datetime
from fpdf import FPDF
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, Spacer, SimpleDocTemplate, Image, Table, TableStyle
from reportlab.lib import colors

from database import DBConnectionManager

def comprehensive_analysis_report():
    filename = 'output/analysis.txt'
    print("Starting comprehensive analysis data saving...")

    try:
        conn = DBConnectionManager.connect_to_database()
        cursor = conn.cursor()

        with open(filename, 'w') as f:
            f.write('--- Analysis of Android Malware Hashes ---\n\n')
            write_total_entries(cursor, f)
            write_category_analysis(cursor, f)
            write_year_month_analysis(cursor, f)
            save_top_hashes(cursor)

            print(f"Comprehensive analysis data successfully saved to {filename}")

    except IOError as error:
        print(f"Error writing analysis to file: {error}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        DBConnectionManager.close_database_connection(conn)


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

def create_additional_report():
    filename = 'output/additional_report.pdf'
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    
    content = []
    
    # Executive Summary
    content.append(Paragraph("Executive Summary", styles['Heading1']))
    executive_summary_text = """
    <para align=justify>
    This executive summary provides a high-level overview of the comprehensive analysis conducted on the
    Android malware hashes dataset. Our analysis has uncovered significant trends and patterns that have
    implications for cybersecurity measures and malware tracking efforts.
    </para>
    """
    content.append(Paragraph(executive_summary_text, styles['BodyText']))
    content.append(Spacer(1, 12))
    
    # Methodology
    content.append(Paragraph("Methodology", styles['Heading1']))
    methodology_text = """
    <para align=justify>
    The methodology section delineates the systematic approach adopted in this analysis, encompassing data
    collection, preprocessing, exploratory data analysis, and the application of advanced statistical methods
    and machine learning algorithms for predictive modeling and clustering.
    </para>
    """
    content.append(Paragraph(methodology_text, styles['BodyText']))
    content.append(Spacer(1, 12))
    
    # Interpretation of Results
    content.append(Paragraph("Interpretation of Results", styles['Heading1']))
    interpretation_text = """
    <para align=justify>
    The interpretation of results section provides an in-depth discussion of the analysis outcomes. It deciphers
    the visualizations, explains the significance of the identified clusters, and offers insights drawn from the
    patterns observed in the malware name distributions.
    </para>
    """
    content.append(Paragraph(interpretation_text, styles['BodyText']))
    content.append(Spacer(1, 12))
    
    # Include some images from the analysis
    content.append(Paragraph("Cluster Distribution", styles['Heading2']))
    content.append(Image('output/combined_category_clusters.png', width=500, height=250))
    content.append(Spacer(1, 12))
    
    # Include a table of data if needed
    content.append(Paragraph("Sample Data Table", styles['Heading2']))
    data = [['Header 1', 'Header 2', 'Header 3'], ['Cell 1', 'Cell 2', 'Cell 3']]
    table = Table(data)
    table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                               ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                               ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                               ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                               ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                               ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                               ('GRID', (0, 0), (-1, -1), 1, colors.black)]))
    content.append(table)
    

    # Build PDF
    doc.build(content)
    print(f"The additional report has been created: {filename}")
