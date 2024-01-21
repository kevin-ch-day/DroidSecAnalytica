# create_analysis_report.py

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, Spacer, SimpleDocTemplate, Image, Table, TableStyle
from reportlab.lib import colors

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
