import json
import datetime
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
from sklearn.cluster import KMeans
from fpdf import FPDF

from utils import app_utils
from database import DBConnectionManager

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

def hash_data_excel():
    filename = 'output/android_hash_data.xlsx'
    print("Starting Excel export...")
    try:
        with DBConnectionManager.connect_to_database() as conn:
            print("Connected to the database. Exporting data to Excel...")
            sql = "SELECT * FROM android_malware_hashes"
            df = pd.read_sql(sql, conn)
            df.to_excel(filename, index=False)
            print(f"Data successfully exported to Excel: {filename}")
    except Exception as error:
        print(f"Error exporting data to Excel: {error}")

def hash_data_csv():
    filename = 'output/android_hash_data.csv'
    print("Starting CSV export...")
    try:
        with DBConnectionManager.connect_to_database() as conn:
            print("Connected to the database. Exporting data to CSV...")
            query = "SELECT * FROM android_malware_hashes"
            df = pd.read_sql(query, conn)
            df.to_csv(filename, index=False)
            print(f"Data successfully exported to CSV: {filename}")
    except Exception as error:
        print(f"Error exporting data to CSV: {error}")

def hash_data_txt():
    filename = 'output/android_malware_data.txt'
    print("Starting data export to TXT file...")
    try:
        conn = DBConnectionManager.connect_to_database()
        print("Connected to database. Retrieving data...")
        cursor = conn.cursor()
        sql = "SELECT * FROM android_malware_hashes"
        cursor.execute(sql)
        rows = cursor.fetchall()

        if rows:
            headers = [i[0] for i in cursor.description]  # Extracting column headers
            max_lengths = [len(str(max([str(row[i]) for row in rows], key=len))) for i in range(len(headers))]
            headers_line = ' | '.join([headers[i].ljust(max_lengths[i]) for i in range(len(headers))])
            app_utils.write_data_to_file(filename, headers_line, max_lengths, rows)
            print(f"Data successfully written to TXT file: {filename}")
        else:
            print("No data found in the database to export.")

        DBConnectionManager.close_database_connection(conn)
    except Exception as error:
        print(f"Error writing data to TXT file: {error}")


def save_top_hashes(cursor):
    filename = 'output/hash_analysis.txt'
    print("Generating top hash analysis...")
    try:
        with open(filename, 'a') as analysis_file:
            analysis_file.write("\nTop 10 Most Common Hashes:\n")
            app_utils.write_top_hashes("MD5 Hashes", analysis_file, cursor, "md5")
            app_utils.write_top_hashes("SHA1 Hashes", analysis_file, cursor, "sha1")
            app_utils.write_top_hashes("SHA256 Hashes", analysis_file, cursor, "sha256")
            print(f"Top hashes analysis written to {filename}")
    except IOError as error:
        print(f"Error writing analysis to file: {error}")

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

def write_total_entries(cursor, file):
    print("Fetching total entries...")
    sql = "SELECT COUNT(*) FROM android_malware_hashes"
    cursor.execute(sql)
    total_entries = cursor.fetchone()[0]
    file.write(f"Total Entries: {total_entries}\n\n")

def write_category_analysis(cursor, file):
    """ Write the analysis of data by malware categories to the provided file. """
    print("Analyzing data by category...")
    sql = "SELECT malware_name_1, COUNT(*) FROM android_malware_hashes GROUP BY malware_name_1"
    cursor.execute(sql)
    category_counts = cursor.fetchall()

    if not category_counts:
        file.write("No category data available.\n\n")
        return

    for category, count in category_counts:
        file.write(f"**{category}**\n")
        file.write(f"Category Count: {count} entries\n")

        # Analyze similarities within malware categories
        similar_categories = app_utils.find_similar_categories(category, category_counts)
        file.write("Similar Categories: ")
        file.write(", ".join(similar_categories) if similar_categories else "None")
        file.write("\n\n")

def write_year_month_analysis(cursor, file):
    """ Write the analysis of data by year and month to the provided file. """
    print("Analyzing data by year and month...")
    sql = "SELECT year, month, COUNT(*) FROM android_malware_hashes GROUP BY year, month"
    cursor.execute(sql)
    year_month_counts = cursor.fetchall()

    if not year_month_counts:
        file.write("No year-month data available.\n\n")
        return

    file.write("Malware Entries by Year and Month:\n")
    for year, month, count in year_month_counts:
        year_str = f"Year: {year}" if year else "Year: Unknown"
        month_str = f"Month: {month}" if month else "Month: Unknown"
        file.write(f"{year_str}, {month_str}, Count: {count}\n")
    file.write("\n")

def write_category_analysis(cursor, file):
    print("Analyzing data by primary and secondary categories...")
    
    # Advanced Analysis for malware_name_1
    file.write("Primary Category Advanced Analysis:\n")
    advanced_category_analysis(cursor, file, 'malware_name_1')

    # Advanced Analysis for malware_name_2
    file.write("\nSecondary Category Advanced Analysis:\n")
    advanced_category_analysis(cursor, file, 'malware_name_2')

    # Combined Analysis of both categories
    file.write("\nCombined Category Advanced Analysis:\n")
    write_combined_category_data(cursor, file)

def advanced_category_analysis(cursor, file, category_column):
    """ Advanced helper function to write category data with predictive analytics and visualization. """
    sql = f"SELECT {category_column}, COUNT(*) FROM android_malware_hashes GROUP BY {category_column}"
    cursor.execute(sql)
    category_data = cursor.fetchall()

    if not category_data:
        file.write(f"No data available for {category_column}.\n\n")
        return

    # Convert data to DataFrame for advanced analysis
    df = pd.DataFrame(category_data, columns=[category_column, 'Count'])
    
    # Predictive Analytics: Example - Forecasting future trends
    # Visualization: Category distribution
    visualize_category_distribution(df, category_column)

    # Writing analysis results to file
    for category, count in category_data:
        category_str = category if category else "Unknown"
        file.write(f"**{category_str}**\n")
        file.write(f"Category Count: {count} entries\n")
        # Additional advanced analysis here
        file.write("\n")

def write_combined_category_data(cursor, file):
    """ Advanced analysis of combined category data. """
    sql = """
        SELECT malware_name_1, malware_name_2, COUNT(*) 
        FROM android_malware_hashes 
        GROUP BY malware_name_1, malware_name_2
    """
    cursor.execute(sql)
    combined_counts = cursor.fetchall()

    if not combined_counts:
        file.write("No combined category data available.\n\n")
        return

    # Advanced Analysis: Cross-category comparison, correlation analysis, etc.
    for name1, name2, count in combined_counts:
        name1_str = name1 if name1 else "Unknown"
        name2_str = name2 if name2 else "Unknown"
        file.write(f"Primary: **{name1_str}**, Secondary: **{name2_str}**, Count: {count}\n")
        
def visualize_category_distribution(df, category_column):
    plt.figure(figsize=(12, 8))
    sns.barplot(x=category_column, y='Count', data=df.sort_values('Count', ascending=False))
    plt.title(f'Distribution of {category_column} - Total Counts')
    plt.xlabel('Category')
    plt.ylabel('Total Count')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()  # Adjust the plot to ensure everything fits without overlapping
    plt.savefig(f'output/{category_column}_distribution.png')
    plt.close()
    
def write_combined_category_data(cursor, file):
    """ Advanced analysis of combined category data with clustering. """
    sql = """
        SELECT malware_name_1, malware_name_2, COUNT(*) 
        FROM android_malware_hashes 
        GROUP BY malware_name_1, malware_name_2
    """
    cursor.execute(sql)
    combined_data = cursor.fetchall()

    if not combined_data:
        file.write("No combined category data available.\n\n")
        return

    # Clustering for Cross-Category Insights
    df_combined = pd.DataFrame(combined_data, columns=['Name1', 'Name2', 'Count'])
    cluster_insights(df_combined)

    # Writing combined category analysis
    for name1, name2, count in combined_data:
        file.write(f"Primary: **{name1 if name1 else 'Unknown'}**, Secondary: **{name2 if name2 else 'Unknown'}**, Count: {count}\n")

def cluster_insights(df):
    # Preparing the data for clustering
    # For demonstration, let's assume we're using 'Count' as the feature for clustering
    X = df[['Count']].values
    
    # Determine the optimal number of clusters, for this example we choose 3
    kmeans = KMeans(n_clusters=3, random_state=0).fit(X)
    df['Cluster'] = kmeans.labels_

    # Visualization of Clusters
    visualize_clusters(df)


def visualize_clusters(df):
    plt.figure(figsize=(12, 8))
    
    # Adjust the transparency (alpha) if points are dense
    sns.scatterplot(data=df, x='Name1', y='Count', hue='Cluster', palette='viridis', alpha=0.7)
    
    plt.title('Cluster Distribution in Combined Category Data')
    plt.xlabel('Primary Category')
    plt.ylabel('Count')
    
    # Ensure the legend does not obscure the data
    plt.legend(title='Cluster', loc='upper right')
    
    # Rotate x-axis labels if they are dense
    plt.xticks(rotation=45, ha='right')
    
    # Annotations for key findings or unusual data points
    # Example: annotating the highest count in each cluster
    for cluster in df['Cluster'].unique():
        cluster_data = df[df['Cluster'] == cluster]
        highest_point = cluster_data.loc[cluster_data['Count'].idxmax()]
        plt.text(x=highest_point['Name1'], y=highest_point['Count'], s='Highest', color='red')
    
    plt.tight_layout()  # Adjust the plot to ensure everything fits without overlapping
    plt.savefig('output/combined_category_clusters.png')
    plt.close()

def visualize_category_distribution_interactive(df, category_column):
    fig = px.bar(
        df.sort_values('Count', ascending=False), 
        x=category_column, 
        y='Count',
        title=f'Distribution of {category_column} - Total Counts',
        labels={'Count': 'Total Count', category_column: 'Category'},
        template='plotly_white'
    )
    fig.update_layout(
        xaxis_title="Category",
        yaxis_title="Total Count",
        xaxis_tickangle=-45
    )
    fig.write_image(f'output/{category_column}_distribution.png')
    fig.show()

def visualize_clusters_interactive(df):
    fig = px.scatter(
        df, 
        x='Name1', 
        y='Count', 
        color='Cluster', 
        title='Cluster Distribution in Combined Category Data',
        labels={'Count': 'Count', 'Name1': 'Primary Category'},
        template='plotly_white',
        hover_data=['Name1', 'Name2']  # Show additional data on hover
    )
    fig.update_traces(marker=dict(size=12, opacity=0.8, line=dict(width=2, color='DarkSlateGrey')))
    fig.update_layout(
        xaxis_title="Primary Category",
        yaxis_title="Count",
        legend_title="Cluster"
    )
    fig.write_image('output/combined_category_clusters.png')
    fig.show()

# Function to write JSON data to a file
def write_json_to_file(filename, data):
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)
    print(f"Data written to file: {filename}")
