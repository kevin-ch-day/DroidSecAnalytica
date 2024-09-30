# reporting_menu.py

import pandas as pd
from db_operations import db_analysis_func
from . import report_data_func
from utils import user_prompts, app_display, file_output_func, statistical_visuals

# Set up logging
REPORTING_LOG_PATH = 'logs/reporting.log'

def report_generation_menu():
    while True:
        menu_title = "Reporting Menu"
        menu_options = {
            1: "Detection Results",
            2: "Permisssion Analysis Results I",
            3: "Permisssion Analysis Results II"
        }
        app_display.display_menu(menu_title, menu_options)
        user_choice = user_prompts.user_menu_choice("\nChoice: ", [str(i) for i in range(4)])

        # Report to main menu
        if user_choice == '0':
            break
        
        # virusTotalDetectionResults
        elif user_choice == '1':
            virusTotalDetectionResults()

        # permission_reports_alpha
        elif user_choice == '2':
            permission_reports_alpha()
        
        # permission_reports_beta
        elif user_choice == '3':
            permission_reports_beta()

        # permission_reports_gamma
        elif user_choice == '3':
            print("FIX: permission_reports_gamma() COMMENTED OUT [!!]")
            #permission_reports_gamma()
            pass

        # Invalid choice
        else:
            print("Invalid choice.")

        user_prompts.pause_until_keypress()

def virusTotalDetectionResults():
    excel_path = "virusTotalDetectionResults.xlsx"
    results = db_analysis_func.fetch_overall_vt_detection()
    df = pd.DataFrame(results)

    # Cleaning and formatting data as specified
    df['DroidSecAnalytica'] = df['DroidSecAnalytica'].str.replace('AndroidOS:', '')
    df['DroidSecAnalytica'] = df['DroidSecAnalytica'].str.replace('Android:', '')
    df['Kaspersky'] = df['Kaspersky'].str.replace('HEUR:', '', regex=False)
    
    # Rename 'Malicious/Total AV' to 'AV Detection' and reorder columns
    df['AV Detection'] = df['Malicious'].astype(str) + '/' + df['Total AV'].astype(str)
    
    # Round '%' column to two decimals and append '%'
    df['%'] = df['%'].astype(float).round(2).astype(str) + '%'
    
    # Extracting classification from 'DroidSecAnalytica'
    df['Classification'] = df['DroidSecAnalytica'].str.extract(r'\[(.*?)\]')

    # Check if 'Malicious' and 'Total AV' columns exist before attempting to drop them
    if 'Malicious' in df.columns and 'Total AV' in df.columns:
        df.drop(['Malicious', 'Total AV'], axis=1, inplace=True)

    # Specifying the exact order of columns for the DataFrame before writing to Excel
    df = df[['ID', 'Family', 'DroidSecAnalytica', 'Classification', 'Kaspersky', 'First Submission', 'AV Detection', '%']]
    
    # Calculate family averages and write to an Excel sheet
    report_data_func.calculate_family_averages(df)

    # Write the DataFrame to an Excel file
    df.to_excel(excel_path, index=False, engine='openpyxl')
    print(f"Data written to {excel_path} successfully.")

def permission_reports_alpha():
    try:
        # Perform data analysis directly
        known_permissions_analysis = report_data_func.analyze_known_permissions()
        unknown_permissions_analysis = report_data_func.analyze_unknown_permissions()

        if known_permissions_analysis is None:
            print("Data analysis failed. Please check the logs for details.")
            return

        # Generating visualizations
        print("\nGenerating Permission Charts...")
        try:
            if known_permissions_analysis:
                # Generate pie chart for known permissions analysis
                title = "Known Permissions Analysis"
                filename = "known_permissions_pie_chart.png"
                statistical_visuals.generate_pie_chart(known_permissions_analysis, title, filename)

            if unknown_permissions_analysis:
                # Generate bar chart for unknown permissions analysis
                title = "Unknown Permissions Analysis"
                xlabel = "Risk Assessment"
                ylabel = "Frequency"
                filename = "unknown_permissions_bar_chart.png"
                statistical_visuals.generate_bar_chart(unknown_permissions_analysis, title, xlabel, ylabel, filename)

        except Exception as e:
            print(f"An error occurred during visualization generation: {str(e)}")

        # Generating text and Excel outputs
        print("\nGenerating Permission Data...")
        try:
            # Known permissions
            if known_permissions_analysis is not None:
                file_output_func.generate_text_output(known_permissions_analysis, "known_permissions_analysis.txt")
                file_output_func.generate_excel_output(known_permissions_analysis, "known_permissions_analysis.xlsx")

            # Unknown permissions
            if unknown_permissions_analysis is not None:
                file_output_func.generate_text_output(unknown_permissions_analysis, "unknown_permissions_analysis.txt")
                file_output_func.generate_excel_output(unknown_permissions_analysis, "unknown_permissions_analysis.xlsx")

        except Exception as e:
            print(f"An error occurred during output generation: {str(e)}")

    except Exception as e:
        print(f"An error occurred during data analysis: {str(e)}")

def permission_reports_beta():
    print("Starting Android Permissions Analysis...")
    #md5_hashes = read_md5_hashes()
    #df = fetch_and_analyze_permissions(md5_hashes)
    df = report_data_func.fetch_and_analyze_permissions(None)
    if df is None:
        print("No data..")
    
    else:
        report_data_func.generate_permission_matrices_by_level(df)
        distribution = report_data_func.analyze_distribution(df)
        protection_counts = report_data_func.analyze_protection_counts(df)
        unique_permissions = report_data_func.find_unique_permissions(df)
        common_permissions = report_data_func.find_common_permissions(df)

        # Generate individual reports
        file_output_func.generate_excel_output(distribution, 'distribution')
        file_output_func.generate_excel_output(protection_counts, 'protection_counts')
        file_output_func.generate_excel_output(unique_permissions, 'unique_permissions')
        file_output_func.generate_excel_output(common_permissions, 'common_permissions')

# def permission_reports_gamma():
#     try:
#         md5_hashes = file_utils.read_hash_list('Input\\hashes-md5.txt')
#         excel_filename = 'Output\\Analysis_Permission_Matrix.xlsx'

#         if not md5_hashes:
#             print("No hashes found or file not found.")
        
#         else:
#             with pd.ExcelWriter(excel_filename, engine='xlsxwriter') as writer:
#                 analysis_func.add_detailed_analysis_and_risk_assessment(md5_hashes, writer)
                
#                 for protection_level in ['dangerous', 'normal', 'signature%']:
#                     analysis_func.process_standard_permissions(md5_hashes, protection_level, writer)
                
#                 analysis_func.process_manufacturer_permissions(md5_hashes, writer)
#                 file_utils.style_excel_writer(writer)
                
#                 print(f"\n{excel_filename} file generated.")

#     except Exception as e:
#         print(f"Unexpected error occurred: {e}")
