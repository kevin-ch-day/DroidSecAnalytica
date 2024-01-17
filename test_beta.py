# virustotal_analysis.py

import requests
import json
import datetime
import numpy as np

API_KEY = '848c2f7d2499138423f7416f61b8a3e42d8dd9a429ca9bc6f4f478c590c8eec7'

def format_date(timestamp):
    if timestamp:
        try:
            return datetime.datetime.fromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            return "Invalid Date"
    return "N/A"

def determine_hash_type(hash_string):
    if (hash_string) == 32:
        return "MD5"
    elif (hash_string) == 40:
        return "SHA1"
    elif (hash_string) == 64:
        return "SHA256"
    else:
        return "Unknown"

def query_virustotal(api_key, hash_value):
    print("Querying VirusTotal API...")
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error occurred: {e}")
        return None

def write_json_to_file(filename, data):
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)

def write_analysis_to_file(filename, analysis):
    with open(filename, 'w') as file:
        file.write(analysis)

def extract_hashes(data):
    return {
        "MD5": data.get("md5", "N/A"),
        "SHA1": data.get("sha1", "N/A"),
        "SHA256": data.get("sha256", "N/A")
    }

def extract_file_relationships(data):
    relationships = data.get("relationships", {})
    return {
        "Related URLs": [url.get("url", "N/A") for url in relationships.get("urls", {}).get("data", [])],
        "Related Domains": [domain.get("domain", "N/A") for domain in relationships.get("domains", {}).get("data", [])]
        # Add more relationships as needed
    }

def extract_detailed_scan_results(last_analysis_results):
    detailed_results = {}
    for engine, result in last_analysis_results.items():
        detailed_results[engine] = result.get("result", "N/A")
    return {"Detailed Scan Results": detailed_results}


def extract_file_metadata(data):
    return {
        "File Type": data.get("type_description", "Unknown"),
        "Upload Date": format_date(data.get("first_submission_date")),
        "Latest Report": format_date(data.get("last_analysis_date")),
        "Community Reputation": data.get("reputation", "N/A")
    }

def calculate_vote_statistics(last_analysis_stats):
    stats = {
        "Malicious Votes": last_analysis_stats.get("malicious", 0),
        "Harmless Votes": last_analysis_stats.get("harmless", 0),
        "Suspicious Votes": last_analysis_stats.get("suspicious", 0),
        "Undetected Votes": last_analysis_stats.get("undetected", 0)
    }
    stats["Total Votes"] = sum(last_analysis_stats.values())
    if stats["Total Votes"] > 0:
        stats["Malicious Percentage"] = "{:.2f}%".format((stats["Malicious Votes"] / stats["Total Votes"]) * 100)
    else:
        stats["Malicious Percentage"] = "N/A"
    return stats

def classify_threat(stats):
    if stats["Malicious Votes"] > stats["Harmless Votes"]:
        return "Potentially Malicious"
    elif stats["Suspicious Votes"] > stats["Harmless Votes"]:
        return "Suspicious"
    else:
        return "Likely Safe"

def format_list(items):
    return '\n    - ' + '\n    - '.join(items) if items else 'None'

def format_dict(dictionary):
    formatted = ''
    for key, value in dictionary.items():
        formatted += f'\n    {key}: '
        if isinstance(value, list):
            formatted += format_list(value)
        elif isinstance(value, dict):
            formatted += format_dict(value)
        else:
            formatted += str(value)
    return formatted

def format_analysis_results(analysis):
    analysis.update({'Advanced Analysis': advanced_analysis(analysis)})

    formatted_results = ['VirusTotal Analysis Report:']
    for key, value in analysis.items():
        formatted_results.append(f'{key}:')
        if isinstance(value, list):
            formatted_results.append(format_list(value))
        elif isinstance(value, dict):
            formatted_results.append(format_dict(value))
        else:
            formatted_results.append(f'    {value}')
    return '\n'.join(formatted_results)

def advanced_analysis(analysis):
    threat_levels = {
        'Low': 0,
        'Medium': 0,
        'High': 0
    }
    if 'Malicious Percentage' in analysis:
        malicious_percent = analysis['Malicious Percentage'].rstrip('%')
        if malicious_percent != 'N/A':
            malicious_percent = float(malicious_percent)
            if malicious_percent < 20:
                threat_levels['Low'] += 1
            elif malicious_percent < 50:
                threat_levels['Medium'] += 1
            else:
                threat_levels['High'] += 1
    return threat_levels
def extract_and_analyze_data(response):
    data = response.get("data", {}).get("attributes", {})
    last_analysis_stats = data.get("last_analysis_stats", {})
    last_analysis_results = data.get("last_analysis_results", {})

    analysis = {}
    analysis.update(extract_hashes(data))
    analysis.update(extract_file_metadata(data))
    analysis.update(calculate_vote_statistics(last_analysis_stats))
    analysis["Classification"] = classify_threat(analysis)
    analysis.update(extract_file_relationships(data))
    analysis.update(extract_detailed_scan_results(last_analysis_results))
    analysis.update(extract_historical_data_and_tags(data))
    analysis.update(extract_file_names(data))

    return format_analysis_results(analysis)

def extract_file_names(data):
    file_names = {
        "File Names": data.get("names", [])
    }
    return file_names

def extract_historical_data_and_tags(data):
    historical_data_and_tags = {
        "First Seen": format_date(data.get("first_seen_itw_date")),
        "Last Seen": format_date(data.get("last_seen_itw_date")),
        "Tags": data.get("tags", [])
    }
    return historical_data_and_tags

def perform_statistical_analysis(analysis):
    '''
    Perform statistical analysis on the analysis data.
    This is a placeholder function and should be modified according to the project's needs.
    Example: Analyzing the distribution of votes, calculating averages, etc.
    '''
    # Example statistical analysis
    # Calculate the average of malicious, harmless, and suspicious votes
    total_votes = analysis.get("Total Votes", 0)
    malicious_votes = analysis.get("Malicious Votes", 0)
    harmless_votes = analysis.get("Harmless Votes", 0)
    suspicious_votes = analysis.get("Suspicious Votes", 0)

    if total_votes > 0:
        avg_malicious_votes = malicious_votes / total_votes
        avg_harmless_votes = harmless_votes / total_votes
        avg_suspicious_votes = suspicious_votes / total_votes
    else:
        avg_malicious_votes = avg_harmless_votes = avg_suspicious_votes = 0

    statistical_results = {
        "Average Malicious Votes": avg_malicious_votes,
        "Average Harmless Votes": avg_harmless_votes,
        "Average Suspicious Votes": avg_suspicious_votes
    }

    return statistical_results

# Improved Data Formatting
def improved_format_analysis_results(analysis):
    formatted_results = ["VirusTotal Analysis Report:", "="*30]
    
    def format_section(title, data):
        section = [f"\n{title}:", "-"*len(title)]
        if isinstance(data, list):
            formatted_data = '\n  - '.join(data) if data else "None"
            section.append(f"  - {formatted_data}")
        elif isinstance(data, dict):
            for sub_key, sub_value in data.items():
                section.append(f"    {sub_key}: {sub_value}")
        else:
            section.append(f"    {data}")
        return section

    for key, value in analysis.items():
        formatted_results.extend(format_section(key, value))

    # Adding statistical analysis results
    formatted_results.extend(format_section("Advanced Analysis", perform_statistical_analysis(analysis)))

    return "\n".join(formatted_results)

def extract_and_analyze_data(response):
    # Extract specific data points
    data = response.get("data", {}).get("attributes", {})
    last_analysis_stats = data.get("last_analysis_stats", {})
    last_analysis_results = data.get("last_analysis_results", {})

    # Extracting basic information
    analysis = {
        "Hash Value": data.get("sha256", "N/A"),
        "File Type": data.get("type_description", "Unknown"),
        "Upload Date": data.get("first_submission_date", "N/A"),
        "Latest Report": data.get("last_analysis_date", "N/A"),
        "Community Reputation": data.get("reputation", "N/A"),
        "Malicious Votes": last_analysis_stats.get("malicious", 0),
        "Harmless Votes": last_analysis_stats.get("harmless", 0),
        "Suspicious Votes": last_analysis_stats.get("suspicious", 0),
        "Undetected Votes": last_analysis_stats.get("undetected", 0),
        "Total Votes": sum(last_analysis_stats.values())
    }

    # Extract detailed scan results from each antivirus engine
    detailed_scan_results = {engine: result.get("category", "N/A") for engine, result in last_analysis_results.items()}
    analysis["Detailed Scan Results"] = detailed_scan_results

    # Advanced Analysis Logic (Placeholder)
    # Here you can implement more complex analysis based on the extracted data
    # Example: Calculating percentages, identifying trends, classifications based on the data

    return analysis


def enhanced_analysis(analysis):
    ''' Perform additional analysis on the data '''
    # Placeholder for future advanced analysis
    return analysis

def analyze_threat_levels(analysis):
    ''' Analyze the threat levels based on votes and percentages '''
    if 'Malicious Percentage' in analysis and analysis['Malicious Percentage'] != 'N/A':
        malicious_percentage = float(analysis['Malicious Percentage'].rstrip('%'))
        if malicious_percentage > 75:
            return 'High Threat'
        elif malicious_percentage > 50:
            return 'Moderate Threat'
        else:
            return 'Low Threat'
    return 'Unknown Threat Level'

def analyze_community_feedback(analysis):
    ''' Analyze community feedback and reputation '''
    reputation = analysis.get('Community Reputation', 'N/A')
    if reputation != 'N/A':
        if reputation < -10:
            return 'Negative Community Feedback'
        elif reputation > 10:
            return 'Positive Community Feedback'
        else:
            return 'Neutral Community Feedback'
    return 'No Community Feedback'

def perform_statistical_analysis(analysis_data):
    ''' Perform statistical analysis on the data '''
    # Placeholder for statistical analysis logic
    # Example: Calculate mean, median, or other statistical metrics
    # This can be expanded based on specific analysis requirements
    return analysis_data

def enhanced_analysis(analysis):
    ''' Perform additional enhancements on the analysis '''
    # Adding more depth to the analysis
    # This is a placeholder for future enhancements
    return analysis

def main():
    hash_value = '4593635ba742e49a64293338a383f482f0f1925871157b5c4b1222e79909e838'
    response = query_virustotal(API_KEY, hash_value)

    if response:
        # Write raw JSON response to file
        print("Writing raw data to file...")
        write_json_to_file('output/raw_virustotal_data.json', response)

        # Extract, Analyze, and Format data
        analysis_results = extract_and_analyze_data(response)

        # Perform enhanced analysis
        enhanced_results = enhanced_analysis(analysis_results)

        # Perform statistical analysis
        statistical_results = perform_statistical_analysis(enhanced_results)

        # Write Analysis Results to a human-readable file
        print("Writing analysis results to file...")
        write_analysis_to_file('output/formatted_analysis_results.txt', format_analysis_results(statistical_results))

        print("Analysis completed. Raw data saved to raw_virustotal_data.json")
        print("Analysis results saved to formatted_analysis_results.txt")


if __name__ == "__main__":
    main()
