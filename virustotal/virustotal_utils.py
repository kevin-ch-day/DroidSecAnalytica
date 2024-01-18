from datetime import datetime
import pycountry

def print_file_info(results):
    print(f"File Resource: {results['resource']}")
    print(f"Permalink: {results['permalink']}")
    print(f"Response Code: {results['response_code']}")
    print(f"Scan Date: {results['scan_date']}")
    print(f"Scan ID: {results['scan_id']}")

def print_hash_values(results):
    md5 = results['md5']
    sha1 = results['sha1']
    sha256 = results['sha256']
    
    print(f"\nHash Values:")
    print("-" * 40)
    print(f"MD5: {md5}")
    print(f'SHA1: {sha1}')
    print(f'SHA256: {sha256}')

def print_scan_results(results):
    print(f"\nScan Results")
    print("-" * 40)
    print(f"Total Scanners: {results['total']}")
    print(f"Positive Scanners: {results['positives']}")

def print_time_since_scan(results):
    scan_date = datetime.strptime(results['scan_date'], "%Y-%m-%d %H:%M:%S")
    current_date = datetime.now()
    time_difference = current_date - scan_date
    print(f"Time Since Scan: {time_difference.days} days")

def print_header():
    print("\nVirusTotal Report")
    print("-" * 40)

def display_scan_detail_results(results):
    if 'error' in results:
        print(f'Error: {results["error"]}')
    else:
        for key, value in results.items():
            if key != 'scans':
                print(f'{key}: {value}')

        if 'scans' in results:
            print("\nScanner Results:")
            for scanner, result in results['scans'].items():
                print(f'{scanner}')
                print(f'Result: {result["result"]}')
                print(f'Detection: {result.get("detected")}')
                print(f'Update: {result.get("update")}')
                print(f'Scan Date: {result.get("scan_date")}')
                print()

def analyze_detection_ratio(positives, total):
    detection_ratio = (positives / total) * 100
    return detection_ratio

def behavioral_analysis(results):
    if 'behavioral_info' in results:
        behavioral_info = results['behavioral_info']
        return f"Behavioral Analysis:\n{behavioral_info}\nRecommendation: Investigate the suspicious behavioral patterns."
    return ""

def get_country_info(country_code):
    try:
        country = pycountry.countries.get(alpha_2=country_code)
        if country:
            continent = pycountry.subdivisions.get(code=f"{country.alpha_2}01")
            if continent:
                continent_name = continent.name
            else:
                continent_name = "Unknown"
            return f"Continent: {continent_name}, Name: {country.name}, Alpha-2 Code: {country.alpha_2}, Alpha-3 Code: {country.alpha_3}"
        else:
            return "Country not found in the pycountry database."
    except Exception as e:
        return f"Error fetching country information: {str(e)}"