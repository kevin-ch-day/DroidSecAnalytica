import virustotal_utils

def display_scan_results(results):
    if 'error' in results:
        print(f'Error: {results["error"]}')
        return
    
    print(f'\nVerbose Message: {results["verbose_msg"]}')
    
    virustotal_utils.print_header()
    virustotal_utils.print_file_info(results)
    virustotal_utils.print_hash_values(results)
    virustotal_utils.print_scan_results(results)
    print_data_science_analysis(results)
    virustotal_utils.print_time_since_scan(results)
    print()

if __name__ == "__main__":
    file_hash = '9fa1e4b615d69f04da261267331a202b'
    response = virustotal_utils.fetch_virustotal_report(file_hash)
    display_scan_results(response)