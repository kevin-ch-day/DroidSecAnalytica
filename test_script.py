from virustotal import vt_analysis, vt_requests

def main():
    hash_value = '889392ed44a613bb3618f6b9a05a663f801c9cd7086ff8d3d7531c3bc57d97be'
    print(f"Hash: {hash_value}")
    response = vt_requests.query_hash(hash_value)
    analysis_name = "Hash Analysis 3/8/2024"
    vt_analysis.process_vt_response(response, analysis_name)

# Run the function
if __name__ == "__main__":
    main()