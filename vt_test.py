from virustotal import vt_analysis, vt_requests

def test_hash_analysis():
    hash_value = '57f8a57320eeed2f5b5a316d67319191ce717cc51384318966b61f95722e275f'
    response = vt_requests.query_hash(hash_value)
    analysis_name = "Test Hash Analysis 2/13/2024"
    vt_analysis.process_vt_response(response, analysis_name)