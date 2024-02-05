import vt_response, vt_androguard


def user_vt_data_processing(response):
    data = vt_response.parse_virustotal_response(response)
    print("\nVirusTotal.com Response:")
    print(data)
    
    andro_data = vt_androguard.androguard_data(response)
    if andro_data:
        print("\nPermissions:")
        permissions = andro_data.get_permissions()
        for i in permissions:
            print(i)

def auto_vt_data_processing(response):
    data = vt_response.parse_virustotal_response(response)
    andro_data = vt_androguard.androguard_data(response)
    if andro_data:
        permissions = andro_data.get_permissions()