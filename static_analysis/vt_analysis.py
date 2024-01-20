import os
from . import vt_requests
from . import vt_response_handler

def is_file_path(input_str):
    return os.path.isfile(input_str)

def get_user_input(prompt):
    return input(prompt).strip()

def virustotal_menu():
    while True:
        print("\nVirusTotal Analysis Menu\n")
        print("1. Submit a Hash for Analysis")
        print("2. Submit an APK File for Analysis")
        print("0. Exit")
        choice = get_user_input("\nEnter your choice (0-2): ")

        if choice == '1':
            #hash_value = get_user_input("Enter the hash value: ")
            hash_value = '9fa1e4b615d69f04da261267331a202b'
            result = vt_requests.query_hash(hash_value)
            if result:
                #vt_response_handler.save_json_response(result, "hash_analysis.json")
                vt_response_handler.parse_response(result)
            else:
                print("Error in processing the hash request.")
        
        elif choice == '2':
            file_path = get_user_input("Enter the path to the APK file: ")
            if is_file_path(file_path):
                result = vt_requests.query_apk(file_path)
                if result:
                    vt_response_handler.parse_response(result)
                else:
                    print("Error in processing the APK file request.")
            else:
                print("Invalid file path. Please enter a valid APK file path.")
        
        elif choice == '0':
            print("\nExiting the VirusTotal Analysis Tool.")
            break
        
        else:
            print("Invalid choice. Please enter a number between 1 and 3.")

def test_alpha():
    hash_value = '9fa1e4b615d69f04da261267331a202b'
    result = vt_requests.query_hash(hash_value)
    if result:
        #vt_response_handler.save_json_response(result, "hash_analysis.json")
        vt_response_handler.parse_response(result)
    else:
        print("Error in processing the hash request.")

if __name__ == "__main__":
    test_alpha()
