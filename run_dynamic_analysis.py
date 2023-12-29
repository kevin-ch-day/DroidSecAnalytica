import os
from dynamic_analysis import dynamic_main

def main():
    # Provide the path to the APK file you want to analyze
    apk_path = "SharkBot.apk"

    # Check if the provided APK file exists
    if not os.path.exists(apk_path):
        print("Invalid file path. Please provide a valid APK file path.")
        return

    # Perform dynamic analysis
    analysis_result = dynamic_main.perform_dynamic_analysis(apk_path)

    # Display the analysis result
    print("\nDynamic Analysis Result:")
    print(f"Analysis Status: {analysis_result['Analysis Status']}")
    print("Additional Information:")
    print(analysis_result['Additional Information'])

if __name__ == "__main__":
    main()
