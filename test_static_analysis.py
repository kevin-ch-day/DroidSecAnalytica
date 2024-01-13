import static_analysis.static_analysis as static

def main():
    apk_path = "b7b6ae08971e111291e2dffe48667c42.apk"
    static.run_static_analysis(apk_path)

if __name__ == "__main__":
    main()
