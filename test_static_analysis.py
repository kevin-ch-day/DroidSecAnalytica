import static_analysis.static_analysis as static

def main():
    apk_path = "0d00206b8e9814ec56c8ed8cff4de107.apk"
    static.run_static_analysis(apk_path)

if __name__ == "__main__":
    main()
