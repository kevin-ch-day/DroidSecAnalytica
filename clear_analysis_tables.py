from database import DBTableManagement

def main():
    DBTableManagement.truncate_analysis_data_tables()

if __name__ == "__main__":
    main()