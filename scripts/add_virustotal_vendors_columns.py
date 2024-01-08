import mysql.connector

# Database credentials and details
DB_HOST = "localhost"
DB_USER = "dbadmin"
DB_PASSWORD = "Password01"
DB_DATABASE = "droidsecanalytica"

# Establishing the database connection
try:
    mydb = mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_DATABASE
    )
    mycursor = mydb.cursor()

    # Reading vendor names and preparing SQL statements
    vendors = []
    with open('virustotal_vendor_names.txt', 'r') as file:
        for line in file:
            vendor_name = line.strip().replace(" ", "_").replace("-", "_")
            vendors.append(f"ADD COLUMN {vendor_name} VARCHAR(200)")

    # Combining SQL statements into a single ALTER TABLE command
    sql = "ALTER TABLE virustotal_analysis " + ", ".join(vendors)
    mycursor.execute(sql)
    mydb.commit()

    print(mycursor.rowcount, "record(s) affected")

except mysql.connector.Error as error:
    print("Error: ", error)
finally:
    if mydb.is_connected():
        mycursor.close()
        mydb.close()
