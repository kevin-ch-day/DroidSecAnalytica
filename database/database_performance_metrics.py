import logging
import mysql.connector

def display_performance_metrics(conn):
    try:
        cursor = conn.cursor()
        metrics = ["Queries", "Threads_running"]

        for metric in metrics:
            cursor.execute(f"SHOW STATUS LIKE '{metric}';")
            result = cursor.fetchone()
            if result:
                print(f"{metric}: {result[1]}")
            else:
                logging.warning(f"Metric '{metric}' not found.")

    except mysql.connector.Error as e:
        logging.error(f"Error displaying performance metrics: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred while displaying performance metrics: {e}")

def show_query_count(cursor):
    cursor.execute("SHOW STATUS LIKE 'Queries';")
    query_count = cursor.fetchone()
    print(f"\nTotal Queries Executed: {query_count[1]}")

def show_slow_queries(cursor):
    cursor.execute("SHOW STATUS LIKE 'Slow_queries';")
    slow_queries = cursor.fetchone()
    print(f"Slow Queries: {slow_queries[1]}")

def show_memory_usage(cursor):
    cursor.execute("SHOW STATUS LIKE 'Max_used_connections';")
    max_used_connections = cursor.fetchone()
    print(f"Max Used Connections: {max_used_connections[1]}")

def show_thread_info(cursor):
    cursor.execute("SHOW STATUS LIKE 'Threads_connected';")
    threads_connected = cursor.fetchone()
    print(f"Threads Connected: {threads_connected[1]}")

    cursor.execute("SHOW STATUS LIKE 'Threads_running';")
    threads_running = cursor.fetchone()
    print(f"Threads Running: {threads_running[1]}")

def show_detailed_server_status(cursor):
    sql = "SHOW STATUS WHERE `variable_name` = 'Uptime' OR `variable_name` LIKE '%bytes%' OR `variable_name` LIKE '%table%' OR `variable_name` LIKE 'Key_%';"
    cursor.execute(sql)
    for variable_name, value in cursor.fetchall():
        print(f"{variable_name.replace('_', ' ').title()}: {value}")
