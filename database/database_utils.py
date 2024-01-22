def format_disk_usage(disk_usage):
    if not disk_usage:
        print("No disk usage data available.")
        return

    print(f"\n{'Database'.ljust(20)} | {'Size in MB'.rjust(10)}")
    print("-" * 33)
    for db_name, size_mb in disk_usage:
        print(f"{db_name.ljust(20)} | {str(size_mb).rjust(10)}")

def format_seconds_to_dhms(seconds):
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{days}d {hours}h {minutes}m {seconds}s"
