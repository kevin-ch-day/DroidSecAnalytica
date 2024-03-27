# display_utils.py

import pandas as pd
import matplotlib.pyplot as plt

def display_results(data, title="Query Results"):
    """
    Display query results as a pandas DataFrame.
    """
    if data:
        df = pd.DataFrame(data)
        print(f"\n{title}:")
        print(df.to_string(index=False))
    else:
        print("No data to display.")

def display_menu(title, options):
    """
    Display a menu with options.
    """
    print(f"\n** {title} **")
    for key, description in options.items():
        print(f"{key}. {description}")
    print()

def visualize_data(df, chart_type="bar", title="Data Visualization", x_label=None, y_label=None, rotation=None):
    """
    Visualize data using matplotlib.
    """
    if not df.empty:
        plt.figure(figsize=(10, 6))  # Adjust figure size
        ax = df.plot(kind=chart_type, x='prefix', y='count', title=title, legend=None)
        ax.set_xlabel(x_label if x_label else 'Permission Prefix', fontsize=12)  # Increase x-axis label font size
        ax.set_ylabel(y_label if y_label else 'Count', fontsize=12)  # Increase y-axis label font size
        ax.tick_params(axis='both', which='major', labelsize=10)  # Increase tick label font size
        ax.grid(True, linestyle='--', alpha=0.7)  # Add grid lines
        plt.xticks(rotation=rotation if rotation else 45)
        plt.tight_layout()
        plt.show()
    else:
        print("No data to visualize.")

def display_error(message):
    """
    Display an error message.
    """
    print(f"Error: {message}")

def display_vendor_permissions(permissions_by_vendor):
    print("\nPermissions Associated with Vendors")
    print("-----------------------------------")
    for vendor, permissions in sorted(permissions_by_vendor.items(), key=lambda x: x[0]):
        print(f"{vendor}: {len(permissions)}")

def display_vendor_permissions_detailed(permissions_by_vendor):
    print("\nDetailed Permissions Associated with Vendors")
    print("---------------------------------------------")
    for vendor, permissions in sorted(permissions_by_vendor.items(), key=lambda x: x[0]):
        print(f"{vendor}: {len(permissions)}")
        for perm in permissions:
            print(f"    - {perm}")
        print()

def display_unrecognized_permissions(unrecognized_permissions):
    print("\nSummary of Suspicious Unknown Permissions")
    print("-----------------------------------------")
    if unrecognized_permissions:
        for prefix, perms in sorted(unrecognized_permissions.items(), key=lambda x: x[0]):
            print(f"{prefix}: {len(perms)}")
    else:
        print("No suspicious unknown permissions found.")

def display_unrecognized_permissions_detailed(unrecognized_permissions):
    print("\nDetailed Suspicious Unknown Permissions")
    print("---------------------------------------")
    if unrecognized_permissions:
        for prefix, perms in sorted(unrecognized_permissions.items(), key=lambda x: x[0]):
            print(f"{prefix}: {len(perms)}")
            for perm in perms:
                print(f"    - {perm}")
            print()
    else:
        print("No suspicious unknown permissions found.")

def print_header(title):
    print(f"\n*~~*~~* [{title}] *~~*~~*\n")

def confirm_and_migrate_permissions(permissions_by_vendor, unknown_permissions, migrate_func):
    user_input = input("\nTransfer permissions to the manufacturer permissions table? (yes/no): ")
    if user_input.lower() == 'yes':
        migrate_func(permissions_by_vendor, unknown_permissions)

def print_migration_summary(total_migrated, errors):
    print("\n[Migration Summary]")
    print("-----------------------------------")
    print(f"[Total Permissions Migrated: {total_migrated}")
    if errors:
        print("[Errors encountered]")
        for error in errors:
            print(f"-- {error}")
