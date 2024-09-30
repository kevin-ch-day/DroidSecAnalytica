import os
import json
import pandas as pd

def convert_dict_for_json(data):
    for key, value in data.items():
        if isinstance(value, pd.Series):
            data[key] = value.tolist()  # Convert Series to list
        elif isinstance(value, pd.DataFrame):
            data[key] = value.to_dict()  # Convert DataFrame to dict
    return data

def generate_text_output(data, filename):
    output_dir = "output\\text"
    os.makedirs(output_dir, exist_ok=True)
    file_path = os.path.join(output_dir, filename)
    
    try:
        with open(file_path, 'w') as f:
            if isinstance(data, dict):
                # Convert any Series in the dictionary to lists
                data = convert_dict_for_json(data)
                # Convert the dictionary to a JSON string
                f.write(json.dumps(data, indent=4))
            elif isinstance(data, pd.DataFrame):
                # Convert DataFrame to a string
                f.write(data.to_string())
            elif isinstance(data, pd.Series):
                # Convert Series to a dictionary, then serialize to JSON
                f.write(json.dumps(data.to_dict(), indent=4))
            else:
                # Convert other data types to a string directly
                f.write(str(data))
        
        print(f"Text output written to {file_path}")

    except Exception as e:
        print(f"An error occurred while generating text output: {e}")


def generate_excel_output(data, filename):
    output_dir = "output\\excel"
    os.makedirs(output_dir, exist_ok=True)

    # Ensure the filename has a valid extension
    if not filename.endswith('.xlsx'):
        filename += '.xlsx'

    file_path = os.path.join(output_dir, filename)

    try:
        if isinstance(data, pd.DataFrame):
            # Save DataFrame directly
            data.to_excel(file_path, index=False)
            print(f"Excel output written to {file_path}")
        
        elif isinstance(data, pd.Series):
            # Convert Series to DataFrame before saving
            data.to_frame().to_excel(file_path, index=False)
            print(f"Excel output written to {file_path}")
        
        elif isinstance(data, dict):
            # Try converting dict to DataFrame
            df = pd.DataFrame.from_dict(data, orient='index')
            df.to_excel(file_path, index=False)
            print(f"Excel output written to {file_path}")
        
        else:
            raise ValueError(f"Data must be a Pandas DataFrame, Series, or dictionary to generate an Excel output. Type received: {type(data)}")
    
    except Exception as e:
        print(f"An error occurred while generating excel output: {e}")
