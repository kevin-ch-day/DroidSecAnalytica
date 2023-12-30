import os
import joblib

# Define the path to the directory containing your machine learning models
MODEL_DIR = "models"

def change_model():
    """
    Implementation of changing the machine learning model.
    """
    print("Changing the machine learning model...")

    # List available models in the 'models' directory
    available_models = os.listdir(MODEL_DIR)

    if not available_models:
        print("No machine learning models found.")
        return

    # Display available models to the user
    print("Available models:")
    for idx, model_name in enumerate(available_models, start=1):
        print(f"{idx}. {model_name}")

    # Prompt the user to select a model
    try:
        model_idx = int(input("Enter the number of the model to use: ")) - 1
        selected_model = available_models[model_idx]

        # Load the selected model
        model_path = os.path.join(MODEL_DIR, selected_model)
        model = joblib.load(model_path)

        # Now you can use the 'model' for APK analysis

        print(f"Using model: {selected_model}")
    except (ValueError, IndexError):
        print("Invalid model selection. Please enter a valid number.")
