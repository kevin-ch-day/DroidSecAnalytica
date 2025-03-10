#!/bin/bash

# Define the python command, default to python3
PYTHON_CMD=${PYTHON_CMD:-python3}

# Check if Python 3 is installed
command -v $PYTHON_CMD >/dev/null 2>&1 || { 
    echo >&2 "Python 3 is required but it's not installed. Aborting."; 
    exit 1; 
}

$PYTHON_CMD -W ignore main.py

# Check if script ran successfully
if [ $? -ne 0 ]; then
    echo "Error occurred running main.py"
    exit 1
else
    echo "Script executed successfully."
fi