#!/bin/bash

echo "Website Security & Blocking Tool"
echo "========================================"
echo

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed or not in PATH."
    echo "Please install Python 3 from https://python.org"
    exit 1
fi

# Check if the main script exists
if [ ! -f "website_security_tool.py" ]; then
    echo "Error: website_security_tool.py not found in current directory."
    echo "Please make sure you're running this from the correct folder."
    exit 1
fi

# Install dependencies if needed
echo "Checking dependencies..."
pip3 install -r requirements.txt > /dev/null 2>&1

# Run the tool
echo "Starting the application..."
echo
python3 website_security_tool.py

# Check if the script exited with an error
if [ $? -ne 0 ]; then
    echo
    echo "An error occurred. Please check the messages above."
    read -p "Press Enter to continue..."
fi 