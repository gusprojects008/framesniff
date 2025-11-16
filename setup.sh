#!/bin/bash

set -e

echo ">>> Checking required system packages..."

for pkg in python iw; do
    if ! command -v "$pkg" >/dev/null 2>&1; then
        echo "Error: '$pkg' is not installed. Please install it before running this setup."
        exit 1
    fi
done

echo ">>> All required system packages are present."
echo

echo ">>> Python environment setup instructions:"
echo
echo "1. Create a virtual environment:"
echo "     python -m venv venv"
echo
echo "2. Activate the virtual environment:"
echo "     source venv/bin/activate"
echo
echo "3. Install dependencies from requirements.txt:"
echo "     pip install -r requirements.txt"
echo
echo ">>> After that, you can run the tool normally:"
echo "     venv/bin/python framesniff.py --help"
echo
echo ">>> Setup instructions completed."
