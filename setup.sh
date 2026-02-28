#!/usr/bin/env bash

RED_BOLD='\033[1;31m'
RESET='\033[0m'

set -euo pipefail

PROJECT_NAME="framesniff"
VENV_DIR=".venv"
VENV_PYTHON="$VENV_DIR/bin/python"

print_step() {
    echo
    echo "==> $1"
}

print_ok() {
    echo "✔ $1"
}

print_error() {
    echo "✖ $1"
    exit 1
}

print_step "Checking required system dependencies..."

for pkg in python iw; do
    if ! command -v "$pkg" >/dev/null 2>&1; then
        print_error "Missing dependency: $pkg"
    fi
done

print_ok "All required system dependencies are available."

print_step "Setting up virtual environment..."

if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    print_ok "Virtual environment created."
else
    print_ok "Virtual environment already exists."
fi

source "$VENV_DIR/bin/activate"

print_step "Upgrading pip..."
python -m pip install --upgrade pip >/dev/null

print_step "Installing dependencies..."

if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    print_ok "Dependencies installed."
else
    print_error "requirements.txt not found."
fi

print_step "Setup completed successfully!"

echo
echo -e "${RED_BOLD}Use the Python interpreter that is inside $VENV_PYTHON ${RESET}"
echo
echo "Run normally:"
echo "  source $VENV_DIR/bin/activate"
echo "  sudo $VENV_PYTHON framesniff.py --help"
echo
