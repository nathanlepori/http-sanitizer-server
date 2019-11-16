#!/usr/bin/env bash

# Move to script directory
cd "$(dirname "$0")" || exit

# Create virtual environment using Python 3
python3 -m venv ./venv

# Install requirements from venv
./venv/bin/pip install -r requirements.txt
