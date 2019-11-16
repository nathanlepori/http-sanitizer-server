# Move to script directory
Set-Location -Path $PSScriptRoot

# Create virtual environment using Python 3
py -3 -m venv .\venv

# Install requirements from venv
.\venv\Scripts\pip.exe install -r requirements.txt
