# Get venv python interpreter
$python = Join-Path -Path $PSScriptRoot -ChildPath "venv\Scripts\python.exe"
# Get entrypoint script
$http_sanitizer_server = Join-Path -Path $PSScriptRoot -ChildPath "http_sanitizer_server.py"

# Execute using the venv Python interpreter
& $python $http_sanitizer_server
