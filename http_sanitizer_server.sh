#!/usr/bin/env bash

# Get script dir
script_dir=$(dirname "$0")
# Get venv python interpreter
python="${script_dir}/venv/bin/python"
# Get entrypoint script
http_sanitizer_server="${script_dir}/http_sanitizer_server.py"

# Execute using the venv Python interpreter
eval "$python $http_sanitizer_server"
