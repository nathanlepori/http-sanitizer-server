# HTTP Sanitizer Server
## Installation
1. Install virtualenv (optional)
```
# Windows
py -m venv ./venv
# Linux
venv ./venv
```
2. Install dependencies

`pip install -r requirements.txt`
3. Start the server

`python http-sanitizer-server.py`

Note: this software only supports Python 3.
## Squid cache configuration
Configure Squid cache to support the two ICAP services offered by this software. The server is running on port 13440 
by default. The following sample configuration is provided.
```
icap_enable on
icap_persistent_connections off
icap_log /var/log/squid/icap.log

icap_service xss_auditor respmod_precache bypass=off icap://127.0.0.1:13440/xss_auditor
adaptation_access xss_auditor allow all

icap_service body_sanitizer reqmod_precache bypass=off icap://127.0.0.1:13440/body_sanitizer
adaptation_access body_sanitizer allow all
```
Restarting Squid cache may be needed after changing the configuration.
