# HTTP Sanitizer Server
## Installation
This software doesn't need to be installed. Just run the executable for the system you are using. No support for 
execution in the background is currently offered.

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
