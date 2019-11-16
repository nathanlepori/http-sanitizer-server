# HTTP Sanitizer Server
## Usage
1. Install Python  
Make sure Python 3 is installed on your system.

```
# Windows
py -3 --version
# Linux
python3 --version
```

2. Run installation script
```
# Windows (cmd)
install.cmd
# Windows (Powershell)
.\install.ps1
# Linux
./install.sh
```

3. Start the server
```
# Windows (cmd)
http_sanitizer_server.cmd
# Windows (Powershell)
.\http_sanitizer_server.ps1
# Linux
./http_sanitizer_server.sh
```

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
⚠ Restarting Squid cache may be needed after changing the configuration.  
⚠ Make sure HTTP Sanitizer Server is already running before restarting Squid, or the connection may sometimes fail.

Of course Squid cache and HTTP Sanitizer Server can be run on two different hosts by providing a different IP/domain 
into the squid configuration file, but since ICAP does not provide support for traffic encryption, the communication 
has to be secured by external means.

For more information the official documentation can be found [here](https://wiki.squid-cache.org/Features/ICAP).

## Screenshots
![browser banner](https://github.com/nathanlepori/http-sanitizer-server/raw/master/docs/screenshot1.jpg)
![server log](https://github.com/nathanlepori/http-sanitizer-server/raw/master/docs/screenshot2.jpg)
