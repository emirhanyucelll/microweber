# Microweber CMS v2.0.20 – Host Header Injection (OOB DNS & HTTP)
# Date: 2026-01-06
# Exploit Author: Emirhan Yücel
# Vendor Homepage: https://microweber.com
# Software Link: https://github.com/microweber/microweber
# Version: 2.0.20
# Tested on: Windows 11, Linux
# CVE: Pending Assignment
# Category: Web Application

# 1. Vulnerability Summary

# Microweber CMS version 2.0.20 is affected by a Host Header Injection vulnerability.
# The application relies on the user-supplied Host HTTP header to construct absolute URLs in server responses without proper validation or sanitization.

# As a result, an attacker can supply an arbitrary domain in the Host header and cause the application to reference this external domain in its responses.
# This behavior was confirmed using Out-of-Band (OOB) DNS and HTTP interactions.

# 2. Affected Endpoint
# Request
# Method: GET
# Path: /microweber-master/
# Vulnerable Header: Host

# Proof of Concept (PoC)

# The following request demonstrates the issue by supplying an attacker-controlled OAST domain in the Host header.

# HTTP Request 1

GET /microweber-master/ HTTP/1.1
Host: d5emqa7plkfnqn0e6ung4ojox6jjar8et.oast.online
User-Agent: Mozilla/5.0
Accept: */*
Connection: close

# HTTP Request 1

GET /microweber-master/api/user/forgot-password HTTP/1.1
Host: evil.com
User-Agent: Mozilla/5.0
Accept: */*
Connection: close

# 4. Observed Behavior

# After sending the request:
# The application generates absolute resource URLs based on the supplied Host header.
# The injected domain is reflected in the response.
# The server initiates outbound DNS and HTTP requests to the supplied domain.
# This confirms that the application trusts the Host header and uses it during response generation.

# 5. Out-of-Band (OOB) Interaction Evidence
# An OAST service (Interactsh) was used to verify the vulnerability.
# Observations
# DNS lookup requests were received by the OAST server.
# HTTP requests originating from the target server were logged.
# The requests occurred immediately after the crafted HTTP request was sent.
# This confirms server-side processing and rules out client-side manipulation.

# 6. Security Impact
# This vulnerability can be abused for:
# Cache poisoning
# Password reset poisoning
# Account takeover (depending on deployment)
# Open redirect chains
# Bypassing security controls relying on host validation
# The impact increases significantly if the application is used behind reverse proxies or load balancers.

# References
# https://portswigger.net/web-security/host-header
# https://owasp.org/www-community/attacks/Host_header_injection





























