# pushr-origin-resolver
A simple Python3 resolver used internally by Pushr to resolve origin IPs of pull zones

This recursive DNS server will query Google's `8.8.8.8` and Cloudflare's `1.1.1.1` public DNS servers. It will return a default response if the name can not be resolved to avoid Nginx proxy reload and startup errors. At Pushr we use this server with Nginx's `resolver` directive. It will not respond to ANY type queries.
