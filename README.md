# tls_cipher_check

SSL/TLS ciphers security verification using Nmap scanning (script ssl-enum-ciphers) and https://ciphersuite.info/ API.

Example usage:
```
python tls_ciphers_check.py --host google.pl
```

with optional parameters:
```
python tls_ciphers_check.py --host google.pl --port 443 --report report_name
```

Prerequisites
* Python 3
* Nmap
