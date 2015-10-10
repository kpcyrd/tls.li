---
layout: default
ciphers: ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA
hsts: max-age=31536000; includeSubdomains; preload
---

Generate CSR
============

```sh
openssl req -new -sha256 -newkey rsa:4096 -keyout example.com.key -nodes -out example.com.csr
```

nginx
=====

```
ssl_certificate /etc/nginx/example.com.crt;
ssl_certificate_key /etc/nginx/example.com.key;

ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;

ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
## Only strong ciphers in PFS mode
ssl_ciphers '{{ page.ciphers }}';

# 31536000 == 1 year
# submit your page for preloading at http://hstspreload.appspot.com/
add_header Strict-Transport-Security "{{ page.hsts }}";
add_header X-Frame-Options DENY;
```

apache2
=======

```
SSLEngine on
SSLCertificateFile /etc/apache2/ssl/www.example.com.crt
SSLCertificateKeyFile /etc/apache2/ssl/www.example.com.key

SSLProtocol all -SSLv2 -SSLv3
SSLCipherSuite {{ page.ciphers }}
SSLHonorCipherOrder on

# 31536000 == 1 year
# submit your page for preloading at http://hstspreload.appspot.com/
Header alway set Strict-Transport-Security "{{ page.hsts }}"
Header alway set X-Frame-Options "DENY"
```

postfix
=======

```
smtpd_tls_cert_file=/etc/postfix/noisebridge.net-cert.pem
smtpd_tls_key_file=/etc/postfix/noisebridge.net-key.pem
smtpd_tls_ciphers = high
smtpd_tls_exclude_ciphers = aNULL, MD5, DES, 3DES, DES-CBC3-SHA, RC4-SHA, AES256-SHA, AES128-SHA
smtpd_use_tls =yes
smtp_tls_protocols = !SSLv2, !SSLv3, TLSv1
smtpd_tls_mandatory_protocols = TLSv1
smtp_tls_note_starttls_offer = yes
smtpd_tls_received_header = yes
smtpd_tls_session_cache_database = btree:${queue_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:${queue_directory}/smtp_scache
```
