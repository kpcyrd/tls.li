---
layout: default
ciphers: ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK
mediumCiphers: ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA
hsts: max-age=31536000; includeSubdomains; preload
---

Generate CSR
============

    openssl req -new -sha256 -newkey rsa:4096 -keyout example.com.key -nodes -out example.com.csr

Self-sign
=========

    openssl x509 -req -days 365 -in example.com.csr -signkey example.com.key -out example.com.crt

Generate dhparam
================

    openssl dhparam 2048 -out /etc/nginx/dhparam.pem

nginx
=====

    ssl_certificate /etc/nginx/example.com.crt;
    ssl_certificate_key /etc/nginx/example.com.key;

    # Diffie-Hellman parameter for DHE ciphersuites, recommended 2048 bits
    ssl_dhparam /etc/nginx/dhparam.pem;

    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:50m;
    ssl_session_timeout 1d;

    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ## Only strong ciphers in PFS mode
    ssl_ciphers '{{ page.ciphers }}';
    ## Support intermediate clients
    #ssl_ciphers '{{ page.mediumCiphers }}';

    # 31536000 == 1 year
    # submit your page for preloading at http://hstspreload.appspot.com/
    add_header Strict-Transport-Security "{{ page.hsts }}";
    add_header X-Frame-Options DENY;

apache2
=======

    SSLEngine on
    SSLCertificateFile /etc/apache2/ssl/www.example.com.crt
    SSLCertificateKeyFile /etc/apache2/ssl/www.example.com.key

    SSLProtocol all -SSLv2 -SSLv3 -TLSv1
    SSLCipherSuite {{ page.ciphers }}
    SSLHonorCipherOrder on

    # 31536000 == 1 year
    # submit your page for preloading at http://hstspreload.appspot.com/
    Header alway set Strict-Transport-Security "{{ page.hsts }}"
    Header alway set X-Frame-Options "DENY"

postfix
=======

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
