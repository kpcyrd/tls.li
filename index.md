---
layout: default
ciphers: ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA
---

nginx
=====

	ssl_certificate /etc/nginx/example.com.crt;
	ssl_certificate_key /etc/nginx/example.com.key;
	ssl_prefer_server_ciphers on;
	ssl_session_cache shared:SSL:10m;
	ssl_session_timeout 10m;
	# Only strong ciphers in PFS mode
	ssl_ciphers {{ page.ciphers }};
	ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
