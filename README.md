
&nbsp;
<h3 align="center">EXYNEX</h3>

<p align="center">
  cli tool for static and dynamic analise of android apk. 
</p>

</p>

<hr />

![python lint](https://github.com/vmprog/apk_explorer/blob/exynex_dev/badges/pylint.svg)

<p>This command line utility allows you to perform static and dynamic analysis of android apk files.</p>

<p>Static analysis allows you to obtain the following data:</p>

- Application name
- App package
- App version
- Version code
- APK checksum
	- android_id
	- advertising_id
	- imei
	- google_account
	- wifi_ssid
	- geo: (latitude, longitude)
- urls - strings that look like URLs
- domains - strings that look like domain names
- libraries - list of .so libraries from the APK
- classes - list of Java/Kotlin classes from the binary
- permissions - set of permissions from the app manifest
- activities - list of registered activities from the app manifest
						]
<p>Dynamic analysis allows you to obtain the following data:</p>

- network_activity:
	- requests
		- timestamp - Time from the app startup (ms)
		- proto (HTTP/TLS/TCP/UDP)
		- remote_ip
		- tls_sni
		- http_request_url
		- http_request_method
		- http_request_body_length
		- http_response_status
		- http_response_body_length
		
	- requested_permissions

