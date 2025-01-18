

testcert:
	openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 \
		-out mailp-test.cert \
		-keyout mailp-test.key \
		-subj "/CN=mailp-test.local"
