CA.key:
	openssl genrsa -out CA.key 2048

CA.pem: CA.key
	yes "" | openssl req -x509 -new -nodes -key CA.key -sha256 -days 1825 -out CA.pem -addext keyUsage=critical,keyCertSign

new_cert.pem: nethsm.csr CA.pem
	openssl x509 -req -days 1825 -in nethsm.csr -CA CA.pem  \
		-CAkey CA.key -out new_cert.pem -set_serial 01 -sha256

.PHONY: clean
clean:
	rm -rf CA.key CA.pem new_cert.pem nethsm.csr
