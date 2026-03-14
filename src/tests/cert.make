CA.key:
	openssl genrsa -out CA.key 2048

CA.pem: CA.key
	openssl req -x509 -new -nodes -key CA.key -sha256 -days 1825 -out CA.pem \
		-addext keyUsage=critical,keyCertSign -batch

new_cert.pem: nethsm.csr CA.pem
	openssl x509 -req -days 1825 -in nethsm.csr -CA CA.pem -copy_extensions copy \
		-CAkey CA.key -out new_cert.pem -set_serial 01 -sha256

witness.key:
	openssl genrsa -out witness.key 2048

witness.pem: witness.key CA.pem
	rm -rf witness.csr
	openssl req -new -sha256 -key witness.key -subj "/C=US/ST=CA/O=MyOrg, Inc./CN=witness" \
		-addext "subjectAltName=IP:192.168.1.100,IP:169.254.169.1,IP:172.22.1.2,IP:172.22.1.3,IP:172.22.1.4,IP:fc00:22:1::100" \
		--out witness.csr
	openssl x509 -req -days 1825 -in witness.csr -CA CA.pem -copy_extensions copy \
		-CAkey CA.key -out witness.pem -set_serial 01 -sha256

.PHONY: clean
clean:
	rm -rf new_cert.pem nethsm.csr witness.key witness.pem

.PHONY: clean-all
clean-all:
	rm -rf CA.key CA.pem new_cert.pem nethsm.csr witness.key witness.pem

# vi: ft=make
