all: system-design.pdf operator-manual.pdf nethsm-api.html

apidoc: nethsm-api.html

nethsm-api.html: nethsm-api.raml
	raml2html $< -o $@ || \
	docker run --rm -v $(PWD):/raml mattjtodd/raml2html -i /raml/$< -o /raml/$@

system-design.pdf: system-design.md MuenSubjects.png EncryptionArchitecture.png DataModel.png
	pandoc -N --toc -V colorlinks=1 $< -o $@

operator-manual.pdf: operator-manual.md
	pandoc -N --toc -V colorlinks=1 $< -o $@

.PHONY: clean

clean:
	$(RM) system-design.pdf operator-manual.pdf nethsm-api.html
