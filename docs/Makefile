all: system-design.pdf operator-manual.pdf

system-design.pdf: system-design.md MuenSubjects.png EncryptionArchitecture.png DataModel.png
	pandoc -N --toc -V colorlinks=1 $< -o $@

operator-manual.pdf: operator-manual.md
	pandoc -N --toc -V colorlinks=1 $< -o $@

.PHONY: clean

clean:
	$(RM) system-design.pdf operator-manual.pdf nethsm-api.html
