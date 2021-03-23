mock-build: uinit

uinit: $(wildcard *.go) $(wildcard script/*.go)
	GOPATH=$$PWD/../../.. go build

mock-run:
	./uinit mock
