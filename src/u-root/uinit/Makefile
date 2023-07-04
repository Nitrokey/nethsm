# Copyright 2023 - 2023, Nitrokey GmbH
# SPDX-License-Identifier: EUPL-1.2

mock-build: uinit

uinit: $(wildcard *.go) $(wildcard script/*.go)
	GOPATH=$$PWD/../../.. go build

mock-run:
	./uinit mock
