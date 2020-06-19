#!/bin/sh

curl http://localhost:8080/api/v1/system/info -D headers.out -o body.out
