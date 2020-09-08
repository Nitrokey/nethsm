#!/usr/bin/env bash

set -ex

test_one () {
    "../../../keyfender/_build/default/test/test_server.exe" &
    PID=$!
    sleep 2
    ./setup.sh || (kill $PID ; exit 3)
    ./command.sh || (kill $PID ; exit 4)
    ./shutdown.sh || (kill $PID ; exit 5)

    diff -w -u <(grep "^HTTP" headers.out) <(grep "^HTTP" headers.expected)
    if [ ! -f body.skip ]; then
      diff -w -u body.out body.expected
    fi

    # if exists, run ./wrong_json_cmd.sh and see if we get a 400
    if [ -e wrong_json_cmd.sh ]; then
      "../../../keyfender/_build/default/test/test_server.exe" &
      PID=$!
      sleep 2
      ./setup.sh || (kill $PID ; exit 3)
      ./wrong_json_cmd.sh || (kill $PID ; exit 4)
      ./shutdown.sh || (kill $PID ; exit 5)

      diff -w -u <(grep "^HTTP" wrong_json_headers.out) <(echo "HTTP/1.1 400 Bad Request")
    fi

    # if exists, run ./wrong_key_cmd.sh and see if we get a 404
    if [ -e wrong_key_cmd.sh ]; then
      "../../../keyfender/_build/default/test/test_server.exe" &
      PID=$!
      sleep 2
      ./setup.sh || (kill $PID ; exit 3)
      ./wrong_key_cmd.sh || (kill $PID ; exit 4)
      ./shutdown.sh || (kill $PID ; exit 5)

      diff -w -u <(grep "^HTTP" wrong_key_headers.out) <(echo "HTTP/1.1 404 Not Found")
    fi

}

for test_dir in $(ls generated/); do
    (cd generated/${test_dir}; test_one) || exit 1
done
