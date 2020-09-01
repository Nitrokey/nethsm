#!/usr/bin/env bash

set -ex

test_one () {
    "../../../keyfender/_build/default/test/test_server.exe" &
    PID=$!
    sleep 2
    ./setup.sh || (kill $PID ; exit 3)
    ./command.sh || (kill $PID ; exit 4)
    NITROHSM_URL="http://localhost:8080/api" ../../shutdown_test.sh || (kill $PID ; exit 5)

    #diff -u <(grep -v "^date: " headers.out) <(grep -v "^date: " headers.expected)
    if [ ! -f body.skip ]; then
      diff -u body.out body.expected
    fi
}

for x in $(find . -type d -maxdepth 1 | grep -v '^.$' | grep -v '^..$'); do
  cd $x;
  test_one;
  cd ..
done
