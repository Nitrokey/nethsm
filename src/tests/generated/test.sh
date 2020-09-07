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
}

for x in $(find . -type d -maxdepth 1 | grep -v '^.$' | grep -v '^..$'); do
  cd $x;
  test_one;
  cd ..
done
