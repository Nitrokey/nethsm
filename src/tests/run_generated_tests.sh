#!/usr/bin/env bash

set -e

suffix="_cmd.sh";

expected_code () {
    headers=$1
    basename "$headers" | cut -d "_" -f 1
}

actual_code () {
    headers=$1
    grep "^HTTP" "$headers" | cut -d ' ' -f 2
}

headers () {
    file=$1
    name=${file%$suffix}; #remove
    echo "${name}_headers.out"
}

test_endpoint () {
    echo "--------------------------------------------------------------------"
    echo " Starting test for endpoint $(basename `pwd`)"
    echo "--------------------------------------------------------------------"
    set -x
    "../../../keyfender/_build/default/test/test_server.exe" &
    SERVER_PID=$!
    sleep 2
    ./setup.sh || (kill $SERVER_PID ; exit 3)

    pwd
    for cmd in $(ls -1 ./4*${suffix}); do
      $cmd || (kill $SERVER_PID ; exit 4)
      headers=$(headers $cmd)
      diff -w -u <(actual_code "$headers") <(expected_code "$headers")
    done;

    if [ -e ./cmd.sh ]; then # does not exist for wrong-state tests
      ./cmd.sh || (kill $SERVER_PID ; exit 4)

      diff -w -u <(actual_code headers.out) <(actual_code headers.expected)
      if [ ! -f body.skip ]; then
        diff -w -u body.out body.expected
      fi
    fi
    ./shutdown.sh || (kill $SERVER_PID ; exit 5)
}

for test_dir in $(ls generated/); do
    (cd generated/${test_dir}; test_endpoint)
done
