#!/usr/bin/env bash

set -ex

expected_code () {
    headers=$1
    basename $headers | cut -d "_" -f 1
}

actual_code () {
    headers=$1
    grep "^HTTP" $headers | cut -d ' ' -f 2
}

headers () {
    file=$1
    suffix="_cmd.sh";
    name=${file%$suffix}; #remove
    echo $file"_headers.out"
}

test_one () {
    "../../../keyfender/_build/default/test/test_server.exe" &
    PID=$!
    sleep 2
    ./setup.sh || (kill $PID ; exit 3)

    # if exists, run ./wrong_json_cmd.sh and see if we get a 400
    if [ -e 400_wrong_json_cmd.sh ]; then
      ./400_wrong_json_cmd.sh || (kill $PID ; exit 4)
      diff -w -u <(actual_code 400_wrong_json_headers.out) <(expected_code 400_wrong_json_headers.out)
    fi

    # if exists, run ./wrong_key_cmd.sh and see if we get a 404
    if [ -e 404_wrong_key_cmd.sh ]; then
      ./404_wrong_key_cmd.sh || (kill $PID ; exit 4)
      diff -w -u <(head -n 1 404_wrong_key_headers.out | cut -f 2 -d ' ') <(echo "404")
    fi

    # if exists, run ./wrong_user_cmd.sh and see if we get a 404
    if [ -e 404_wrong_user_cmd.sh ]; then
      ./404_wrong_user_cmd.sh || (kill $PID ; exit 4)
      diff -w -u <(head -n 1 404_wrong_user_headers.out | cut -f 2 -d ' ') <(echo "404")
    fi

    # if exists, run ./wrong_auth_cmd.sh and see if we get a 403
    if [ -e 403_wrong_auth_cmd.sh ]; then
      ./403_wrong_auth_cmd.sh || (kill $PID ; exit 4)
      diff -w -u <(head -n 1 403_wrong_auth_headers.out | cut -f 2 -d ' ') <(echo "403")
    fi

    ./command.sh || (kill $PID ; exit 4)
    ./shutdown.sh || (kill $PID ; exit 5)

    diff -w -u <(grep "^HTTP" headers.out) <(grep "^HTTP" headers.expected)
    if [ ! -f body.skip ]; then
      diff -w -u body.out body.expected
    fi

}

for test_dir in $(ls generated/); do
    (cd generated/${test_dir}; test_one)
done
