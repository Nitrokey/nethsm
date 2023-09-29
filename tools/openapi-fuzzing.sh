#!/bin/sh

cd src/tests

# This is about the maximum number of tests that can be run without a crash
TEST_COUNT=500000


failed=0

# No auth
../keyfender/_build/default/test/test_server.exe 2> /dev/null &
sleep 2
NETHSM_URL="http://localhost:8080/api" ./provision_test.sh
openapi-fuzzer run -i 405 --max-test-case-count $TEST_COUNT --spec ../../api.json --url http://localhost:8080/api/v1
if [ $? -ne 0 ]; then
    failed=1
fi
pkill test_server.exe || true

# Operator
../keyfender/_build/default/test/test_server.exe 2> /dev/null &
sleep 2
NETHSM_URL="http://localhost:8080/api" ./provision_test.sh
openapi-fuzzer run -i 405 --max-test-case-count $TEST_COUNT --spec ../../api.json --url http://localhost:8080/api/v1   -H 'Authorization: Basic b3BlcmF0b3I6T3BlcmF0b3JPcGVyYXRvcg=='
if [ $? -ne 0 ]; then
    failed=1
fi
pkill test_server.exe || true

# Administrator
../keyfender/_build/default/test/test_server.exe 2> /dev/null  &
sleep 2
NETHSM_URL="http://localhost:8080/api" ./provision_test.sh
openapi-fuzzer run -i 405 --max-test-case-count $TEST_COUNT --spec ../../api.json --url http://localhost:8080/api/v1 -H 'Authorization: Basic YWRtaW46QWRtaW5pc3RyYXRvcg=='
if [ $? -ne 0 ]; then
    failed=1
fi
pkill test_server.exe || true

exit $failed