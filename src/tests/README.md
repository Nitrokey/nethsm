## End to end testing

This directory contains shell scripts for end-to-end testing of a NetHSM, and
an OCaml program which generates tests from the OpenAPI specification (in
../../docs/nethsm-api.json).

The test generation works on each endpoint individually. For each endpoint,
HTTP requests and expected results are generated. Depending on the required
authentication and HSM state, respective positive (expected to succeed) and
negative (expected to fail) test cases are generated. The request is an
invocation of curl, where headers and body are checked against the examples from
the OpenAPI spec (if they exist and are not dynamic). Some endpoints are skipped
(see the "let skip_endpoints = " list in generate_api_tests.ml), and for some 
endpoints the body comparison is skipped (see the "let skip_body_endpoints = " 
list in generate_api_tests.ml). Only the HTTP response code is checked (not any 
further HTTP headers).

From the OpenAPI spec, the following information is used:
- The list of endpoints
- The desired state of the HSM (each endpoint has a "(state)" attribute)
- The required authentication (each endpoint has a "(role)" attribute)
- The positive HTTP response code (2xx)
- Example data (in the OpenAPI type definitions)

For each endpoint, all three HTTP methods (GET / PUT / POST) are tested. Also,
the HSM in each state is tested (Unprovisioned, Locked, Operational) - where the
requests to the HSM not in the desired state is expected to return a 412
response. An endpoint that needs authentication (where role <> Public) one
request is done with good authentication (expectation is a positive (2xx)
response), one request with a user that has a different role (expectation is a
403 response), and one request without authentication (expectation is a 401
response) is done.

If a user or a key was part of the URL, another request with a non-existing
user/key is invoked (with the expectation of a 404 response). If json data was
transmitted, another request with malformed json is executed (expecting a 400
response).

What is not tested / verified are negative HTTP response codes or lack thereof
in the OpenAPI spec.

All generated tests are shell scripts (that invoke curl), which are invoked by
./run_generated_tests.sh. They expect an unprovisioned NetHSM which is
provisioned with users and keys via shell scripts, and in the end shutdown.

## Files

The OCaml files producing the tests:
- dune
- dune-project
- generate_api_tests.ml

Some shell scripts are usable on their own, others are used by the generated
tests.

- common_functions.sh -- common functions used by the shell scripts
- gnuplot.sh -- invokes gnuplot to render a png from metrics
- load_test.sh -- does key generation, signing, decryption, random generation HTTP calls
- metrics_gnuplot.sh -- outputs a file for use by gnuplot.sh, requesting the metrics endpoint once a second
- provision_test.sh -- provisions a HSM
- run_generated_tests.sh -- executes all tests generated
- shutdown_from_any_state.sh -- cleanly shuts down a HSM after checking its state and moving to the Operational state
- shutdown.sh -- shutdown or rest or reboot a HSM
- unlock.sh -- unlocks a locked HSM
