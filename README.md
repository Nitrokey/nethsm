# NitroHSM

## Test coverage reporting

For OCaml there is a PPX (preprocessor) which can collect coverage information called bisect_ppx. The keyfender library is instrumented (see src/keyfender/dune for details) if the environment BISECT_ENABLE is set to "yes".

To collect coverage information about the tests:

(a) install bisect_ppx (opam install bisect_ppx)
(b) export BISECT_ENABLE=yes in your shell
(c) dune runtest
(d) mkdir coverage && bisect-ppx-report -I _build/default/src/keyfender -html coverage _build/default/src/keyfender/test/bisect000*
(e) browse to coverage/index.html
