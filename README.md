# NitroHSM

## Building S-Keyfender

Opam >= 2.0.0 and OCaml >= 4.07.0 and mirage >= 3.7.0 is required.

The unikernel S-Keyfender depends on the library keyfender, developed in this repository as wel, which needs to be pinned:

``opam pin add keyfender `pwd`/src/keyfender#HEAD``

This will install the opam depencies of keyfender, including an extended `webmachine` used in keyfender.

Once keyfender is installed, the following steps are necessary to compile S-Keyfender:

```
$ cd src/s_keyfender
$ mirage configure -t hvt
$ make
```

This results in the unikernel `keyfender.hvt`. Keyfender is setup with two network interfaces:
- the default one is used for the internal network (its IP address can be configured via boot parameters),
- the second one (in solo5 "external", otherwise "tap1") to be bridged to the external network.

The HTTP endpoints are listening on the second network interface, it's IP address is persisted in the KV store, defaults to `192.168.1.1`.

Currently, the KV store in use is in-memory -- this means that configuration information and data (users and keys) is not persisted across reboots.

For initial provisioning, in `src/keyfender/tests` there is `notes.sh` with the `curl` command line to provision the NitroHSM, and `provision.json` containing the necessary json data.

## Test coverage reporting

For OCaml there is a PPX (preprocessor) which can collect coverage information called bisect_ppx. The keyfender library is instrumented (see src/keyfender/dune for details) if the environment BISECT_ENABLE is set to "yes".

To collect coverage information about the tests:

(a) install bisect_ppx (opam install bisect_ppx)
(b) export BISECT_ENABLE=yes in your shell
(c) dune runtest
(d) mkdir coverage && bisect-ppx-report -I _build/default/src/keyfender -html coverage _build/default/src/keyfender/test/bisect000*
(e) browse to coverage/index.html
