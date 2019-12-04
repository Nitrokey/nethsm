# NitroHSM

## Building

Opam >= 2.0.0 and OCaml >= 4.07.0 and mirage >= 3.7.0 is required.

Ensure that you have cloned this repository with all submodules, or run:

```
git submodule update --init --recursive
```

If you are starting from an empty OPAM switch, run:

```
make prepare
```

To build the system for local development work, run:

```
make build
```

## Running

To run the system on a local machine, first ensure that you have set up the required network interfaces by running:

```
sudo tools/setup-net-dev.sh
```

This script will set up the following TAP interfaces on your local system:

- _tap200_: configured as `192.168.1.100/24`, used to communicate with the "external" interface of the NitroHSM.
- _tap201_: configured as `169.254.169.2/24`, used to provide Git storage to S-Keyfender.

Then run:

```
make run
```

This will create the required Git repositories for storage and, if not yet running, start a Git daemon on `169.254.169.2`. It will then run S-Keyfender using Solo5/hvt in the foreground.

You should now be able to access S-Keyfender on `192.168.1.1`, for example:

```
$ curl -k https://192.168.1.1/api/v1/health/state
```

Produces

```
{"state":"Unprovisioned"}
```

For initial provisioning, in `src/keyfender/tests` there is `notes.sh` with the `curl` command line to provision the NitroHSM, and `provision.json` containing the necessary json data.

## Test coverage reporting

For OCaml there is a PPX (preprocessor) which can collect coverage information called bisect_ppx. The keyfender library is instrumented (see src/keyfender/dune for details) if the environment BISECT_ENABLE is set to "yes".

To collect coverage information about the tests:

(a) install bisect_ppx (opam install bisect_ppx)
(b) export BISECT_ENABLE=yes in your shell
(c) dune runtest
(d) mkdir coverage && bisect-ppx-report -I _build/default/src/keyfender -html coverage _build/default/src/keyfender/test/bisect000*
(e) browse to coverage/index.html
