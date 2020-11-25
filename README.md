# NitroHSM

The NitroHSM software can be built either as components that run on your local machine (the "Local Development System") or as a full emulated Muen system (the "Muen System").

In either case, running `make` in this directory will produce a short help. The following sections detail how to build and run the software.

## Use of Git submodules in this repository

This repository uses several large Git submodules, including recursive submodules for Muen and Coreboot. These submodule also use relative URLs in their `.gitmodules` and cloning this repository recursively **WILL NOT WORK**.

`make prepare` will call out to `tools/init-git-submodules.sh` which will do the right thing and initialise all _required_ submodules depending on the `MODE` you have passed to `make`. See that script for the gory details.

## Local Development System

The local development system builds only the subset of the codebase required to run an `S-Keyfender` instance against a local Git repository for data storage. This is the default if a `MODE` is not specified to `make`.

### Building without Docker

This is supported on Linux and FreeBSD systems, and to a lesser extent on Mac (`MODE=test` only).

1. Ensure you have installed OPAM >= 2.0.0 and OCaml >= 4.10.1. We recommend that you use the latest OCaml release, at the moment 4.11.1.
2. Create a new OPAM switch for NitroHSM development, using a known-good commit of `ocaml/opam-repository`:
    
       opam repo add nitrohsm-default git+https://github.com/ocaml/opam-repository#$(cat .opam-repository-commit) --dont-select
       opam switch create nitrohsm 4.11.1 --repos nitrohsm-default
       eval $(opam env)

3. Build the system with:

       make -j$(nproc) build

### Building with Docker

1. To enter the Docker container, run:

       make local-container-enter
       # If you want to use a locally built image, run:
       # make DOCKER_IMAGE_NAME=nethsm-builder local-container-enter
   
2. Once inside the container, run:

       make local-container-setup

3. Build the system with:

       make -j$(nproc) build

Notes:

- The Docker container will bind mount your checked out NitroHSM repository as `/builds/nitrokey/nitrohsm` in the container. `make local-container-setup` attempts to fix permissions on `$HOME` in the container if your UID is not `1000`.
- The Docker container is run with `--net=host`. This is intentional, so that you can talk to a running NitroHSM from the host.
- `/dev/net/tun` and `/dev/kvm` (if present and the host user can access it) are passed through to the container.
- Due to the above, `make local-container-enter` will work only on a Linux host (i.e. not Docker for Mac, for example).

### Running

To run the local development system on your local machine, first ensure that you have set up the required network interfaces _on the host_ by running:

```
sudo tools/setup-net-dev.sh
```

This script will set up the following TAP interfaces on your local system:

- _tap200_: configured as `192.168.1.100/24`, used to communicate with the "external" interface of the NitroHSM.
- _tap201_: configured as `169.254.169.2/24`, used to provide Git storage to S-Keyfender.

Then run, either in the Docker container or on the host:

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

For initial provisioning, you can run `src/tests/provision_test.sh`. See the other scripts in that directory for more end to end tests.

### Test Coverage Reporting

For OCaml there is a PPX (preprocessor) which can collect coverage information called `bisect_ppx`. The keyfender library is instrumented (see `src/keyfender/dune` for details) if the environment `BISECT_ENABLE` is set to `yes`.

To collect coverage information about the tests:

1. install `bisect_ppx` (`opam install 'bisect_ppx>=2.1.0'`)
2. `export MODE=test` in your shell
3. `make coverage`
5. browse to obj/coverage/index.html

## Muen System

Building the full Muen system, either for development under KVM, or for target hardware, is only supported using the provided Docker container. To build, follow these steps:

1. To enter the Docker container, run:

       make local-container-enter
   
2. Once inside the container, run:

       make local-container-setup

3. Build the system with:

       # For QEMU/KVM:
       make -j$(nproc) MODE=muen MUEN_TARGET=qemu-kvm build
       # For Supermicro X11SSH-TF:
       make -j$(nproc) MODE=muen MUEN_TARGET=supermicro-x11ssh-tf build

Notes:

- See "Building with Docker" in the "Local Development System" section.

### Running

Running the Muen system using KVM has some additional requirements:

- The host system must have a recent _Intel_ CPU with VT-d and IOMMU.
- The host system must be running at least Linux kernel 5.4.x, or have commit `04f11ef45810da5ae2542dd78cc353f3761bd2cb` applied as a patch. This commit will eventually make it into LTS kernels, but as of this writing has not.
- Nested virtualization must be enabled for KVM.
- The _host_ user running the Docker container must have permissions to access `/dev/kvm`.

To run the Muen system, inside the Docker container, do:

```
make -j5 MODE=muen run
```

This will start QEMU in a detached `screen` session. Note that the VGA console is not used, follow `run/serial.out` for the system console.
