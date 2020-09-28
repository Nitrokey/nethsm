# NitroHSM

The NitroHSM software can be built either as components that run on your local machine (the "Local Development System") or as a full emulated Muen system (the "Muen System").

In either case, running `make` in this directory will produce a short help. The following sections detail how to build and run the software.

## Use of Git submodules in this repository

This repository uses several large Git submodules, including recursive submodules for Muen. Cloning all submodules recursively is **NOT** recommended, unless you have a lot of patience, bandwidth and disk space (>3 GB).

In order to avoid this, the `prepare` target (part of `make build`) will clone only those submodules that are required for the `MODE` you are building the system for, and use shallow clones where appropriate.

If you are building the Muen System, you **must** add the contents of the `gitconfig.ad` file in this repository your `~/.gitconfig` for all Git submodules to work correctly.

If you need all Git submodules to be fully cloned (e.g. when updating submodule references), then run:

```
git submodule update --init --no-recommend-shallow --recursive
```

in a **fresh** clone of this repository.

## Local Development System

This is the default if a `MODE` is not specified to `make`.

**Requirements:**

Opam >= 2.0.0 and OCaml >= 4.10.0 and mirage >= 3.8.1 is required.

To ensure you're on an up-to-date opam repository, execute:

```
opam update
```

### Building

To build the system for local development work, run in a fresh opam switch and a fresh clone of this repository:

```
make build
```

#### Build issues

If you encounter build issues, this may be due to a dirty repository. To clean it, please execute:

```
make distclean
```

Check that you don't have any pinned opam packaages, the output of the following command should be empty:

```
opam pin
```

### Running

To run the system on your local machine, first ensure that you have set up the required network interfaces by running:

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

### Test Coverage Reporting

For OCaml there is a PPX (preprocessor) which can collect coverage information called `bisect_ppx`. The keyfender library is instrumented (see `src/keyfender/dune` for details) if the environment `BISECT_ENABLE` is set to `yes`.

To collect coverage information about the tests:

1. install `bisect_ppx` (`opam install 'bisect_ppx>=2.1.0'`)
2. `export MODE=test` in your shell
3. `make coverage`
5. browse to obj/coverage/index.html

## Muen System

**Requirements:**

The following requirements are based on using Debian 10.x as the build system.

If you want to also **run** the built system image under KVM/QEMU, please see the additional requirements in the "Running" section below.

**TODO**: Add a Dockerfile with all requirements pre-installed? Building in Docker is not yet verified to work.

**MirageOS (S-Keyfender) unikernel**

At a minimum, the following system packages are required:

```
build-essential git libseccomp-dev linux-libc-dev pkg-config
```

OPAM >= 2.0.0 and OCaml >= 4.08.0 and mirage >= 3.8.0 are required.

**Muen SK**

This list is based on that from the Muen SK website, with additions not listed there, but required by the `devel` branch of Muen that our source tree is based on.

The following system packages are required:

```
acpica-tools bc binutils-dev bison flex git-core \
gnuplot grub-pc-bin lcov libc6-dev libelf-dev libiberty-dev \
libxml2-utils make tidy wget xorriso xsltproc zlib1g-dev \
python-pip python-setuptools python-lxml python-colorlog \
python-wheel
```

Additionally, [LIEF](https://github.com/lief-project/LIEF) 0.9.0 needs to be installed via PIP:

```
pip install lief==0.9.0
```

You will need the AdaCore GNAT/SPARK Community 2019 toolchain from their [libre](https://muen.sk/#libre) site. The installer available there requires an X11 connection, you can use the following recipe to install without an X display:

```
git clone https://github.com/AdaCore/gnat_community_install_script.git /tmp/gnat_script
curl -sSL "https://www.codelabs.ch/download/ada/gnat-community-2019-20190517-x86_64-linux-bin" -o /tmp/gnat_installer.bin
sh /tmp/gnat_script/install_package.sh /tmp/gnat_installer.bin /opt/gnat
rm -rf /tmp/gnat*

```
after which you should add the AdaCore toolchains to your `$PATH`:

```
export PATH=/opt/gnat/bin:/opt/spark/bin:$PATH
```

**U-Root and initramfs for Linux subjects**

Install Go 1.13.x from the binary [packages](https://golang.org/dl), and ensure that `go` is in your `$PATH`. You do _not_ need to set `$GOPATH`, the build system will use its own internal value for this.

Install a Musl libc toolchain, from the [musl.cc](https://musl.cc/) website, specifically the x86\_64 to x86\_64 "cross" [toolchain](https://musl.cc/x86_64-linux-musl-cross.tgz). This is used to cross-compile a static `git` for the initramfs. Normally installed in `/usr/local`, ensure that the `bin` directory is in your `$PATH`.

**NitroHSM Muen integration**

The following system packages are required:

```
cgpt e2fsprogs grub-common grub-pc-bin
```

### Building

To build the Muen system image, run:

```
make -j5 MODE=muen build
```

This will build S-Keyfender, the Muen system image and finally both a GRUB image used for booting QEMU "from ROM" (`obj/grub.img`) and a virtual disk containing the Muen system image and a partition for stateful data (`obj/disk.img`).

### Running

Running the Muen system using KVM/QEMU has some additional requirements:

- The host system must have a recent _Intel_ CPU with VT-d and IOMMU.
- The host system must be running at least Linux kernel 5.4.x, or have commit `04f11ef45810da5ae2542dd78cc353f3761bd2cb` applied as a patch. This commit will eventually make it into LTS kernels, but as of this writing has not.

To run the Muen system, use:

```
make -j5 MODE=muen run
```

This will start QEMU in a detached `screen` session. Note that the VGA console is not used, follow `run/serial.out` for the system console.
