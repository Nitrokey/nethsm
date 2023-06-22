# Developer Manual

## Hardware

### Prodrive Hermes

To deploy NetHSM onto a Prodrive Hermes system the following steps are to be taken:

- Flash coreboot firmware.
- Install the NetHSM system image and data on a hard drive.

This guide assumes that the full repository with Prodrive Hermes as the hardware plattform
was compiled. The build artifacts from the `objs` directory must be available.
Please refer to chapter [Software](#software) to learn more about how to compile the NetHSM software.

#### Flash NetHSM firmware

The NetHSM firmware can be either installed with raw firmware files, or a firmware update file.

##### Flashing with raw firmware files

The follwing instructions need the `coreboot.rom` file, and a USB device with a bootable Linux, e.g. grml, that includes the `flashroom` utility.

Currently the generated `coreboot.rom` does not contain an IFD, this means
the resulting image is not suited for flashing it directly on the NAND.

The image can be flashed as follows.

1. Open the BMC frontend in the browser, navigate to *Administration* -> *Firmware update* -> *BIOS*.
2. Upload a (release) bios update to enable booting a "simple" Linux.
3. Fully power off the system (real power off, not just mainboard's the power button).
4. Connect the bootable USB device. To interact with the system the BMC remote console shall be used.
5. Before booting into the system make sure the linux commandline arguments contain: `nopat iomem=relaxed` in order to enable flashing the NAND using `flashrom`.
6. Once inside the Linux system, start `sshd` and copy over the `coreboot.rom` into the running system.
7. Flash the (bios region) of the NAND using the command `flashrom --ifd -i bios -p internal --noverify-all -w coreboot.rom`.
8. Once this is done, shut off the system completely.

##### Flashing with firmware update file

The following instructions need the `bios.swu` file.

The image can be flashed as follows.

1. Open the BMC frontend in the browser, navigate to *Administration* -> *Firmware update* -> *BIOS*.
2. Upload the `bios.swu` file.
3. Fully power off the system (real power off, not just mainboard's the power button).

#### Install NetHSM system software

The NetHSM system software can be either installed manually on a hard disk drive, or with the guided installer.

##### Installing manually on hard disk drive

The following instructions need the `system.img.cpio` file, and the `cgpt` and `e2fsprogs` utilities.

1. Connect a hard-drive to your computer (any data on the device will be deleted!)
2. The following steps assume your hard-drive is available as `/dev/sdb`, please adapt accordingly!
3. Install the *NetHSM System Image* with the command `tools/nethsm-install.sh /dev/sdb objs/system.img.cpio`.
4. Make sure to properly eject/umount the partitions.
5. Connect the hard disk drive with the Prodrive Hermes.
6. Turn on the NetHSM.

##### Installing with guided installer

The following instructions need the `installer.img` file.

The installer can be run as follows.

1. Open the BMC frontend in the browser, navigate to *development-board* -> *Virtual Media*.
2. Open the tab *usb0* and choose *Attach Media* -> *Stream file local via browser* and select the `installer.img` file.
3. Open the menu *Overview*. In the box *development-board* set the dropdown box to *On*, to turn on the NetHSM.
4. The installation can be controlled in the menu *development-board* -> *Remote KVM*.
5. After the installation is complete open the menu *Virtual Media* -> *usb0* and press *Eject* to remove the installer image.

## Software

The NetHSM software can be built either as components that run on your local machine (the "Local Development System") or as a full emulated Muen system (the "Muen System").

In either case, running `make` in this directory will produce a short help. The following sections detail how to build and run the software.

### Local build

The local development system builds only the subset of the codebase required to run an `S-Keyfender` instance against a local Git repository for data storage. This is the default if a `MODE` is not specified to `make`.

This is supported on Linux and FreeBSD systems, and to a lesser extent on Mac (`MODE=test` only).

1. Ensure you have installed OPAM >= 2.0.0 and OCaml >= 4.10.1. We recommend that you use the latest OCaml release, at the moment 4.11.1.
2. Create a new OPAM switch for NetHSM development, using a known-good commit of `ocaml/opam-repository`:

    ```
    opam repo add nethsm-default git+https://github.com/ocaml/opam-repository#$(cat .opam-repository-commit) --dont-select
    opam switch create nethsm 4.11.1 --repos nethsm-default
    eval $(opam env)
    ```

3. Build the system with:

    ```
    make -j$(nproc) build
    ```

#### Running

To run the local development system on your local machine, first ensure that you have set up the required network interfaces _on the host_ by running:

```
sudo tools/setup-net-dev.sh
```

This script will set up the following TAP interfaces on your local system:

- _tap200_: configured as `192.168.1.100/24`, used to communicate with the "external" interface of the NetHSM.
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

### Build with Docker

1. To enter the Docker container, run:

    ```
    make local-container-enter
    # If you want to use a locally built image, run:
    # make DOCKER_IMAGE_NAME=nethsm-builder local-container-enter
    ```

2. Once inside the container, run:

    ```
    make local-container-setup
    ```

3. Build the system with:

    ```
    make -j$(nproc) build
    ```

Notes:

- The Docker container will bind mount your checked out NetHSM repository as `/builds/nitrokey/nethsm` in the container. `make local-container-setup` attempts to fix permissions on `$HOME` in the container if your UID is not `1000`.
- The Docker container is run with `--net=host`. This is intentional, so that you can talk to a running NetHSM from the host.
- `/dev/net/tun` and `/dev/kvm` (if present and the host user can access it) are passed through to the container.
- Due to the above, `make local-container-enter` will work only on a Linux host (i.e. not Docker for Mac, for example).

#### Caching

Both `ccache` and the dune [cache](https://github.com/ocaml/dune/blob/master/doc/caching.rst) can be used to speed up the build. This is especially useful for the Muen system, where local build times from a clean tree without caching are on the order of 35 minutes. This is experimental, and currently requires some additional setup after the `make local-container-setup` step:

To build with `ccache`, before invoking `make` in the container, run:

```
export PATH=/usr/lib/ccache:$PATH
export CCACHE_DIR=$PWD/cache/ccache
export CCACHE_BASEDIR=$PWD
```

When invoking `make`, add `USE_CCACHE=1` to the command line for correct operation.

To enable the dune cache, before invoking `make` in the container, run:

```
mkdir -p $PWD/cache/dune
export XDG_CACHE_HOME=$PWD/cache
mkdir -p $HOME/.config/dune
cat <<EOM >$HOME/.config/dune/config
(lang dune 2.7)
(cache enabled)
(cache-transport direct)
EOM
```

This will eventually be integrated better into `make local-container-setup`.

#### Test Coverage Reporting

For OCaml there is a PPX (preprocessor) which can collect coverage information called `bisect_ppx`. The keyfender library is instrumented (see `src/keyfender/dune` for details) if dune is called with `--instrument-with bisect_ppx`.

To collect coverage information about the tests:

1. install `bisect_ppx` (`opam install 'bisect_ppx>=2.5.0'`)
2. `export MODE=test` in your shell
3. `make coverage`
5. browse to obj/coverage/index.html

#### Running

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

### Release process

#### Changes

During the build process, the version number from the toplevel CHANGES.md file is used. The version number is MAJOR.MINOR. Downgrades are only allowed in the same MAJOR line.

To release a new version 42.5, add the following to the top of CHANGES.md: "# 42.5 (2022-02-27)"

Add the changes (as a markdown list) before the previous release marker. This will be taken as user-visible changes in the update image.

## Additional information

### System Console

The system console is exposed over the serial port on the back of the NetHSM hardware.
Configuration information can be found in the [user documentation](https://docs.nitrokey.com/nethsm/administration#logging).
