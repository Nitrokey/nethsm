# syntax=docker/dockerfile:1.4
# Dockerfile for NetHSM build environment.
#
# Based on Muen tools/docker/Dockerfile.muen-dev-env, with additions required
# to build a MODE=dev and MODE=muen NetHSM system.
#
# Building the Docker container locally:
#
#   docker build -t nethsm-builder -f Dockerfile.nethsm-builder .
#

# Base image
ARG distro_version=ubuntu:22.04
FROM ${distro_version} AS base

LABEL maintainer "Sven Anderson <sven@anderson.de>"
LABEL description "This image provides the build environment for the NetHSM project"

# Muen: Required packages
ARG muen_packages="acpica-tools amtterm autoconf automake autopoint bc bison bzip2 \
  ca-certificates ccache cpio curl file flex gawk gettext git-core \
  gnupg inotify-tools iputils-ping iucode-tool kmod lcov libc6-dev \
  libcurl4-gnutls-dev libelf-dev libfreetype6-dev libgmp10-dev libiberty-dev \
  libncurses-dev libseccomp-dev libssl-dev libxml2-utils lighttpd make mtools \
  openssh-client patch picocom pkg-config python3-minimal python3-lxml \
  python3-colorlog python3-setuptools python3-pip python3-rangehttpserver \
  python3-wheel qemu-system-x86 rsync screen tidy unzip vim wget \
  xfonts-unifont xorriso xsltproc xxd xz-utils zlib1g-dev"

# Mirage/Solo5/NetHSM: Required packages
# Note: Some of these would be installed by "opam depext" automatically during
# the build process, but we do this now to save time and downloads later.
ARG nethsm_packages="cgpt e2fsprogs grub-common grub-pc-bin jq libgmp-dev \
  libseccomp-dev linux-libc-dev m4 parallel perl pkg-config zip \
  sudo libprotobuf-dev protobuf-compiler software-properties-common"

ARG additional_packages="g++ zlib1g git-merge-changelog git-lfs opensc pcscd \
  scdaemon libtool less joe"

RUN rm -f /etc/apt/apt.conf.d/docker-clean; echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

ARG DEBIAN_FRONTEND=noninteractive
RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/var/cache/apt,sharing=locked \
  --mount=type=cache,target=/var/lib/apt,sharing=locked <<EOF
  apt-get update
  apt-get install -qq -y --no-install-recommends $muen_packages $nethsm_packages $additional_packages
  add-apt-repository ppa:stefanberger/swtpm-focal
  apt-get update
  apt-get install -qq -y --no-install-recommends libtpms0 swtpm
  pip install --no-cache-dir lxml colorlog lief==0.14.1
EOF

RUN --mount=type=tmpfs,target=/tmp <<EOF
  useradd --create-home opam
  chown -R opam:opam /home/opam
  echo 'opam ALL=(ALL:ALL) NOPASSWD:ALL' > /etc/sudoers.d/opam
  chmod 440 /etc/sudoers.d/opam
  chown root:root /etc/sudoers.d/opam
  sed -i.bak 's/^Defaults.*requiretty//g' /etc/sudoers
  sudo mkdir /nethsm-tools
  sudo chown opam:opam /nethsm-tools
EOF

RUN --mount=type=tmpfs,target=/tmp <<EOF
  curl -sSL "https://github.com/alire-project/alire/releases/download/v2.0.1/alr-2.0.1-bin-x86_64-linux.zip" -o /tmp/alr.zip
  unzip /tmp/alr.zip bin/alr -d /usr/local
EOF

USER opam

ENV ALIRE_SETTINGS_DIR=/opt/gnat/alire

RUN <<EOF
  mkdir -p -m 0700 /home/opam/.ssh
  ssh-keyscan git.nitrokey.com >> /home/opam/.ssh/known_hosts
EOF

FROM base AS musl
# NetHSM: Install musl-cross toolchain
# TODO: Verify hash of downloaded toolchain
RUN --mount=type=tmpfs,target=/tmp <<EOF
  curl -sSL "http://musl.cc/x86_64-linux-musl-cross.tgz" -o /tmp/musl-cross.tar.gz
  sudo tar -C /opt -xzf /tmp/musl-cross.tar.gz
EOF

FROM musl AS mke2fs
RUN --mount=type=tmpfs,target=/tmp <<EOF
  curl -sSL "https://github.com/tytso/e2fsprogs/archive/v1.47.1.tar.gz" -o /tmp/e2fsprogs.tar.gz
  mkdir -p /tmp/e2fsprogs/build
  tar -C /tmp/e2fsprogs --strip-components=1 -xzf /tmp/e2fsprogs.tar.gz
  cd /tmp/e2fsprogs/build
  ../configure \
  --host=x86_64-linux-musl \
  --enable-libuuid \
  --enable-libblkid \
  --disable-nls \
  CC="/opt/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc" \
  LDFLAGS=-static
  make -j$(nproc) PROG_SUBDIRS=misc
  strip misc/mke2fs
  mkdir -p /nethsm-tools/bin
  cp misc/mke2fs /nethsm-tools/bin/
EOF

FROM musl AS sfdisk
RUN --mount=type=tmpfs,target=/tmp <<EOF
  curl -sSL "https://github.com/util-linux/util-linux/archive/v2.40.2.tar.gz" -o /tmp/util-linux.tar.gz
  mkdir -p /tmp/util-linux
  tar -C /tmp/util-linux --strip-components=1 -xzf /tmp/util-linux.tar.gz
  cd /tmp/util-linux
  sed -i s/^enable_fdisk=.*/enable_fdisk=no/ configure.ac
  sed -i s/^enable_cfdisk=.*/enable_cfdisk=no/ configure.ac
  ./autogen.sh
  ./configure --host=x86_64-linux-musl \
  --disable-shared --disable-nls \
  --disable-all-programs \
  --enable-libfdisk --enable-libuuid --enable-libsmartcols \
  --enable-fdisks --enable-static-programs=sfdisk \
  --without-tinfo --without-systemd --without-python \
  CC="/opt/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc"
  make
  strip sfdisk.static
  mkdir -p /nethsm-tools/bin
  cp sfdisk.static /nethsm-tools/bin/sfdisk
EOF

FROM base AS ada
# Muen: Install AdaCore toolchain
RUN --mount=type=tmpfs,target=/tmp <<EOF
  sudo mkdir /opt/gnat
  sudo chown opam:opam /opt/gnat
  git clone --depth 1 https://git.codelabs.ch/alire/muen-dev-env.git /opt/gnat/muen-dev-env
  make -C /opt/gnat/muen-dev-env -j$(nproc)
EOF

FROM ada AS muen
RUN --mount=type=tmpfs,target=/tmp <<EOF
  mkdir -p /nethsm-tools/muen
  git clone --depth 1 -b v1.1.1 https://git.codelabs.ch/git/muen.git /nethsm-tools/muen
  git -C /nethsm-tools/muen submodule update --init --depth 50
EOF

# remove ABI changes for our old solo5
COPY --chown=1000:1000 muen-1.1.1.patch /nethsm-tools/muen
RUN patch -d /nethsm-tools/muen -i muen-1.1.1.patch -p1

# patches for z790
COPY --chown=1000:1000 z790.patch /nethsm-tools/muen/
RUN patch -d /nethsm-tools/muen -i z790.patch -p1

RUN --mount=type=tmpfs,target=/tmp bash -c "\
  source /opt/gnat/muen-dev-env/env; \
  make -C /nethsm-tools/muen -j$(nproc) tools \
  "

FROM base AS uroot
RUN --mount=type=tmpfs,target=/tmp <<EOF
  curl -sSL "https://go.dev/dl/go1.22.3.linux-amd64.tar.gz" -o /tmp/go.tar.gz
  sudo tar -C /opt -xzf /tmp/go.tar.gz
EOF

RUN --mount=type=tmpfs,target=/tmp <<EOF
  curl -sSL "https://github.com/u-root/u-root/archive/v0.14.0.tar.gz" -o /tmp/u-root.tar.gz
  mkdir -p /nethsm-tools/u-root
  tar -C /nethsm-tools/u-root --strip-components=1 -xzf /tmp/u-root.tar.gz
  cd /nethsm-tools/u-root
  /opt/go/bin/go build
EOF

FROM base AS builder
RUN --mount=type=tmpfs,target=/tmp <<EOF
  cd /tmp
  curl -sL https://raw.githubusercontent.com/ocaml/opam/master/shell/install.sh | sh -s -- --download-only
  sudo install opam-2* /usr/local/bin/opam
EOF

RUN --mount=type=tmpfs,target=/tmp <<EOF
  opam init -a --disable-sandboxing --bare git+https://github.com/ocaml/opam-repository
EOF

RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/home/opam/.opam/download-cache,uid=1000,gid=1000 <<EOF
  OPAMJOBS=$(nproc) opam switch create default ocaml-variants.4.14.0+options ocaml-options-only-flambda
  opam switch set default
EOF

ARG OPAM_REPOSITORY_COMMIT
COPY --chown=1000:1000 keyfender.opam.locked /home/opam/
COPY --chown=1000:1000 unikernel-preinstall.opam.locked /home/opam/
COPY --chown=1000:1000 gmp-freestanding /home/opam/gmp-6.3.0/
RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/home/opam/.opam/download-cache,uid=1000,gid=1000 <<EOF
  opam repository set-url default git+https://github.com/ocaml/opam-repository#${OPAM_REPOSITORY_COMMIT}
  curl -sSL "https://gmplib.org/download/gmp/gmp-6.3.0.tar.xz" | tar Jxpf - -C /home/opam
  patch -p1 -d /home/opam/gmp-6.3.0/ </home/opam/gmp-6.3.0/libgmp-fat.patch
  opam pin -y -n gmp-freestanding.6.3.0 /home/opam/gmp-6.3.0/
  opam pin -y -n solo5-bindings-muen 'https://github.com/nitrokey/nethsm-solo5.git#nethsm'
  opam update
  OPAMJOBS=$(nproc) opam install -y dune containers ezjsonm yaml ocamlformat
  OPAMJOBS=$(nproc) opam install -y --deps-only --with-test --locked --ignore-pin-depends /home/opam/keyfender.opam.locked
  OPAMJOBS=$(nproc) opam install -y --deps-only --with-test --locked --ignore-pin-depends /home/opam/unikernel-preinstall.opam.locked
EOF

# Remove opam cache directory
RUN rmdir /home/opam/.opam/download-cache 2>/dev/null || true

COPY --link --chown=1000:1000 --from=mke2fs /nethsm-tools/bin/mke2fs /nethsm-tools/bin/
COPY --link --chown=1000:1000 --from=sfdisk /nethsm-tools/bin/sfdisk /nethsm-tools/bin/
COPY --link --chown=1000:1000 --from=ada /opt/gnat /opt/gnat/
COPY --link --chown=1000:1000 --from=muen /nethsm-tools/muen /nethsm-tools/muen/
COPY --link --chown=1000:1000 --from=uroot /opt/go /opt/go/
COPY --link --chown=1000:1000 --from=uroot /nethsm-tools/u-root /nethsm-tools/u-root/

ARG COMMIT_ID
LABEL opam_repo_commit ${OPAM_REPOSITORY_COMMIT}
LABEL builder_id ${COMMIT_ID}
ENV OPAM_REPO_COMMIT ${OPAM_REPOSITORY_COMMIT}
ENV BUILDER_ID ${COMMIT_ID}

# Setup environment
ENV LANG C.UTF-8
ENV PATH /opt/x86_64-linux-musl-cross/bin:/opt/go/bin:/opt/gnat/bin:$PATH
WORKDIR /builds/nitrokey/nethsm
ENTRYPOINT [ "opam", "exec", "--" ]
CMD [ "bash" ]
