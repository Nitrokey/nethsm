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
ARG distro_version=ubuntu:20.04
FROM ${distro_version} AS base

LABEL maintainer "Sven Anderson <sven@anderson.de>"
LABEL description "This image provides the build environment for the NetHSM project"

# Muen: Required packages
ARG muen_packages="acpica-tools amtterm autoconf automake autopoint bc binutils-dev \
        bison bzip2 ca-certificates ccache cpio curl file flex git-core gnupg gnuplot \
        inotify-tools kmod lcov libc6-dev libcurl4-gnutls-dev libelf-dev \
        libfreetype6-dev libiberty-dev libncurses-dev libseccomp-dev libssl-dev \
        libxml2-utils make mtools openssh-client patch picocom pkg-config python3 python3-pip \
        g++ git-merge-changelog python-is-python3 libtool qemu-system-x86 rsync \
        screen tidy unzip vim wget xfonts-unifont xorriso xsltproc xz-utils zlib1g-dev"

# Mirage/Solo5/NetHSM: Required packages
# Note: Some of these would be installed by "opam depext" automatically during
# the build process, but we do this now to save time and downloads later.
ARG nethsm_packages="cgpt e2fsprogs grub-common grub-pc-bin jq libgmp-dev \
        libseccomp-dev linux-libc-dev m4 parallel perl pkg-config \
        sudo libprotobuf-dev protobuf-compiler software-properties-common"

RUN apt-get update && \
        DEBIAN_FRONTEND=noninteractive apt-get install -qq -y \
        --no-install-recommends \
        $muen_packages $nethsm_packages \
        && add-apt-repository ppa:stefanberger/swtpm-focal \
        && apt update \
        && DEBIAN_FRONTEND=noninteractive apt install -qq -y --no-install-recommends \
        libtpms0 \
        swtpm \
        && pip install --no-cache-dir lxml colorlog lief \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home opam \
        && chown -R opam:opam /home/opam \
        && echo 'opam ALL=(ALL:ALL) NOPASSWD:ALL' > /etc/sudoers.d/opam \
        && chmod 440 /etc/sudoers.d/opam \
        && chown root:root /etc/sudoers.d/opam \
        && sed -i.bak 's/^Defaults.*requiretty//g' /etc/sudoers \
        && sudo mkdir /nethsm-tools \
        && sudo chown opam:opam /nethsm-tools

USER opam

# NetHSM: Install musl-cross toolchain
# TODO: Verify hash of downloaded toolchain
RUN curl -sSL "http://musl.cc/x86_64-linux-musl-cross.tgz" -o /tmp/musl-cross.tar.gz \
        && sudo tar -C /opt -xzf /tmp/musl-cross.tar.gz \
        && rm /tmp/musl-cross.tar.gz

RUN curl -sSL "https://github.com/tytso/e2fsprogs/archive/v1.46.5.tar.gz" -o /tmp/e2fsprogs.tar.gz \
        && mkdir -p /tmp/e2fsprogs/build \
        && tar -C /tmp/e2fsprogs --strip-components=1 -xzf /tmp/e2fsprogs.tar.gz \
        && cd /tmp/e2fsprogs/build \
        && ../configure \
        --host=x86_64-linux-musl \
        --enable-libuuid \
        --enable-libblkid \
        --disable-nls \
        CC="/opt/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc" \
        LDFLAGS=-static \
        && make -j$(nproc) PROG_SUBDIRS=misc \
        && strip misc/mke2fs \
        && mkdir -p /nethsm-tools/bin \
        && cp misc/mke2fs /nethsm-tools/bin/ \
        && cd \
        && rm -rf /tmp/e2fsprogs /tmp/e2fsprogs.tar.gz

RUN curl -sSL "https://github.com/util-linux/util-linux/archive/v2.38.1.tar.gz" -o /tmp/util-linux.tar.gz \
        && mkdir -p /tmp/util-linux \
        && tar -C /tmp/util-linux --strip-components=1 -xzf /tmp/util-linux.tar.gz \
        && cd /tmp/util-linux \
        && sed -i s/^enable_fdisk=.*/enable_fdisk=no/ configure.ac \
        && sed -i s/^enable_cfdisk=.*/enable_cfdisk=no/ configure.ac \
        && ./autogen.sh \
        && ./configure --host=x86_64-linux-musl \
        --disable-shared --disable-nls \
        --disable-all-programs \
        --enable-libfdisk --enable-libuuid --enable-libsmartcols \
        --enable-fdisks --enable-static-programs=sfdisk \
        --without-tinfo --without-systemd --without-python \
        CC="/opt/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc" \
        && make \
        && strip sfdisk.static \
        && mkdir -p /nethsm-tools/bin \
        && cp sfdisk.static /nethsm-tools/bin/sfdisk \
        && cd \
        && rm -rf /tmp/util-linux /tmp/util-linux.tar.gz

# Muen: Install AdaCore toolchain
RUN git clone --depth=1 https://github.com/AdaCore/gnat_community_install_script.git /tmp/gnat_script \
        && curl -sSL "https://community.download.adacore.com/v1/f3a99d283f7b3d07293b2e1d07de00e31e332325?filename=gnat-2021-20210519-x86_64-linux-bin" -o /tmp/gnat_installer.bin \
        && sudo sh /tmp/gnat_script/install_package.sh /tmp/gnat_installer.bin /opt/gnat \
        && rm -rf /tmp/gnat*

RUN mkdir -p /nethsm-tools/muen \
        && git clone --depth 1 -b v1.0.0 https://git.codelabs.ch/git/muen.git /nethsm-tools/muen \
        && cd /nethsm-tools/muen \
        && git submodule update --init --depth 50 \
        && make PATH=/opt/gnat/bin:$PATH -j$(nproc) tools

# patch muennet until it's fixed upstream
COPY muennet-tailroom.patch /tmp/
RUN cd /nethsm-tools/muen/components/linux/modules/muennet \
        && patch </tmp/muennet-tailroom.patch

ARG GITLAB_TOKEN
RUN mkdir -p /nethsm-tools/coreboot \
        && git clone --depth 50 -b nethsm https://gitlab-ci-token:${GITLAB_TOKEN}@git.nitrokey.com/nitrokey/nethsm/coreboot.git /nethsm-tools/coreboot \
        && cd /nethsm-tools/coreboot \
        && git remote set-url origin https://github.com/coreboot/coreboot.git \
        && git submodule update --checkout --init --depth 50

RUN if [ -d /downloads ] ; then mkdir -p /downloads/tarballs \
        && ln -s /downloads/tarballs /nethsm-tools/coreboot/util/crossgcc/ ; fi \
        && make -C /nethsm-tools/coreboot PATH=/opt/gnat/bin:$PATH CPUS=$(nproc) crossgcc-i386

RUN cd /nethsm-tools/coreboot/payloads/external/GRUB2 \
        && git clone --depth 50 -b nethsm https://gitlab-ci-token:${GITLAB_TOKEN}@git.nitrokey.com/nitrokey/nethsm/grub.git grub2 \
        && mkdir grub2/gnulib && cd grub2/gnulib \
        && git init && git remote add origin https://github.com/coreutils/gnulib \
        && git fetch origin --depth 1 $(sed -n s/^GNULIB_REVISION=//p ../bootstrap.conf) \
        && git reset --hard FETCH_HEAD

RUN curl -sSL "https://go.dev/dl/go1.19.linux-amd64.tar.gz" -o /tmp/go.tar.gz \
        && sudo tar -C /opt -xzf /tmp/go.tar.gz \
        && rm /tmp/go.tar.gz

RUN curl -sSL "https://github.com/u-root/u-root/archive/v0.9.0.tar.gz" -o /tmp/u-root.tar.gz \
        && mkdir -p /nethsm-tools/u-root \
        && tar -C /nethsm-tools/u-root --strip-components=1 -xzf /tmp/u-root.tar.gz \
        && cd /nethsm-tools/u-root \
        && /opt/go/bin/go build \
        && rm /tmp/u-root.tar.gz

RUN cd /tmp \
        && curl -sL https://raw.githubusercontent.com/ocaml/opam/master/shell/install.sh | sh -s -- --download-only \
        && sudo install opam-2* /usr/local/bin/opam \
        && rm opam-2*

ARG OPAM_REPOSITORY_COMMIT
RUN opam init -a --disable-sandboxing --bare \
        git+https://github.com/ocaml/opam-repository#${OPAM_REPOSITORY_COMMIT} \
        && rm -rf /home/opam/.opam/download-cache \
        && if [ -d /downloads ] ; then mkdir -p /downloads/opam \
        &&   ln -s /downloads/opam /home/opam/.opam/download-cache ; fi \
        && OPAMJOBS=$(nproc) opam switch create 4.14 ocaml-variants.4.14.0+options ocaml-options-only-flambda \
        && eval $(opam env) \
        && opam update \
        && OPAMJOBS=$(nproc) opam install -y dune 'mirage>=3.10.4' 'functoria<4' 'bisect_ppx>=2.5.0' containers ezjsonm yaml \
        && if [ -h /home/opam/.opam/download-cache ] ; then rm /home/opam/.opam/download-cache ; fi

ARG COMMIT_ID
RUN sudo /bin/sh -c "echo ${COMMIT_ID} > /.builder_id"

LABEL opam_repo_commit ${OPAM_REPOSITORY_COMMIT}
LABEL builder_id ${COMMIT_ID}

# Setup environment
ENV LANG C.UTF-8
ENV PATH /opt/x86_64-linux-musl-cross/bin:/opt/go/bin:$PATH
WORKDIR /builds/nitrokey/nethsm
ENTRYPOINT [ "opam", "exec", "--" ]
CMD [ "bash" ]
