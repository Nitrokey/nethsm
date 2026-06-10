ARG distro_version=golang:alpine3.22
FROM ${distro_version} AS builder

RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/var/cache/apk,sharing=locked <<EOF
  apk add curl openssl rsync git mercurial make gcc patch musl-dev \
    linux-headers pkgconfig gmp-dev libseccomp-dev m4 protobuf protobuf-dev \
    coreutils unzip bubblewrap sudo openssh-client bash
  cd /tmp
  curl -sL https://raw.githubusercontent.com/ocaml/opam/master/shell/install.sh | sh -s -- --download-only
  install opam-2* /usr/local/bin/opam
EOF

RUN --mount=type=tmpfs,target=/tmp <<EOF
  adduser -D opam
  chown -R opam:opam /home/opam
  echo 'opam ALL=(ALL:ALL) NOPASSWD:ALL' > /etc/sudoers.d/opam
  chmod 440 /etc/sudoers.d/opam
  chown root:root /etc/sudoers.d/opam
  sed -i.bak 's/^Defaults.*requiretty//g' /etc/sudoers
EOF

USER opam

RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/var/cache/apk,sharing=locked <<EOF
  opam init -a --disable-sandboxing --bare
EOF

ARG ocaml_version="ocaml-variants.4.14.2+options ocaml-options-only-flambda"
RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/home/opam/.opam/download-cache,uid=1000,gid=1000 <<EOF
  OPAMJOBS=$(nproc) opam switch create default ${ocaml_version}
  opam switch set default
EOF

# copy mode: avoid EXDEV when cache is on separate partition
ENV DUNE_CACHE="enabled" DUNE_CACHE_STORAGE_MODE="copy"

RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/home/opam/.opam/download-cache,uid=1000,gid=1000 --mount=type=cache,target=/home/opam/.cache/dune,sharing=shared,uid=1000,gid=1000 --mount=type=cache,target=/var/cache/apk,sharing=locked <<EOF
  opam update
  OPAMJOBS=$(nproc) opam install -y dune opam-monorepo mirage=4.9.0
EOF

RUN --mount=type=tmpfs,target=/tmp --mount=type=bind,source=.git,target=/repo <<EOF
  git config --global --add safe.directory /repo
  git clone --depth=1 /repo /home/opam/nethsm
EOF

WORKDIR /home/opam/nethsm

RUN <<EOF
  mkdir -p -m 0700 ~/.ssh
  ssh-keyscan git.nitrokey.com >> ~/.ssh/known_hosts
EOF

# RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/home/opam/.opam/download-cache,uid=1000,gid=1000 <<EOF
#   OPAMJOBS=$(nproc) opam exec -- make -j$(nproc) build-keyfender
# EOF

RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/home/opam/.opam/download-cache,uid=1000,gid=1000 --mount=type=cache,target=/home/opam/.cache/dune,sharing=shared,uid=1000,gid=1000 --mount=type=cache,target=/var/cache/apk,sharing=locked  <<EOF
  OPAMJOBS=$(nproc) opam pin add -y -n keyfender.dev src/keyfender
  make src/keyfender/softwareVersion src/keyfender/buildTag src/s_keyfender/update_key_store/key.pem
  make ${PWD}/src/s_keyfender/htdocs/api_docs
EOF

RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/home/opam/.opam/download-cache,uid=1000,gid=1000 --mount=type=cache,target=/home/opam/.cache/dune,sharing=shared,uid=1000,gid=1000 <<EOF
  export OPAMJOBS=$(nproc)
  cd src/s_keyfender
  opam exec -- mirage configure --no-depext -t unix --no-platform --single-interface
  opam exec -- make -j$(nproc) depends
EOF

RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/home/opam/.opam/download-cache,uid=1000,gid=1000 --mount=type=cache,target=/home/opam/.cache/dune,sharing=shared,uid=1000,gid=1000 <<EOF
  export OPAMJOBS=$(nproc)
  cd src/s_keyfender
  opam exec -- make -j$(nproc) build
  cp dist/keyfender dist/keyfender.unix
EOF

# COPY vendor/mirage-tcpip /mirage-tcpip

# RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/home/opam/.opam/download-cache,uid=1000,gid=1000 <<EOF
#   OPAMJOBS=$(nproc) opam pin -y add tcpip.9.0.1 /mirage-tcpip/.
# EOF

RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/home/opam/.opam/download-cache,uid=1000,gid=1000 --mount=type=cache,target=/home/opam/.cache/dune,sharing=shared,uid=1000,gid=1000 <<EOF
  export OPAMJOBS=$(nproc)
  cd src/s_keyfender
  opam exec -- mirage configure --no-depext -t unix --internal-net=direct --external-net=direct
  opam exec -- make -j$(nproc) depends
EOF

RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/home/opam/.opam/download-cache,uid=1000,gid=1000 --mount=type=cache,target=/home/opam/.cache/dune,sharing=shared,uid=1000,gid=1000 <<EOF
  export OPAMJOBS=$(nproc)
  cd src/s_keyfender
  opam exec -- make -j$(nproc) build
  cp dist/keyfender dist/keyfender.tap
EOF

RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/home/opam/go/pkg/mod,uid=1000,gid=1000 --mount=type=cache,target=/home/opam/.cache/go-build,uid=1000,gid=1000 <<EOF
CGO_ENABLED=0 <<EOF
	go build -o src/container/alpine/tlsproxy src/container/alpine/tlsproxy.go
EOF

RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/home/opam/go/pkg/mod,uid=1000,gid=1000 --mount=type=cache,target=/home/opam/.cache/go-build,uid=1000,gid=1000 <<EOF
	cd src/u-root && CGO_ENABLED=0 go build -tags testing -o ./uinit/uinit ./uinit
EOF

RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/home/opam/go/pkg/mod,uid=1000,gid=1000 --mount=type=cache,target=/home/opam/.cache/go-build,uid=1000,gid=1000 <<EOF
	cd src/tests && CGO_ENABLED=0 go build ./perftest.go
EOF

FROM builder AS prod_builder

RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/home/opam/.opam/download-cache,uid=1000,gid=1000 --mount=type=cache,target=/home/opam/.cache/dune,sharing=shared,uid=1000,gid=1000 --mount=type=cache,target=/var/cache/apk,sharing=locked <<EOF
  OPAMJOBS=$(nproc) opam exec -- make -j$(nproc) build-keyfender
EOF

FROM ${distro_version} AS nethsm_production

RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/var/cache/apk,sharing=locked <<EOF
  apk add iptables curl gmp
EOF

EXPOSE 8443

COPY src/container/alpine/start-production.sh /start.sh
COPY --from=prod_builder \
  /home/opam/.opam/default/bin/solo5-hvt \
  /home/opam/nethsm/src/s_keyfender/dist/keyfender.hvt \
  /home/opam/nethsm/src/s_keyfender/dist/keyfender.unix \
  /home/opam/nethsm/src/container/alpine/tlsproxy \
  /

ENTRYPOINT [ "/start.sh" ]

FROM alpine AS nethsm_test

# Install the same version and binary of etcd/etcdutl than production

COPY Makefile.sub /Makefile

RUN --mount=type=tmpfs,target=/tmp <<EOF
  apk add --no-cache gmp make curl
  cd / && make -f /Makefile //etcd-download # really needs to be '//'
  mv /etcd-download/etcd /bin
  mv /etcd-download/etcdutl /bin
  rm -r /Makefile /etcd-download
EOF

RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/var/cache/apk,sharing=locked <<EOF
  apk add curl tcpdump iproute2 libcap nmap-nping arping screen
EOF

VOLUME /data

EXPOSE 8443

COPY src/container/alpine/start-test.sh /start.sh
COPY --from=builder \
  /home/opam/nethsm/src/s_keyfender/dist/keyfender.unix \
  /
COPY --from=builder \
  /home/opam/nethsm/src/s_keyfender/dist/keyfender.tap \
  /
COPY src/container/alpine/start-debug.sh /
COPY --from=builder /home/opam/nethsm/src/u-root/uinit/uinit /
COPY --from=builder /home/opam/nethsm/src/tests/perftest /
COPY src/container/alpine/provision.sh /

ENTRYPOINT [ "/start.sh" ]
