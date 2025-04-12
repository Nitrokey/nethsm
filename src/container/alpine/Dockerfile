ARG distro_version=alpine:3.16
FROM ${distro_version} AS builder

RUN --mount=type=tmpfs,target=/tmp <<EOF
  apk add curl openssl rsync git mercurial make gcc go patch musl-dev \
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

RUN --mount=type=tmpfs,target=/tmp <<EOF
  opam init -a --disable-sandboxing --bare
EOF

ARG ocaml_version="ocaml-variants.4.14.2+options ocaml-options-only-flambda"
RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/home/opam/.opam/download-cache,uid=1000,gid=1000 <<EOF
  OPAMJOBS=$(nproc) opam switch create default ${ocaml_version}
  opam switch set default
EOF

ARG OPAM_REPOSITORY_COMMIT
COPY --chown=1000:1000 src/container/builder/gmp-freestanding /home/opam/gmp-6.3.0/
RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/home/opam/.opam/download-cache,uid=1000,gid=1000 <<EOF
  curl -sSL "https://gmplib.org/download/gmp/gmp-6.3.0.tar.xz" | tar Jxpf - -C /home/opam
  patch -p1 -d /home/opam/gmp-6.3.0/ </home/opam/gmp-6.3.0/libgmp-fat.patch
  opam pin -y -n gmp-freestanding.6.3.0 /home/opam/gmp-6.3.0/
  opam update
  OPAMJOBS=$(nproc) opam install -y dune opam-monorepo mirage
EOF

RUN --mount=type=tmpfs,target=/tmp --mount=type=bind,source=.git,target=/repo <<EOF
  git clone /repo /home/opam/nethsm
EOF

WORKDIR /home/opam/nethsm

RUN <<EOF
  mkdir -p -m 0700 ~/.ssh
  ssh-keyscan git.nitrokey.com >> ~/.ssh/known_hosts
EOF

RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/home/opam/.opam/download-cache,uid=1000,gid=1000 <<EOF
  OPAMJOBS=$(nproc) opam exec -- make -j$(nproc) build-keyfender
EOF

RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/home/opam/.opam/download-cache,uid=1000,gid=1000 <<EOF
  export OPAMJOBS=$(nproc)
  cd src/s_keyfender
  opam exec -- mirage configure --no-depext -t unix --no-platform --single-interface
  opam exec -- make -j$(nproc)
  cp dist/keyfender dist/keyfender.unix
EOF

RUN CGO_ENABLED=0 go build -o src/container/alpine/tlsproxy src/container/alpine/tlsproxy.go

FROM ${distro_version} as nethsm_production

RUN --mount=type=tmpfs,target=/tmp <<EOF
  apk add --no-cache iptables curl gmp
EOF

EXPOSE 8443

COPY src/container/alpine/start-production.sh /start.sh
COPY --from=builder \
  /home/opam/.opam/default/bin/solo5-hvt \
  /home/opam/nethsm/src/s_keyfender/dist/keyfender.hvt \
  /home/opam/nethsm/src/s_keyfender/dist/keyfender.unix \
  /home/opam/nethsm/src/container/alpine/tlsproxy \
  /

ENTRYPOINT /start.sh

FROM ${distro_version} as nethsm_test

RUN --mount=type=tmpfs,target=/tmp <<EOF
  apk add --no-cache gmp
  apk add etcd --no-cache --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community
EOF

VOLUME /data

EXPOSE 8443

COPY src/container/alpine/start-test.sh /start.sh
COPY --from=builder \
  /home/opam/nethsm/src/s_keyfender/dist/keyfender.unix \
  /

ENTRYPOINT /start.sh
