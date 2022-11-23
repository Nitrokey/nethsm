ARG distro_version=alpine:3.15
FROM ${distro_version} AS builder

RUN --mount=type=tmpfs,target=/tmp <<EOF
  apk add curl openssl rsync git mercurial make gcc patch musl-dev \
    linux-headers pkgconfig gmp-dev libseccomp-dev m4 protobuf protobuf-dev \
    coreutils unzip bubblewrap sudo openssh-client
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

ARG ocaml_version="ocaml-variants.4.14.0+options ocaml-options-only-flambda"
RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/home/opam/.opam/download-cache,uid=1000,gid=1000 <<EOF
  OPAMJOBS=$(nproc) opam switch create default ${ocaml_version}
  opam switch set default
EOF

ARG OPAM_REPOSITORY_COMMIT
RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/home/opam/.opam/download-cache,uid=1000,gid=1000 <<EOF
  opam repository set-url default git+https://github.com/ocaml/opam-repository#${OPAM_REPOSITORY_COMMIT}
  opam update
  OPAMJOBS=$(nproc) opam install -y dune 'mirage>=3.10.4' 'functoria<4'
EOF

RUN --mount=type=tmpfs,target=/tmp --mount=type=bind,source=.git,target=/repo <<EOF
  git clone -s /repo /home/opam/nethsm
EOF

WORKDIR /home/opam/nethsm

RUN --mount=type=tmpfs,target=/tmp <<EOF
  cp -a src/container/static/ src/s_keyfender/htdocs
  mkdir -p src/s_keyfender/htdocs/api_docs
  cp docs/nethsm-api.yaml src/s_keyfender/htdocs/api_docs/
  curl -sSL "https://github.com/swagger-api/swagger-ui/archive/master.tar.gz" -o /tmp/swagger-ui.tar.gz
  mkdir -p /tmp/swagger-ui
  tar -C /tmp/swagger-ui --strip-components=1 -xzf /tmp/swagger-ui.tar.gz
  # Sets NetHSM API specification file
  sed -i 's/url: "https:\/\/petstore.swagger.io\/v2\/swagger.json",/url: ".\/nethsm-api.yaml"\,/g' \
    /tmp/swagger-ui/dist/swagger-initializer.js
  # Removes the SwaggerUI top bar
  sed -i '/layout: "StandaloneLayout"\|SwaggerUIStandalonePreset/d' \
    /tmp/swagger-ui/dist/swagger-initializer.js
  cp -a /tmp/swagger-ui/dist/* src/s_keyfender/htdocs/api_docs/
EOF

RUN <<EOF
  mkdir -p -m 0700 ~/.ssh
  ssh-keyscan git.nitrokey.com >> ~/.ssh/known_hosts
EOF

RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/home/opam/.opam/download-cache,uid=1000,gid=1000 \
  --mount=type=ssh,required=true,uid=1000,gid=1000 <<EOF
  OPAMJOBS=$(nproc) opam exec -- make -j$(nproc) build-keyfender
EOF

RUN --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/home/opam/.opam/download-cache,uid=1000,gid=1000 \
  --mount=type=ssh,required=true,uid=1000,gid=1000 <<EOF
  export OPAMJOBS=$(nproc)
  cd src/s_keyfender
  opam exec -- mirage configure --no-depext -t unix --no-platform=true \
    --http=8080 --https=8443 --single-interface --retry=true \
    --platform=127.0.0.1
  opam exec -- make -j$(nproc) depend
  opam exec -- make -j$(nproc) build
  cp keyfender keyfender.unix
EOF

FROM ${distro_version}

RUN --mount=type=tmpfs,target=/tmp <<EOF
  apk add --no-cache iptables curl gmp
  apk add etcd --no-cache --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing
EOF

VOLUME /data

EXPOSE 8443

COPY src/container/alpine/start.sh /

ENTRYPOINT /start.sh

COPY --from=builder \
  /home/opam/.opam/default/bin/solo5-hvt \
  /home/opam/nethsm/src/s_keyfender/keyfender.hvt \
  /home/opam/nethsm/src/s_keyfender/keyfender.unix \
  /
