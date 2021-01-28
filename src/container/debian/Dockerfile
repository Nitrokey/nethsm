FROM ocaml/opam:debian-10-ocaml-4.11-flambda AS builder

ARG GIT_USER
ARG GIT_PASSWORD
ARG GIT_COMMIT=master

RUN cd /home/opam \
  && [ ! -d nethsm ] \
  && git clone https://$GIT_USER:$GIT_PASSWORD@git.dotplex.com/nitrokey/nethsm/nethsm.git \
  && cd nethsm \
  && git reset --hard $GIT_COMMIT \
  && cd ..

RUN cd /home/opam/opam-repository \
  && git fetch origin master \
  && git reset --hard $(cat /home/opam/nethsm/.opam-repository-commit) \
  && opam update \
  && cd -

WORKDIR /home/opam/nethsm

RUN opam exec -- make fetch-submodules

RUN opam exec -- make -j$(nproc) build-keyfender

COPY static src/s_keyfender/htdocs

RUN rm src/s_keyfender/keyfender.hvt && opam exec -- make -j$(nproc) build-keyfender

FROM debian:buster

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    iptables \
    git \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

VOLUME /data

EXPOSE 8443

COPY debian/start.sh /

ENTRYPOINT /start.sh

COPY --from=builder \
  /home/opam/.opam/4.11/bin/solo5-hvt \
  /home/opam/nethsm/src/s_keyfender/keyfender.hvt \
  /home/opam/nethsm/tools/setup-net-dev.sh \
  /
