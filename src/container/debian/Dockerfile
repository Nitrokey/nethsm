#FROM ocaml/opam2:latest
FROM ocaml/opam:debian-10-ocaml-4.11 AS builder

ARG TOKEN=1VJw4yyua61piTDCzPax
ARG OPAM_REF=f86b6d27e1

RUN cd /home/opam/opam-repository \
  && git fetch origin master \
  && git reset --hard $OPAM_REF \
  && opam update \
  && cd -

RUN cd /home/opam \
  && git clone https://oauth2:$TOKEN@git.dotplex.com/nitrokey/nethsm.git

WORKDIR /home/opam/nethsm

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
