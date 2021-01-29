#FROM ocaml/opam2:latest
FROM ocaml/opam:alpine-3.12-ocaml-4.11-flambda AS builder

ARG GIT_USER
ARG GIT_PASSWORD
ARG GIT_COMMIT=master
ARG OPAM_REF=f86b6d27e1

RUN cd /home/opam/opam-repository \
  && git fetch origin master \
  && git reset --hard $OPAM_REF \
  && opam update \
  && cd -

RUN cd /home/opam \
  && [ ! -d nethsm ] \
  && git clone https://$GIT_USER:$GIT_PASSWORD@git.dotplex.com/nitrokey/nethsm/nethsm.git \
  && cd nethsm \
  && git reset --hard $GIT_COMMIT \
  && cd ..

WORKDIR /home/opam/nethsm

RUN opam exec -- make fetch-submodules

RUN opam exec -- make -j$(nproc) build-keyfender

COPY static src/s_keyfender/htdocs

RUN rm src/s_keyfender/keyfender.hvt && opam exec -- make -j$(nproc) build-keyfender

FROM alpine:3.12

RUN apk add --no-cache iptables git-daemon curl

VOLUME /data

EXPOSE 8443

COPY alpine/start.sh /

ENTRYPOINT /start.sh

COPY --from=builder \
  /home/opam/.opam/4.11/bin/solo5-hvt \
  /home/opam/nethsm/src/s_keyfender/keyfender.hvt \
  /
