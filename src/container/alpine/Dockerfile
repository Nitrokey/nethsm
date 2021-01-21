#FROM ocaml/opam2:latest
FROM ocaml/opam:alpine-3.12-ocaml-4.11-flambda AS builder

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

RUN opam exec -- make build-keyfender

COPY static src/s_keyfender/htdocs

RUN rm src/s_keyfender/keyfender.hvt && opam exec -- make build-keyfender

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
