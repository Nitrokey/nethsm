FROM ocaml/opam:alpine-3.15-ocaml-4.13-flambda AS builder

ADD .git/ /tmp/repo

RUN git clone -s /tmp/repo /home/opam/nethsm

RUN cd /home/opam/opam-repository \
  && git remote set-url origin https://github.com/ocaml/opam-repository.git \
  && git fetch origin master \
  && git reset --hard $(cat /home/opam/nethsm/.opam-repository-commit) \
  && opam update \
  && cd -

WORKDIR /home/opam/nethsm

RUN opam exec -- make fetch-submodules

RUN opam exec -- make -j$(nproc) build-keyfender

COPY src/container/static src/s_keyfender/htdocs

RUN rm src/s_keyfender/keyfender.hvt && opam exec -- make -j$(nproc) build-keyfender

RUN cd src/s_keyfender \
  && opam exec -- mirage configure -t unix --no-platform=true \
  --http=8080 --https=8443 --single-interface --retry=true \
  --remote=git://127.0.0.1/keyfender-data.git \
  && opam exec -- make depend \
  && opam exec -- make build

FROM alpine:3.15

RUN apk add --no-cache iptables git-daemon curl gmp

VOLUME /data

EXPOSE 8443

COPY src/container/alpine/start.sh /

ENTRYPOINT /start.sh

COPY --from=builder \
  /home/opam/.opam/4.13/bin/solo5-hvt \
  /home/opam/nethsm/src/s_keyfender/keyfender.hvt \
  /home/opam/nethsm/src/s_keyfender/keyfender \
  /
