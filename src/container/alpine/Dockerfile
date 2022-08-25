ARG ocaml_version=ocaml-4.14-flambda
ARG distro_version=alpine
FROM ocaml/opam:${distro_version}-${ocaml_version} AS builder

ADD .git/ /tmp/repo

RUN git clone -s /tmp/repo /home/opam/nethsm

WORKDIR /home/opam/nethsm

RUN opam exec -- make -j$(nproc) local-container-setup

RUN opam exec -- make -j$(nproc) build-keyfender

COPY src/container/static src/s_keyfender/htdocs

RUN rm src/s_keyfender/keyfender.hvt && opam exec -- make -j$(nproc) build-keyfender

RUN cd src/s_keyfender \
  && opam exec -- mirage configure -t unix --no-platform=true \
  --http=8080 --https=8443 --single-interface --retry=true \
  --platform=127.0.0.1 \
  && opam exec -- make depend \
  && opam exec -- make build \
  && cp keyfender keyfender.unix

FROM alpine:3.15

RUN apk add --no-cache iptables curl gmp \
  && apk add etcd --no-cache --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing

VOLUME /data

EXPOSE 8443

COPY src/container/alpine/start.sh /

ENTRYPOINT /start.sh

COPY --from=builder \
  /home/opam/.opam/4.14/bin/solo5-hvt \
  /home/opam/nethsm/src/s_keyfender/keyfender.hvt \
  /home/opam/nethsm/src/s_keyfender/keyfender.unix \
  /
