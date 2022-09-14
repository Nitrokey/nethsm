ARG ocaml_version=ocaml-4.14-flambda
ARG distro_version=alpine
FROM ocaml/opam:${distro_version}-${ocaml_version} AS builder

ADD .git/ /tmp/repo

RUN sudo ln /usr/bin/opam-2.1 /usr/local/bin/opam \
  && git clone -s /tmp/repo /home/opam/nethsm

WORKDIR /home/opam/nethsm

RUN cp -a src/container/static/ src/s_keyfender/htdocs \
  && mkdir -p src/s_keyfender/htdocs/api_docs \
  && cp docs/nethsm-api.yaml src/s_keyfender/htdocs/api_docs/ \
  && curl -sSL "https://github.com/swagger-api/swagger-ui/archive/master.tar.gz" -o /tmp/swagger-ui.tar.gz \
  && mkdir -p /tmp/swagger-ui \
  && tar -C /tmp/swagger-ui --strip-components=1 -xzf /tmp/swagger-ui.tar.gz \
  # Sets NetHSM API specification file
  && sed -i 's/url: "https:\/\/petstore.swagger.io\/v2\/swagger.json",/url: ".\/nethsm-api.yaml"\,/g' \
  /tmp/swagger-ui/dist/swagger-initializer.js \
  # Removes the SwaggerUI top bar
  && sed -i '/layout: "StandaloneLayout"\|SwaggerUIStandalonePreset/d' \
  /tmp/swagger-ui/dist/swagger-initializer.js \
  && cp -a /tmp/swagger-ui/dist/* src/s_keyfender/htdocs/api_docs/ \
  && rm -r /tmp/swagger-ui*

RUN OPAMJOBS=$(nproc) opam exec -- make -j$(nproc) local-container-setup build-keyfender

RUN export OPAMJOBS=$(nproc) && cd src/s_keyfender \
  && opam exec -- mirage configure --no-depext -t unix --no-platform=true \
  --http=8080 --https=8443 --single-interface --retry=true \
  --platform=127.0.0.1 \
  && opam exec -- make -j$(nproc) depend \
  && opam exec -- make -j$(nproc) build \
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
