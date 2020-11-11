#FROM ocaml/opam2:latest
FROM ocaml/opam2:debian-10-ocaml-4.11 AS builder

# token: 1VJw4yyua61piTDCzPax

RUN git fetch origin master && git reset --hard f86b6d27e1 && opam update

RUN sudo apt-get install zlib1g-dev

RUN cd $HOME && git clone https://oauth2:1VJw4yyua61piTDCzPax@git.dotplex.com/nitrokey/nitrohsm.git

WORKDIR $HOME/nitrohsm

RUN opam exec -- make build

COPY static src/s_keyfender/htdocs

RUN rm src/s_keyfender/keyfender.hvt && opam exec -- make build-keyfender

FROM debian:buster

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
  && apt-get install \
    simpleproxy \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

VOLUME /data

EXPOSE 8443

COPY start.sh /

ENTRYPOINT /start.sh

COPY --from=builder \
  /home/opam/.opam/4.11/bin/solo5-hvt \
  /home/opam/nitrohsm/src/git/git \
  /home/opam/nitrohsm/src/git/git-daemon \
  /bin/

COPY --from=builder \
  /home/opam/nitrohsm/src/s_keyfender/keyfender.hvt \
  /home/opam/nitrohsm/tools/setup-net-dev.sh \
  /
