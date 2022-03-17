#!/bin/bash -ex

# requires: opam install ocaml-protoc-plugin

rm -rf gen
mkdir gen
protoc -I ./proto \
  "--ocaml_out=annot=[@@deriving show { with_path = false}];open=Stubs;open=Google_types:./gen/" \
  etcd/api/etcdserverpb/rpc.proto \
  etcd/api/mvccpb/kv.proto \
  etcd/api/authpb/auth.proto \
  etcd/api/versionpb/version.proto
