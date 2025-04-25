#!/bin/bash -ex

# requires: opam install ocaml-protoc-plugin

rm -rf gen
mkdir gen
protoc -I ./proto \
  "--ocaml_out=annot=[@@deriving show { with_path = false}]:./gen/" \
  etcd/api/etcdserverpb/rpc.proto \
  etcd/api/mvccpb/kv.proto \
  etcd/api/authpb/auth.proto \
  etcd/api/versionpb/version.proto

mkdir gen/google_types

protoc -I ./proto --ocaml_out=./gen/google_types/ \
  google/protobuf/timestamp.proto \
  google/protobuf/field_mask.proto \
  google/protobuf/api.proto \
  google/protobuf/duration.proto \
  google/protobuf/struct.proto \
  google/protobuf/wrappers.proto \
  google/protobuf/source_context.proto \
  google/protobuf/any.proto \
  google/protobuf/type.proto \
  google/protobuf/empty.proto \
  google/protobuf/descriptor.proto
