This is a vendored ocaml_protoc_plugin with ppx removed.

How to (in repo root directory):

$ cp src/ocaml_protoc_plugin/*.mli .../src/s_keyfender/etcd_client/ocaml_protoc_plugin/
$ mkdir -p pp/src/ocaml_protoc_plugin
$ for i in src/ocaml_protoc_plugin/*.ml ; do dune describe pp $i > pp/$i ; done
$ cp pp/src/ocaml_protoc_plugin/* .../src/s_keyfender/etcd_client/ocaml_protoc_plugin/
