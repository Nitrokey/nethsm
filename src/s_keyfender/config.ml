(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Mirage

let default_net ?gw ip : ipv4_config =
  let ip = Ipaddr.V4.of_string_exn ip in
  let gateway = Option.map (fun x -> Ipaddr.V4.of_string_exn x) gw in
  let network = Ipaddr.V4.Prefix.make 24 ip in
  { network; gateway }

let default_net_v6 ?gw ip : ipv6_config =
  let ip = Ipaddr.V6.of_string_exn ip in
  let gateway = Option.map (fun x -> Ipaddr.V6.of_string_exn x) gw in
  let network = Ipaddr.V6.Prefix.make 120 ip in
  { network; gateway }

let external_stack =
  let ipv4_config = default_net ~gw:"169.254.100.1" "169.254.100.2" in
  let ipv6_config = default_net_v6 ~gw:"fc00:1:100::1" "fc00:1:100::2" in
  generic_stackv4v6 ~group:"external" ~ipv4_config ~ipv6_config
    (netif ~group:"external" "external")

let internal_stack =
  let ipv4_config = default_net "169.254.169.1" in
  let ipv6_config = default_net_v6 "fc00:1:169::1" in
  generic_stackv4v6 ~group:"internal" ~ipv4_config ~ipv6_config
    (netif ~group:"internal" "internal")

let htdocs_key = Key.(value @@ kv_ro ~group:"htdocs" ())
let htdocs = generic_kv_ro ~key:htdocs_key "htdocs"
let update_key_store_key = Key.(value @@ kv_ro ~group:"update_key_store" ())

let update_key_store =
  generic_kv_ro ~key:update_key_store_key "update_key_store"

let single_interface =
  let doc =
    Key.Arg.info
      ~doc:"Use the same interface for the internal and the external stacks."
      [ "single-interface" ]
  in
  Key.(create "single-interface" Arg.(flag doc))

let external_stack =
  if_impl (Key.value single_interface) internal_stack external_stack

let malloc_metrics_conf =
  let connect info _ _ =
    match Key.get (Info.context info) Key.target with
    | #Mirage.Key.mode_solo5 ->
        code ~pos:__POS__
          "Lwt.return (Metrics_lwt.periodically (Solo5_os.Memory.metrics \
           ~quick:true ~tags:Metrics.Tags.[] ()))"
    | _ -> code ~pos:__POS__ "Lwt.return_unit"
  in
  let packages = [ package "metrics-lwt" ] in
  Impl.abstract (impl ~connect ~packages "malloc_metrics" (typ ()))

let bisect_key =
  let doc =
    Key.Arg.info ~doc:"Enable bisect_ppx for the unikernel" [ "bisect-ppx" ]
  in
  Key.(create "bisect-ppx" Arg.(flag doc))

let bisect_ppx_conf =
  let keys = [ Mirage.Key.v bisect_key ] in
  let packages_v = Key.if_ (Key.value bisect_key) [ package "bisect_ppx" ] [] in
  Impl.abstract (impl "bisect_ppx" ~keys ~packages_v (typ ()))

let no_platform_key =
  let doc =
    Key.Arg.info ~doc:"Skip platform communication (do not use in production)."
      [ "no-platform" ]
  in
  Key.(create "no-platform" Arg.(flag doc))

let no_scrypt_key =
  let doc =
    Key.Arg.info ~doc:"Use fast insecure scrypt parameters for testing."
      [ "no-scrypt" ]
  in
  Key.(create "no-scrypt" Arg.(flag doc))

let memtrace_key =
  let doc =
    Key.Arg.info ~docv:"PORT" ~doc:"Enable memtrace listener on specified port."
      [ "memtrace" ]
  in
  Key.(create "memtrace" Arg.(opt Cmdliner.Arg.(some int) None doc))

type build_args = Build_args

let build_args = typ Build_args

let build_conf =
  let arg_true = impl "Args.Conf.True" (typ ()) in
  let arg_false = impl "Args.Conf.False" (typ ()) in
  let bool_arg key =
    let b = Mirage.Key.value key in
    if_impl b arg_true arg_false
  in
  let dune _ =
    List.map Dune.stanza
      [ (* "(copy_files# ./etcd/*.ml)"; "(copy_files# ./etcd/gen/*.ml)" *) ]
  in
  let keys = List.map Key.v [ memtrace_key ] in
  let connect info _ _ =
    let s =
      match Mirage.Key.get (Info.context info) memtrace_key with
      | None -> "None"
      | Some x -> Printf.sprintf "(Some %d)" x
    in
    code ~pos:__POS__ "Lwt.return Args.Conf.{ memtrace_port=%s }" s
  in
  impl ~keys ~connect ~dune "Args.Conf.Make"
    (typ () @-> typ () @-> typ () @-> build_args)
  $ bool_arg no_platform_key $ bool_arg no_scrypt_key
  $ bool_arg single_interface

let main =
  let packages =
    [
      package "keyfender";
      package
        ~sublibs:[ "stack-direct"; "tcp"; "udp"; "icmpv4"; "ipv6"; "ipv4" ]
        "tcpip";
      package "conduit-mirage";
      package "cohttp-mirage";
      package ~min:"3.10.4" "mirage-runtime";
      package ~min:"0.3.0" ~sublibs:[ "mirage" ] "logs-syslog";
      (* package "metrics-lwt"; *)
      package "digestif";
      package "memtrace-mirage";
      package ~libs:[ "etcd_client" ] "ocaml";
      package ~max:"0.13.0" "h2-lwt";
      package
        ~pin:
          "git+https://github.com/dialohq/ocaml-grpc.git#b629b55fc15964c5e9455058725519d3f7cfc9a7"
        "grpc";
      package
        ~pin:
          "git+https://github.com/dialohq/ocaml-grpc.git#b629b55fc15964c5e9455058725519d3f7cfc9a7"
        "grpc-lwt";
    ]
  in
  main ~pos:__POS__ ~packages
    ~deps:[ bisect_ppx_conf; malloc_metrics_conf ]
    "Unikernel.Main"
    (kv_ro @-> kv_ro @-> stackv4v6 @-> stackv4v6 @-> build_args @-> job)

let () =
  register "keyfender"
    [
      main $ update_key_store $ htdocs $ internal_stack $ external_stack
      $ build_conf;
    ]
