(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Mirage

let internal_stack =
  let default_internal : ipv4_config =
    let ip = Ipaddr.V4.of_string_exn "169.254.169.1" in
    let network = Ipaddr.V4.Prefix.make 24 ip in
    { network = network ; gateway = None }
  in
  generic_stackv4v6 ~group:"internal" ~ipv4_config:default_internal
    (netif ~group:"internal" "internal")

let htdocs_key = Key.(value @@ kv_ro ~group:"htdocs" ())
let htdocs = generic_kv_ro ~key:htdocs_key "htdocs"

let update_key_store_key = Key.(value @@ kv_ro ~group:"update_key_store" ())
let update_key_store = generic_kv_ro ~key:update_key_store_key "update_key_store"

let http_port =
  let doc = Key.Arg.info ~doc:"Listening HTTP port." ["http"] in
  Key.(create "http_port" Arg.(opt int 80 doc))

let https_port =
  let doc = Key.Arg.info ~doc:"Listening HTTPS port." ["https"] in
  Key.(create "https_port" Arg.(opt int 443 doc))

let remote =
  let doc = Key.Arg.info ~doc:"Remote git repository." ["remote"] in
  Key.(create "remote" Arg.(opt string "git://169.254.169.2/keyfender-data.git" doc))

let platform =
  let doc = Key.Arg.info ~doc:"Platform IP." ["platform"] in
  let default_ip = Ipaddr.V4.of_string_exn "169.254.169.2" in
  Key.(create "platform" Arg.(opt ipv4_address default_ip doc))

let platform_port =
  let doc = Key.Arg.info ~doc:"Platform port." ["platform-port"] in
  Key.(create "platform-port" Arg.(opt int 1023 doc))

(* This parameter uses an integer since mirage does not properly handle
   (boolean) flags provided at configuration time (they are not preserved in
   key_gen.ml). TODO report and fix upstream. *)
let retry =
  let doc = Key.Arg.info ~doc:"Retry to connect DB until we succeed." ["retry"] in
  Key.(create "retry" Arg.(opt bool false doc))

let no_platform =
  let doc =
    Key.Arg.info ~doc:"Skip platform communication (do not use in production)."
      ["no-platform"]
  in
  Key.(create "no-platform" Arg.(opt bool false doc))

let memtrace =
  let doc =
    Key.Arg.info ~doc:"Enable memtrace listener on specified port."
      ["memtrace"]
  in
  Key.(create "memtrace" Arg.(opt (some int) None doc))

let no_scrypt =
  let doc =
    Key.Arg.info ~doc:"Use fast insecure scrypt parameters for testing."
      ["no-scrypt"]
  in
  Key.(create "no-scrypt" Arg.(opt bool false doc))


(* the IP configuration for the external/public network interface is in
   the KV store above -- i.e. only available at runtime. this implies we
   cannot yet connect the ip stack, but have to manually do that in the
   unikernel (after reading the key from store)
*)
type reconfigurable_stack = Reconfigurable_stack

let reconfigurable_stack = typ Reconfigurable_stack

let reconfigurable_stack_direct =
  impl @@ object
    inherit base_configurable
    method ty = random @-> mclock @-> network @-> ethernet @-> arpv4 @-> reconfigurable_stack
    method module_name = "Reconfigurable_stack.Direct"
    method name = "reconfigurable_stackd_direct"
    method! connect _ modname = function
      | [ _random; _mclock; network; ethernet; arpv4 ] ->
        Fmt.str "%s.connect %s %s %s" modname network ethernet arpv4
      | _ -> assert false
  end

let pre_configured_stack =
  impl @@ object
    inherit base_configurable
    method ty = stackv4v6 @-> reconfigurable_stack
    method module_name = "Reconfigurable_stack.Fixed"
    method name = "pre_configured_stack"
    method! connect _ modname = function
      | [ stack ] ->
        Fmt.str "%s.connect %s" modname stack
      | _ -> assert false
  end

let external_netif = Key.(if_impl is_solo5
  (netif ~group:"external" "external")
  (netif ~group:"external" "tap1"))

let external_eth = etif external_netif

let external_arp = arp external_eth

let tcpv4v6_of_stackv4v6 =
  impl @@ object
       inherit base_configurable
       method ty = stackv4v6 @-> tcpv4v6
       method module_name = "Git_mirage_happy_eyeballs.TCPV4V6"
       method name = "tcpv4v6_of_stackv4v6"
       method! connect _ modname = function
         | [ stackv4v6 ] -> Fmt.str {ocaml|%s.connect %s|ocaml} modname stackv4v6
         | _ -> assert false
    end

let single_interface =
  let doc =
    Key.Arg.info ~doc:"Use the same interface for the internal and the external stacks."
      ["single-interface"]
  in
  Key.(create "single-interface" Arg.(flag doc))

let external_reconfigurable_stack =
  if_impl (Key.value single_interface)
    (pre_configured_stack $ internal_stack)
    (reconfigurable_stack_direct
    $ default_random
    $ default_monotonic_clock
    $ external_netif
    $ external_eth
    $ external_arp)

let malloc_metrics_conf =
  impl @@ object
    inherit base_configurable
    method ty = typ ()
    method module_name = ""
    method name = "malloc_metrics"
    method! connect info _ _ =
      match Key.get (Info.context info) Key.target with
      | #Mirage_key.mode_solo5 -> "Lwt.return (Metrics_lwt.periodically (OS.MM.malloc_metrics ~tags:[]))"
      | _ -> "Lwt.return_unit"
  end
  |> abstract

let bisect_key =
  let doc =
    Key.Arg.info ~doc:"Enable bisect_ppx for the unikernel"
      ["bisect-ppx"]
  in
  Key.(create "bisect-ppx" Arg.(flag doc))

let bisect_ppx_conf =
  impl @@ object
    inherit base_configurable
    method ty = typ ()
    method module_name = ""
    method name = "bisect_ppx"
    method! keys = [ Key.abstract bisect_key ]
    method! packages =
      Key.if_
        (Key.value bisect_key)
        [ package "bisect_ppx" ]
        []
  end
  |> abstract

let main =
  let packages = [
    package "keyfender";
    package ~min:"7.1.2" ~sublibs:["stack-direct";"tcp";"udp";"icmpv4";"ipv6";"ipv4"] "tcpip";
    package "conduit-mirage";
    package "cohttp-mirage";
    package ~min:"3.10.4" "mirage-runtime";
    package ~min:"0.3.0" ~sublibs:["mirage"] "logs-syslog";
    package "metrics-lwt";
    package "digestif";
    package "memtrace-mirage";
    package ~sublibs:["google_types"] "ocaml-protoc-plugin";
    package ~pin:"git+ssh://git@git.nitrokey.com:/nitrokey/nethsm/vendor/ocaml-h2.git#41440ce9ab516ec5457128e6a10cc8037394d1f7" "h2";
    package ~pin:"git+ssh://git@git.nitrokey.com:/nitrokey/nethsm/vendor/ocaml-h2.git#41440ce9ab516ec5457128e6a10cc8037394d1f7" "h2-lwt";
    package ~pin:"git+ssh://git@git.nitrokey.com:/nitrokey/nethsm/vendor/ocaml-grpc.git#0d6542c8276a4db2a7dcb1ceca50c81de2c26a73" "grpc";
    package ~pin:"git+ssh://git@git.nitrokey.com:/nitrokey/nethsm/vendor/ocaml-grpc.git#0d6542c8276a4db2a7dcb1ceca50c81de2c26a73" "grpc-lwt";
  ] in
  let keys =
    Key.[
      abstract http_port; abstract https_port;
      abstract remote;
      abstract retry ;
      abstract no_platform ; abstract platform ; abstract platform_port ;
      abstract memtrace ; abstract no_scrypt
    ]
  in
  foreign
    ~packages ~keys ~deps:[malloc_metrics_conf; bisect_ppx_conf]

    "Unikernel.Main"
    (random @-> pclock @-> mclock @-> kv_ro @-> kv_ro @->
     stackv4v6 @->
     reconfigurable_stack @->
     job)

let () =
  register "keyfender"
    [ main $ default_random $ default_posix_clock $ default_monotonic_clock $ update_key_store $ htdocs $
      internal_stack $ external_reconfigurable_stack
    ]
