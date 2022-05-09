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
  let doc = Key.Arg.info ~doc:"Retry git pull until we succeed." ["retry"] in
  Key.(create "retry" Arg.(opt bool false doc))

let no_platform =
  let doc =
    Key.Arg.info ~doc:"Skip platform communication (do not use in production)."
      ["no-platform"]
  in
  Key.(create "no-platform" Arg.(opt bool false doc))

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

(* git / mimic configuration *)
type mimic = Mimic

let mimic = typ Mimic

let mimic_count =
  let v = ref (-1) in
  fun () -> incr v ; !v

let mimic_conf () =
  let packages = [ package "mimic" ] in
  impl @@ object
       inherit base_configurable
       method ty = mimic @-> mimic @-> mimic
       method module_name = "Mimic.Merge"
       method! packages = Key.pure packages
       method name = Fmt.str "merge_ctx%02d" (mimic_count ())
       method! connect _ _modname =
         function
         | [ a; b ] -> Fmt.str "Lwt.return (Mimic.merge %s %s)" a b
         | [ x ] -> Fmt.str "%s.ctx" x
         | _ -> Fmt.str "Lwt.return Mimic.empty"
     end

let merge ctx0 ctx1 = mimic_conf () $ ctx0 $ ctx1

let mimic_tcp_conf =
  let packages = [ package "git-mirage" ~sublibs:[ "tcp" ] ~min:"3.8.0" ~max:"3.9.0" ] in
  impl @@ object
       inherit base_configurable
       method ty = tcpv4v6 @-> mimic @-> mimic
       method module_name = "Git_mirage_tcp.Make"
       method! packages = Key.pure packages
       method name = "tcp_ctx"
       method! connect _ modname = function
         | [ _tcpv4v6; ctx ] ->
           Fmt.str {ocaml|%s.connect %s|ocaml}
             modname ctx
         | _ -> assert false
     end

let mimic_tcp_impl tcpv4v6 happy_eyeballs = mimic_tcp_conf $ tcpv4v6 $ happy_eyeballs

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

let mimic_happy_eyeballs_conf =
  let packages = [ package "git-mirage" ~sublibs:[ "happy-eyeballs" ] ~min:"3.8.0" ~max:"3.9.0" ] in
  impl @@ object
       inherit base_configurable
       method ty = random @-> time @-> mclock @-> pclock @-> stackv4v6 @-> mimic
       method module_name = "Git_mirage_happy_eyeballs.Make"
       method! packages = Key.pure packages
       method name = "happy_eyeballs_ctx"
       method! connect _ modname = function
         | [ _random; _time; _mclock; _pclock; stackv4v6; ] ->
           Fmt.str {ocaml|%s.connect %s|ocaml} modname stackv4v6
         | _ -> assert false
     end

let mimic_happy_eyeballs_impl random time mclock pclock stackv4v6 =
  mimic_happy_eyeballs_conf $ random $ time $ mclock $ pclock $ stackv4v6

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

let main =
  let packages = [
    package "keyfender";
    package ~sublibs:["stack-direct";"tcp";"udp";"icmpv4";"ipv6";"ipv4"] "tcpip";
    package "conduit-mirage";
    package "cohttp-mirage";
    package ~min:"3.10.4" "mirage-runtime";
    package ~min:"2.10.0" ~max:"3.0.0" "irmin-mirage";
    package ~min:"2.10.0" ~max:"3.0.0" "irmin-git";
    package ~min:"0.3.0" ~sublibs:["mirage"] "logs-syslog";
    package "metrics-lwt";
  ] in
  let keys =
    Key.[
      abstract http_port; abstract https_port;
      abstract remote;
      abstract retry ;
      abstract no_platform ; abstract platform ; abstract platform_port
    ]
  in
  foreign
    ~packages ~keys ~deps:[malloc_metrics_conf]
    "Unikernel.Main"
    (console @-> random @-> pclock @-> mclock @-> kv_ro @-> kv_ro @->
     stackv4v6 @-> mimic @->
     reconfigurable_stack @->
     job)

let mimic stackv4v6 time random mclock pclock =
  let mdns = mimic_happy_eyeballs_impl random time mclock pclock stackv4v6 in
  mimic_tcp_impl (tcpv4v6_of_stackv4v6 $ stackv4v6) mdns

let () =
  register "keyfender"
    [ main $ default_console $ default_random $ default_posix_clock $ default_monotonic_clock $ update_key_store $ htdocs $
      internal_stack $ mimic internal_stack default_time default_random default_monotonic_clock default_posix_clock $
      external_reconfigurable_stack
    ]
