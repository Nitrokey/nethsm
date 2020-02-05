open Mirage

let internal_stack =
  let default_internal =
    let ip = Ipaddr.V4.of_string_exn "169.254.169.1" in
    let network = Ipaddr.V4.Prefix.make 24 ip in
    { network = network, ip ; gateway = None }
  in
  generic_stackv4 ~group:"internal" ~config:default_internal
    (netif ~group:"internal" "internal")

let htdocs_key = Key.(value @@ kv_ro ~group:"htdocs" ())
let htdocs = generic_kv_ro ~key:htdocs_key "htdocs"

let http_port =
  let doc = Key.Arg.info ~doc:"Listening HTTP port." ["http"] in
  Key.(create "http_port" Arg.(opt int 80 doc))

let https_port =
  let doc = Key.Arg.info ~doc:"Listening HTTPS port." ["https"] in
  Key.(create "https_port" Arg.(opt int 443 doc))

let remote =
  let doc = Key.Arg.info ~doc:"Remote git repository." ["remote"] in
  Key.(create "remote" Arg.(opt string "git://169.254.169.2/keyfender-data.git" doc))

(* This parameter uses an integer since mirage does not properly handle
   (boolean) flags provided at configuration time (they are not preserved in
   key_gen.ml). TODO report and fix upstream. *)
let retry =
  let doc = Key.Arg.info ~doc:"Retry git pull until we succeed (>0 for enable)." ["retry"] in
  Key.(create "retry" Arg.(opt int 0 doc))

(* the IP configuration for the external/public network interface is in
   the KV store above -- i.e. only available at runtime. this implies we
   cannot yet connect the ip stack, but have to manually do that in the
   unikernel (after reading the key from store)
*)
let external_netif = Key.(if_impl is_solo5 (netif "external") (netif "tap1"))
let external_eth = etif external_netif
let external_arp = arp external_eth

let main =
  let packages = [
    package "keyfender";
    package ~sublibs:["stack-direct";"tcp";"udp";"icmpv4"] "tcpip";
    package "conduit-mirage";
    package "cohttp-mirage";
    package ~min:"3.7.1" "mirage-runtime";
    package ~min:"2.0.0" "irmin-mirage";
    package ~min:"2.0.0" "irmin-mirage-git";
    package ~sublibs:["mirage"] "logs-syslog";
  ] in
  let keys = Key.[ abstract http_port; abstract https_port; abstract remote; abstract retry ] in
  foreign
    ~packages ~keys ~deps:[abstract nocrypto]
    "Unikernel.Main"
    (console @-> random @-> pclock @-> mclock @-> kv_ro @->
     stackv4 @-> resolver @-> conduit @->
     network @-> ethernet @-> arpv4 @-> job)

let () =
  register "keyfender"
    [ main $ default_console $ default_random $ default_posix_clock $ default_monotonic_clock $ htdocs $
      internal_stack $ resolver_dns internal_stack $ conduit_direct internal_stack $
      external_netif $ external_eth $ external_arp ]
