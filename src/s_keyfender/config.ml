open Mirage

let internal_stack = generic_stackv4 default_network

let htdocs_key = Key.(value @@ kv_ro ~group:"htdocs" ())
let htdocs = generic_kv_ro ~key:htdocs_key "htdocs"

let http_port =
  let doc = Key.Arg.info ~doc:"Listening HTTP port." ["http"] in
  Key.(create "http_port" Arg.(opt int 8080 doc))

let store = (* direct_kv_rw "store" *) kv_rw_mem ()

let https_port =
  let doc = Key.Arg.info ~doc:"Listening HTTPS port." ["https"] in
  Key.(create "https_port" Arg.(opt int 4433 doc))

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
  ] in
  let keys = List.map Key.abstract [ http_port; https_port ] in
  foreign
    ~packages ~keys ~deps:[abstract nocrypto]
    "Unikernel.Main"
    (random @-> pclock @-> mclock @-> kv_ro @-> kv_rw @-> stackv4 @->
     network @-> ethernet @-> arpv4 @-> job)

let () =
  register "keyfender"
    [ main $ default_random $ default_posix_clock $ default_monotonic_clock $
      htdocs $ store $ internal_stack $
      external_netif $ external_eth $ external_arp ]
