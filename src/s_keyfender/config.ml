open Mirage

let internal_stack =
  let default_internal : ipv4_config =
    let ip = Ipaddr.V4.of_string_exn "169.254.169.1" in
    let network = Ipaddr.V4.Prefix.make 24 ip in
    { network = network ; gateway = None }
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
let external_netif = Key.(if_impl is_solo5 (netif "external") (netif "tap1"))
let external_eth = etif external_netif
let external_arp = arp external_eth

(* git / mimic configuration *)
type mimic = Mimic

let mimic = typ Mimic

let mimic_tcp_conf ~edn () =
  let packages = [ package "git-mirage" ~sublibs:[ "tcp" ] ] in
  let edn = Key.abstract edn in
  impl @@ object
       inherit base_configurable
       method ty = stackv4 @-> mimic
       method! keys = [ edn ]
       method module_name = "Git_mirage_tcp.Make"
       method! packages = Key.pure packages
       method name = "tcp_ctx"
       method! connect _ modname =
         function
         | [ stack ] ->
             Fmt.str
               {|let tcp_ctx0 = %s.with_stack %s %s.ctx in
                 Lwt.return tcp_ctx0|}
               modname stack modname
         | _ -> assert false
     end

let mimic_tcp_impl ~edn stackv4 = mimic_tcp_conf ~edn () $ stackv4

let mimic_git_conf ~edn () =
  let packages = [ package "git-mirage" ] in
  let edn = Key.abstract edn in
  impl @@ object
       inherit base_configurable
       method ty = stackv4 @-> mimic @-> mimic
       method! keys = [ edn ]
       method module_name = "Git_mirage.Make"
       method! packages = Key.pure packages
       method name = "git_ctx"
       method! connect _ modname =
         function
         | [ _ ; mimic ] ->
           Fmt.str
             {|let git_ctx0 = %s.with_smart_git_endpoint (%a) %s in
             let git_ctx1 = %s.with_resolv git_ctx0 in
             Lwt.return git_ctx1|}
             modname Key.serialize_call edn mimic
             modname
         | _ -> assert false
     end

let mimic_git_impl ~edn stackv4 mimic_tcp =
  mimic_git_conf ~edn () $ stackv4 $ mimic_tcp

let main =
  let packages = [
    package "keyfender";
    package ~sublibs:["stack-direct";"tcp";"udp";"icmpv4"] "tcpip";
    package "conduit-mirage";
    package "cohttp-mirage";
    package ~min:"3.10.1" "mirage-runtime";
    package ~min:"2.3.0" "irmin-mirage";
    package ~min:"2.3.0" "irmin-mirage-git";
    package ~min:"3.1.0" "git";
    package ~max:"0.3.0" ~sublibs:["mirage"] "logs-syslog";
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
    ~packages ~keys
    "Unikernel.Main"
    (console @-> random @-> pclock @-> mclock @-> kv_ro @->
     stackv4 @-> mimic @->
     network @-> ethernet @-> arpv4 @->
     job)

let mimic ~edn stackv4 =
  let mtcp = mimic_tcp_impl ~edn stackv4 in
  mimic_git_impl ~edn stackv4 mtcp

let () =
  register "keyfender"
    [ main $ default_console $ default_random $ default_posix_clock $ default_monotonic_clock $ htdocs $
      internal_stack $ mimic ~edn:remote internal_stack $
      external_netif $ external_eth $ external_arp
    ]
