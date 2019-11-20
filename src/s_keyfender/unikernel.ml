open Lwt.Infix

(* Logging *)
let https_src = Logs.Src.create "keyfender" ~doc:"Keyfender (NitroHSM)"
module Log = (val Logs.src_log https_src : Logs.LOG)

module Main
    (Rng: Mirage_random.S) (Pclock: Mirage_clock.PCLOCK) (Mclock : Mirage_clock.MCLOCK)
    (Static_assets: Mirage_kv.RO) (Store: Mirage_kv.RW)
    (Internal_stack: Mirage_stack.V4)
    (External_net: Mirage_net.S) (External_eth : Mirage_protocols.ETHERNET) (External_arp : Mirage_protocols.ARP)
=
struct
  module Time = OS.Time
  module Ext_ipv4 = Static_ipv4.Make(Rng)(Mclock)(External_eth)(External_arp)
  module Ext_icmp = Icmpv4.Make(Ext_ipv4)
  module Ext_udp = Udp.Make(Ext_ipv4)(Rng)
  module Ext_tcp = Tcp.Flow.Make(Ext_ipv4)(Time)(Mclock)(Rng)
  module Ext_stack = Tcpip_stack_direct.Make(Time)(Rng)(External_net)(External_eth)(External_arp)(Ext_ipv4)(Ext_icmp)(Ext_udp)(Ext_tcp)
  module Conduit = Conduit_mirage.With_tcp(Ext_stack)
  module Http = Cohttp_mirage.Server_with_conduit

  module Hsm = Keyfender.Hsm.Make(Rng)(Store)(Pclock)
  module Webserver = Keyfender.Server.Make(Rng)(Http)(Hsm)

  let start _random _pclock _mclock _assets store _internal_stack ext_net ext_eth ext_arp _nocrypto =
    Hsm.boot store >>= fun hsm_state ->
    Hsm.network_configuration hsm_state >>= fun (ip, network, gateway) ->
    Ext_ipv4.connect ~ip:(network, ip) ?gateway ext_eth ext_arp >>= fun ipv4 ->
    Ext_icmp.connect ipv4 >>= fun icmp ->
    Ext_udp.connect ipv4 >>= fun udp ->
    Ext_tcp.connect ipv4 >>= fun tcp ->
    Ext_stack.connect ext_net ext_eth ext_arp ipv4 icmp udp tcp >>= fun ext_stack ->
    Conduit.connect ext_stack Conduit_mirage.empty >>= Conduit_mirage.with_tls >>= fun conduit ->
    Http.connect conduit >>= fun http ->
    Hsm.certificate_chain hsm_state >>= fun (cert, chain, `RSA priv) ->
    let certificates = `Single (cert :: chain, priv) in
    let tls_cfg = Tls.Config.server ~certificates () in
    let https_port = Key_gen.https_port () in
    let tls = `TLS (tls_cfg, `TCP https_port) in
    let http_port = Key_gen.http_port () in
    let tcp = `TCP http_port in
    let open Webserver in
    let https =
      Log.info (fun f -> f "listening on %d/TCP" https_port);
      http tls @@ serve @@ dispatch hsm_state
    in
    let http =
      Log.info (fun f -> f "listening on %d/TCP" http_port);
      http tcp @@ serve (redirect https_port)
    in
    Lwt.join [ https; http ]

end
