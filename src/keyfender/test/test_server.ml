open Lwt.Infix

(* Logging *)
let https_src = Logs.Src.create "keyfender" ~doc:"Keyfender (NitroHSM)"
module Log = (val Logs.src_log https_src : Logs.LOG)

module Time = struct
  let sleep_ns duration = Lwt_unix.sleep (Duration.to_f duration)
end

module Conduit = Conduit_mirage.With_tcp(Tcpip_stack_socket)
module Http = Cohttp_mirage.Server_with_conduit

module Hsm_clock = Keyfender.Hsm_clock.Make(Pclock)
module Store = Mirage_kv_mem.Make(Hsm_clock)
module Hsm = Keyfender.Hsm.Make(Mirage_random_test)(Store)(Time)(Mclock)(Hsm_clock)
module Webserver = Keyfender.Server.Make(Mirage_random_test)(Http)(Hsm)

let () =
  Printexc.record_backtrace true;
  Fmt_tty.setup_std_outputs ();
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level (Some Debug);
  Mirage_crypto_rng_unix.initialize ();
  Lwt_main.run
  begin
    Store.connect () >>= fun store ->
    Hsm.boot store >>= fun hsm_state ->
    Hsm.network_configuration hsm_state >>= fun (ip, _network, _gateway) ->
    Tcpv4_socket.connect (Some ip) >>= fun tcp ->
    Udpv4_socket.connect (Some ip) >>= fun udp ->
    Tcpip_stack_socket.connect [ip] udp tcp >>= fun stack ->
    Conduit.connect stack Conduit_mirage.empty >>= Conduit_mirage.with_tls >>= fun conduit ->
    Http.connect conduit >>= fun http ->
    Hsm.certificate_chain hsm_state >>= function
    | (cert, chain, `RSA priv) ->
      let certificates = `Single (cert :: chain, priv) in
      let tls_cfg = Tls.Config.server ~certificates () in
      let https_port = 4433 in
      let tls = `TLS (tls_cfg, `TCP https_port) in
      let http_port = 8080 in
      let tcp = `TCP http_port in
      let open Webserver in
      let https =
        Log.info (fun f -> f "listening on %d/TCP" https_port);
        http tls @@ serve @@ dispatch hsm_state
      in
      let http =
        Log.info (fun f -> f "listening on %d/TCP" http_port);
        http tcp @@ serve @@ dispatch hsm_state
      in
      Lwt.join [ https; http ]
    | _ -> Lwt.fail_with "only RSA certificate chains supported"
  end
