(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Lwt.Infix

(* Logging *)
let https_src = Logs.Src.create "keyfender" ~doc:"Keyfender (NetHSM)"

module Log = (val Logs.src_log https_src : Logs.LOG)

module Conduit = Conduit_mirage.TCP (Tcpip_stack_socket.V4V6)
module Conduit_tls = Conduit_mirage.TLS (Conduit)
module Srv = Cohttp_mirage.Server.Make (Conduit_tls)
module Kv_mem = struct
  include Mirage_kv_mem
  let batch dict ?retries:_ f = f dict
end

module Hsm =
  Keyfender.Hsm.Make (Keyfender.Kv_ext.Make_ranged (Kv_mem))

module Webserver = Keyfender.Server.Make (Srv) (Hsm)

let platform =
  {
    Keyfender.Json.deviceId = "0000000000";
    deviceKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    pcr = [];
    akPub = [];
    hardwareVersion = "N/A";
    firmwareVersion = "N/A";
  }

let () =
  Keyfender.Crypto.set_test_params ();
  let update_key =
    match
      X509.Public_key.decode_pem [%blob "public.pem"]
    with
    | Ok (`RSA key) -> key
    | Ok _ -> invalid_arg "No RSA key from manufacturer. Contact manufacturer."
    | Error (`Msg m) -> invalid_arg m
  in
  Printexc.record_backtrace true;
  Fmt_tty.setup_std_outputs ();
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level (Some Debug);
  Mirage_crypto_rng_unix.use_default ();
  Lwt_main.run
    ( Kv_mem.connect () >>= fun store ->
      Hsm.boot ~platform update_key store >>= fun (hsm_state, mvar, _) ->
      let any = Ipaddr.V4.Prefix.global in
      Tcpv4v6_socket.connect ~ipv4_only:true ~ipv6_only:false any None
      >>= fun tcp ->
      Udpv4v6_socket.connect ~ipv4_only:true ~ipv6_only:false any None
      >>= fun udp ->
      Tcpip_stack_socket.V4V6.connect udp tcp >>= fun stack ->
      let certificates = Hsm.own_cert hsm_state in
      let tls_cfg = Result.get_ok @@ Tls.Config.server ~certificates () in
      let https_port = 4433 in
      let tls = `TLS (tls_cfg, `TCP https_port) in
      let http_port = 8080 in
      let tcp = `TCP http_port in
      let http = Srv.listen stack in
      let open Webserver in
      let https =
        Log.info (fun f -> f "listening on %d/TCP" https_port);
        http tls @@ serve @@ dispatch hsm_state
      in
      let http =
        Log.info (fun f -> f "listening on %d/TCP" http_port);
        http tcp @@ serve @@ dispatch hsm_state
      in
      Lwt.async (fun () -> https);
      Lwt.async (fun () -> http);
      let rec handle_cb () =
        Lwt_mvar.take mvar >>= function
        | Hsm.Shutdown -> Lwt.return_unit
        | _ -> handle_cb ()
      in
      handle_cb () )
