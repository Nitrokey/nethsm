open Lwt.Infix

(* Logging *)
let https_src = Logs.Src.create "keyfender" ~doc:"Keyfender (NitroHSM)"
module Log = (val Logs.src_log https_src : Logs.LOG)

module Main
    (Rng: Mirage_types_lwt.RANDOM) (Pclock: Mirage_types.PCLOCK) (Static_assets: Mirage_types_lwt.KV_RO) (Store: Mirage_types_lwt.KV_RW) (Http: Cohttp_lwt.S.Server) =
struct

  module Hsm = Keyfender.Hsm.Make(Rng)(Store)
  module Webserver = Keyfender.Server.Make(Rng)(Pclock)(Http)(Hsm)

  let start _random _clock _assets store http =
    Hsm.make store >>= fun hsm_state ->
    Hsm.certificate hsm_state >>= fun certificates ->
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
