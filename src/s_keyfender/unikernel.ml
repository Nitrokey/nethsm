open Lwt.Infix

(* Logging *)
let https_src = Logs.Src.create "keyfender" ~doc:"Keyfender (NitroHSM)"
module Log = (val Logs.src_log https_src : Logs.LOG)

module Main
    (R: Mirage_types_lwt.RANDOM) (Pclock: Mirage_types.PCLOCK) (Static_assets: Mirage_types_lwt.KV_RO) (Server_keys: Mirage_types_lwt.KV_RO) (Http: Cohttp_lwt.S.Server) =
struct

  module X509 = Tls_mirage.X509(Server_keys)(Pclock)
  module Webserver = Keyfender.Server.Make(R)(Pclock)(Http)

  let tls_init kv =
    X509.certificate kv `Default >|= fun cert ->
    Tls.Config.server ~certificates:(`Single cert) ()

  let start _random _clock _assets server_keys http =
    tls_init server_keys >>= fun cfg ->
    let https_port = Key_gen.https_port () in
    let tls = `TLS (cfg, `TCP https_port) in
    let http_port = Key_gen.http_port () in
    let tcp = `TCP http_port in
    let open Webserver in
    let https =
      Log.info (fun f -> f "listening on %d/TCP" https_port);
      http tls @@ serve dispatch
    in
    let http =
      Log.info (fun f -> f "listening on %d/TCP" http_port);
      http tcp @@ serve (redirect https_port)
    in
    Lwt.join [ https; http ]

end
