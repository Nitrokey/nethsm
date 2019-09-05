open Lwt.Infix

(* Logging *)
let https_src = Logs.Src.create "keyfender" ~doc:"Keyfender (NitroHSM)"
module Log = (val Logs.src_log https_src : Logs.LOG)

module Main
    (Pclock: Mirage_types.PCLOCK) (Static_assets: Mirage_types_lwt.KV_RO) (Server_keys: Mirage_types_lwt.KV_RO) (Http: Cohttp_lwt.S.Server) =
struct

  module X509 = Tls_mirage.X509(Server_keys)(Pclock)

  (* given a URI, find the appropriate file,
   * and construct a response with its contents. *)
  let rec dispatcher fs uri =
    match Uri.path uri with
    | "" | "/" -> dispatcher fs (Uri.with_path uri "index.html")
    | path ->
      let header =
        Cohttp.Header.init_with "Strict-Transport-Security" "max-age=31536000"
      in
      let mimetype = Magic_mime.lookup path in
      let headers = Cohttp.Header.add header "content-type" mimetype in
      Lwt.catch
        (fun () ->
           let failf fmt = Fmt.kstrf Lwt.fail_with fmt in
           Static_assets.get fs (Mirage_kv.Key.v path) >>= function
           | Error e -> failf "get: %a" Static_assets.pp_error e
           | Ok body ->
             Http.respond_string ~status:`OK ~body ~headers ())
        (fun _exn ->
           Http.respond_not_found ())

  (* Redirect to the same address, but in https. *)
  let redirect port uri =
    let new_uri = Uri.with_scheme uri (Some "https") in
    let new_uri = Uri.with_port new_uri (Some port) in
    Log.info (fun f -> f "[%s] -> [%s]"
                      (Uri.to_string uri) (Uri.to_string new_uri)
                  );
    let headers = Cohttp.Header.init_with "location" (Uri.to_string new_uri) in
    Http.respond ~headers ~status:`Moved_permanently ~body:`Empty ()

  let serve dispatch =
    let callback (_, cid) request _body =
      let uri = Cohttp.Request.uri request in
      let cid = Cohttp.Connection.to_string cid in
      Log.info (fun f -> f "[%s] serving %s." cid (Uri.to_string uri));
      dispatch uri
    in
    let conn_closed (_,cid) =
      let cid = Cohttp.Connection.to_string cid in
      Log.info (fun f -> f "[%s] closing" cid);
    in
    Http.make ~conn_closed ~callback ()

  let tls_init kv =
    X509.certificate kv `Default >>= fun cert ->
    let conf = Tls.Config.server ~certificates:(`Single cert) () in
    Lwt.return conf

  let start _clock data keys http =
    tls_init keys >>= fun cfg ->
    let https_port = Key_gen.https_port () in
    let tls = `TLS (cfg, `TCP https_port) in
    let http_port = Key_gen.http_port () in
    let tcp = `TCP http_port in
    let https =
      Log.info (fun f -> f "listening on %d/TCP" https_port);
      http tls @@ serve (dispatcher data)
    in
    let http =
      Log.info (fun f -> f "listening on %d/TCP" http_port);
      http tcp @@ serve (redirect https_port)
    in
    Lwt.join [ https; http ]

end
