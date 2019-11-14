open Lwt.Infix

let access_src = Logs.Src.create "http.access" ~doc:"HTTP server access log"
module Access_log = (val Logs.src_log access_src : Logs.LOG)

module Make_handlers (R : Mirage_random.C) (Clock : Mirage_clock.PCLOCK) (Hsm : Hsm.S) = struct

  module WmClock = struct
    let now () =
      let ts = Clock.now_d_ps () in
      let span = Ptime.Span.v ts in
      match Ptime.Span.to_int_s span with
      | None -> 0
      | Some seconds -> seconds
  end

  module Wm = Webmachine.Make(Lwt)(WmClock)

  module Info = Handler_info.Make(Wm)(Hsm)
  module Health = Handler_health.Make(Wm)(Hsm)
  module Provision = Handler_provision.Make(Wm)(Hsm)
  module Unlock = Handler_unlock.Make(Wm)(Hsm)
  module Random = Handler_random.Make(Wm)(Hsm)
  module Config = Handler_config.Make(Wm)(Hsm)
  module Users = Handler_users.Make(Wm)(Hsm)
  module Keys = Handler_keys.Make(Wm)(Hsm)
  module System = Handler_system.Make(Wm)(Hsm)

  let routes hsm_state = [
    ("/info", fun () -> new Info.handler hsm_state) ;
    ("/health/:ep", fun () -> new Health.handler hsm_state) ;
    ("/provision", fun () -> new Provision.handler hsm_state) ;
    ("/unlock", fun () -> new Unlock.handler hsm_state) ;
    ("/random", fun () -> new Random.handler hsm_state) ;
    ("/config/tls/:ep", fun () -> new Config.handler_tls hsm_state) ;
    ("/config/:ep", fun () -> new Config.handler hsm_state) ;
    ("/users", fun () -> new Users.handler_users hsm_state) ;
    ("/users/:id/passphrase", fun () -> new Users.handler_passphrase hsm_state) ;
    ("/users/:id", fun () -> new Users.handler hsm_state) ;
    ("/keys", fun () -> new Keys.handler_keys hsm_state) ;
    ("/keys/generate", fun () -> new Keys.handler_keys_generate hsm_state) ;
    ("/keys/:id", fun () -> new Keys.handler hsm_state) ;
    ("/keys/:id/public.pem", fun () -> new Keys.handler_public hsm_state) ;
    ("/keys/:id/csr.pem", fun () -> new Keys.handler_csr hsm_state) ;
    ("/keys/:id/decrypt", fun () -> new Keys.handler_decrypt hsm_state) ;
    ("/keys/:id/sign", fun () -> new Keys.handler_sign hsm_state) ;
    ("/keys/:id/cert", fun () -> new Keys.handler_cert hsm_state) ;
    ("/system/restore", fun () -> new System.handler_restore hsm_state) ;
    ("/system/:ep", fun () -> new System.handler hsm_state) ;
  ]
end

module Make (R : Mirage_random.C) (Clock : Mirage_clock.PCLOCK) (Http: Cohttp_lwt.S.Server) (Hsm : Hsm.S) = struct

  module Handlers = Make_handlers(R)(Clock)(Hsm)

  (* Route dispatch. Returns [None] if the URI did not match any pattern, server should return a 404 [`Not_found]. *)
  let dispatch hsm_state request body =
    let now () = Ptime.v (Clock.now_d_ps ()) in
    let start = now () in
    Access_log.info (fun m -> m "request %s %s"
                        (Cohttp.Code.string_of_method (Cohttp.Request.meth request))
                        (Cohttp.Request.resource request));
    Access_log.debug (fun m -> m "request headers %s"
                         (Cohttp.Header.to_string (Cohttp.Request.headers request)) );
    Handlers.Wm.dispatch' (Handlers.routes hsm_state) ~body ~request
    >|= begin function
      | None        -> (`Not_found, Cohttp.Header.init (), `String "Not found", [])
      | Some result -> result
    end
    >>= fun (status, headers, body, path) ->
    let stop = now () in
    let diff = Ptime.diff stop start in
    Access_log.info (fun m -> m "response %d response time %a"
                        (Cohttp.Code.code_of_status status)
                        Ptime.Span.pp diff) ;
    Access_log.debug (fun m -> m "%s %s path: %s"
                         (Cohttp.Code.string_of_method (Cohttp.Request.meth request))
                         (Uri.path (Cohttp.Request.uri request))
                         (Astring.String.concat ~sep:", " path)) ;
    Http.respond ~headers ~body ~status ()

  (* Redirect to https *)
  let redirect port request _body =
    let uri = Cohttp.Request.uri request in
    let new_uri = Uri.with_scheme uri (Some "https") in
    let new_uri = Uri.with_port new_uri (Some port) in
    Logs.info (fun f -> f "[%s] -> [%s]"
                      (Uri.to_string uri) (Uri.to_string new_uri)
                  );
    let headers = Cohttp.Header.init_with "location" (Uri.to_string new_uri) in
    Http.respond ~headers ~status:`Moved_permanently ~body:`Empty ()

  let serve cb =
    let callback (_, cid) request body =
      let uri = Cohttp.Request.uri request in
      let cid = Cohttp.Connection.to_string cid in
      Logs.info (fun f -> f "[%s] serving %s." cid (Uri.to_string uri));
      cb request body
    in
    let conn_closed (_,cid) =
      let cid = Cohttp.Connection.to_string cid in
      Logs.info (fun f -> f "[%s] closing" cid);
    in
    Http.make ~conn_closed ~callback ()

end
