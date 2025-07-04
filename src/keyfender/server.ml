(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Lwt.Infix

let access_src = Logs.Src.create "http.access" ~doc:"HTTP server access log"

module Access_log = (val Logs.src_log access_src : Logs.LOG)

module Make_handlers (R : Mirage_random.S) (Hsm : Hsm.S) = struct
  module WmClock = struct
    let now () =
      let now_ptime = Hsm.now () in
      match Ptime.Span.to_int_s @@ Ptime.to_span now_ptime with
      | None -> 0
      | Some seconds -> seconds
  end

  module Wm = Webmachine.Make (Lwt) (WmClock)
  module Info = Handler_info.Make (Wm) (Hsm)
  module Health = Handler_health.Make (Wm) (Hsm)
  module Metrics = Handler_metrics.Make (Wm) (Hsm)
  module Provision = Handler_provision.Make (Wm) (Hsm)
  module Unlock = Handler_unlock.Make (Wm) (Hsm)
  module Random = Handler_random.Make (Wm) (Hsm)
  module Config = Handler_config.Make (Wm) (Hsm)
  module Users = Handler_users.Make (Wm) (Hsm)
  module Keys = Handler_keys.Make (Wm) (Hsm)
  module Namespace = Handler_namespaces.Make (Wm) (Hsm)
  module System = Handler_system.Make (Wm) (Hsm)

  let routes hsm_state ip =
    List.map
      (fun (p, h) -> ("/api/v1" ^ p, h))
      [
        ("/info", fun () -> new Info.info hsm_state);
        ("/health/alive", fun () -> new Health.alive hsm_state);
        ("/health/ready", fun () -> new Health.ready hsm_state);
        ("/health/state", fun () -> new Health.state hsm_state);
        ("/metrics", fun () -> new Metrics.metrics hsm_state ip);
        ("/provision", fun () -> new Provision.provision hsm_state);
        ("/unlock", fun () -> new Unlock.unlock hsm_state ip);
        ("/lock", fun () -> new Unlock.lock hsm_state ip);
        ("/random", fun () -> new Random.random hsm_state ip);
        ( "/config/unlock-passphrase",
          fun () -> new Config.unlock_passphrase hsm_state ip );
        ( "/config/unattended-boot",
          fun () -> new Config.unattended_boot hsm_state ip );
        ("/config/tls/public.pem", fun () -> new Config.tls_public hsm_state ip);
        ("/config/tls/cert.pem", fun () -> new Config.tls_cert hsm_state ip);
        ("/config/tls/csr.pem", fun () -> new Config.tls_csr hsm_state ip);
        ("/config/tls/generate", fun () -> new Config.tls_generate hsm_state ip);
        ("/config/network", fun () -> new Config.network hsm_state ip);
        ("/config/logging", fun () -> new Config.logging hsm_state ip);
        ( "/config/backup-passphrase",
          fun () -> new Config.backup_passphrase hsm_state ip );
        ("/config/time", fun () -> new Config.time hsm_state ip);
        ("/users", fun () -> new Users.handler_users hsm_state ip);
        ( "/users/:id/passphrase",
          fun () -> new Users.handler_passphrase hsm_state ip );
        ("/users/:id", fun () -> new Users.handler hsm_state ip);
        ("/users/:id/tags", fun () -> new Users.handler_tags hsm_state ip);
        ( "/users/:id/tags/:tag",
          fun () -> new Users.handler_tags_tag hsm_state ip );
        ("/keys", fun () -> new Keys.handler_keys hsm_state ip);
        ("/keys/generate", fun () -> new Keys.handler_keys_generate hsm_state ip);
        ("/keys/:id", fun () -> new Keys.handler hsm_state ip);
        ("/keys/:id/public.pem", fun () -> new Keys.handler_public hsm_state ip);
        ("/keys/:id/csr.pem", fun () -> new Keys.handler_csr hsm_state ip);
        ("/keys/:id/decrypt", fun () -> new Keys.handler_decrypt hsm_state ip);
        ("/keys/:id/encrypt", fun () -> new Keys.handler_encrypt hsm_state ip);
        ("/keys/:id/sign", fun () -> new Keys.handler_sign hsm_state ip);
        ("/keys/:id/cert", fun () -> new Keys.handler_cert hsm_state ip);
        ( "/keys/:id/restrictions/tags/:tag",
          fun () -> new Keys.handler_restrictions_tags hsm_state ip );
        ("/namespaces", fun () -> new Namespace.handler_namespaces hsm_state ip);
        ("/namespaces/:id", fun () -> new Namespace.handler hsm_state ip);
        ("/system/info", fun () -> new System.info hsm_state ip);
        ("/system/reboot", fun () -> new System.reboot hsm_state ip);
        ("/system/shutdown", fun () -> new System.shutdown hsm_state ip);
        ( "/system/factory-reset",
          fun () -> new System.factory_reset hsm_state ip );
        ("/system/update", fun () -> new System.update hsm_state ip);
        ( "/system/commit-update",
          fun () -> new System.commit_update hsm_state ip );
        ( "/system/cancel-update",
          fun () -> new System.cancel_update hsm_state ip );
        ("/system/backup", fun () -> new System.backup hsm_state ip);
        ("/system/restore", fun () -> new System.restore hsm_state ip);
      ]
end

module type Server = sig
  module IO : Cohttp_lwt.IO

  type conn = IO.conn * Cohttp.Connection.t
  type t

  val respond :
    ?headers:Cohttp.Header.t ->
    ?flush:bool ->
    status:Cohttp.Code.status_code ->
    body:Cohttp_lwt.Body.t ->
    unit ->
    (Cohttp.Response.t * Cohttp_lwt.Body.t) Lwt.t

  val make :
    ?conn_closed:(conn -> unit) ->
    callback:
      (conn ->
      Ipaddr.t ->
      Cohttp.Request.t ->
      Cohttp_lwt.Body.t ->
      (Cohttp.Response.t * Cohttp_lwt.Body.t) Lwt.t) ->
    unit ->
    t
end

module Make (R : Mirage_random.S) (Http : Server) (Hsm : Hsm.S) = struct
  module Handlers = Make_handlers (R) (Hsm)

  (* Route dispatch. Returns [None] if the URI did not match any pattern, server should return a 404 [`Not_found]. *)
  let dispatch hsm_state ip request body =
    let start = Hsm.now () in
    Access_log.info (fun m ->
        m "request %s %s"
          (Cohttp.Code.string_of_method (Cohttp.Request.meth request))
          (Cohttp.Request.resource request));
    Access_log.debug (fun m ->
        m "request headers %s"
          (Cohttp.Header.to_string (Cohttp.Request.headers request)));
    (Lwt.catch
       (fun () ->
         Handlers.Wm.dispatch' (Handlers.routes hsm_state ip) ~body ~request)
       (fun e ->
         if e = Out_of_memory then Gc.compact ();
         Lwt.return_some
           ( `Service_unavailable,
             Cohttp.Header.init (),
             `String (Printexc.to_string e),
             [] ))
     >|= function
     | None -> (`Not_found, Cohttp.Header.init (), `String "Not found", [])
     | Some result -> result)
    >>= fun (status, headers, body, path) ->
    let stop = Hsm.now () in
    let diff = Ptime.diff stop start in
    Access_log.info (fun m ->
        m "response %d response time %a"
          (Cohttp.Code.code_of_status status)
          Ptime.Span.pp diff);
    Access_log.debug (fun m ->
        m "%s %s path: %s"
          (Cohttp.Code.string_of_method (Cohttp.Request.meth request))
          (Uri.path (Cohttp.Request.uri request))
          (Astring.String.concat ~sep:", " path));
    Hsm.Metrics.http_status status;
    Hsm.Metrics.http_response_time (Ptime.Span.to_float_s diff);
    Http.respond ~flush:false ~headers ~body ~status ()

  (* Redirect to https *)
  let redirect port _ip request _body =
    let uri = Cohttp.Request.uri request in
    let new_uri = Uri.with_scheme uri (Some "https") in
    let new_uri =
      Uri.with_port new_uri (if port = 443 then None else Some port)
    in
    Access_log.debug (fun f ->
        f "[%s] -> [%s]" (Uri.to_string uri) (Uri.to_string new_uri));
    let headers = Cohttp.Header.init_with "location" (Uri.to_string new_uri) in
    Http.respond ~flush:false ~headers ~status:`Moved_permanently ~body:`Empty
      ()

  let serve cb =
    let callback (_, cid) ip request body =
      let ip =
        match ip with
        | Ipaddr.V4 ip -> ip
        | V6 _ ->
            Access_log.err (fun m -> m "IPv6 not supported");
            Ipaddr.V4.localhost
      in
      Access_log.debug (fun m -> m "IP of client is %a" Ipaddr.V4.pp ip);
      let uri = Cohttp.Request.uri request in
      let cid = Cohttp.Connection.to_string cid in
      Access_log.debug (fun f -> f "[%s] serving %s." cid (Uri.to_string uri));
      cb ip request body
    in
    let conn_closed (_, cid) =
      let cid = Cohttp.Connection.to_string cid in
      Access_log.debug (fun f -> f "[%s] closing" cid)
    in
    Http.make ~conn_closed ~callback ()
end
