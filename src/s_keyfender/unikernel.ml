open Lwt.Infix

(* Logging *)
let https_src = Logs.Src.create "keyfender" ~doc:"Keyfender (NetHSM)"
module Log = (val Logs.src_log https_src : Logs.LOG)

module Main
    (Console: Mirage_console.S)
    (Rng: Mirage_random.S) (Pclock: Mirage_clock.PCLOCK) (Mclock: Mirage_clock.MCLOCK)
    (Static_assets: Mirage_kv.RO)
    (Internal_stack: Mirage_stack.V4V6) (_ : sig end)
    (External_net: Mirage_net.S) (External_eth: Mirage_protocols.ETHERNET) (External_arp: Mirage_protocols.ARP)
=
struct
  module Time = OS.Time
  module Ext_ipv4 = Static_ipv4.Make(Rng)(Mclock)(External_eth)(External_arp)
  module Ext_ipv6 = Ipv6.Make(External_net)(External_eth)(Rng)(Time)(Mclock)
  module Ext_icmp = Icmpv4.Make(Ext_ipv4)
  module Ext_ip = Tcpip_stack_direct.IPV4V6(Ext_ipv4)(Ext_ipv6)
  module Ext_udp = Udp.Make(Ext_ip)(Rng)
  module Ext_tcp = Tcp.Flow.Make(Ext_ip)(Time)(Mclock)(Rng)
  module Ext_stack = Tcpip_stack_direct.MakeV4V6(Time)(Rng)(External_net)(External_eth)(External_arp)(Ext_ip)(Ext_icmp)(Ext_udp)(Ext_tcp)

  module Conduit = Conduit_mirage.TCP(Ext_stack)
  module Conduit_tls = Conduit_mirage.TLS(Conduit)
  module Http = Cohttp_mirage.Server.Make(Conduit_tls)

  module Hsm_clock = Keyfender.Hsm_clock.Make(Pclock)
  module Git_store = Store.KV_RW(Irmin_git.Mem)(Hsm_clock)

  module Hsm = Keyfender.Hsm.Make(Rng)(Git_store)(Time)(Mclock)(Hsm_clock)
  module Webserver = Keyfender.Server.Make(Rng)(Http)(Hsm)

  module HsmClock = struct
    let now_d_ps () = Ptime.Span.to_d_ps (Ptime.to_span (Hsm.now ()))

    let current_tz_offset_s () = None

    let period_d_ps () = None
  end

  module Log_reporter = Mirage_logs.Make(HsmClock)
  module Syslog = Logs_syslog_mirage.Udp(Console)(HsmClock)(Ext_stack)

  let opt_static_file assets next ip request body =
    let uri = Cohttp.Request.uri request in
    let path = match Uri.path uri with
      | "/" -> "/index.html"
      | p -> p
    in
    Static_assets.get assets (Mirage_kv.Key.v path) >>= function
    | Ok data ->
      let mime_type = Magic_mime.lookup path in
      let headers = Cohttp.Header.init_with "content-type" mime_type in
      Http.respond ~headers ~status:`OK ~body:(`String data) ()
    | _ -> next ip request body

  module T = Internal_stack.TCP
  let write_platform ?additional_data stack cmd =
    if Key_gen.no_platform () then begin
      Log.warn (fun m -> m "Communication to the platform has been disabled with '--no-platform'. This is not meant for production. Skipping to send %s, replying with the empty string." cmd);
      Lwt.return (Ok "")
    end else begin
      Log.debug (fun m -> m "sending %s to platform" cmd);
      Lwt.pick [
        (Time.sleep_ns (Duration.of_sec 30) >|= fun () -> (* XXX: actual timeout TBD *)
         Log.err (fun m -> m "couldn't connect to platform (while sending %s)" cmd);
         Error `Timeout) ;
        T.create_connection (Internal_stack.tcp stack) (Ipaddr.V4 (Key_gen.platform ()), Key_gen.platform_port ()) >>= function
        | Error e ->
          Lwt.return (Error (`Create (Fmt.to_to_string T.pp_error e)))
        | Ok flow ->
          T.write flow (Cstruct.of_string (cmd ^ "\n")) >>= function
          | Error we ->
            T.close flow >|= fun () ->
            Error (`Write (Fmt.to_to_string T.pp_write_error we))
          | Ok () ->
            let rec read data =
              T.read flow >>= function
              | Ok `Eof -> T.close flow >|= fun () -> Error `Eof
              | Ok `Data d ->
                let data' = Cstruct.append data d in
                let str = Cstruct.to_string data' in
                let get_data off str =
                  let str = Astring.String.drop ~min:off ~max:off str in
                  if Astring.String.is_prefix ~affix:" " str then
                    Astring.String.drop ~min:1 ~max:1 str
                  else
                    str
                in
                if Astring.String.is_suffix ~affix:"\n" str then
                  T.close flow >|= fun () ->
                  let str = Astring.String.drop ~rev:true ~min:1 ~max:1 str in
                  if Astring.String.is_prefix ~affix:"OK" str then
                    Ok (get_data 2 str)
                  else if Astring.String.is_prefix ~affix:"ERROR" str then
                    Error (`Remote (get_data 5 str))
                  else
                    Error (`Parse str)
                else
                  read data'
              | Error e ->
                T.close flow >|= fun () ->
                Error (`Read (Fmt.to_to_string T.pp_error e))
            in
            (match additional_data with
             | None -> Lwt.return (Ok ())
             | Some f ->
               let write data =
                 T.write flow (Cstruct.of_string data) >>= function
                 | Error we ->
                   T.close flow >|= fun () ->
                   Error (Fmt.to_to_string T.pp_write_error we)
                 | Ok () -> Lwt.return (Ok ())
               in
               f write) >>= function
            | Ok () -> read Cstruct.empty
            | Error e -> Lwt.return (Error (`Additional e))
      ]
    end

  let pp_platform_err ppf = function
    | `Write err -> Format.fprintf ppf "write error %s" err
    | `Read err -> Format.fprintf ppf "read error %s" err
    | `Create err -> Format.fprintf ppf "error %s while establishing connection" err
    | `Eof -> Format.fprintf ppf "received eof"
    | `Remote err -> Format.fprintf ppf "received error %s" err
    | `Parse err -> Format.fprintf ppf "couldn't decode message %s" err
    | `Timeout -> Format.fprintf ppf "timeout"
    | `Additional err -> Format.fprintf ppf "additional data: %s" err

  let start console _entropy () () assets internal_stack ctx ext_net ext_eth ext_arp =
    Metrics_lwt.periodically (OS.MM.malloc_metrics ~tags:[]);
    Irmin_git.Mem.v (Fpath.v "somewhere") >>= function
    | Error _ -> invalid_arg "Could not create an in-memory git repository."
    | Ok git ->
      let store_connect () =
        let author _ = "keyfender"
        and msg _ = "a keyfender change"
        in
        Git_store.connect git ~depth:1 ~ctx ~author ~msg (Key_gen.remote ())
      in
      let sleep e =
        Log.warn(fun m -> m "Could not connect to remote %s" (Printexc.to_string e));
        Time.sleep_ns (Duration.of_sec 1)
      in
      let rec connect_git () =
        Lwt.catch store_connect
          (fun e -> if Key_gen.retry () then sleep e >>= connect_git else Lwt.fail e)
      in
      connect_git () >>= fun store ->
      Logs.app (fun m -> m "connected to store");
      (* check whether it is empty - irmin's batch operation requires a non-empty store! *)
      (let ign = Mirage_kv.Key.v ".gitignore" in
        Git_store.exists store ign >>= function
        | Ok None ->
          (Git_store.set store ign "" >>= function
            | Ok () -> Lwt.return_unit
            | Error e ->
              Log.err (fun m -> m "couldn't write to store %a" Git_store.pp_write_error e);
              Lwt.fail_with "store not writable")
        | Ok (Some _) -> Lwt.return_unit
        | Error e ->
          Log.err (fun m -> m "couldn't read from store %a" Git_store.pp_error e);
          Lwt.fail_with "store not readable") >>= fun () ->
      (write_platform internal_stack "DEVICE-ID" >>= function
        | Error e ->
          Log.err (fun m -> m "couldn't retrieve device id: %a" pp_platform_err e);
          Lwt.fail_with "failed to retrieve device id from platform"
        | Ok device_id -> Lwt.return device_id) >>= fun device_id ->
      Hsm.boot ~device_id store >>= fun (hsm_state, mvar, res_mvar) ->
      let setup_stack ?gateway cidr =
        Ext_ipv4.connect ~cidr ?gateway ext_eth ext_arp >>= fun ipv4 ->
        Ext_icmp.connect ipv4 >>= fun icmp ->
        Ext_ipv6.connect ~no_init:true ~handle_ra:false ext_net ext_eth >>= fun ipv6 ->
        Ext_ip.connect ~ipv4_only:true ~ipv6_only:false ipv4 ipv6 >>= fun ip ->
        Ext_udp.connect ip >>= fun udp ->
        Ext_tcp.connect ip >>= fun tcp ->
        Ext_stack.connect ext_net ext_eth ext_arp ip icmp udp tcp >|= fun ext_stack ->
        tcp, ext_stack
      and shutdown_stack tcp stack =
        Ext_tcp.disconnect tcp >>= fun () ->
        Ext_stack.disconnect stack
      and setup_log ext_stack log =
        Logs.set_level ~all:true (Some log.Keyfender.Json.logLevel);
        if Ipaddr.V4.compare log.Keyfender.Json.ipAddress Ipaddr.V4.any <> 0
        then
          let reporter =
            let port = log.Keyfender.Json.port in
            Syslog.create console ext_stack ~hostname:"keyfender"
              (Ipaddr.V4 log.Keyfender.Json.ipAddress) ~port ()
          in
          Logs.set_reporter reporter
        else
          Log_reporter.set_reporter (Log_reporter.create ())
      and setup_http_listener http =
        let http_port = Key_gen.http_port () in
        let tcp = `TCP http_port in
        let open Webserver in
        Log.info (fun f -> f "listening on %d/TCP for HTTP" http_port);
        http tcp @@ serve (redirect (Key_gen.https_port ()))
      and setup_https_listener http certificates =
        let tls_cfg = Tls.Config.server ~certificates () in
        let https_port = Key_gen.https_port () in
        let tls = `TLS (tls_cfg, `TCP https_port) in
        let open Webserver in
        Log.info (fun f -> f "listening on %d/TCP for HTTPS" https_port);
        http tls @@ serve @@ opt_static_file assets @@ dispatch hsm_state
      and write_to_platform cmd =
        write_platform internal_stack (Hsm.cb_to_string cmd) >|= function
        | Ok _ -> ()
        | Error e ->
          Logs.err (fun m -> m "error %a communicating with platform"
                       pp_platform_err e)
      in
      let reconfigure_network cidr gateway =
        setup_stack ?gateway cidr >>= fun (tcp, ext_stack) ->
        let http = Http.listen ext_stack in
        Lwt.async (fun () -> setup_http_listener http);
        Lwt.async (fun () -> setup_https_listener http (Hsm.own_cert hsm_state));
        Hsm.Config.log hsm_state >|= fun log ->
        setup_log ext_stack log;
        tcp, ext_stack, http
      in
      let rec handle_cb tcp ext_stack http =
        Lwt_mvar.take mvar >>= function
        | Hsm.Log log ->
          setup_log ext_stack log;
          handle_cb tcp ext_stack http
        | Hsm.Shutdown | Hsm.Reboot | Hsm.Reset as cmd ->
          shutdown_stack tcp ext_stack >>= fun () ->
          write_to_platform cmd
        | Hsm.Tls certificates ->
          Lwt.async (fun () -> setup_https_listener http certificates);
          handle_cb tcp ext_stack http
        | Hsm.Network (cidr, gateway) ->
          shutdown_stack tcp ext_stack >>= fun () ->
          reconfigure_network cidr gateway >>= fun (tcp, ext_stack, http) ->
          handle_cb tcp ext_stack http
        | Hsm.Update (blocks, stream) as cmd ->
          begin
            let additional_data write =
              write (string_of_int blocks ^ "\n") >>= fun r ->
              Lwt_stream.fold_s (fun chunk acc ->
                  match acc with
                  | Ok () -> write chunk
                  | Error e -> Lwt.return (Error e))
                stream r
            in
            write_platform ~additional_data internal_stack (Hsm.cb_to_string cmd) >>= function
            | Ok _ -> Lwt_mvar.put res_mvar (Ok ())
            | Error e -> Lwt_mvar.put res_mvar (Error (Fmt.to_to_string pp_platform_err e))
          end >>= fun () ->
          handle_cb tcp ext_stack http
        | Hsm.Commit_update as cmd ->
          begin
            write_platform internal_stack (Hsm.cb_to_string cmd) >>= function
            | Ok _ -> Lwt_mvar.put res_mvar (Ok ())
            | Error e -> Lwt_mvar.put res_mvar (Error (Fmt.to_to_string pp_platform_err e))
          end >>= fun () ->
          handle_cb tcp ext_stack http
      in
      Hsm.network_configuration hsm_state >>= fun (ip, net, gateway) ->
      let cidr = Ipaddr.V4.Prefix.(make (bits net) ip) in
      reconfigure_network cidr gateway >>= fun (tcp, ext_stack, http) ->
      handle_cb tcp ext_stack http
end
