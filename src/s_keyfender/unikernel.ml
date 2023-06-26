open Lwt.Infix

let _print_banner =
  let msg = Format.sprintf "Starting NetHSM S-Keyfender - version %s (%s)"
    Keyfender.Hsm.software_version Keyfender.Hsm.build_tag
  in
  let sep = String.make ((String.length msg) + 2) '-' in
  Format.printf "+%s+\n| %s |\n+%s+@." sep msg sep

(* Logging *)
let https_src = Logs.Src.create "keyfender" ~doc:"Keyfender (NetHSM)"
module Log = (val Logs.src_log https_src : Logs.LOG)

module Main
    (Console: Mirage_console.S)
    (Rng: Mirage_random.S) (Pclock: Mirage_clock.PCLOCK) (Mclock: Mirage_clock.MCLOCK)
    (Update_key: Mirage_kv.RO)
    (Static_assets: Mirage_kv.RO)
    (Internal_stack: Tcpip.Stack.V4V6)
    (Ext_reconfigurable_stack: Reconfigurable_stack.S)
=
struct
  module Time = OS.Time
  module Ext_stack = Ext_reconfigurable_stack.Stack

  module Conduit = Conduit_mirage.TCP(Ext_stack)
  module Conduit_tls = Conduit_mirage.TLS(Conduit)
  module Http = Cohttp_mirage.Server.Make(Conduit_tls)

  (* module Int_conduit = Conduit_mirage.TCP(Internal_stack) *)
  (* module Resolver = Resolver_mirage.Make(Rng)(Time)(Mclock)(Pclock)(Internal_stack) *)
  (* module Client = H2_mirage.Client(Int_conduit.Flow) *)

  module Hsm_clock = Keyfender.Hsm_clock.Make(Pclock)
  module KV_store = Etcd_store.KV_RW(Internal_stack)

  module Hsm = Keyfender.Hsm.Make(Rng)(KV_store)(Time)(Mclock)(Hsm_clock)
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
                  (read[@tailcall]) data'
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

  let startTrngListener stack port =
    if Key_gen.no_platform () then Lwt.return_unit else
    let module RNG = Mirage_crypto_rng in
    let trng = RNG.Entropy.register_source "trng" in
    let `Acc feed_entropy = RNG.accumulate None trng in
    let rand_block_len = 4096 in
    let rand_block_num = 2 in
    let rand_total_len = rand_block_num * rand_block_len in
    let block_num = rand_block_num * RNG.pools None in
    let platform_ip = Key_gen.platform () in
    let first_package, first_package_notify = Lwt.wait () in
    let chan, push = Lwt_stream.create () in
    Internal_stack.UDP.listen (Internal_stack.udp stack) ~port
      (fun ~src ~dst:_ ~src_port:_ data ->
        (match src with
        | Ipaddr.V4 ip when ip = platform_ip -> push (Some data)
        | ip ->
          Log.warn (fun m -> m "Dropping TRNG package from unknown source: %a" Ipaddr.pp ip));
        Lwt.return_unit
      );
    let rec loop () =
      Lwt.pick [
        (Time.sleep_ns (Duration.of_sec 30) >>= fun () ->
          let msg = "Receiving no entropy from S-Platform! Shutting down!" in
          Log.err (fun m -> m "%s" msg);
          Lwt.fail_with msg);
        Lwt_stream.get chan >|= fun data ->
          let data = Option.get data in
          let data_len = Cstruct.length data in
          Log.debug (fun m -> m "Received %d bytes of data from TRNG: %a ..."
            data_len Cstruct.hexdump_pp (Cstruct.sub data 0 8));
          let block_len = data_len / block_num in
          for i = 0 to pred block_num do
            let offset = i * block_len in
            feed_entropy (Cstruct.sub data offset block_len);
          done;
          if data_len < rand_total_len then Log.err (fun m -> m "Receiving not enough entropy! TRNG or TPM broken?");
          if data_len >= rand_block_len && Lwt.is_sleeping first_package then Lwt.wakeup_later first_package_notify ();
      ] >>= fun () -> (loop[@tailcall]) ()
    in
    Lwt.async loop;
    Log.info (fun m -> m "Waiting for first data from TRNG");
    first_package

  let pp_platform_err ppf = function
    | `Write err -> Format.fprintf ppf "write error %s" err
    | `Read err -> Format.fprintf ppf "read error %s" err
    | `Create err -> Format.fprintf ppf "error %s while establishing connection" err
    | `Eof -> Format.fprintf ppf "received eof"
    | `Remote err -> Format.fprintf ppf "received error %s" err
    | `Parse err -> Format.fprintf ppf "couldn't decode message %s" err
    | `Timeout -> Format.fprintf ppf "timeout"
    | `Additional err -> Format.fprintf ppf "additional data: %s" err

  module Memtrace = Memtrace.Make(Hsm_clock)(Ext_stack.TCP)

  let cache_settings = {
    Keyfender.Cached_store.cache_size = 1024;
    refresh_delay_s = Some 5.;
    evict_delay_s = 10.;
  }

let dummy_platform = {
  Keyfender.Json.deviceId = "0000000000" ;
  deviceKey = "no platform" ;
  pcr = "" ;
  akPubP256 = "" ;
  akPubP384 = "" ;
}

  let start console _entropy () () update_key_store assets internal_stack ext_stack () () =
      let entropy_port = 4444 in
      startTrngListener internal_stack entropy_port >>= fun () ->
      let sleep e =
        Log.warn (fun m ->
            m "Could not connect to KV store: %s\nRetrying in 1 second..." e);
        Time.sleep_ns (Duration.of_sec 1)
      in
      let rec store_connect () =
        KV_store.connect internal_stack >>= function
          | Ok store -> Lwt.return store
          | Error e ->
            let err = Fmt.to_to_string KV_store.pp_error e in
            if Key_gen.retry () then sleep err >>= fun () -> (store_connect[@tailcall]) ()
            else Lwt.fail_with err
      in
      store_connect () >>= fun store ->
      Logs.app (fun m -> m "connected to store");
      (let ini = Mirage_kv.Key.v ".initialized" in
        KV_store.exists store ini >>= function
        | Ok None ->
          (KV_store.set store ini "" >>= function
            | Ok () -> Lwt.return_unit
            | Error e ->
              Log.err (fun m -> m "couldn't write to store %a" KV_store.pp_write_error e);
              Lwt.fail_with "store not writable")
        | Ok (Some _) -> Lwt.return_unit
        | Error e ->
          Log.err (fun m -> m "couldn't read from store %a" KV_store.pp_error e);
          Lwt.fail_with "store not readable") >>= fun () ->
      (write_platform internal_stack "PLATFORM-DATA" >>= function
        | Error e ->
          Log.err (fun m -> m "couldn't retrieve platform data: %a" pp_platform_err e);
          Lwt.fail_with "failed to retrieve platform data from platform"
        | Ok "" -> Lwt.return dummy_platform
        | Ok data ->
        match (Keyfender.Json.parse_platform_data data) with
        | Error e ->
          Log.err (fun m -> m "couldn't parse platform data: %s" e);
          Lwt.fail_with "failed to parse platform data from platform"
        | Ok x -> Lwt.return x) >>= fun platform ->
      (Update_key.get update_key_store (Mirage_kv.Key.v "key.pem") >>= function
        | Error e ->
          Log.err (fun m -> m "couldn't retrieve update key: %a" Update_key.pp_error e);
          Lwt.fail_with "missing update key"
        | Ok data ->
          match X509.Public_key.decode_pem (Cstruct.of_string data) with
          | Ok `RSA key -> Lwt.return key
          | Ok _ ->
            Log.err (fun m -> m "No RSA key from manufacturer. Contact manufacturer.");
            Lwt.fail_with "update key not in RSA format"
          | Error `Msg m ->
            Lwt.fail_with ("couldn't decode update key: " ^ m)
      ) >>= fun update_key ->
      Hsm.boot ~cache_settings ~platform update_key store >>= fun (hsm_state, mvar, res_mvar) ->
      let setup_log stack log =
        Logs.set_level ~all:true (Some log.Keyfender.Json.logLevel);
        if Ipaddr.V4.compare log.Keyfender.Json.ipAddress Ipaddr.V4.any <> 0
        then
          let reporter =
            let port = log.Keyfender.Json.port in
            Syslog.create console stack ~hostname:"keyfender"
              (Ipaddr.V4 log.Keyfender.Json.ipAddress) ~port ()
          in
          Logs.set_reporter (Keyfender.Logs_sequence_number.reporter reporter)
        else
          let logs = Log_reporter.create () in
          Log_reporter.set_reporter logs;
          Logs.set_reporter
            (Keyfender.Logs_sequence_number.reporter
              (Log_reporter.reporter logs))
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
        Ext_reconfigurable_stack.setup ext_stack ?gateway cidr >>= fun () ->
        let stack = Ext_reconfigurable_stack.stack ext_stack in
        let http = Http.listen stack in
        Lwt.async (fun () -> setup_http_listener http);
        Lwt.async (fun () -> setup_https_listener http (Hsm.own_cert hsm_state));
        Hsm.Config.log hsm_state >|= fun log ->
        setup_log stack log;
        http
      in
      let rec handle_cb http =
        Lwt_mvar.take mvar >>= function
        | Hsm.Log log ->
          setup_log (Ext_reconfigurable_stack.stack ext_stack) log;
          (handle_cb[@tailcall]) http
        | Hsm.Shutdown | Hsm.Reboot | Hsm.Factory_reset as cmd ->
          Ext_reconfigurable_stack.disconnect ext_stack >>= fun () ->
          write_to_platform cmd
        | Hsm.Tls certificates ->
          Lwt.async (fun () -> setup_https_listener http certificates);
          (handle_cb[@tailcall]) http
        | Hsm.Network (cidr, gateway) ->
          Ext_reconfigurable_stack.disconnect ext_stack >>= fun () ->
          reconfigure_network cidr gateway >>= fun http ->
          (handle_cb[@tailcall]) http
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
          (handle_cb[@tailcall]) http
        | Hsm.Commit_update as cmd ->
          begin
            write_platform internal_stack (Hsm.cb_to_string cmd) >>= function
            | Ok _ -> Lwt_mvar.put res_mvar (Ok ())
            | Error e -> Lwt_mvar.put res_mvar (Error (Fmt.to_to_string pp_platform_err e))
          end >>= fun () ->
          (handle_cb[@tailcall]) http
      in
      Hsm.network_configuration hsm_state >>= fun (ip, net, gateway) ->
      let cidr = Ipaddr.V4.Prefix.(make (bits net) ip) in
      reconfigure_network cidr gateway >>= fun http ->
      (match Key_gen.memtrace () with
       | None -> ()
       | Some port ->
         Ext_reconfigurable_stack.Stack.TCP.listen
           Ext_reconfigurable_stack.(Stack.tcp (stack ext_stack))
           ~port
           (fun f ->
              (* only allow a single tracing client *)
              match Memtrace.Memprof_tracer.active_tracer () with
              | Some _ ->
                Logs.warn (fun m -> m "tracing already active");
                Ext_reconfigurable_stack.Stack.TCP.close f
              | None ->
                Logs.info (fun m -> m "starting tracing");
                let tracer = Memtrace.start_tracing ~context:None ~sampling_rate:1e-4 f in
                Lwt.async (fun () ->
                    Ext_reconfigurable_stack.Stack.TCP.read f >|= fun _ ->
                    Logs.warn (fun m -> m "tracing read returned, closing");
                    Memtrace.stop_tracing tracer);
                Lwt.return_unit));
      handle_cb http
end
