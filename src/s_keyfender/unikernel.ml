(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Lwt.Infix

let _print_banner =
  let msg =
    Format.sprintf "Starting NetHSM S-Keyfender - version %s (%s)"
      Keyfender.Hsm.software_version Keyfender.Hsm.build_tag
  in
  let sep = String.make (String.length msg + 2) '-' in
  Format.printf "+%s+\n| %s |\n+%s+@." sep msg sep

(* Logging *)
let https_src = Logs.Src.create "keyfender" ~doc:"Keyfender (NetHSM)"

module Log = (val Logs.src_log https_src : Logs.LOG)

module Stack_nodelay (Stack : Tcpip.Stack.V4V6) = struct
  include Stack

  module TCP = struct
    include Stack.TCP

    let write = Stack.TCP.write_nodelay
    let writev = Stack.TCP.writev_nodelay

    let listen t ~port ?keepalive fn =
      let fn flow =
        Lwt.catch
          (fun () -> fn flow)
          (fun e ->
            close flow >>= fun () ->
            if e = Out_of_memory then Gc.compact ();
            Lwt.return_unit)
      in
      Stack.TCP.listen t ~port ?keepalive fn
  end
end

module Main
    (Update_key : Mirage_kv.RO)
    (Static_assets : Mirage_kv.RO)
    (Internal_stack : Tcpip.Stack.V4V6)
    (Ext_reconfigurable_stack : Reconfigurable_stack.S)
    (Conf_args : Args.Conf.S) =
struct
  module Ext_stack = Ext_reconfigurable_stack.Stack
  module Conduit = Conduit_mirage.TCP (Stack_nodelay (Ext_stack))
  module Conduit_tls = Conduit_mirage.TLS (Conduit)
  module Srv = Cohttp_mirage.Server.Make (Conduit_tls)

  (* module Int_conduit = Conduit_mirage.TCP(Internal_stack) *)
  (* module Resolver = Resolver_mirage.Make(Rng)(Time)(Mclock)(Pclock)(Internal_stack) *)
  (* module Client = H2_mirage.Client(Int_conduit.Flow) *)

  module KV_store = Etcd_store.KV_RW (Stack_nodelay (Internal_stack))
  module Hsm = Keyfender.Hsm.Make (KV_store)
  module Webserver = Keyfender.Server.Make (Srv) (Hsm)
  module Log_reporter = Mirage_logs
  module Syslog = Logs_syslog_mirage.Udp (Ext_stack)

  let opt_static_file assets next ip request body =
    let uri = Cohttp.Request.uri request in
    let path = match Uri.path uri with "/" -> "/index.html" | p -> p in
    Static_assets.get assets (Mirage_kv.Key.v path) >>= function
    | Ok data ->
        let mime_type = Magic_mime.lookup path in
        let headers = Cohttp.Header.init_with "content-type" mime_type in
        Srv.respond ~headers ~status:`OK ~body:(`String data) ()
    | _ -> next ip request body

  module T = Internal_stack.TCP

  let write_platform ?additional_data stack cmd =
    if Conf_args.no_platform then (
      Log.warn (fun m ->
          m
            "Communication to the platform has been disabled with \
             '--no-platform'. This is not meant for production. Skipping to \
             send %s, replying with the empty string."
            cmd);
      Lwt.return (Ok ""))
    else (
      Log.debug (fun m -> m "sending %s to platform" cmd);
      Lwt.pick
        [
          ( Mirage_sleep.ns (Duration.of_sec 30) >|= fun () ->
            (* XXX: actual timeout TBD *)
            Log.err (fun m ->
                m "couldn't connect to platform (while sending %s)" cmd);
            Error `Timeout );
          ( T.create_connection (Internal_stack.tcp stack)
              (Ipaddr.V4 (Args.platform ()), Args.platform_port ())
          >>= function
            | Error e ->
                Lwt.return (Error (`Create (Fmt.to_to_string T.pp_error e)))
            | Ok flow -> (
                T.write flow (Cstruct.of_string (cmd ^ "\n")) >>= function
                | Error we ->
                    T.close flow >|= fun () ->
                    Error (`Write (Fmt.to_to_string T.pp_write_error we))
                | Ok () -> (
                    let rec read data =
                      T.read flow >>= function
                      | Ok `Eof -> T.close flow >|= fun () -> Error `Eof
                      | Ok (`Data d) ->
                          let data' = Cstruct.append data d in
                          let str = Cstruct.to_string data' in
                          let get_data off str =
                            let str =
                              Astring.String.drop ~min:off ~max:off str
                            in
                            if Astring.String.is_prefix ~affix:" " str then
                              Astring.String.drop ~min:1 ~max:1 str
                            else str
                          in
                          if Astring.String.is_suffix ~affix:"\n" str then
                            T.close flow >|= fun () ->
                            let str =
                              Astring.String.drop ~rev:true ~min:1 ~max:1 str
                            in
                            if Astring.String.is_prefix ~affix:"OK" str then
                              Ok (get_data 2 str)
                            else if Astring.String.is_prefix ~affix:"ERROR" str
                            then Error (`Remote (get_data 5 str))
                            else Error (`Parse str)
                          else (read [@tailcall]) data'
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
                        f write)
                    >>= function
                    | Ok () -> read Cstruct.empty
                    | Error e -> Lwt.return (Error (`Additional e)))) );
        ])

  let startTrngListener stack port =
    if Conf_args.no_platform then Lwt.return_unit
    else
      let module RNG = Mirage_crypto_rng in
      let trng = RNG.Entropy.register_source "trng" in
      let (`Acc feed_entropy) = RNG.accumulate None trng in
      let trng_block_len = 4096 in
      let pools = RNG.pools None in
      let platform_ip = Args.platform () in
      let first_package, first_package_notify = Lwt.wait () in
      let chan, push = Lwt_stream.create () in
      let split_data data =
        let len = String.length data in
        if len < trng_block_len then (String.empty, data)
        else
          String.
            ( sub data 0 trng_block_len,
              sub data trng_block_len (len - trng_block_len) )
      in
      Internal_stack.UDP.listen (Internal_stack.udp stack) ~port
        (fun ~src ~dst:_ ~src_port:_ data ->
          (match src with
          | Ipaddr.V4 ip when ip = platform_ip ->
              push (Some (Cstruct.to_string data))
          | ip ->
              Log.warn (fun m ->
                  m "Dropping TRNG package from unknown source: %a" Ipaddr.pp ip));
          Lwt.return_unit);
      let rec loop () =
        Lwt.pick
          [
            ( Mirage_sleep.ns (Duration.of_sec 30) >>= fun () ->
              let msg =
                "Receiving no entropy from S-Platform! Shutting down!"
              in
              Log.err (fun m -> m "%s" msg);
              Lwt.fail_with msg );
            ( Lwt_stream.get chan >|= fun data ->
              let trng_data, tpm_data = split_data (Option.get data) in
              if String.length trng_data = trng_block_len then (
                Log.debug (fun m ->
                    m "Received %d bytes of data from TRNG: %a ..."
                      trng_block_len Hex.pp
                      (Hex.of_string (String.sub trng_data 0 8)));
                let block_len = trng_block_len / pools in
                for i = 0 to pred pools do
                  let offset = i * block_len in
                  feed_entropy (String.sub trng_data offset block_len)
                done;
                if Lwt.is_sleeping first_package then
                  Lwt.wakeup_later first_package_notify ())
              else Log.err (fun m -> m "Receiving no entropy from TRNG!");
              if String.length tpm_data > 0 then feed_entropy tpm_data
              else Log.err (fun m -> m "Receiving no entropy from TPM!") );
          ]
        >>= fun () -> (loop [@tailcall]) ()
      in
      Lwt.async loop;
      Log.info (fun m -> m "Waiting for first data from TRNG");
      first_package

  let pp_platform_err ppf = function
    | `Write err -> Format.fprintf ppf "write error %s" err
    | `Read err -> Format.fprintf ppf "read error %s" err
    | `Create err ->
        Format.fprintf ppf "error %s while establishing connection" err
    | `Eof -> Format.fprintf ppf "received eof"
    | `Remote err -> Format.fprintf ppf "received error %s" err
    | `Parse err -> Format.fprintf ppf "couldn't decode message %s" err
    | `Timeout -> Format.fprintf ppf "timeout"
    | `Additional err -> Format.fprintf ppf "additional data: %s" err

  module Memtrace = Memtrace.Make (Ext_stack.TCP)

  let cache_settings =
    {
      Keyfender.Cached_store.cache_size = 1024;
      refresh_delay_s = Some 5.;
      evict_delay_s = 10.;
    }

  let dummy_platform : Keyfender.Json.platform_data =
    {
      Keyfender.Json.deviceId = "0000000000";
      deviceKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
      pcr = [];
      akPub = [];
      hardwareVersion = "N/A";
      firmwareVersion = "N/A";
    }

  let start update_key_store assets internal_stack ext_stack
      (conf_args : Args.Conf.args) () () =
    let ( let* ) = Lwt.bind in
    let* () =
      if not (Args.start ()) then Lwt.fail_with "--start parameter required"
      else Lwt.return_unit
    in
    if Conf_args.no_scrypt then Keyfender.Crypto.set_test_params ();
    let entropy_port = 4444 in
    let* () = startTrngListener internal_stack entropy_port in
    let sleep e =
      Log.warn (fun m ->
          m "Could not connect to KV store: %s\nRetrying in 1 second..." e);
      Mirage_sleep.ns (Duration.of_sec 1)
    in
    let rec store_connect () =
      KV_store.connect internal_stack >>= function
      | Ok store -> Lwt.return store
      | Error e ->
          let err = Fmt.to_to_string KV_store.pp_error e in
          let* () = sleep err in
          (store_connect [@tailcall]) ()
    in
    let* store = store_connect () in
    Logs.app (fun m -> m "connected to store");
    let ini = Mirage_kv.Key.v ".initialized" in
    let* () =
      KV_store.exists store ini >>= function
      | Ok None -> (
          KV_store.set store ini "" >>= function
          | Ok () -> Lwt.return_unit
          | Error e ->
              Log.err (fun m ->
                  m "couldn't write to store %a" KV_store.pp_write_error e);
              Lwt.fail_with "store not writable")
      | Ok (Some _) -> Lwt.return_unit
      | Error e ->
          Log.err (fun m -> m "couldn't read from store %a" KV_store.pp_error e);
          Lwt.fail_with "store not readable"
    in
    let* platform =
      write_platform internal_stack "PLATFORM-DATA" >>= function
      | Error e ->
          Log.err (fun m ->
              m "couldn't retrieve platform data: %a" pp_platform_err e);
          Lwt.fail_with "failed to retrieve platform data from platform"
      | Ok "" -> (
          match Args.device_key () with
          | None -> Lwt.return dummy_platform
          | Some x -> (
              Log.info (fun m -> m "device key set with --device-key option");
              match Base64.decode x with
              | Ok _ ->
                  Lwt.return
                    { dummy_platform with Keyfender.Json.deviceKey = x }
              | Error _ ->
                  Lwt.fail_with "device key is not a valid Base64 string"))
      | Ok data -> (
          match Keyfender.Json.parse_platform_data data with
          | Error e ->
              Log.err (fun m ->
                  m "couldn't parse platform data: %s\ndata: %s" e data);
              Lwt.fail_with "failed to parse platform data from platform"
          | Ok x -> Lwt.return x)
    in
    let* update_key =
      Update_key.get update_key_store (Mirage_kv.Key.v "key.pem") >>= function
      | Error e ->
          Log.err (fun m ->
              m "couldn't retrieve update key: %a" Update_key.pp_error e);
          Lwt.fail_with "missing update key"
      | Ok data -> (
          match X509.Public_key.decode_pem data with
          | Ok (`RSA key) -> Lwt.return key
          | Ok _ ->
              Log.err (fun m ->
                  m "No RSA key from manufacturer. Contact manufacturer.");
              Lwt.fail_with "update key not in RSA format"
          | Error (`Msg m) -> Lwt.fail_with ("couldn't decode update key: " ^ m)
          )
    in
    let* hsm_state, mvar, res_mvar =
      Hsm.boot ~cache_settings ~platform update_key store
    in
    let setup_log stack log =
      Logs.set_level ~all:true (Some log.Keyfender.Json.logLevel);
      if Ipaddr.V4.compare log.Keyfender.Json.ipAddress Ipaddr.V4.any <> 0 then
        let reporter =
          let port = log.Keyfender.Json.port in
          Syslog.create stack ~hostname:"keyfender"
            (Ipaddr.V4 log.Keyfender.Json.ipAddress) ~port ()
        in
        Logs.set_reporter (Keyfender.Logs_sequence_number.reporter reporter)
      else
        let logs = Log_reporter.create () in
        Logs.set_reporter (Keyfender.Logs_sequence_number.reporter logs)
    and setup_http_listener http =
      let http_port = Args.http_port () in
      let tcp = `TCP http_port in
      let open Webserver in
      Log.info (fun f -> f "listening on %d/TCP for HTTP" http_port);
      http tcp @@ serve (redirect (Args.https_port ()))
    and setup_https_listener http certificates =
      match Tls.Config.server ~certificates () with
      | Error e -> assert false
      | Ok tls_cfg ->
          let https_port = Args.https_port () in
          let tls = `TLS (tls_cfg, `TCP https_port) in
          let open Webserver in
          Log.info (fun f -> f "listening on %d/TCP for HTTPS" https_port);
          http tls @@ serve @@ opt_static_file assets @@ dispatch hsm_state
    and write_to_platform cmd =
      write_platform internal_stack (Hsm.cb_to_string cmd) >|= function
      | Ok _ -> ()
      | Error e ->
          Logs.err (fun m ->
              m "error %a communicating with platform" pp_platform_err e)
    in
    let reconfigure_network cidr gateway =
      let* () = Ext_reconfigurable_stack.setup ext_stack ?gateway cidr in
      let stack = Ext_reconfigurable_stack.stack ext_stack in
      let http = Srv.listen stack in
      Lwt.async (fun () -> setup_http_listener http);
      Lwt.async (fun () -> setup_https_listener http (Hsm.own_cert hsm_state));
      let* log = Hsm.Config.log hsm_state in
      setup_log stack log;
      Lwt.return http
    in
    let rec handle_cb http =
      Lwt_mvar.take mvar >>= function
      | Hsm.Log log ->
          setup_log (Ext_reconfigurable_stack.stack ext_stack) log;
          (handle_cb [@tailcall]) http
      | (Hsm.Shutdown | Hsm.Reboot | Hsm.Factory_reset) as cmd ->
          let* () = Ext_reconfigurable_stack.disconnect ext_stack in
          write_to_platform cmd
      | Hsm.Tls certificates ->
          Lwt.async (fun () -> setup_https_listener http certificates);
          (handle_cb [@tailcall]) http
      | Hsm.Network (cidr, gateway) ->
          let* () = Ext_reconfigurable_stack.disconnect ext_stack in
          let* http = reconfigure_network cidr gateway in
          (handle_cb [@tailcall]) http
      | Hsm.Update (blocks, stream) as cmd ->
          let additional_data write =
            let* r = write (string_of_int blocks ^ "\n") in
            Lwt_stream.fold_s
              (fun chunk acc ->
                match acc with
                | Ok () -> write chunk
                | Error e -> Lwt.return (Error e))
              stream r
          in
          let* () =
            write_platform ~additional_data internal_stack
              (Hsm.cb_to_string cmd)
            >>= function
            | Ok _ -> Lwt_mvar.put res_mvar (Ok ())
            | Error e ->
                Lwt_mvar.put res_mvar
                  (Error (Fmt.to_to_string pp_platform_err e))
          in
          (handle_cb [@tailcall]) http
      | Hsm.Commit_update as cmd ->
          let* () =
            write_platform internal_stack (Hsm.cb_to_string cmd) >>= function
            | Ok _ -> Lwt_mvar.put res_mvar (Ok ())
            | Error e ->
                Lwt_mvar.put res_mvar
                  (Error (Fmt.to_to_string pp_platform_err e))
          in
          (handle_cb [@tailcall]) http
    in
    let* ip, net, gateway = Hsm.network_configuration hsm_state in
    let cidr = Ipaddr.V4.Prefix.(make (bits net) ip) in
    let* () =
      if not Conf_args.no_platform then (
        (* wait for S-Net to startup *)
        let delay = 4 in
        Log.info (fun m ->
            m "Waiting %n seconds to make sure S-Net is up" delay);
        Mirage_sleep.ns (Duration.of_sec delay))
      else Lwt.return_unit
    in
    let* http = reconfigure_network cidr gateway in
    (match conf_args.memtrace_port with
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
                let tracer =
                  Memtrace.start_tracing ~context:None ~sampling_rate:1e-4 f
                in
                Lwt.async (fun () ->
                    Ext_reconfigurable_stack.Stack.TCP.read f >|= fun _ ->
                    Logs.warn (fun m -> m "tracing read returned, closing");
                    Memtrace.stop_tracing tracer);
                Lwt.return_unit));
    handle_cb http
end
