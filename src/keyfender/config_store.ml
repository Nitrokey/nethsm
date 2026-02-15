(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Lwt.Infix

(* unencrypted configuration store *)
(* contains everything that is needed for booting *)
module Make (KV : Kv_ext.RW) = struct
  let local_config_prefix device_id = "local/" ^ device_id ^ "/config"
  let global_config_prefix = "config"

  type _ k =
    | Unlock_salt : string k
    | Certificate : (X509.Certificate.t * X509.Certificate.t list) k
    | Cluster_CA : X509.Certificate.t k
    | Private_key : X509.Private_key.t k
    | Version : Version.t k
    | Ip_config : Json.network k
    | Backup_salt : string k
    | Backup_key : string k
    | Log_config : Json.log k
    | Time_offset : Ptime.span k
    | Unattended_boot : bool k

  module K = struct
    type 'a t = 'a k

    let compare : type a b. a t -> b t -> (a, b) Gmap.Order.t =
     fun t t' ->
      let open Gmap.Order in
      match (t, t') with
      | Unlock_salt, Unlock_salt -> Eq
      | Unlock_salt, _ -> Lt
      | _, Unlock_salt -> Gt
      | Certificate, Certificate -> Eq
      | Certificate, _ -> Lt
      | _, Certificate -> Gt
      | Cluster_CA, Cluster_CA -> Eq
      | Cluster_CA, _ -> Lt
      | _, Cluster_CA -> Gt
      | Private_key, Private_key -> Eq
      | Private_key, _ -> Lt
      | _, Private_key -> Gt
      | Version, Version -> Eq
      | Version, _ -> Lt
      | _, Version -> Gt
      | Ip_config, Ip_config -> Eq
      | Ip_config, _ -> Lt
      | _, Ip_config -> Gt
      | Backup_salt, Backup_salt -> Eq
      | Backup_salt, _ -> Lt
      | _, Backup_salt -> Gt
      | Backup_key, Backup_key -> Eq
      | Backup_key, _ -> Lt
      | _, Backup_key -> Gt
      | Log_config, Log_config -> Eq
      | Log_config, _ -> Lt
      | _, Log_config -> Gt
      | Time_offset, Time_offset -> Eq
      | Time_offset, _ -> Lt
      | _, Time_offset -> Gt
      | Unattended_boot, Unattended_boot -> Eq
    (* | Unattended_boot, _ -> Lt | _, Unattended_boot -> Gt *)
  end

  include Gmap.Make (K)

  let name : type a. a k -> string = function
    | Unlock_salt -> "unlock-salt"
    | Certificate -> "certificate"
    | Cluster_CA -> "cluster-ca"
    | Private_key -> "private-key"
    | Version -> "version"
    | Ip_config -> "ip-config"
    | Backup_salt -> "backup-salt"
    | Backup_key -> "backup-key"
    | Log_config -> "log-config"
    | Time_offset -> "time-offset"
    | Unattended_boot -> "unattended-boot"

  let encode_one_cert crt =
    let data = X509.Certificate.encode_der crt in
    let l = String.length data in
    let buf = Bytes.create (l + 4) in
    Bytes.set_int32_be buf 0 (Int32.of_int l);
    Bytes.blit_string data 0 buf 4 l;
    Bytes.unsafe_to_string buf

  let to_string : type a. a k -> a -> string =
   fun k v ->
    match (k, v) with
    | Unlock_salt, salt -> salt
    | Certificate, (server, chain) ->
        (* maybe upstream/extend X509.Certificate *)
        String.concat "" (List.map encode_one_cert (server :: chain))
    | Cluster_CA, ca -> encode_one_cert ca
    | Private_key, key ->
        (* TODO encode_der (x509 0.8.1) *)
        X509.Private_key.encode_pem key
    | Version, v -> Version.to_string v
    | Ip_config, (network : Json.network) ->
        Json.network_to_yojson network |> Yojson.Safe.to_string
    | Backup_salt, s -> s
    | Backup_key, s -> s
    | Log_config, (log : Json.log) ->
        Json.log_to_yojson log |> Yojson.Safe.to_string
    | Time_offset, span -> (
        match Ptime.Span.to_int_s span with
        | Some s -> string_of_int s
        | None -> "0")
    | Unattended_boot, b -> if b then "1" else "0"

  let guard p err = if p then Ok () else Error (`Msg err)

  let decode_one_cert data =
    let total = String.length data in
    let open Rresult.R.Infix in
    guard (total >= 4) "invalid data (no length field)" >>= fun () ->
    let len = Option.get (Int32.unsigned_to_int (String.get_int32_be data 0)) in
    guard (total - 4 >= len) "invalid data (too short)" >>= fun () ->
    X509.Certificate.decode_der (String.sub data 4 len)

  let of_string : type a. a k -> string -> (a, [> `Msg of string ]) result =
   fun key data ->
    match key with
    | Unlock_salt -> Ok data
    | Certificate -> (
        let rec decode data acc =
          let total = String.length data in
          if total = 0 then Ok (List.rev acc)
          else
            match decode_one_cert data with
            | Ok cert ->
                let len =
                  Option.get
                    (Int32.unsigned_to_int (String.get_int32_be data 0))
                in
                decode
                  (String.sub data (len + 4) (total - len - 4))
                  (cert :: acc)
            | Error e -> Error e
        in
        match decode data [] with
        | Ok (server :: chain) -> Ok (server, chain)
        | Ok [] -> Error (`Msg "empty certificate chain")
        | Error e -> Error e)
    | Cluster_CA -> decode_one_cert data
    | Private_key -> X509.Private_key.decode_pem data
    | Version -> Version.of_string data
    | Ip_config ->
        Json.decode Json.network_of_yojson data
        |> Result.map_error (fun s -> `Msg s)
    | Backup_salt -> Ok data
    | Backup_key -> Ok data
    | Log_config ->
        Json.decode Json.log_of_yojson data
        |> Result.map_error (fun s -> `Msg s)
    | Time_offset -> (
        try Ok (Ptime.Span.of_int_s (int_of_string data))
        with Failure _ -> Error (`Msg "invalid time offset"))
    | Unattended_boot -> (
        match data with
        | "0" -> Ok false
        | "1" -> Ok true
        | x -> Rresult.R.error_msgf "unexpected unattended boot value: %s" x)

  (* global configs are shared by all nodes in a cluster
     - they are stored in /config/xxx while local ones are in /DEVICE-ID/config/xxx
     - they cannot be encrypted with device-specific keys *)
  let is_global_config : type a. a k -> bool = function
    | Version (* the store version is for the whole cluster *)
    | Cluster_CA (* the root CA must be shared to maintain communication *)
    | Backup_key | Backup_salt ->
        true
    | Time_offset (* offset might be different for different hardware *)
    | Unlock_salt | Certificate | Private_key | Ip_config | Log_config
    | Unattended_boot ->
        false

  (* "early" configs cannot be encrypted with the domain key, as they are
     needed to unlock the domain key. They are stored with a derivative of the
     device key *)
  let is_needed_before_unlock : type a. a k -> bool = function
    | Unlock_salt (* needed during unlock *)
    | Certificate | Private_key (* needed for HTTPS *)
    | Ip_config (* needed for clients to talk to us *)
    | Log_config (* used at boot, though could be late if needed *)
    | Unattended_boot (* needed at boot *)
    | Time_offset (* needed by (at least) web server *)
    | Version (* needed immediately at boot for migrations *) ->
        true
    | Backup_salt | Backup_key (* not used in Unprovisioned mode *)
    | Cluster_CA (* needed by etcd but cached on platform *) ->
        false

  let key_path device_id key =
    let prefix =
      if is_global_config key then global_config_prefix
      else local_config_prefix device_id
    in
    Mirage_kv.Key.(add (v prefix) (name key))

  let pp_error ppf = function
    | `Kv e -> KV.pp_error ppf e
    | `Kv_write e -> KV.pp_write_error ppf e
    | `Msg msg -> Fmt.string ppf msg
    | `Missing_domain_key -> Fmt.string ppf "cannot read this key before unlock"

  type write_error =
    [ `Kv of KV.write_error | `Msg of string | `Missing_domain_key ]

  type t = {
    kv : KV.t;
    device_id : string;
    (* store extended version instead? *)
    config_device_key : string;
    mutable config_domain_key : string option;
    force_disable_decryption : bool;
        (* used exclusively during migration from unencrypted to encrypted *)
    mutable post_migration_writes :
      (unit -> (unit, write_error) Lwt_result.t) list;
  }

  module type Codec = sig
    val encrypt : _ k -> string -> string
    val decrypt : _ k -> string -> (string, [> `Msg of string ]) result
  end

  let noop_codec =
    (module struct
      let encrypt : type a. a k -> string -> string =
        (* safety check so we don't misuse this codec *)
        function
        | Version -> fun x -> x
        | _ ->
            fun _ ->
              failwith "can never write unencrypted data other than Version"

      let decrypt _ x = Ok x
    end : Codec)

  let single_codec ?(device_id = "") encryption_key =
    (module struct
      let adata k = key_path device_id k |> Mirage_kv.Key.to_string

      let encrypt k data =
        let adata = adata k in
        let key = Crypto.GCM.of_secret encryption_key in
        Crypto.encrypt Mirage_crypto_rng.generate ~key ~adata data

      let decrypt k data =
        let adata = adata k in
        let key = Crypto.GCM.of_secret encryption_key in
        Rresult.R.error_to_msg ~pp_error:Crypto.pp_decryption_error
          (Crypto.decrypt ~key ~adata data)
    end : Codec)

  let select_codec t key =
    let locality = if is_global_config key then `Global else `Local in
    let timing = if is_needed_before_unlock key then `Early else `Late in
    match (locality, timing, t.config_domain_key) with
    | `Global, `Early, _ -> Ok noop_codec
    | _, `Late, None -> Error `Missing_domain_key
    | `Local, `Early, _ ->
        Ok (single_codec ~device_id:t.device_id t.config_device_key)
    | `Global, `Late, Some dom_key -> Ok (single_codec dom_key)
    | `Local, `Late, Some dom_key ->
        Ok (single_codec ~device_id:t.device_id dom_key)

  let get t key =
    let ( let* ) = Result.bind in
    KV.get t.kv (key_path t.device_id key) >|= function
    | Ok data ->
        let* c =
          if t.force_disable_decryption then Ok noop_codec
          else select_codec t key
        in
        let module C = (val c) in
        let* decrypted = C.decrypt key data in
        of_string key decrypted
    | Error e -> Error (`Kv e)

  let get_opt t key =
    get t key >|= function
    | Error (`Kv (`Not_found _)) -> Ok None
    | Ok data -> Ok (Some data)
    | Error e -> Error e

  let exists t key =
    let key = key_path t.device_id key in
    KV.exists t.kv key >|= function
    | Ok (Some _) -> Ok true
    | Ok None -> Ok false
    | Error e -> Error (`Kv e)

  let batch t f = KV.batch t.kv (fun b -> f { t with kv = b })

  let set t key value =
    let ( let* ) = Lwt_result.bind in
    let* c = select_codec t key |> Lwt_result.lift in
    let module C = (val c) in
    let data = to_string key value |> C.encrypt key in
    KV.set t.kv (key_path t.device_id key) data >|= function
    | Ok () -> Ok ()
    | Error e -> Error (`Kv e)

  let pp_write_error ppf = function
    | `Kv e -> KV.pp_write_error ppf e
    | `Msg msg -> Fmt.string ppf msg
    | `Missing_domain_key ->
        Fmt.string ppf "cannot write this key before unlock"

  let remove t key = KV.remove t.kv (key_path t.device_id key)
  let digest t key = KV.digest t.kv (key_path t.device_id key)

  let connect kv ~device_id ~device_key =
    let extend k t = Digestif.SHA256.(digest_string (k ^ t) |> to_raw_string) in
    let config_device_key = extend device_key "early_config_store" in
    {
      kv;
      device_id;
      config_device_key;
      config_domain_key = None;
      force_disable_decryption = false;
      post_migration_writes = [];
    }

  let provide_config_domain_key t k =
    t.config_domain_key <- Some k;
    Lwt_list.fold_left_s
      (fun acc op ->
        let open Lwt_result.Infix in
        Lwt.return acc >>= fun () -> op ())
      (Ok ()) t.post_migration_writes

  let forget_config_domain_key t = t.config_domain_key <- None

  type local_backup = {
    unlock_salt : string option;
    certificate : (X509.Certificate.t * X509.Certificate.t list) option;
    private_key : X509.Private_key.t option;
    ip_config : Json.network option;
    backup_salt : string option;
    backup_key : string option;
    log_config : Json.log option;
    time_offset : Ptime.span option;
    unattended_boot : bool option;
  }

  let backup_local_config t =
    let ( let* ) = Lwt_result.bind in
    let get_opt' t k =
      let open Lwt.Infix in
      get_opt t k >|= function
      | Ok x -> Ok x
      | Error e ->
          Logs.warn (fun f -> f "could not read key %s: %a" (name k) pp_error e);
          Ok None
    in

    let* unlock_salt = get_opt' t Unlock_salt in
    let* certificate = get_opt' t Certificate in
    let* private_key = get_opt' t Private_key in
    let* ip_config = get_opt' t Ip_config in
    let* backup_salt = get_opt' t Backup_salt in
    let* backup_key = get_opt' t Backup_key in
    let* log_config = get_opt' t Log_config in
    let* time_offset = get_opt' t Time_offset in
    let* unattended_boot = get_opt' t Unattended_boot in
    Lwt_result.return
      {
        unlock_salt;
        certificate;
        private_key;
        ip_config;
        backup_salt;
        backup_key;
        log_config;
        time_offset;
        unattended_boot;
      }

  let restore_local_config t (b : local_backup) =
    let ( let* ) = Lwt_result.bind in
    let set_opt k = function
      | None -> Lwt_result.return ()
      | Some v -> set t k v
    in
    let* () = set_opt Unlock_salt b.unlock_salt in
    let* () = set_opt Certificate b.certificate in
    let* () = set_opt Private_key b.private_key in
    let* () = set_opt Ip_config b.ip_config in
    let* () = set_opt Backup_salt b.backup_salt in
    let* () = set_opt Backup_key b.backup_key in
    let* () = set_opt Log_config b.log_config in
    let* () = set_opt Time_offset b.time_offset in
    let* () = set_opt Unattended_boot b.unattended_boot in
    Lwt_result.return ()

  let migrate_v0_v1 t =
    let old = { t with device_id = ""; force_disable_decryption = true } in
    let set_or_delay t k data =
      let go () = set t k data in
      let wrap_write_error = function
        | Error (`Kv e) -> Error (`Kv_write e)
        | Error (`Msg m) -> Error (`Msg m)
        | Error `Missing_domain_key ->
            t.post_migration_writes <- go :: t.post_migration_writes;
            Ok ()
        | Ok () -> Ok ()
      in
      go () >|= wrap_write_error
    in
    let just_move (type a) (k : a k) =
      if is_global_config k then Lwt.return (Ok ())
      else
        get_opt old k >>= function
        | Error e -> Lwt.return (Error e)
        | Ok None -> Lwt.return (Ok ())
        | Ok (Some data) -> set_or_delay t k data
    in
    let migrate_log_config () =
      KV.get t.kv (key_path "" Log_config) >>= function
      | Error (`Not_found _) -> Lwt.return (Ok ())
      | Error e -> Lwt.return (Error (`Kv e))
      | Ok data -> (
          let ip, port, level =
            ( String.sub data 0 4,
              String.sub data 4 2,
              String.sub data 6 (String.length data - 6) )
          in
          match Ipaddr.V4.of_octets ip with
          | Error e -> Lwt.return (Error e)
          | Ok ip -> (
              let port = String.get_uint16_be port 0 in
              match Logs.level_of_string level with
              | Error (`Msg msg) -> Lwt.return (Error (`Msg msg))
              | Ok None -> Lwt.return (Error (`Msg "invalid log level"))
              | Ok (Some level) ->
                  let new_config =
                    {
                      Json.ipAddress = Some (Ipaddr.V4 ip);
                      logLevel = level;
                      port;
                    }
                  in
                  set_or_delay t Log_config new_config))
    in
    let migrate_ip_config () =
      KV.get t.kv (key_path "" Ip_config) >>= function
      | Error (`Not_found _) -> Lwt.return (Ok ())
      | Error e -> Lwt.return (Error (`Kv e))
      | Ok data -> (
          let route_str, ip_str, netmask_str =
            (String.sub data 0 4, String.sub data 4 4, String.sub data 8 4)
          in
          try
            let route = Ipaddr.V4.of_octets_exn route_str in
            let address = Ipaddr.V4.of_octets_exn ip_str in
            let netmask = Ipaddr.V4.of_octets_exn netmask_str in
            let prefix = Ipaddr.V4.Prefix.of_netmask_exn ~netmask ~address in
            let new_config =
              {
                Json.ipv4 = { cidr = prefix; gateway = Some route };
                ipv6 = None;
              }
            in
            set_or_delay t Ip_config new_config
          with Ipaddr.Parse_error (msg, _) -> Lwt.return (Error (`Msg msg)))
    in

    let open Lwt_result.Infix in
    just_move Ip_config >>= fun () ->
    just_move Log_config >>= fun () ->
    just_move Time_offset >>= fun () ->
    just_move Unlock_salt >>= fun () ->
    just_move Certificate >>= fun () ->
    just_move Private_key >>= fun () ->
    just_move Backup_salt >>= fun () ->
    just_move Backup_key >>= fun () ->
    just_move Unattended_boot >>= fun () ->
    migrate_log_config () >>= fun () ->
    migrate_ip_config () >>= fun () -> set_or_delay t Version Version.V1
end
