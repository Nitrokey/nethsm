(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Lwt.Infix

(* unencrypted configuration store *)
(* contains everything that is needed for booting *)
module Make (KV : Kv_ext.Platform) = struct
  let local_config_prefix device_id = "local/" ^ device_id ^ "/config"
  let global_config_prefix = "config"

  type migration = Migration of (string * string) [@@deriving yojson]
  type migrations = migration list [@@deriving yojson]
  (* list of string representations of K-V to write on unlock. we don't use k
     recursively to avoid GADT issues and unwated recursion *)

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
    | Pending_unlock_migrations : migrations k
    | Restore_in_progress : unit k (* if key exists, then restore in progress *)

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
      | Unattended_boot, _ -> Lt
      | _, Unattended_boot -> Gt
      | Pending_unlock_migrations, Pending_unlock_migrations -> Eq
      | Pending_unlock_migrations, _ -> Lt
      | _, Pending_unlock_migrations -> Gt
      | Restore_in_progress, Restore_in_progress -> Eq
    (* | Restore_in_progress, _ -> Lt | _, Restore_in_progress -> Gt *)
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
    | Pending_unlock_migrations -> "pending-unlock-migrations"
    | Restore_in_progress -> "restore-in-progress"

  type packed_k = P : _ k -> packed_k

  let of_name : string -> packed_k option = function
    | "unlock-salt" -> Some (P Unlock_salt)
    | "certificate" -> Some (P Certificate)
    | "cluster-ca" -> Some (P Cluster_CA)
    | "private-key" -> Some (P Private_key)
    | "version" -> Some (P Version)
    | "ip-config" -> Some (P Ip_config)
    | "backup-salt" -> Some (P Backup_salt)
    | "backup-key" -> Some (P Backup_key)
    | "log-config" -> Some (P Log_config)
    | "time-offset" -> Some (P Time_offset)
    | "unattended-boot" -> Some (P Unattended_boot)
    | "pending-unlock-migrations" -> Some (P Pending_unlock_migrations)
    | "restore-in-progress" -> Some (P Restore_in_progress)
    | _ -> None

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
    | Pending_unlock_migrations, l ->
        migrations_to_yojson l |> Yojson.Safe.to_string
    | Restore_in_progress, () -> ""

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
    | Pending_unlock_migrations ->
        Json.decode migrations_of_yojson data
        |> Result.map_error (fun s -> `Msg s)
    | Restore_in_progress -> Ok ()

  (* global configs are shared by all nodes in a cluster
     - they are stored in /config/xxx while local ones are in /local/DEVICE-ID/config/xxx
     - they cannot be encrypted with device-specific keys *)
  let is_global_config : type a. a k -> bool = function
    | Version (* the store version is for the whole cluster *)
    | Cluster_CA (* the root CA must be shared to maintain communication *)
    | Backup_key | Backup_salt | Restore_in_progress ->
        true
    | Time_offset (* offset might be different for different hardware *)
    | Unlock_salt | Certificate | Private_key | Ip_config | Log_config
    | Unattended_boot | Pending_unlock_migrations ->
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
    | Version (* needed immediately at boot for migrations *)
    | Restore_in_progress (* no associated value *)
    | Pending_unlock_migrations
      (* needed at unlock, could be "late" but makes sense to be device-encrypted *)
      ->
        true
    | Backup_salt | Backup_key (* not used in Unprovisioned mode *)
    | Cluster_CA (* needed by etcd but cached on platform *) ->
        false

  type error = [ `Kv of KV.error | `Msg of string | `Missing_domain_key ]

  let pp_error ppf = function
    | `Kv e -> KV.pp_error ppf e
    | `Kv_write e -> KV.pp_write_error ppf e
    | `Msg msg -> Fmt.string ppf msg
    | `Missing_domain_key ->
        Fmt.string ppf "cannot access this key before unlock"

  type write_error =
    [ error | `Kv_write of KV.write_error | `Restore_in_progress ]

  let pp_write_error ppf = function
    | #error as e -> pp_error ppf e
    | `Kv_write e -> KV.pp_write_error ppf e
    | `Restore_in_progress ->
        Fmt.string ppf "cannot restore while restore already in progress"

  type t = {
    kv : KV.t;
    device_id : string;
    config_device_key : string;
    config_domain_key : string option ref;
    migration_in_progress : bool;
        (* used exclusively during migration from unencrypted to encrypted *)
  }

  let key_path' ~migration_in_progress ~device_id key =
    let prefix =
      if is_global_config key || migration_in_progress then global_config_prefix
      else local_config_prefix device_id
    in
    Mirage_kv.Key.(add (v prefix) (name key))

  let key_path t key =
    key_path' ~migration_in_progress:t.migration_in_progress
      ~device_id:t.device_id key

  module type Codec = sig
    val encrypt : _ k -> string -> string
    val decrypt : _ k -> string -> (string, [> `Msg of string ]) result
  end

  let noop_codec =
    (module struct
      let encrypt : type a. a k -> string -> string =
        (* safety check so we don't misuse this codec *)
        function
        | Version | Restore_in_progress -> fun x -> x
        | _ ->
            fun _ ->
              failwith
                "can never write unencrypted data other than Version or \
                 Restore_in_progress"

      let decrypt _ x = Ok x
    end : Codec)

  let single_codec t encryption_key =
    (module struct
      let adata k = key_path t k |> Mirage_kv.Key.to_string

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
    match (locality, timing, !(t.config_domain_key)) with
    | `Global, `Early, _ -> Ok noop_codec
    | _, `Late, None -> Error `Missing_domain_key
    | `Local, `Early, _ -> Ok (single_codec t t.config_device_key)
    | `Global, `Late, Some dom_key ->
        Ok (single_codec { t with device_id = "" } dom_key)
    | `Local, `Late, Some dom_key -> Ok (single_codec t dom_key)

  let get t key =
    let ( let* ) = Result.bind in
    (* if we're reading from a V0 store, read all as global *)
    KV.get t.kv (key_path t key) >|= function
    | Ok data ->
        let* c =
          if t.migration_in_progress then Ok noop_codec else select_codec t key
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
    let key = key_path t key in
    KV.exists t.kv key >|= function
    | Ok (Some _) -> Ok true
    | Ok None -> Ok false
    | Error e -> Error (`Kv e)

  let batch t f = KV.batch t.kv (fun b -> f { t with kv = b })

  let set : type a. t -> a k -> a -> (unit, write_error) Lwt_result.t =
   fun t key value ->
    let ( let* ) = Lwt_result.bind in
    (* if trying to acquire restore-in-progress lock,
       force to atomically check that it is not set before *)
    let set_f t k v =
      match key with
      | Restore_in_progress ->
          let* ok =
            KV.atomic_set_if_no_restore t k v
            |> Lwt_result.map_error (fun e -> `Kv_write e)
          in
          if ok then Lwt_result.return ()
          else Lwt_result.fail `Restore_in_progress
      | _ -> KV.set t k v |> Lwt_result.map_error (fun e -> `Kv_write e)
    in
    let* c = select_codec t key |> Lwt_result.lift in
    let module C = (val c) in
    let data = to_string key value |> C.encrypt key in
    set_f t.kv (key_path t key) data

  let remove t key =
    KV.remove t.kv (key_path t key)
    |> Lwt_result.map_error (fun e -> `Kv_write e)

  let digest t key = KV.digest t.kv (key_path t key)
  let restore_in_progress t = exists t Restore_in_progress

  let apply_pending_unlock_migrations t =
    let ( let** ) = Lwt_result.bind in
    let** migrations_opt = get_opt t Pending_unlock_migrations in
    let apply_one t (Migration (k, v)) =
      match of_name k with
      | Some (P key) ->
          let** data = of_string key v |> Lwt_result.lift in
          let path = key_path t key in
          Logs.info (fun f -> f "migrating %a" Mirage_kv.Key.pp path);
          set t key data
      | None ->
          Lwt.return (Fmt.error_msg "invalid stored migration key: '%s'" k)
    in
    match migrations_opt with
    | None | Some [] -> Lwt_result.return ()
    | Some migrations ->
        Logs.info (fun f -> f "Applying post unlock migrations");
        batch t (fun t ->
            let** () =
              Lwt_list.fold_left_s
                (fun acc m ->
                  match acc with
                  | Ok () -> apply_one t m
                  | Error e -> Lwt.return (Error e))
                (Ok ()) migrations
            in
            remove t Pending_unlock_migrations)

  let make_migration k data =
    let data_string = to_string k data in
    let key_string = name k in
    Migration (key_string, data_string)

  let append_pending_unlock_migrations t new_migrations =
    let ( let** ) = Lwt_result.bind in
    let** migrations_opt = get_opt t Pending_unlock_migrations in
    let to_set =
      match migrations_opt with
      | None -> new_migrations
      | Some existing_migrations -> existing_migrations @ new_migrations
    in
    set t Pending_unlock_migrations to_set

  let connect kv ~device_id ~device_key =
    let extend k t = Digestif.SHA256.(digest_string (k ^ t) |> to_raw_string) in
    let config_device_key = extend device_key "early_config_store" in
    {
      kv;
      device_id;
      config_device_key;
      config_domain_key = ref None;
      migration_in_progress = false;
    }

  let provide_config_domain_key t k =
    t.config_domain_key := Some k;
    apply_pending_unlock_migrations t

  let forget_config_domain_key t = t.config_domain_key := None

  type local_backup = {
    unlock_salt : string option;
    certificate : (X509.Certificate.t * X509.Certificate.t list) option;
    private_key : X509.Private_key.t option;
    ip_config : Json.network option;
    log_config : Json.log option;
    time_offset : Ptime.span option;
    unattended_boot : bool option;
        (* pending_unlock_migrations has never a reason to be backed up itself *)
  }

  (* all keys that are domain-encrypted (global+late) *)
  type domain_encrypted_backup = {
    backup_key : string option;
    backup_salt : string option;
  }

  let clear_local_config t =
    let ( let* ) = Lwt_result.bind in
    let* () = remove t Unlock_salt in
    let* () = remove t Certificate in
    let* () = remove t Private_key in
    let* () = remove t Ip_config in
    let* () = remove t Log_config in
    let* () = remove t Time_offset in
    let* () = remove t Unattended_boot in
    let* () = remove t Pending_unlock_migrations in
    Lwt_result.return ()

  (* lenient: does not fail on error *)
  let get_opt' t k =
    let open Lwt.Infix in
    get_opt t k >|= function
    | Ok x -> Ok x
    | Error e ->
        Logs.warn (fun f -> f "could not read key %s: %a" (name k) pp_error e);
        Ok None

  (* partial = only backup unlock salt *)
  let backup_local_config ?(partial = false) t =
    let ( let* ) = Lwt_result.bind in

    let* unlock_salt = get_opt' t Unlock_salt in
    if partial then
      Lwt_result.return
        {
          unlock_salt;
          certificate = None;
          private_key = None;
          ip_config = None;
          log_config = None;
          time_offset = None;
          unattended_boot = None;
        }
    else
      let* certificate = get_opt' t Certificate in
      let* private_key = get_opt' t Private_key in
      let* ip_config = get_opt' t Ip_config in
      let* log_config = get_opt' t Log_config in
      let* time_offset = get_opt' t Time_offset in
      let* unattended_boot = get_opt' t Unattended_boot in
      Lwt_result.return
        {
          unlock_salt;
          certificate;
          private_key;
          ip_config;
          log_config;
          time_offset;
          unattended_boot;
        }

  let set_opt t k = function
    | None -> Lwt_result.return ()
    | Some v ->
        let dst = key_path t k in
        Logs.debug (fun f -> f "restoring %a" Mirage_kv.Key.pp dst);
        set t k v

  let restore_local_config t (b : local_backup) =
    let ( let* ) = Lwt_result.bind in
    batch t (fun t ->
        let* () = set_opt t Unlock_salt b.unlock_salt in
        let* () = set_opt t Certificate b.certificate in
        let* () = set_opt t Private_key b.private_key in
        let* () = set_opt t Ip_config b.ip_config in
        let* () = set_opt t Log_config b.log_config in
        let* () = set_opt t Time_offset b.time_offset in
        let* () = set_opt t Unattended_boot b.unattended_boot in
        Lwt_result.return ())

  (* Migrate stored v0 configs from:
      - v0 format (unencrypted, all global)
      to:
      - v1 format (encrypted, global or local)
      If partial: unlock move unlock salt.

      All keys are rewritten even if their path do not change, since we must
      encrypt the previously cleartext data.

      All keys that need domain key for encryption (backup salt, key, cluster
      CA) are only migrated later when the domain key is provided (at unlock)

      Returns the number of migrations that were deferred
  *)
  let migrate_v0_v1 ~partial t =
    let ( let** ) = Lwt_result.bind in
    Logs.info (fun m -> m "Migrating config store from V0 to V1");
    forget_config_domain_key t;
    (* assume the domain key is unavailable *)
    let old = { t with device_id = ""; migration_in_progress = true } in
    let deferred_migrations = ref [] in
    let after () =
      (* only actually persist the migrations at the end, so we don't write the
         same key multiple times *)
      append_pending_unlock_migrations t !deferred_migrations >|= function
      | Ok () -> Ok (List.length !deferred_migrations)
      | Error e -> Error e
    in
    batch t (fun t ->
        (* - if we can, set the key to the value
           - if we cannot because we need the domain key:
               - delete the key now
               - remember we need to write it after unlock
        *)
        let set_or_remove_and_delay ~remove t k data =
          let src = key_path old k in
          let dst = key_path t k in
          Logs.info (fun f ->
              f "migrating %a to %a" Mirage_kv.Key.pp src Mirage_kv.Key.pp dst);
          set t k data >>= function
          | Error `Restore_in_progress -> Lwt_result.return ()
          | Error `Missing_domain_key -> (
              Logs.info (fun f ->
                  f "need domain key to migrate %a! deferring to after unlock"
                    Mirage_kv.Key.pp src);
              remove () >|= function
              | Ok () ->
                  let new_migration = make_migration k data in
                  deferred_migrations := new_migration :: !deferred_migrations;
                  Ok ()
              | Error e -> Error e)
          | x -> Lwt.return x
        in
        let move k data =
          (* we are not allowed to delete and set the same key in the same
             transaction, so:
             - if the migration does not change the key, do not delete if now,
               and only delete it later if we have to defer the migration
            - if the migration changes the key, we can safely delete it now,
              and pass a no-op
          *)
          let do_remove () = remove old k in
          let src = key_path old k in
          let dst = key_path t k in
          let** remove =
            if Mirage_kv.Key.equal src dst then Lwt_result.return do_remove
            else
              let** () = do_remove () in
              Lwt_result.return (fun () -> Lwt_result.return ())
          in
          set_or_remove_and_delay ~remove t k data
        in
        let migrate_generic (type a) (k : a k) =
          get_opt old k >>= function
          | Error e -> Lwt.return (Error e)
          | Ok None -> Lwt.return (Ok ())
          | Ok (Some data) -> move k data
        in
        let migrate_log_config () =
          KV.get t.kv (key_path old Log_config) >>= function
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
                      move Log_config new_config))
        in
        let migrate_ip_config () =
          KV.get t.kv (key_path old Ip_config) >>= function
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
                let prefix =
                  Ipaddr.V4.Prefix.of_netmask_exn ~netmask ~address
                in
                let new_config =
                  {
                    Json.ipv4 = { cidr = prefix; gateway = Some route };
                    ipv6 = None;
                  }
                in
                move Ip_config new_config
              with Ipaddr.Parse_error (msg, _) ->
                Lwt.return (Error (`Msg msg)))
        in

        let open Lwt_result.Infix in
        migrate_generic Unlock_salt >>= fun () ->
        migrate_generic Backup_salt >>= fun () ->
        migrate_generic Backup_key >>= fun () ->
        if not partial then
          (* Ip_config and Log_config are migrated and moved at the same time *)
          migrate_generic Time_offset >>= fun () ->
          migrate_generic Certificate >>= fun () ->
          migrate_generic Private_key >>= fun () ->
          migrate_generic Unattended_boot >>= fun () ->
          migrate_log_config () >>= fun () ->
          migrate_ip_config () >>= fun () ->
          move Version Version.V1 >>= fun () -> after ()
        else after ())
end
