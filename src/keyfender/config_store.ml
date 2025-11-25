(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Lwt.Infix

(* unencrypted configuration store *)
(* contains everything that is needed for booting *)
module Make (KV : Kv_ext.RW) = struct
  let config_prefix device_id = device_id ^ "/config"

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

  let is_global_config : type a. a k -> bool = function
    | Version (* the store version is for the whole cluster *)
    | Cluster_CA (* the root CA must be shared to maintain communication *) ->
        true
    | Time_offset (* offset might be different for different hardware *)
    | Unlock_salt | Certificate | Private_key | Ip_config | Backup_salt
    | Backup_key | Log_config | Unattended_boot ->
        false

  let key_path device_id key =
    let device_id = if is_global_config key then "" else device_id in
    Mirage_kv.Key.(add (v (config_prefix device_id)) (name key))

  let pp_error ppf = function
    | `Kv e -> KV.pp_error ppf e
    | `Kv_write e -> KV.pp_write_error ppf e
    | `Msg msg -> Fmt.string ppf msg

  type t = { kv : KV.t; device_id : string }

  let get t key =
    KV.get t.kv (key_path t.device_id key) >|= function
    | Ok data -> of_string key data
    | Error e -> Error (`Kv e)

  let get_opt t key =
    get t key >|= function
    | Error (`Kv (`Not_found _)) -> Ok None
    | Ok data -> Ok (Some data)
    | Error e -> Error e

  let batch t f = KV.batch t.kv (fun b -> f { t with kv = b })

  let set t key value =
    let data = to_string key value in
    KV.set t.kv (key_path t.device_id key) data

  let remove t key = KV.remove t.kv (key_path t.device_id key)
  let digest t key = KV.digest t.kv (key_path t.device_id key)
  let connect kv device_id = { kv; device_id }

  let migrate_v0_v1 t =
    let old = { t with device_id = "" } in
    let just_move (type a) (k : a k) =
      if is_global_config k then Lwt.return (Ok ())
      else
        get_opt old k >>= function
        | Error e -> Lwt.return (Error e)
        | Ok None -> Lwt.return (Ok ())
        | Ok (Some data) ->
            set t k data >|= fun r -> Result.map_error (fun e -> `Kv_write e) r
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
                  set t Log_config new_config
                  |> Lwt_result.map_error (fun e -> `Kv_write e)))
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
            set t Ip_config new_config
            |> Lwt_result.map_error (fun e -> `Kv_write e)
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
    migrate_ip_config () >>= fun () ->
    set t Version Version.V1 |> Lwt_result.map_error (fun e -> `Kv_write e)
end
