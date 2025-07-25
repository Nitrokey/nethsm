(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Lwt.Infix

(* unencrypted configuration store *)
(* contains everything that is needed for booting *)
module Make (KV : Kv_ext.RW) = struct
  let config_prefix = "config"

  type _ k =
    | Unlock_salt : string k
    | Certificate : (X509.Certificate.t * X509.Certificate.t list) k
    | Private_key : X509.Private_key.t k
    | Version : Version.t k
    | Ip_config : (Ipaddr.V4.t * Ipaddr.V4.Prefix.t * Ipaddr.V4.t option) k
    | Backup_salt : string k
    | Backup_key : string k
    | Log_config : (Ipaddr.V4.t * int * Logs.level) k
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
    | Private_key -> "private-key"
    | Version -> "version"
    | Ip_config -> "ip-config"
    | Backup_salt -> "backup-salt"
    | Backup_key -> "backup-key"
    | Log_config -> "log-config"
    | Time_offset -> "time-offset"
    | Unattended_boot -> "unattended-boot"

  let to_string : type a. a k -> a -> string =
   fun k v ->
    match (k, v) with
    | Unlock_salt, salt -> salt
    | Certificate, (server, chain) ->
        (* maybe upstream/extend X509.Certificate *)
        let encode_one crt =
          let data = X509.Certificate.encode_der crt in
          let l = String.length data in
          let buf = Bytes.create (l + 4) in
          Bytes.set_int32_be buf 0 (Int32.of_int l);
          Bytes.blit_string data 0 buf 4 l;
          Bytes.unsafe_to_string buf
        in
        String.concat "" (List.map encode_one (server :: chain))
    | Private_key, key ->
        (* TODO encode_der (x509 0.8.1) *)
        X509.Private_key.encode_pem key
    | Version, v -> Version.to_string v
    | Ip_config, (ip, prefix, route) ->
        let route' = match route with None -> Ipaddr.V4.any | Some x -> x in
        String.concat ""
          [
            Ipaddr.V4.to_octets route';
            Ipaddr.V4.to_octets ip;
            Ipaddr.V4.to_octets (Ipaddr.V4.Prefix.netmask prefix);
          ]
    | Backup_salt, s -> s
    | Backup_key, s -> s
    | Log_config, (ip, port, level) ->
        let port_cs = Bytes.create 2 in
        Bytes.set_uint16_be port_cs 0 port;
        String.concat ""
          [
            Ipaddr.V4.to_octets ip;
            Bytes.unsafe_to_string port_cs;
            Logs.level_to_string (Some level);
          ]
    | Time_offset, span -> (
        match Ptime.Span.to_int_s span with
        | Some s -> string_of_int s
        | None -> "0")
    | Unattended_boot, b -> if b then "1" else "0"

  let of_string : type a. a k -> string -> (a, [> `Msg of string ]) result =
   fun key data ->
    let open Rresult.R.Infix in
    let guard p err = if p then Ok () else Error (`Msg err) in
    match key with
    | Unlock_salt -> Ok data
    | Certificate -> (
        let rec decode data acc =
          let total = String.length data in
          if total = 0 then Ok (List.rev acc)
          else
            guard (total >= 4) "invalid data (no length field)" >>= fun () ->
            let len =
              Option.get (Int32.unsigned_to_int (String.get_int32_be data 0))
            in
            guard (total - 4 >= len) "invalid data (too short)" >>= fun () ->
            match X509.Certificate.decode_der (String.sub data 4 len) with
            | Ok cert ->
                decode
                  (String.sub data (len + 4) (total - len - 4))
                  (cert :: acc)
            | Error e -> Error e
        in
        match decode data [] with
        | Ok (server :: chain) -> Ok (server, chain)
        | Ok [] -> Error (`Msg "empty certificate chain")
        | Error e -> Error e)
    | Private_key -> X509.Private_key.decode_pem data
    | Version -> Version.of_string data
    | Ip_config ->
        guard
          (String.length data = 12)
          "expected exactly 12 bytes for IP configuration"
        >>= fun () ->
        let route_str, ip_str, netmask_str =
          (String.sub data 0 4, String.sub data 4 4, String.sub data 8 4)
        in
        Ipaddr.V4.of_octets route_str >>= fun route ->
        Ipaddr.V4.of_octets ip_str >>= fun address ->
        Ipaddr.V4.of_octets netmask_str >>= fun netmask ->
        Ipaddr.V4.Prefix.of_netmask ~netmask ~address >>= fun prefix ->
        (if Ipaddr.V4.compare route Ipaddr.V4.any = 0 then Ok None
         else if Ipaddr.V4.Prefix.mem route prefix then Ok (Some route)
         else Error (`Msg "route not on local network"))
        >>| fun route' -> (address, prefix, route')
    | Backup_salt -> Ok data
    | Backup_key -> Ok data
    | Log_config -> (
        let ip, port, level =
          ( String.sub data 0 4,
            String.sub data 4 2,
            String.sub data 6 (String.length data - 6) )
        in
        Ipaddr.V4.of_octets ip >>= fun ip ->
        let port = String.get_uint16_be port 0 in
        match Logs.level_of_string level with
        | Error (`Msg msg) -> Error (`Msg msg)
        | Ok None -> Error (`Msg "invalid log level")
        | Ok (Some level) -> Ok (ip, port, level))
    | Time_offset -> (
        try Ok (Ptime.Span.of_int_s (int_of_string data))
        with Failure _ -> Error (`Msg "invalid time offset"))
    | Unattended_boot -> (
        match data with
        | "0" -> Ok false
        | "1" -> Ok true
        | x -> Rresult.R.error_msgf "unexpected unattended boot value: %s" x)

  let key_path key = Mirage_kv.Key.(add (v config_prefix) (name key))

  let pp_error ppf = function
    | `Kv e -> KV.pp_error ppf e
    | `Msg msg -> Fmt.string ppf msg

  let get kv key =
    KV.get kv (key_path key) >|= function
    | Ok data -> of_string key data
    | Error e -> Error (`Kv e)

  let get_opt kv key =
    get kv key >|= function
    | Error (`Kv (`Not_found _)) -> Ok None
    | Ok data -> Ok (Some data)
    | Error e -> Error e

  let batch = KV.batch

  let set kv key value =
    let data = to_string key value in
    KV.set kv (key_path key) data

  let remove kv key = KV.remove kv (key_path key)
  let digest kv key = KV.digest kv (key_path key)
end
