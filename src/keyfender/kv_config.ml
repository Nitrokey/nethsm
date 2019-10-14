open Lwt.Infix

(* unencrypted configuration store *)
module Make (KV : Mirage_kv_lwt.RW) = struct

  let config_prefix = "config"

  type _ k =
    | Unlock_salt : Cstruct.t k
    | Certificate : (X509.Certificate.t * X509.Certificate.t list) k
    | Private_key : X509.Private_key.t k
    | Version : Version.t k

  module K = struct
    type 'a t = 'a k

    let compare : type a b. a t -> b t -> (a, b) Gmap.Order.t = fun t t' ->
      let open Gmap.Order in
      match t, t' with
      | Unlock_salt, Unlock_salt -> Eq | Unlock_salt, _ -> Lt | _, Unlock_salt -> Gt
      | Certificate, Certificate -> Eq | Certificate, _ -> Lt | _, Certificate -> Gt
      | Private_key, Private_key -> Eq | Private_key, _ -> Lt | _, Private_key -> Gt
      | Version, Version -> Eq (* | Version, _ -> Lt | _, Version -> Gt *)
  end

  include Gmap.Make(K)

  let name : type a. a k -> string = function
    | Unlock_salt -> "unlock-salt"
    | Certificate -> "certificate"
    | Private_key -> "private-key"
    | Version -> "version"

  let to_string : type a. a k -> a -> string = fun k v ->
    match k, v with
    | Unlock_salt, salt -> Cstruct.to_string salt
    | Certificate, (server, chain) ->
      (* maybe upstream/extend X509.Certificate *)
      let encode_one crt =
        let data = X509.Certificate.encode_der crt in
        let len_buf = Cstruct.create 4 in
        Cstruct.BE.set_uint32 len_buf 0 (Int32.of_int (Cstruct.len data));
        Cstruct.(to_string (append len_buf data))
      in
      String.concat "" (List.map encode_one (server :: chain))
    | Private_key, key ->
      (* TODO encode_der (x509 0.8.1) *)
      Cstruct.to_string (X509.Private_key.encode_pem key)
    | Version, v -> Version.to_string v

  let of_string : type a. a k -> string -> (a, [> `Msg of string ]) result =
    fun key data ->
    match key with
    | Unlock_salt -> Ok (Cstruct.of_string data)
    | Certificate ->
      begin
        let rec decode data acc =
          let total = Cstruct.len data in
          if total = 0 then
            Ok (List.rev acc)
          else if total < 4 then
            Error (`Msg "invalid data (no length field)")
          else
            let len = Int32.to_int (Cstruct.BE.get_uint32 data 0) in
            if total - 4 < len then
              Error (`Msg "invalid data (too short)")
            else
              match X509.Certificate.decode_der (Cstruct.sub data 4 len) with
              | Ok cert -> decode (Cstruct.shift data (len + 4)) (cert :: acc)
              | Error e -> Error e
        in
        match decode (Cstruct.of_string data) [] with
        | Ok (server :: chain) -> Ok (server, chain)
        | Ok [] -> Error (`Msg "empty certificate")
        | Error e -> Error e
      end
    | Private_key -> X509.Private_key.decode_pem (Cstruct.of_string data)
    | Version -> Version.of_string data

  let key_path key = Mirage_kv.Key.(add (v config_prefix) (name key))

  let pp_error ppf = function
    | `Kv e -> KV.pp_error ppf e
    | `Msg msg -> Fmt.string ppf msg

  let get kv key =
    KV.get kv (key_path key) >|= function
    | Ok data -> of_string key data
    | Error e -> Error (`Kv e)

  let set kv key value =
    let data = to_string key value in
    KV.set kv (key_path key) data
end
