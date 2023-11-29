(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Lwt.Infix

module Make (R : Mirage_random.S) (KV : Mirage_kv.RW) = struct
  type t = { kv : KV.t; prefix : Mirage_kv.Key.t; key : Crypto.GCM.key }
  type slot = Authentication | Key

  let slot_to_string = function
    | Authentication -> "authentication"
    | Key -> "key"

  let pp_slot ppf slot = Fmt.string ppf (slot_to_string slot) [@@coverage off]

  type error =
    [ Mirage_kv.error
    | `Kv of KV.error
    | `Crypto of Crypto.decrypt_error
    | `Invalid_key of KV.key ]

  type write_error =
    [ Mirage_kv.write_error | `Kv of KV.write_error | `Invalid_key of KV.key ]

  type version_error = [ error | `Msg of string ]

  let pp_error ppf = function
    | #Mirage_kv.error as e -> Mirage_kv.pp_error ppf e
    | `Kv e -> KV.pp_error ppf e
    | `Crypto e -> Crypto.pp_decryption_error ppf e
    | `Invalid_key k -> Fmt.pf ppf "Invalid key '%a'" Mirage_kv.Key.pp k

  let pp_write_error ppf = function
    | #Mirage_kv.write_error as e -> Mirage_kv.pp_write_error ppf e
    | `Kv e -> KV.pp_write_error ppf e
    | `Invalid_key k -> Fmt.pf ppf "Invalid key '%a'" Mirage_kv.Key.pp k

  type key = Mirage_kv.Key.t

  (* check that the key is not reserved for internal usage and
     run the function *)
  let with_key_check key fn =
    if Mirage_kv.Key.equal key Version.filename then
      Lwt.return_error (`Invalid_key Version.filename)
    else fn ()

  let lift_kv_err = function Ok x -> Ok x | Error e -> Error (`Kv e)
  let prefix t key = Mirage_kv.Key.append t.prefix key

  let exists t key =
    with_key_check key @@ fun () ->
    KV.exists t.kv (prefix t key) >|= lift_kv_err

  let list t key =
    with_key_check key @@ fun () ->
    KV.list t.kv (prefix t key) >|= function
    | Ok items ->
        let items_without_version =
          List.filter
            (fun (data, _) -> not (String.equal Version.file data))
            items
        in
        Ok items_without_version
    | Error e -> Error (`Kv e)

  let last_modified t key =
    with_key_check key @@ fun () ->
    KV.last_modified t.kv (prefix t key) >|= lift_kv_err

  let digest t key =
    with_key_check key @@ fun () ->
    KV.digest t.kv (prefix t key) >|= lift_kv_err

  let batch t ?retries f = KV.batch ?retries t.kv (fun kv -> f { t with kv })

  let raw_get t key =
    let key' = prefix t key in
    KV.get t.kv key' >|= function
    | Error e -> Error (`Kv e)
    | Ok data -> (
        let adata = Cstruct.of_string (Mirage_kv.Key.to_string key') in
        match Crypto.decrypt ~key:t.key ~adata (Cstruct.of_string data) with
        | Ok decrypted -> Ok (Cstruct.to_string decrypted)
        | Error e -> Error (`Crypto e))

  let prepare_set t key value =
    let key' = prefix t key in
    let adata = Cstruct.of_string (Mirage_kv.Key.to_string key') in
    let data = Cstruct.of_string value in
    let encrypted = Crypto.encrypt R.generate ~key:t.key ~adata data in
    (key', Cstruct.to_string encrypted)

  let raw_set t key value =
    let key', encrypted = prepare_set t key value in
    KV.set t.kv key' encrypted

  let set_version t version =
    raw_set t Version.filename (Version.to_string version)

  let get_version t =
    raw_get t Version.filename >>= function
    | Ok v -> Lwt.return (Version.of_string v)
    | Error e -> Lwt.return_error e

  let set t key value =
    with_key_check key @@ fun () ->
    raw_set t key value |> Lwt_result.map_error (fun e -> `Kv e)

  let get t key = with_key_check key @@ fun () -> raw_get t key

  let remove t key =
    with_key_check key @@ fun () ->
    KV.remove t.kv (prefix t key) |> Lwt_result.map_error (fun e -> `Kv e)

  let prefix slot =
    let p = slot_to_string slot in
    Mirage_kv.Key.v p

  let v store ~key kv =
    let prefix = prefix store and key = Crypto.GCM.of_secret key in
    { kv; prefix; key }

  let initialize version store ~key kv =
    let open Lwt_result.Infix in
    let t = v store ~key kv in
    set_version t version >|= fun () -> t

  type connect_error =
    [ error | `Msg of string | `Version_smaller of Version.t * Version.t ]

  let pp_connect_error ppf = function
    | #error as e -> pp_error ppf e
    | `Msg msg -> Fmt.string ppf msg
    | `Version_smaller (current, stored) ->
        Fmt.pf ppf "current version %a smaller than stored version %a"
          Version.pp current Version.pp stored
  [@@coverage off]

  let unlock version store ~key kv =
    let open Lwt_result.Infix in
    let prefix = prefix store and key = Crypto.GCM.of_secret key in
    let t = { kv; prefix; key } in
    get_version t >>= fun v ->
    Lwt.return
      (match Version.compare version v with
      | `Equal -> Ok (`Kv t)
      | `Greater -> Ok (`Version_greater (v, t))
      | `Smaller -> Error (`Version_smaller (version, v)))

  let disconnect _t = Lwt.return_unit
  let slot_auth = slot_to_string Authentication
  let slot_key = slot_to_string Key

  let slot_of_key key =
    match Mirage_kv.Key.segments key with
    | _ :: v :: _ when String.equal v Version.file -> None
    | prefix :: _ when String.equal prefix slot_auth -> Some Authentication
    | prefix :: _ when String.equal prefix slot_key -> Some Key
    | _ -> None

  let prefix_of_slot = function
    | Authentication -> Mirage_kv.Key.v slot_auth
    | Key -> Mirage_kv.Key.v slot_key
end
