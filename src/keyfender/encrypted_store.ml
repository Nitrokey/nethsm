open Lwt.Infix

module Make (R : Mirage_random.S) (KV : Mirage_kv.RW) = struct

  type t = {
    kv : KV.t ;
    prefix : Mirage_kv.Key.t ;
    key : Crypto.GCM.key
  }

  type slot = Authentication | Key

  let slot_to_string = function
    | Authentication -> "authentication"
    | Key -> "key"

  let pp_slot ppf slot = Fmt.string ppf (slot_to_string slot)
  [@@coverage off]

  type error =
    [ Mirage_kv.error | `Kv of KV.error | `Crypto of Crypto.decrypt_error ]

  type write_error = KV.write_error

  let pp_error ppf = function
    | #Mirage_kv.error as e -> Mirage_kv.pp_error ppf e
    | `Kv e -> KV.pp_error ppf e
    | `Crypto e -> Crypto.pp_decryption_error ppf e

  let pp_write_error = KV.pp_write_error

  type key = Mirage_kv.Key.t

  let lift_kv_err = function
    | Ok x -> Ok x
    | Error e -> Error (`Kv e)

  let prefix t key = Mirage_kv.Key.append t.prefix key

  let exists t key = KV.exists t.kv (prefix t key) >|= lift_kv_err

  let list t key =
    KV.list t.kv (prefix t key) >|= function
    | Ok items -> Ok (List.filter (fun (data, _) -> not (String.equal ".version" data)) items)
    | Error e -> Error (`Kv e)

  let last_modified t key = KV.last_modified t.kv (prefix t key) >|= lift_kv_err

  let digest t key = KV.digest t.kv (prefix t key) >|= lift_kv_err

  let batch t ?retries:_ f = f t

  let remove t key = KV.remove t.kv (prefix t key)

  let get t key =
    let key' = prefix t key in
    KV.get t.kv key' >|= function
    | Error e -> Error (`Kv e)
    | Ok data ->
      let adata = Cstruct.of_string (Mirage_kv.Key.to_string key') in
      match Crypto.decrypt ~key:t.key ~adata (Cstruct.of_string data) with
      | Ok decrypted -> Ok (Cstruct.to_string decrypted)
      | Error e -> Error (`Crypto e)

  let prepare_set t key value =
    let key' = prefix t key in
    let adata = Cstruct.of_string (Mirage_kv.Key.to_string key') in
    let data = Cstruct.of_string value in
    let encrypted = Crypto.encrypt R.generate ~key:t.key ~adata data in
    key', Cstruct.to_string encrypted

  let set t key value =
    let key', encrypted = prepare_set t key value in
    KV.set t.kv key' encrypted

  let prefix slot =
    let p = slot_to_string slot in
    Mirage_kv.Key.v p

  let v store ~key kv =
    let prefix = prefix store
    and key = Crypto.GCM.of_secret key
    in
    { kv ; prefix ; key }

  let initialize version store ~key kv =
    let open Lwt_result.Infix in
    let t = v store ~key kv in
    set t Version.filename (Version.to_string version) >|= fun () ->
    t

  type connect_error =
    [ error | `Msg of string | `Version_smaller of Version.t * Version.t ]

  let pp_connect_error ppf = function
    | #error as e -> pp_error ppf e
    | `Msg msg -> Fmt.string ppf msg
    | `Version_smaller (current, stored) ->
      Fmt.pf ppf "current version %a smaller than stored version %a"
        Version.pp current Version.pp stored [@@coverage off]

  let unlock version store ~key kv =
    let open Lwt_result.Infix in
    let prefix = prefix store
    and key = Crypto.GCM.of_secret key
    in
    let t = { kv ; prefix ; key } in
    get t Version.filename >>= fun stored_version ->
    Lwt.return (Version.of_string stored_version) >>= fun v ->
    Lwt.return (match Version.compare version v with
        | `Equal -> Ok (`Kv t)
        | `Greater -> Ok (`Version_greater (v, t))
        | `Smaller -> Error (`Version_smaller (version, v)))

  let disconnect _t = Lwt.return_unit
end
