open Lwt.Infix

module Make (R : Mirage_random.C) (KV : Mirage_kv_lwt.RW) = struct

  type +'a io = 'a Lwt.t

  type t = {
    kv : KV.t ;
    prefix : Mirage_kv.Key.t ;
    key : Crypto.GCM.key
  }

  type error =
    [ Mirage_kv.error | `Kv of KV.error | `Crypto of Crypto.decrypt_error ]

  type write_error = KV.write_error

  let pp_error ppf = function
    | #Mirage_kv.error as e -> Mirage_kv.pp_error ppf e
    | `Kv e -> KV.pp_error ppf e
    | `Crypto e -> Crypto.pp_decryption_error ppf e

  let pp_write_error = KV.pp_write_error

  type key = Mirage_kv.Key.t

  type value = string (* maybe Cstruct.t *)

  let lift_kv_err = function
    | Ok x -> Ok x
    | Error e -> Error (`Kv e)

  let prefix t key = Mirage_kv.Key.append t.prefix key

  let exists t key = KV.exists t.kv (prefix t key) >|= lift_kv_err

  let list t key = KV.list t.kv (prefix t key) >|= lift_kv_err

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

  let set t key value =
    let key' = prefix t key in
    let adata = Cstruct.of_string (Mirage_kv.Key.to_string key') in
    let data = Cstruct.of_string value in
    let encrypted = Crypto.encrypt R.generate ~key:t.key ~adata data in
    KV.set t.kv key' (Cstruct.to_string encrypted)

  let connect ?(init = false) version store ~key kv =
    let prefix = match store with
      | `Authentication -> "authentication"
      | `Key -> "keys"
    in
    let prefix = Mirage_kv.Key.v prefix
    and key = Crypto.GCM.of_secret key
    in
    let t = { kv ; prefix ; key } in
    let version_filename = Mirage_kv.Key.v ".version" in
    (if init then
       set t version_filename (Version.to_string version) >|=
       Rresult.R.error_to_msg ~pp_error:pp_write_error
     else
       (get t version_filename >|= function
         | Error e -> Rresult.R.error_msgf "%a" pp_error e
         | Ok stored_version -> match Version.of_string stored_version with
           | Error e -> Error e
           | Ok v -> match Version.compare version v with
             | `Equal -> Ok ()
             | _ -> Error (`Different_version (t, v)))) >|= function
    | Ok () -> Ok t
    | Error e -> Error e

  let disconnect _t = Lwt.return_unit
end
