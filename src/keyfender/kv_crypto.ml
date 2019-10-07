open Lwt.Infix

module Make (R : Mirage_random.C) (KV : Mirage_kv_lwt.RW) = struct

  type +'a io = 'a Lwt.t

  type t = {
    kv : KV.t ;
    prefix : Mirage_kv.Key.t ;
    key : Crypto.GCM.key
  }

  (* TODO fix/extend errors (may need tweaks to mirage-kv!?) *)
  type error = KV.error (* [ `Kv of Mirage_kv.error | `Not_authenticated ] *)

  type write_error = KV.write_error

  let pp_error = KV.pp_error
  (* | `Not_authenticated -> Fmt.pf ppf "not authenticated" *)

  let pp_write_error = KV.pp_write_error

  type key = Mirage_kv.Key.t

  type value = string (* maybe Cstruct.t *)

  let prefix t key = Mirage_kv.Key.append t.prefix key

  let exists t key = KV.exists t.kv (prefix t key)

  let list t key = KV.list t.kv (prefix t key)

  let last_modified t key = KV.last_modified t.kv (prefix t key)

  let digest t key = KV.digest t.kv (prefix t key)

  let batch t ?retries:_ f = f t

  let remove t key = KV.remove t.kv (prefix t key)

  let get t key =
    let key' = prefix t key in
    KV.get t.kv key' >|= function
    | Error e -> Error e
    | Ok data ->
      let adata = Cstruct.of_string (Mirage_kv.Key.to_string key') in
      match Crypto.decrypt ~key:t.key ~adata (Cstruct.of_string data) with
      | Ok decrypted -> Ok (Cstruct.to_string decrypted)
      | Error _ -> Error (`Not_found key') (* TODO: better error! *)

  let set t key value =
    let key' = prefix t key in
    let adata = Cstruct.of_string (Mirage_kv.Key.to_string key') in
    let data = Cstruct.of_string value in
    let encrypted = Crypto.encrypt R.generate ~key:t.key ~adata data in
    KV.set t.kv key' (Cstruct.to_string encrypted)

  let connect store ~key kv =
    let prefix = match store with
      | `Authentication -> "authentication"
      | `Key -> "keys"
    in
    let prefix = Mirage_kv.Key.v prefix
    and key = Crypto.GCM.of_secret key
    in
    { kv ; prefix ; key }

  let disconnect _t = Lwt.return_unit
end
