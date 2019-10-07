open Lwt.Infix

module Make (R : Mirage_random.C) (KV : Mirage_kv_lwt.RW) = struct

  type t = KV.t

  let dk_prefix = "domain-key"

  let name = function
    | `Passphrase -> "0"

  let key_path slot = Mirage_kv.Key.(add (v dk_prefix) (name slot))

  let adata slot = Cstruct.of_string (dk_prefix ^ name slot)

  let get t slot ~unlock_key =
    KV.get t (key_path slot) >|= function
    | Error _ -> Error (`Msg "domain key not found")
    | Ok data ->
      let key = Crypto.GCM.of_secret unlock_key in
      Crypto.decrypt ~key ~adata:(adata slot) (Cstruct.of_string data)

  let set t slot ~unlock_key data =
    let adata = Cstruct.of_string (dk_prefix ^ name slot) in
    let key = Crypto.GCM.of_secret unlock_key in
    let enc_data = Crypto.encrypt R.generate ~key ~adata data in
    KV.set t (key_path slot) (Cstruct.to_string enc_data)
end
