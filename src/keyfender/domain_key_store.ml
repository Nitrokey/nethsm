open Lwt.Infix

module Make (R : Mirage_random.S) (KV : Mirage_kv.RW) = struct

  type t = KV.t

  let dk_prefix = "domain-key"

  type slot = Passphrase | Device_id

  let name = function
    | Passphrase -> "0"
    | Device_id -> "1"

  let key_path slot = Mirage_kv.Key.(add (v dk_prefix) (name slot))

  let adata slot = Cstruct.of_string (dk_prefix ^ name slot)

  let get t slot ~unlock_key =
    KV.get t (key_path slot) >|= function
    | Error _ -> Error (`Msg "domain key not found")
    | Ok data ->
      let key = Crypto.GCM.of_secret unlock_key in
      Rresult.R.error_to_msg ~pp_error:Crypto.pp_decryption_error
        (Crypto.decrypt ~key ~adata:(adata slot) (Cstruct.of_string data))

  let set t slot ~unlock_key data =
    let adata = Cstruct.of_string (dk_prefix ^ name slot) in
    let key = Crypto.GCM.of_secret unlock_key in
    let enc_data = Crypto.encrypt R.generate ~key ~adata data in
    KV.set t (key_path slot) (Cstruct.to_string enc_data)

  let remove t slot = KV.remove t (key_path slot)
end
