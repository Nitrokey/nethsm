(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Lwt.Infix

module Make (KV : Kv_ext.RW) = struct
  let dk_prefix device_id = device_id ^ "/domain-key"

  type slot = Attended | Unattended

  let name = function Attended -> "attended" | Unattended -> "unattended"

  let key_path device_id slot =
    Mirage_kv.Key.(add (v (dk_prefix device_id)) (name slot))

  let adata device_id slot = dk_prefix device_id ^ name slot

  type t = { kv : KV.t; device_id : string }

  let get t slot ~encryption_key =
    KV.get t.kv (key_path t.device_id slot) >|= function
    | Error _ -> Error (`Msg "domain key not found")
    | Ok data ->
        let key = Crypto.GCM.of_secret encryption_key in
        Rresult.R.error_to_msg ~pp_error:Crypto.pp_decryption_error
          (Crypto.decrypt ~key ~adata:(adata t.device_id slot) data)

  let set t slot ~encryption_key data =
    let adata = adata t.device_id slot in
    let key = Crypto.GCM.of_secret encryption_key in
    let enc_data = Crypto.encrypt Mirage_crypto_rng.generate ~key ~adata data in
    KV.set t.kv (key_path t.device_id slot) enc_data

  let remove t slot = KV.remove t.kv (key_path t.device_id slot)

  let connect kv device_id = {kv; device_id}
end
