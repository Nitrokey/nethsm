(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Lwt.Infix

module Make (KV : Kv_ext.RW) = struct
  type t = KV.t

  let dk_prefix = "domain-key"

  type slot = Attended | Unattended

  let name = function Attended -> "attended" | Unattended -> "unattended"
  let key_path slot = Mirage_kv.Key.(add (v dk_prefix) (name slot))
  let adata slot = dk_prefix ^ name slot

  let get t slot ~encryption_key =
    KV.get t (key_path slot) >|= function
    | Error _ -> Error (`Msg "domain key not found")
    | Ok data ->
        let key = Crypto.GCM.of_secret encryption_key in
        Rresult.R.error_to_msg ~pp_error:Crypto.pp_decryption_error
          (Crypto.decrypt ~key ~adata:(adata slot) data)

  let set t slot ~encryption_key data =
    let adata = dk_prefix ^ name slot in
    let key = Crypto.GCM.of_secret encryption_key in
    let enc_data = Crypto.encrypt Mirage_crypto_rng.generate ~key ~adata data in
    KV.set t (key_path slot) enc_data

  let remove t slot = KV.remove t (key_path slot)
end
