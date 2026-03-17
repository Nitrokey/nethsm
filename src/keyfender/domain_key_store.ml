(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Lwt.Infix

module Make (KV : Kv_ext.RW) = struct
  let dk_prefix_v0 = "domain-key"
  let dk_prefix device_id = "local/" ^ device_id ^ "/domain-key"

  type slot = Attended | Unattended

  let name = function Attended -> "attended" | Unattended -> "unattended"

  let key_path device_id slot =
    Mirage_kv.Key.(add (v (dk_prefix device_id)) (name slot))

  let key_path_v0 slot = Mirage_kv.Key.(add (v dk_prefix_v0) (name slot))
  let adata device_id slot = dk_prefix device_id ^ name slot
  let adata_v0 slot = dk_prefix_v0 ^ name slot

  type t = { kv : KV.t; device_id : string }

  let get t slot ~encryption_key =
    KV.get t.kv (key_path t.device_id slot) >>= function
    | Error _ -> Lwt_result.fail (`Msg "domain key not found")
    | Ok data -> (
        let key = Crypto.GCM.of_secret encryption_key in
        match Crypto.decrypt ~key ~adata:(adata t.device_id slot) data with
        | Ok x -> Lwt_result.return x
        | Error `Not_authenticated ->
            (* if decryption failed, try with v0 adata
               in case this domain key was migrated *)
            Rresult.R.error_to_msg ~pp_error:Crypto.pp_decryption_error
              (Crypto.decrypt ~key ~adata:(adata_v0 slot) data)
            |> Lwt.return
        | x ->
            Lwt.return
              (Rresult.R.error_to_msg ~pp_error:Crypto.pp_decryption_error x))

  let set t slot ~encryption_key data =
    let adata = adata t.device_id slot in
    let key = Crypto.GCM.of_secret encryption_key in
    let enc_data = Crypto.encrypt Mirage_crypto_rng.generate ~key ~adata data in
    KV.set t.kv (key_path t.device_id slot) enc_data

  let remove t slot = KV.remove t.kv (key_path t.device_id slot)
  let connect kv device_id = { kv; device_id }

  let move_id kv ~from_id ~to_id =
    let ( let** ) = Lwt_result.bind in
    let ( let* ) = Lwt.bind in
    let move_slot ~mandatory s =
      let from_key = key_path from_id s in
      let* data_opt = KV.get kv from_key in
      match data_opt with
      | Error (`Not_found _) when not mandatory -> Lwt_result.return ()
      | Error _ -> Lwt_result.fail (`Not_found from_key)
      | Ok data ->
          let** () = KV.set kv (key_path to_id s) data in
          KV.remove kv from_key
    in
    if String.equal from_id to_id then Lwt_result.return ()
    else
      let** () = move_slot ~mandatory:true Attended in
      move_slot ~mandatory:false Unattended

  let migrate_v0_v1 t =
    let just_move ?(required = true) slot =
      KV.get t.kv (key_path_v0 slot) >>= function
      | Error e when required ->
          Logs.err (fun f -> f "failed to migrate domain key: %a" KV.pp_error e);
          Lwt_result.fail (`Kv e)
      | Error _ -> Lwt.return (Ok ()) (* slot may not be filled *)
      | Ok data ->
          KV.set t.kv (key_path t.device_id slot) data >|= fun r ->
          Result.map_error (fun e -> `Kv_write e) r
    in
    let open Lwt_result.Infix in
    just_move Attended >>= fun () -> just_move ~required:false Unattended
end
