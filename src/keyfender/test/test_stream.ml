(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Cohttp
open Lwt.Infix

module Kv_mem = struct
  include Mirage_kv_mem

  let batch dict ?retries:_ f = f dict
end

module Hsm = Keyfender.Hsm.Make (Keyfender.Kv_ext.Make_ranged (Kv_mem))
module Handlers = Keyfender.Server.Make_handlers (Hsm)

let request hsm_state ?(body = `Empty) ?(meth = `GET)
    ?(headers = Header.init ()) ?(content_type = "application/json") ?query path
    =
  let headers = Header.replace headers "content-type" content_type in
  let path = "/api/v1" ^ path in
  let uri = Uri.make ~scheme:"http" ~host:"localhost" ~path ?query () in
  let request = Request.make ~meth ~headers uri in
  Handlers.Wm.dispatch' (Handlers.routes hsm_state Ipaddr.V4.any) ~body ~request

let update_key =
  match X509.Public_key.decode_pem [%blob "public.pem"] with
  | Ok (`RSA key) -> key
  | Ok _ -> invalid_arg "No RSA key from manufacturer. Contact manufacturer."
  | Error (`Msg m) -> invalid_arg m

let platform =
  {
    Keyfender.Json.deviceId = "0000000000";
    deviceKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    pcr = [];
    akPub = [];
    hardwareVersion = "N/A";
    firmwareVersion = "N/A";
  }

let unprovisioned_mock () =
  Kv_mem.connect () >>= Hsm.boot ~platform update_key >|= fun (y, _, _) -> y

let operational_mock () =
  unprovisioned_mock () >>= fun state ->
  Hsm.provision state ~unlock:"unlock" ~admin:"test1" Ptime.epoch >>= fun _ ->
  Hsm.User.add state
    { Hsm.Nid.id = "backup"; namespace = None }
    ~role:`Backup ~passphrase:"test2" ~name:"backup"
  >|= fun _ -> state

let auth_header user pass =
  let base64 = Base64.encode_string (user ^ ":" ^ pass) in
  Header.init_with "authorization" ("Basic " ^ base64)

let admin_headers = auth_header "admin" "test1"
let backup_headers = auth_header "backup" "test2"

(* let system_update hsm_state chunk_size chunks =
   let i = ref 0 in
   let gc_stat = Gc.stat () in
   let chunk = String.make chunk_size ' ' in
   let gc_stat' = Gc.stat () in
   (* a string consists of data + header + padding, the latter two are constants each up to 1 word length. *)
   assert (gc_stat'.live_words - gc_stat.live_words < 2 + chunk_size);
   let generator () =
     incr i;
     Lwt.return @@ match !i with
     | 1 -> Some "\000\002sig\000\018A new system image\000\0032.0"
     | x when x <= succ chunks -> Some chunk
     | _ -> None
   in
   let stream = Lwt_stream.from generator in
   let body = `Stream stream in
   let content_type = "application/octet-stream" in
   Gc.full_major ();
   let gc_stat = Gc.stat () in
   Logs.app (fun m -> m "live words before request %d" gc_stat.live_words);
   request hsm_state ~headers:admin_headers ~content_type ~body ~meth:`POST "/system/update" >|= function
   | Some (`OK, _, `String release_notes, _) ->
     let gc_stat = Gc.stat () in
     assert(String.equal "{\"releaseNotes\":\"A new system image\"}" release_notes);
     assert(Hsm.state hsm_state = `Operational);
     assert(chunk_size * chunks > gc_stat.top_heap_words * 8)
   | _ ->
     Gc.full_major ();
     let gc_stat = Gc.stat () in
     Logs.app (fun m -> m "live words after request %d" gc_stat.live_words);
     assert(chunk_size * chunks > gc_stat.top_heap_words * 8);
     assert false *)

let rec add_many_users hsm_state = function
  | 0 -> Lwt.return ()
  | i ->
      let id = { Hsm.Nid.id = string_of_int i; namespace = None } in
      Hsm.User.add hsm_state id ~role:`Operator ~passphrase:"test2"
        ~name:"operator"
      >>= fun _ -> add_many_users hsm_state (i - 1)

let system_backup hsm_state =
  add_many_users hsm_state 100000 >>= fun () ->
  let gc_stat = Gc.stat () in
  Logs.app (fun m ->
      m "top heap words after adding 10000 users %d" gc_stat.top_heap_words);
  let backup_passphrase = "backup passphrase" in
  let passphrase =
    Printf.sprintf "{ \"currentPassphrase\" : \"\", \"newPassphrase\" : %S }"
      backup_passphrase
  in
  request hsm_state ~meth:`PUT ~headers:admin_headers ~body:(`String passphrase)
    "/config/backup-passphrase"
  >>= function
  | Some (`No_content, _, _, _) ->
      let rec do_backup n =
        if n = 0 then Lwt.return ()
        else
          request hsm_state ~meth:`POST ~headers:backup_headers "/system/backup"
          >>= function
          | Some (`OK, _, `Stream s, _) ->
              let size = ref 0 in
              Lwt_stream.iter
                (fun chunk -> size := !size + String.length chunk)
                s
              >>= fun () ->
              Printf.printf "received backup of size %d\n" !size;
              do_backup (n - 1)
          | Some (_c, _h, _b, _s) ->
              Lwt.return
                (Logs.app (fun m ->
                     m " RES: %s" (Cohttp.Code.string_of_status _c)))
          | _ -> assert false
      in
      do_backup 100 >|= fun () ->
      let gc_stat' = Gc.stat () in
      Logs.app (fun m ->
          m "top heap words after .backup %d" gc_stat'.top_heap_words);
      (* a non-streaming backup would use twice the memory of the actual live data *)
      assert (
        float_of_int gc_stat'.top_heap_words
        < 1.33 *. float_of_int gc_stat.top_heap_words)
  | _ -> assert false

let system_restore chunk_size chunks =
  let i = ref 0 in
  let chunk = String.make chunk_size ' ' in
  let content_type = "application/octet-stream" in
  let query =
    [
      ("backupPassphrase", [ "my passphrase" ]);
      ("systemTime", [ "2019-10-30T11:20:50Z" ]);
    ]
  in
  let generator () =
    incr i;
    Lwt.return @@ match !i with x when x <= chunks -> Some chunk | _ -> None
  in
  let stream = Lwt_stream.from generator in
  let body = `Stream stream in
  unprovisioned_mock () >>= fun hsm_state ->
  let gc_stat = Gc.stat () in
  let before = gc_stat.top_heap_words in
  Logs.app (fun m -> m "top heap words before restore %d" before);
  request hsm_state ~meth:`POST ~content_type ~query ~body "/system/restore"
  >|= function
  | Some (`Bad_request, _, _, _) ->
      let gc_stat = Gc.stat () in
      let after = gc_stat.top_heap_words in
      Logs.app (fun m -> m "top heap words after restore %d" after);
      let delta = after - before in
      Logs.app (fun m -> m "heap increase %d" delta);
      ()
  | _ -> assert false

let () =
  Keyfender.Crypto.set_test_params ();
  Printexc.record_backtrace true;
  Fmt_tty.setup_std_outputs ();
  Logs.set_reporter (Logs_fmt.reporter ());
  (*Logs.set_level (Some Debug);*)
  Mirage_crypto_rng_unix.use_default ();
  Lwt_main.run
    ( operational_mock () >>= fun hsm_state ->
      (* system_update hsm_state (1024*1024) 10000 *)
      (* >>= fun () -> *)
      system_backup hsm_state >>= fun () ->
      system_restore (1024 * 1024) (1024 * 1024 * 1023) )
