open Cohttp
open Lwt.Infix

module Time = struct
  let sleep_ns duration = Lwt_unix.sleep (Duration.to_f duration)
end

module Hsm_clock = Keyfender.Hsm_clock.Make(Pclock)
module Kv_mem = Mirage_kv_mem.Make(Hsm_clock)
module Hsm = Keyfender.Hsm.Make(Mirage_random_test)(Kv_mem)(Time)(Mclock)(Hsm_clock)
module Handlers = Keyfender.Server.Make_handlers(Mirage_random_test)(Hsm)

let request hsm_state ?(body = `Empty) ?(meth = `GET) ?(headers = Header.init ()) ?(content_type = "application/json") ?query path =
  let headers = Header.replace headers "content-type" content_type in
  let uri = Uri.make ~scheme:"http" ~host:"localhost" ~path ?query () in
  let request = Request.make ~meth ~headers uri in
  Handlers.Wm.dispatch' (Handlers.routes hsm_state Ipaddr.V4.any) ~body ~request

let unprovisioned_mock () =
  Kv_mem.connect () >>= Hsm.boot 

let operational_mock () =
  unprovisioned_mock () >>= fun state ->
  Hsm.provision state ~unlock:"unlock" ~admin:"test1" Ptime.epoch >>= fun _ ->
  Hsm.User.add state ~id:"operator" ~role:`Operator ~passphrase:"test2" ~name:"operator" >|= fun _ ->
  state

let auth_header user pass =
  let base64 = Cstruct.to_string (Nocrypto.Base64.encode (Cstruct.of_string (user ^ ":" ^ pass))) in
  Header.init_with "authorization" ("Basic " ^ base64)
  
let admin_headers = auth_header "admin" "test1"

let system_update hsm_state chunk_size chunks =
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
    assert false
  
let rec add_many_users hsm_state = function
  | 0 -> Lwt.return ()
  | i ->
    let id = string_of_int i in 
    Hsm.User.add hsm_state ~id ~role:`Operator ~passphrase:"test2" ~name:"operator" >>= fun _ ->
    add_many_users hsm_state (i-1)

let system_backup hsm_state =
  add_many_users hsm_state 10000 >>= fun () ->
  let gc_stat = Gc.stat () in
  Logs.app (fun m -> m "top heap words after adding 10000 users %d" gc_stat.top_heap_words);
  let backup_passphrase = "backup passphrase" in
  let passphrase = Printf.sprintf "{ \"passphrase\" : %S }" backup_passphrase in
  request hsm_state ~meth:`POST ~headers:admin_headers ~body:(`String passphrase) "/config/backup-passphrase" >>= function
  | Some (`No_content, _, _, _) ->
    begin request hsm_state ~meth:`POST ~headers:admin_headers "/system/backup" >>= function
      | Some (`OK, _, `Stream s, _) ->
        let size = ref 0 in 
        Lwt_stream.iter (fun chunk -> size := !size + String.length chunk) s >|= fun () -> 
        let gc_stat' = Gc.stat () in
        Logs.app (fun m -> m "top heap words after backup %d" gc_stat'.top_heap_words);
        (* a non-streaming backup would use twice the memory of the actual live data *)
        assert (float_of_int gc_stat'.top_heap_words < 1.33 *. float_of_int gc_stat.top_heap_words);
        Printf.printf "received backup of size %d\n" !size
      | _ -> assert false
    end
  | _ -> assert false
 
let system_restore chunk_size chunks =
  let i = ref 0 in
  let chunk = String.make chunk_size ' ' in
  let content_type = "application/octet-stream" in
  let query = [ ("backupPassphrase", [ "my passphrase" ]) ; ("systemTime", [ "2019-10-30T11:20:50Z" ]) ] in
  let generator () = 
    incr i;
    Lwt.return @@ match !i with
    | x when x <= chunks -> Some chunk
    | _ -> None
  in
  let stream = Lwt_stream.from generator in
  let body = `Stream stream in
  unprovisioned_mock () >>= fun hsm_state ->
  let gc_stat = Gc.stat () in
  Logs.app (fun m -> m "top heap words before restore %d" gc_stat.top_heap_words);
  request hsm_state ~meth:`POST ~content_type ~query ~body "/system/restore" >|= function
    | Some (`Bad_request, _, _, _) -> 
      let gc_stat = Gc.stat () in
      Logs.app (fun m -> m "top heap words after restore %d" gc_stat.top_heap_words);
      ()
    | _ -> assert false

let () =
  Printexc.record_backtrace true;
  Fmt_tty.setup_std_outputs ();
  Logs.set_reporter (Logs_fmt.reporter ());
  (*Logs.set_level (Some Debug);*)
  Lwt_main.run (
    Nocrypto_entropy_lwt.initialize () >>= fun () ->
  (*  operational_mock () >>= fun hsm_state ->
    system_update hsm_state (1024*1024) 10000 *)(*>>= fun () ->*)
  (*  system_backup hsm_state >>= fun () ->*)
    system_restore (1024*1024) 10
  )


