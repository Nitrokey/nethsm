open Cohttp
open Lwt.Infix

module Kv_mem = Mirage_kv_mem.Make(Pclock)
module Hsm = Keyfender.Hsm.Make(Mirage_random_test)(Kv_mem)(Pclock)
module Handlers = Keyfender.Server.Make_handlers(Mirage_random_test)(Hsm)

let request hsm_state ?(body = `Empty) ?(meth = `GET) ?(headers = Header.init ()) ?(content_type = "application/json") ?query path =
  let headers = Header.replace headers "content-type" content_type in
  let uri = Uri.make ~scheme:"http" ~host:"localhost" ~path ?query () in
  let request = Request.make ~meth ~headers uri in
  Handlers.Wm.dispatch' (Handlers.routes hsm_state) ~body ~request

let operational_mock () =
  Kv_mem.connect () >>= Hsm.boot >>= fun state ->
  Hsm.provision state ~unlock:"unlock" ~admin:"test1" Ptime.epoch >>= fun _ ->
  Hsm.User.add state ~id:"operator" ~role:`Operator ~passphrase:"test2" ~name:"operator" >|= fun _ ->
  state

let auth_header user pass =
  let base64 = Cstruct.to_string (Nocrypto.Base64.encode (Cstruct.of_string (user ^ ":" ^ pass))) in
  Header.init_with "authorization" ("Basic " ^ base64)
  
let admin_headers = auth_header "admin" "test1"

let system_update hsm_state =
  let body = `String "\000\003sig\000\018A new system image\000\0032.0binary data is here" in
  let content_type = "application/octet-stream" in
  request hsm_state ~headers:admin_headers ~content_type ~body ~meth:`POST "/system/update" >|= function
  | Some (`OK, _, `String release_notes, _) ->
    assert(String.equal "{\"releaseNotes\":\"A new system image\"}" release_notes &&
    Hsm.state hsm_state = `Operational)
  | _ -> assert false
  


let () =
  Printexc.record_backtrace true;
  Fmt_tty.setup_std_outputs ();
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level (Some Debug);
  Lwt_main.run (Nocrypto_entropy_lwt.initialize () >>= fun () ->
  operational_mock () >>= fun hsm_state ->
  system_update hsm_state)


