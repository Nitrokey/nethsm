open OUnit
open Cohttp
open Lwt.Infix

module Mock_clock = struct
  let now_d_ps () = (1000, 0L)
  let current_tz_offset_s () = None
  let period_d_ps () = None
end
module Hsm_clock = Keyfender.Hsm_clock.Make(Mock_clock)

module Time = struct
  let sleep_ns duration = Lwt_unix.sleep (Duration.to_f duration)
end

module Kv_mem = Mirage_kv_mem.Make(Hsm_clock)
module Hsm = Keyfender.Hsm.Make(Mirage_random_test)(Kv_mem)(Time)(Mclock)(Hsm_clock)
module Handlers = Keyfender.Server.Make_handlers(Mirage_random_test)(Hsm)

let request ?hsm_state ?(body = `Empty) ?(meth = `GET) ?(headers = Header.init ()) ?(content_type = "application/json") ?query ?(ip = Ipaddr.V4.any) endpoint =
  let headers = Header.replace headers "content-type" content_type in
  let hsm_state' = match hsm_state with
    | None -> Lwt_main.run (Kv_mem.connect () >>= Hsm.boot ~device_id:"test dispatch" >|= fun (y, _, _) -> y)
    | Some x -> x
  in
  let path = "/api/v1" ^ endpoint in
  let uri = Uri.make ~scheme:"http" ~host:"localhost" ~path ?query () in
  let request = Request.make ~meth ~headers uri in
  let resp = Lwt_main.run @@ Handlers.Wm.dispatch' (Handlers.routes hsm_state' ip) ~body ~request in
  hsm_state', resp

let good_platform mbox = Lwt_mvar.put mbox (Ok ())

let operational_mock ?(mbox = good_platform)  () =
  Lwt_main.run (
    Kv_mem.connect () >>= Hsm.boot ~device_id:"test dispatch" >>= fun (state, _, m) ->
    mbox m >>= fun () ->
    Hsm.provision state ~unlock:"unlockPassphrase" ~admin:"test1Passphrase" Ptime.epoch >>= fun _ ->
    Hsm.User.add state ~id:"operator" ~role:`Operator ~passphrase:"test2Passphrase" ~name:"operator" >>= fun _ ->
    Hsm.User.add state ~id:"backup" ~role:`Backup ~passphrase:"test3Passphrase" ~name:"backup" >|= fun _ ->
    state)

let locked_mock () =
  Lwt_main.run (
    (* create an empty in memory key-value store, and a HSM state (unprovisioned) *)
    Kv_mem.connect () >>= fun kv ->
    Hsm.boot ~device_id:"test dispatch" kv >>= fun (state, _, _) ->
    (* provision HSM, leading to state operational (and writes to the kv store) *)
    Hsm.provision state ~unlock:"test1234Passphrase" ~admin:"test1Passphrase" Ptime.epoch >>= fun r ->
    (* create a new HSM state, using the provisioned kv store, with a `Locked state *)
    assert (r = Ok ());
    Hsm.boot ~device_id:"test dispatch" kv >|= fun (y, _, _) -> y)

let auth_header user pass =
  let base64 = Base64.encode_string (user ^ ":" ^ pass) in
  Header.init_with "authorization" ("Basic " ^ base64)

let admin_headers = auth_header "admin" "test1Passphrase"

let operator_headers = auth_header "operator" "test2Passphrase"

let admin_put_request ?(hsm_state = operational_mock()) ?(body = `Empty) ?content_type ?query path =
  let headers = admin_headers in
  request ~meth:`PUT ~hsm_state ~headers ~body ?content_type ?query path

let admin_post_request ?(hsm_state = operational_mock()) ?(body = `Empty) ?content_type ?query path =
  let headers = admin_headers in
  request ~meth:`POST ~hsm_state ~headers ~body ?content_type ?query path

let empty () =
  "a request for / will produce no result"
    @? begin match request "/" with
       | _, None -> true
       | _    -> false
    end

let health_alive_ok () =
  "a request for /health/alive will produce a HTTP 200"
    @? begin match request "/health/alive" with
       | _, Some (`OK, _, _, _) -> true
       | _ -> false
    end

let health_ready_ok () =
  "a request for /health/ready in operational state will produce an HTTP 200"
    @? begin match request ~hsm_state:(operational_mock ()) "/health/ready" with
       | _, Some (`OK, _, _, _) -> true
       | _ -> false
    end

let health_ready_error_precondition_failed () =
  "a request for /health/ready in unprovisioned state will produce an HTTP 412"
    @? begin match request "/health/ready" with
       | _, Some (`Precondition_failed, _, _, _) -> true
       | _ -> false
    end

let health_state_ok () =
  let hsm_state = operational_mock () in
  "a request for /health/state will produce an HTTP 200 and returns the state as json"
    @? begin match request ~hsm_state "/health/state" with
       | _, Some (`OK, _, `String body, _) ->
         String.equal body @@ Yojson.Safe.to_string @@ Keyfender.Json.state_to_yojson @@ Hsm.state hsm_state
       | _ -> false
    end

let random_ok () =
  let body = `String {| { "length": 10 } |} in
  let hsm_state = operational_mock () in
  let headers = operator_headers in
  "a request for /random will produce an HTTP 200 and returns random data"
    @? begin match request ~meth:`POST ~hsm_state ~headers ~body "/random" with
       | _, Some (`OK, _, _, _) -> true
       | _ -> false
    end

let random_error_bad_length () =
  let body = `String {| { "length": 10000 } |} in
  let hsm_state = operational_mock () in
  let headers = operator_headers in
  "a request for /random will produce an HTTP 400"
    @? begin match request ~meth:`POST ~hsm_state ~headers ~body "/random" with
       | _, Some (`Bad_request, _, _, _) -> true
       | _ -> false
    end

let provision_json = {| {
  "unlockPassphrase": "UnlockPassphrase",
  "adminPassphrase": "Administrator",
  "systemTime": "2018-10-30T11:20:50Z"
} |}

let provision_ok () =
  let body = `String provision_json in
  "an initial provision request is successful (state transition to operational, HTTP response 204)"
    @? begin match request ~body ~meth:`POST "/provision" with
       | hsm_state, Some (`No_content, _, _, _) -> Hsm.state hsm_state = `Operational
       | _ -> false
    end

let provision_error_malformed_request () =
  let body = `String ("hallo" ^ provision_json) in
  "an initial provision request with invalid json returns a malformed request with 400"
    @? begin match request ~body ~meth:`POST "/provision" with
       | hsm_state, Some (`Bad_request, _, _, _) -> Hsm.state hsm_state = `Unprovisioned
       | _ -> false
    end

let provision_error_precondition_failed () =
  let body = `String provision_json in
  "an initial provision request is successful, a subsequent provision fails with 412"
    @? begin match request ~body ~meth:`POST "/provision" with
       | hsm_state, Some (`No_content, _, _, _) ->
         begin match request ~hsm_state ~body ~meth:`POST "/provision" with
          | _, Some (`Precondition_failed, _, _, _) -> true
          | _ -> false
         end
       | _ -> false
    end

let system_info_ok () =
  "a request for /system/info with authenticated user returns 200"
   @? begin match request ~hsm_state:(operational_mock ()) ~headers:admin_headers "/system/info" with
      | hsm_state, Some (`OK, _, `String body, _) ->
        String.equal body @@ Yojson.Safe.to_string @@ Keyfender.Json.system_info_to_yojson @@ Hsm.System.system_info hsm_state
      | _ -> false
   end

let system_info_error_authentication_required () =
  "a request for /system/info without authenticated user returns 401"
   @? begin match request ~hsm_state:(operational_mock ()) "/system/info" with
      | _, Some (`Unauthorized, _, _, _) -> true
      | _ -> false
   end

let system_info_error_precondition_failed () =
  "a request for /system/info in unprovisioned state fails with 412"
   @? begin match request "/system/info" with
      | _, Some (`Precondition_failed, _, _, _) -> true
      | _ -> false
   end

let system_info_error_forbidden () =
  "a request for /system/info with authenticated operator returns 403"
   @? begin match request ~hsm_state:(operational_mock ()) ~headers:(auth_header "operator" "test2Passphrase") "/system/info" with
      | _, Some (`Forbidden, _, _, _) -> true
      | _ -> false
   end

let system_reboot_ok () =
  "a request for /system/reboot with authenticated user returns 200"
   @? begin match admin_post_request "/system/reboot" with
      | _, Some (`No_content, _, _, _) -> true
      | _ -> false
   end

let system_shutdown_ok () =
  "a request for /system/shutdown with authenticated user returns 200"
   @? begin match admin_post_request "/system/shutdown" with
      | _, Some (`No_content, _, _, _) -> true
      | _ -> false
   end

let system_reset_ok () =
  "a request for /system/reset with authenticated user returns 200"
   @? begin match admin_post_request "/system/reset" with
      | _, Some (`No_content, _, _, _) -> true
      | _ -> false
   end

let update_key = {|-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDHuCF+uj5UR6li
bLZXsc+fk9JF2YbPF7BymbPFO2tnXQHKBsSqE+wCvh9Yj2kbuJFfN7NrsMyOtCm3
Mqx9LLp0EWZIRl6v6EnG452EEb8VfqmPBGtmls5DHKv5pOUTeObZc/XYKrHTCxgY
igmVYdsZv3QgDH3Ol1hCAeglnjHmKazm+juHem48TJXJwkfl8wEH2H7YHFzgHFo8
oybXklHUHtOgHeDXpIljYHW39qo2apIFkLgc/V8K5JsGbzc6CpGF2TU/qv++o5Uq
vFW6kOoqR1x/91EGJBqUn21BtVuz045h9Dqfbka8lO8a2o4S6CCK3fa1XXolcJmO
dh48C+03AgMBAAECggEAYgLo3SpFIFMyuwyix5KJU8TVclX4JHV5sCPh5y7r3IP2
NtDvfo/cSNRIyctHR8ViAhpxwK25FWcw+aiyoZNrxT4stddi7GzQl/xn9sJGxiOs
znTayDPF8YWGmDLmAJJap+iSg40gS3OsVY6YeWjWf2JHeNroepQnSe1podxqnIqE
jwohzFfFMdRQRFZKmdjxKfLNbSjZ1kIgN6w0lky00l9N8999v6SU+0lvCNVtLB7G
lmmyTBeTXM033Zr3adUXObCPDc5RdyvU66Ubvso41d8KuQQyr+oWdnm/0yJvBEVz
bQ5B8D7mmaQNLpwwx56MlnwtRnpCu6Z1PSsXwOnMkQKBgQD1rLH4NLjNh3r842wz
PjpvE4WhizaMcyZLo7W0+eUj4ceZ7Zw4pLU1zUQB3cCYAHNRz1VQpupxEkiGdGaj
vq4dr0WE/qFzB63tM4aRg2TFQAd9c6ME1L/une5WpDG6jd4Q46cWoj914O5suKjA
q55xcgauy7hP9M8NknqEJypWNQKBgQDQHPwtbig3UrIHP3buTeAfLy2R/GgvqaFc
qvHmcJILO9bxt13HFuoBJAuXYeN/QynWSmI96csKt/TTY8wCtFUrPU57HLbWlbWk
uOa3Lacj+ZzaEJ7FXt3rnOeT/VCrlfbUcO550otE39UA26YRD/27F4+xeBRujHHY
Xlyz81ezOwKBgQDU8A6BuBDF9Dvhna1W7QTw6dbVojhxnA0BWrBQYJj/dN7wyEaz
we9e5r+fbnlURm+t5StpcIOb5eD+yT19h/SaviRfleSSM4HJKvPkhCJ/5XOYhPYz
ZcPGKxU9+6suq3Bi6y8UKyUeIwwFKDj8ZsQ6SD8KmoDyrJoahW+zw86qUQKBgFNY
+Godbv/RH7mlYjVIfRUgKOkJpJRKJHTfhafbt7HGEmyWGnmspKU2UWocaydBt9S5
z6SqKIYvbF7o3gDLRjzd/btyoYtJRAkngEcmgoT26CmxdFTpjIlbOqfbUN6XXdZx
MCEcAGjiGAWS8mxs8hpm8kaKJ+yqVMHp8MilEZ+XAoGBANiqyXB3ONoSEgpVMYpA
m4NUCkaDONP6/r9U10c+ZGqdDQqdGalG5mY8Vq2h8JvmalfA1Q7SqCdWKHtMT0Sx
hKHPVcjl0CKq2SyddQ63uuaKDnrVDRCEO9o9J521GgoGAwPMwI4XqN+JyQgCMVOg
z7vvltQ9fOTqe29fERS2ASgq
-----END PRIVATE KEY-----|} |> Cstruct.of_string |> X509.Private_key.decode_pem |> function
  | Ok `RSA key -> key
  | Ok _ -> invalid_arg "not an RSA key"
  | Error `Msg m -> invalid_arg m

module Pss_sha256 = Mirage_crypto_pk.Rsa.PSS(Mirage_crypto.Hash.SHA256)

let prefix_and_pad s =
  let pad = String.make (512 - String.length s) '\000' in
  String.concat "" [ "\000\000\000\001" ; s ; pad ]

let sign_update u =
  let signature = Pss_sha256.sign ~key:update_key (`Message (Cstruct.of_string u)) in
  let length = Cstruct.length signature in
  let len_buf = Cstruct.create 3 in
  Cstruct.set_uint8 len_buf 0 (length lsr 16);
  Cstruct.BE.set_uint16 len_buf 1 (length land 0xffff);
  Cstruct.to_string (Cstruct.append len_buf signature)

let system_update_ok () =
  let body =
    let data = prefix_and_pad "binary data is here" in
    let update = "\000\000\018A new system image\000\000\0032.0" ^ data in
    `String (sign_update update ^ update)
  in
  "a request for /system/update with authenticated user returns 200"
   @? begin match admin_post_request ~body "/system/update" with
     | hsm_state, Some (`OK, _, `String release_notes, _) ->
       String.equal "{\"releaseNotes\":\"A new system image\"}" release_notes &&
       Hsm.state hsm_state = `Operational
     | _ -> false
   end

let system_update_signature_mismatch () =
  let body =
    let data = prefix_and_pad "binary data is here" in
    let update = "\000\000\018A new system image\000\000\0032.0" ^ data in
    let signature = sign_update (update ^ "\000") in
    `String (signature ^ update)
  in
  "a request for /system/update with authenticated user and bad signature returns 400"
   @? begin match admin_post_request ~body "/system/update" with
     | _, Some (`Bad_request, _, _, _) -> true
     | _ -> false
   end

let system_update_too_much_data () =
  let body =
    let data = (prefix_and_pad "binary data is here") ^ "\000" in
    let update = "\000\000\018A new system image\000\000\0032.0" ^ data in
    let signature = sign_update update in
    `String (signature ^ update)
  in
  "a request for /system/update with authenticated user and too much data returns 400"
   @? begin match admin_post_request ~body "/system/update" with
     | _, Some (`Bad_request, _, _, _) -> true
     | _ -> false
   end

let system_update_too_few_data () =
  let body =
    let data =
      let d = prefix_and_pad "binary data is here" in
      String.sub d 0 (pred (String.length d))
    in
    let update = "\000\000\018A new system image\000\000\0032.0" ^ data in
    let signature = sign_update update in
    `String (signature ^ update)
  in
  "a request for /system/update with authenticated user and too few data returns 400"
   @? begin match admin_post_request ~body "/system/update" with
     | _, Some (`Bad_request, _, _, _) -> true
     | _ -> false
   end

let system_update_invalid_data () =
  let body = `String "\000\000\003signature too long\000\000\018A new system image\000\000\0032.0binary data is here" in
  "a request for /system/update with invalid data fails."
   @? begin match admin_post_request ~body "/system/update" with
      | hsm_state, Some (`Bad_request, _, `String body, _) ->
        Logs.info (fun m -> m "Update with invalid data returned %s" body);
        Hsm.state hsm_state = `Operational
      | _ -> false
   end

let system_update_platform_bad () =
  let body =
    let data = prefix_and_pad "binary data is here" in
    let update = "\000\000\018A new system image\000\000\0032.0" ^ data in
    `String (sign_update update ^ update)
  in
  let hsm_state = operational_mock ~mbox:(fun mbox -> Lwt_mvar.put mbox (Error "platform bad")) () in
  "a request for /system/update with bad platform."
   @? begin match admin_post_request ~hsm_state ~body "/system/update" with
      | hsm_state, Some (`Bad_request, _, _, _) -> Hsm.state hsm_state = `Operational
      | _ -> false
   end

let system_update_version_downgrade () =
  let body =
    let data = prefix_and_pad "binary data is here" in
    let update = "\000\000\018A new system image\000\000\0030.5" ^ data in
    let signature = sign_update update in
    `String (signature ^ update)
  in
  "a request for /system/update trying to send an older software fails."
   @? begin match admin_post_request ~body "/system/update" with
      | hsm_state, Some (`Conflict, _, `String body, _) ->
        Logs.info (fun m -> m "Update with older software version returned %s" body);
        Hsm.state hsm_state = `Operational
      | _ -> false
   end

let operational_mock_with_mbox () =
  Lwt_main.run (
    Kv_mem.connect () >>= Hsm.boot ~device_id:"test dispatch" >>= fun (state, o, m) ->
    Lwt.async (fun () -> let rec go () = Lwt_mvar.take o >>= fun _ -> go () in go ());
    Lwt.async (fun () -> let rec go () = Lwt_mvar.put m (Ok ()) >>= fun () -> go () in go ());
    Hsm.provision state ~unlock:"unlockPassphrase" ~admin:"test1Passphrase" Ptime.epoch >>= fun _ ->
    Hsm.User.add state ~id:"operator" ~role:`Operator ~passphrase:"test2Passphrase" ~name:"operator" >>= fun _ ->
    Hsm.User.add state ~id:"backup" ~role:`Backup ~passphrase:"test3Passphrase" ~name:"backup" >|= fun _ ->
    state)

let system_update_commit_ok () =
  let body =
    let data = prefix_and_pad "binary data is here" in
    let update = "\000\000\018A new system image\000\000\0032.0" ^ data in
    let signature = sign_update update in
    `String (signature ^ update)
  and hsm_state = operational_mock_with_mbox ()
  in
  "a request for /system/commit-update with authenticated user returns 200"
   @? begin match admin_post_request ~hsm_state ~body "/system/update" with
      | hsm_state, Some (`OK, _, _, _) ->
        begin match admin_post_request ~hsm_state "/system/commit-update" with
        | _ , Some (`No_content, _, _, _) -> true
        | _ -> false
        end
      | _ -> false
   end

let system_update_commit_fail () =
  "a request for /system/commit-update without an image previously uploaded fails."
   @? begin match admin_post_request "/system/commit-update" with
      | _ , Some (`Precondition_failed, _, _, _) -> true
      | _ -> false
   end

let system_update_cancel_ok () =
  let body =
    let data = prefix_and_pad "binary data is here" in
    let update = "\000\000\018A new system image\000\000\0032.0" ^ data in
    let signature = sign_update update in
    `String (signature ^ update)
  in
  "a request for /system/cancel-update with authenticated user returns 200"
   @? begin match admin_post_request ~body "/system/update" with
      | hsm_state, Some (`OK, _, _, _) ->
        begin match admin_post_request ~hsm_state "/system/cancel-update" with
        | _ , Some (`No_content, _, _, _) -> true
        | _ -> false
        end
      | _ -> false
   end

let system_backup_and_restore_ok () =
  "a request for /system/restore succeeds"
  @? begin
    let backup_passphrase = "backup passphrase" in
    let passphrase = Printf.sprintf "{ \"passphrase\" : %S }" backup_passphrase in
    match admin_put_request ~body:(`String passphrase) "/config/backup-passphrase" with
    | hsm_state, Some (`No_content, _, _, _) ->
      let headers = auth_header "backup" "test3Passphrase" in
      begin match request ~meth:`POST ~hsm_state ~headers "/system/backup" with
        | _hsm_state, Some (`OK, _, `Stream s, _) ->
          let content_type = "application/octet-stream" in
          let query = [ ("backupPassphrase", [ backup_passphrase ]) ; ("systemTime", [ Ptime.to_rfc3339 Ptime.epoch ]) ] in
          let data = String.concat "" (Lwt_main.run (Lwt_stream.to_list s)) in
          begin match request ~meth:`POST ~content_type ~query ~body:(`String data) "/system/restore" with
            | hsm_state', Some (`No_content, _, _, _) ->
              assert (Hsm.state hsm_state' = `Locked);
              let unlock_json = {|{ "passphrase": "unlockPassphrase" }|} in
              begin match request ~meth:`POST ~body:(`String unlock_json) ~hsm_state:hsm_state' "/unlock" with
                | _, Some (`No_content, _, _, _) ->
                  Hsm.state hsm_state' = `Operational && Lwt_main.run (Hsm.equal hsm_state hsm_state')
                | _ -> false
              end
            | _ -> false
          end
        | _ -> false
      end
    | _ -> false
  end

let readfile filename =
  let fd = Unix.openfile filename [Unix.O_RDONLY] 0 in
  let filesize = (Unix.stat filename).Unix.st_size in
  let buf = Bytes.create filesize in
  let rec read off =
    if off = filesize
    then ()
    else
      let bytes_read = Unix.read fd buf off (filesize - off) in
      read (bytes_read + off)
  in
  read 0;
  Unix.close fd;
  `String (Bytes.to_string buf)

let system_update_from_file_ok () =
  let body = readfile "update.bin" in
  "a request for /system/update with authenticated user and update read from disk returns 200"
   @? begin match admin_post_request ~body "/system/update" with
     | hsm_state, Some (`OK, _, `String _, _) ->
       Hsm.state hsm_state = `Operational
     | _ -> false
   end

let sign_update_ok () =
  let returncode = Sys.command "../bin/sign_update.exe key.pem changes version update.bin --output=signed_update.bin" in
  assert (returncode = 0);
  let body = readfile "signed_update.bin" in
  "a request for /system/update with authenticated user returns 200"
   @? begin match admin_post_request ~body "/system/update" with
     | hsm_state, Some (`OK, _, `String _, _) ->
       Hsm.state hsm_state = `Operational
     | _ -> false
   end

let unlock_json = {|{ "passphrase": "test1234Passphrase" }|}

let unlock_ok () =
  "a request for /unlock unlocks the HSM"
  @? begin match request ~meth:`POST ~body:(`String unlock_json) ~hsm_state:(locked_mock ()) "/unlock" with
  | hsm_state, Some (`No_content, _, _, _) -> Hsm.state hsm_state = `Operational
  | _ -> false
  end

let unlock_failed () =
  "a request for /unlock with the wrong passphrase fails"
  @? begin
    let wrong_passphrase = {|{ "passphrase": "wrong" }|} in
    match request ~meth:`POST ~body:(`String wrong_passphrase) ~hsm_state:(locked_mock ()) "/unlock" with
  | hsm_state, Some (`Bad_request, _, _, _) -> Hsm.state hsm_state = `Locked
  | _ -> false
  end

let unlock_failed_two () =
  "a request for /unlock with the wrong passphrase fails"
  @? begin
    let wrong_passphrase = {|{ "passphrase": "wrongwrongwrong" }|} in
    match request ~meth:`POST ~body:(`String wrong_passphrase) ~hsm_state:(locked_mock ()) "/unlock" with
  | hsm_state, Some (`Forbidden, _, _, _) -> Hsm.state hsm_state = `Locked
  | _ -> false
  end

let unlock_twice () =
  "the first request for /unlock unlocks the HSM, the second fails"
  @? begin match request ~meth:`POST ~body:(`String unlock_json) ~hsm_state:(locked_mock ()) "/unlock" with
  | hsm_state, Some (`No_content, _, _, _) ->
    begin
      match request ~meth:`POST ~body:(`String unlock_json) ~hsm_state "/unlock" with
      | hsm', Some (`Precondition_failed, _, _, _) -> Hsm.state hsm' = `Operational
      | _ -> false
    end
  | _ -> false
  end

let lock_ok () =
  "a request for /lock locks the HSM"
  @? begin match admin_post_request ~hsm_state:(operational_mock ()) "/lock" with
  | hsm_state, Some (`No_content, _, _, _) -> Hsm.state hsm_state = `Locked
  | _ -> false
  end

let lock_failed () =
  "a request for /lock with the wrong passphrase fails"
  @? begin
  let headers = operator_headers in
  let hsm_state = operational_mock() in
  match request ~meth:`POST ~hsm_state ~headers "/lock" with
  | hsm_state, Some (`Forbidden, _, _, _) -> Hsm.state hsm_state = `Operational
  | _ -> false
  end

(* /config *)

let change_unlock_passphrase () =
  "change unlock passphrase succeeds"
  @? begin
  let passphrase = {|{ "passphrase" : "new passphrase" }|} in
  match admin_put_request ~body:(`String passphrase) "/config/unlock-passphrase" with
  | hsm_state, Some (`No_content, _, _, _) ->
    Hsm.lock hsm_state;
    begin match request ~meth:`POST ~body:(`String passphrase) ~hsm_state "/unlock" with
    | hsm_state, Some (`No_content, _, _, _) -> Hsm.state hsm_state = `Operational
    | _ -> false
    end
  | _ -> false
  end

let change_unlock_passphrase_empty () =
  "change to empty unlock passphrase fails"
  @? begin
  let passphrase = {|{ "passphrase" : "" }|} in
  match admin_put_request ~body:(`String passphrase) "/config/unlock-passphrase" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false
  end

let get_unattended_boot_ok () =
  "GET /config/unattended-boot succeeds"
  @? begin
    let headers = admin_headers in
    match request ~headers ~hsm_state:(operational_mock ()) "/config/unattended-boot" with
    | _hsm_state', Some (`OK, _, `String body, _) -> body = {|{"status":"off"}|}
    | _ -> false
  end

let unattended_boot_succeeds () =
  "unattended boot succeeds"
  @? begin
    let store, hsm_state =
      Lwt_main.run (
        Kv_mem.connect () >>= fun store ->
        Hsm.boot ~device_id:"test dispatch" store >>= fun (state, _, _) ->
        Hsm.provision state ~unlock:"unlockPassphrase" ~admin:"test1Passphrase" Ptime.epoch >|= fun _ ->
        store, state)
    in
    match admin_put_request ~body:(`String {|{ "status" : "on" }|}) ~hsm_state "/config/unattended-boot" with
    | _hsm_state', Some (`No_content, _, _, _) ->
      Lwt_main.run (Hsm.boot ~device_id:"test dispatch" store >|= fun (hsm_state, _, _) -> Hsm.state hsm_state = `Operational)
    | _ -> false
  end

let unattended_boot_failed_wrong_device_id () =
  "unattended boot failed (wrong device ID)"
  @? begin
    let store, hsm_state =
      Lwt_main.run (
        Kv_mem.connect () >>= fun store ->
        Hsm.boot ~device_id:"test dispatch" store >>= fun (state, _, _) ->
        Hsm.provision state ~unlock:"unlockPassphrase" ~admin:"test1Passphrase" Ptime.epoch >|= fun _ ->
        store, state)
    in
    match admin_put_request ~body:(`String {|{ "status" : "on" }|}) ~hsm_state "/config/unattended-boot" with
    | _hsm_state', Some (`No_content, _, _, _) ->
      Lwt_main.run (Hsm.boot ~device_id:"test other dispatch" store >|= fun (hsm_state, _, _) -> Hsm.state hsm_state = `Locked)
    | _ -> false
  end

let unattended_boot_failed () =
  "unattended boot fails to unlock"
  @? begin
    let store, hsm_state =
      Lwt_main.run (
        Kv_mem.connect () >>= fun store ->
        Hsm.boot ~device_id:"test dispatch" store >>= fun (state, _, _) ->
        Hsm.provision state ~unlock:"unlockPassphrase" ~admin:"test1Passphrase" Ptime.epoch >|= fun _ ->
        store, state)
    in
    match admin_put_request ~body:(`String {|{ "status" : "on" }|}) ~hsm_state "/config/unattended-boot" with
    | _hsm_state', Some (`No_content, _, _, _) ->
      Lwt_main.run (
        Kv_mem.remove store (Mirage_kv.Key.v "/config/device-id-salt") >>= fun _ ->
        Hsm.boot ~device_id:"test dispatch" store >|= fun (hsm_state, _, _) ->
        Hsm.state hsm_state = `Locked)
    | _ -> false
  end


let get_config_tls_public_pem () =
  "get tls public pem file succeeds"
  @? begin
  let headers = admin_headers in
  match request ~hsm_state:(operational_mock ()) ~meth:`GET ~headers "/config/tls/public.pem" with
  | _, Some (`OK, _, _, _) -> true
  | _ -> false
  end

let get_config_tls_cert_pem () =
  "get tls cert pem file succeeds"
  @? begin
  let headers = admin_headers in
  match request ~hsm_state:(operational_mock ()) ~meth:`GET ~headers "/config/tls/cert.pem" with
  | _, Some (`OK, _, _, _) -> true
  | _ -> false
  end

let put_config_tls_cert_pem () =
  "put tls cert pem file succeeds"
  @? begin
  let headers = admin_headers in
  match request ~hsm_state:(operational_mock ()) ~meth:`GET ~headers "/config/tls/cert.pem" with
  | hsm_state, Some (`OK, _, `String body, _) ->
    begin
      let content_type = "application/x-pem-file" in
      match request ~hsm_state ~meth:`PUT ~headers ~content_type ~body:(`String body) "/config/tls/cert.pem" with
      | _, Some (`Created, headers, _, _) ->
        begin match Cohttp.Header.get headers "location" with
        | None -> false
        | Some loc -> String.equal loc "/api/v1/config/tls/cert.pem"
        end
      | _ -> false
    end
  | _ -> false
  end

let put_config_tls_cert_pem_fail () =
  "post tls cert pem file fail"
  @? begin
    let headers = admin_headers in
    let content_type = "application/x-pem-file" in
    let not_a_pem = "hello this is not pem format" in
    match request ~hsm_state:(operational_mock ()) ~meth:`PUT ~headers ~content_type ~body:(`String not_a_pem) "/config/tls/cert.pem" with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  end

let subject = {|{
    "countryName": "DE",
    "stateOrProvinceName": "",
    "localityName": "Berlin",
    "organizationName": "Nitrokey",
    "organizationalUnitName": "",
    "commonName": "nethsm.local",
    "emailAddress": "info@nitrokey.com"
  }|}

let post_config_tls_csr_pem () =
  "post tls csr pem file succeeds"
  @? begin
  match admin_post_request ~body:(`String subject) "/config/tls/csr.pem" with
  | _, Some (`OK, _, `String body, _) ->
     begin match X509.Signing_request.decode_pem (Cstruct.of_string body) with
     | Ok _ -> true
     | Error _ -> false
     end
  | _ -> false
  end

let config_network_ok () =
  "GET on /config/network succeeds"
  @? begin
    let headers = admin_headers in
  match request ~hsm_state:(operational_mock ()) ~meth:`GET ~headers "/config/network" with
  | _, Some (`OK, _, `String body, _) ->
    String.equal body {|{"ipAddress":"192.168.1.1","netmask":"255.255.255.0","gateway":"0.0.0.0"}|}
  | _ -> false
  end

let config_network_set_ok () =
  "PUT on /config/network succeeds"
  @? begin
    let new_network = {|{"ipAddress":"6.6.6.6","netmask":"255.255.255.0","gateway":"0.0.0.0"}|} in
    match admin_put_request ~body:(`String new_network) "/config/network" with
    | hsm_state, Some (`No_content, _, _, _) ->
      begin match request ~hsm_state ~meth:`GET ~headers:admin_headers "/config/network" with
        | _, Some (`OK, _, `String body, _) -> String.equal body new_network
        | _ -> false
      end
  | _ -> false
  end

let config_network_set_fail () =
  "PUT with invalid IP address on /config/network fails"
  @? begin
    let new_network = {|{"ipAddress":"6.6.6.666","netmask":"255.255.255.0","gateway":"0.0.0.0"}|} in
    match admin_put_request ~body:(`String new_network) "/config/network" with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  end

let config_logging_ok () =
  "GET on /config/logging succeeds"
  @? begin
    let headers = admin_headers in
  match request ~hsm_state:(operational_mock ()) ~meth:`GET ~headers "/config/logging" with
  | _, Some (`OK, _, `String body, _) ->
    String.equal body {|{"ipAddress":"0.0.0.0","port":514,"logLevel":"info"}|}
  | _ -> false
  end

let config_logging_set_ok () =
  "PUT on /config/logging succeeds"
  @? begin
    let new_logging = {|{"ipAddress":"6.6.6.6","port":514,"logLevel":"error"}|} in
    match admin_put_request ~body:(`String new_logging) "/config/logging" with
    | hsm_state, Some (`No_content, _, _, _) ->
      begin match request ~hsm_state ~meth:`GET ~headers:admin_headers "/config/logging" with
        | _, Some (`OK, _, `String body, _) -> String.equal body new_logging
        | _ -> false
      end
  | _ -> false
  end

let config_logging_set_fail () =
  "PUT with invalid logLevel on /config/logging fails"
  @? begin
    let new_logging = {|{"ipAddress":"6.6.6.6","port":514,"logLevel":"nonexisting"}|} in
    match admin_put_request ~body:(`String new_logging) "/config/logging" with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  end

let config_time_ok () =
  "GET on /config/time succeeds"
  @? begin
  match request ~hsm_state:(operational_mock ()) ~headers:admin_headers "/config/time" with
    | _, Some (`OK, _, `String body, _) ->
      begin match Yojson.Safe.from_string body with
        | `Assoc [ "time" , `String time ] ->
          begin match Ptime.of_rfc3339 time with Ok _ -> true | _ -> false end
        | _ -> false
      end
  | _ -> false
  end

let config_time_set_ok () =
  "PUT on /config/time succeeds"
  @? begin
    let new_time = {|{time: "1970-01-01T00:00:00-00:00"}|} in
    match admin_put_request ~body:(`String new_time) "/config/time" with
    | hsm_state, Some (`No_content, _, _, _) ->
      begin match request ~hsm_state ~headers:admin_headers "/config/time" with
        | _, Some (`OK, _, `String body, _) ->
          begin match Yojson.Safe.from_string body with
            | `Assoc [ "time" , `String time ] ->
              begin match Ptime.of_rfc3339 time with Ok _ -> true | _ -> false end
            | _ -> false
          end
        | _ -> false
      end
  | _ -> false
  end

let config_time_set_fail () =
  "PUT with invalid timestamp on /config/time fails"
  @? begin
    let new_time = {|{time: "1234"}|} in
    match admin_put_request ~body:(`String new_time) "/config/time" with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  end

let set_backup_passphrase () =
  "set backup passphrase succeeds"
  @? begin
  let passphrase = {|{ "passphrase" : "my backup passphrase" }|} in
  match admin_put_request ~body:(`String passphrase) "/config/backup-passphrase" with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false
  end

let set_backup_passphrase_empty () =
  "set empty backup passphrase fails"
  @? begin
  let passphrase = {|{ "passphrase" : "" }|} in
  match admin_put_request ~body:(`String passphrase) "/config/backup-passphrase" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false
  end

let invalid_config_version () =
  assert_raises (Invalid_argument "broken NetHSM")
    (fun () ->
       Lwt_main.run (
         Kv_mem.connect () >>= fun data ->
         Kv_mem.set data (Mirage_kv.Key.v "config/version") "abcdef" >>= fun _ ->
         Hsm.boot ~device_id:"test dispatch" data)) ;
  assert_raises (Invalid_argument "broken NetHSM")
    (fun () ->
       Lwt_main.run (
         Kv_mem.connect () >>= fun data ->
         Kv_mem.set data (Mirage_kv.Key.v "config/version") "" >>= fun _ ->
         Hsm.boot ~device_id:"test dispatch" data))

let config_version_but_no_salt () =
  assert_raises (Invalid_argument "fatal!")
    (fun () ->
       Lwt_main.run (
         Kv_mem.connect () >>= fun data ->
         Kv_mem.set data (Mirage_kv.Key.v "config/version") "0" >>= fun _ ->
         Hsm.boot ~device_id:"test dispatch" data))

let users_get () =
  "GET on /users/ succeeds"
  @? begin
  match request ~hsm_state:(operational_mock ()) ~headers:admin_headers "/users" with
  | _, Some (`OK, _, `String data, _) ->
   let expected ={|[{"user":"admin"},{"user":"backup"},{"user":"operator"}]|} in
   String.equal data expected
  | _ -> false
  end

let operator_json = {| { realName: "Jane User", role: "Operator", passphrase: "Very secret" } |}

let users_post () =
  "POST on /users/ succeeds"
  @? begin
  match admin_post_request ~body:(`String operator_json) "/users" with
  | _, Some (`Created, headers, _, _) ->
        begin match Cohttp.Header.get headers "location" with
        | None -> false
        | Some loc -> 
           let prefix = "/api/v1/users/" in
           String.equal (String.sub loc 0 (String.length prefix)) prefix
        end
  | _ -> false
  end

let user_operator_add () =
  "PUT on /users/op succeeds"
  @? begin
  match admin_put_request ~body:(`String operator_json) "/users/op" with
  | _, Some (`Created, headers, _, _) ->
        begin match Cohttp.Header.get headers "location" with
        | None -> false
        | Some loc -> String.equal loc "/api/v1/users/op"
        end
  | _ -> false
  end

let user_operator_add_empty_passphrase () =
  let operator_json = {| { realName: "Jane User", role: "Operator", passphrase: "" } |} in
  "PUT on /users/op succeeds"
  @? begin
  match admin_put_request ~body:(`String operator_json) "/users/op" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false
  end

let user_operator_add_invalid_id () =
  "PUT on /users/op fails (invalid id)"
  @? begin
  match admin_put_request ~body:(`String operator_json) "/users//" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false
  end

let user_operator_delete () =
  "DELETE on /users/operator succeeds"
  @? begin
  match request ~hsm_state:(operational_mock ()) ~meth:`DELETE ~headers:admin_headers "/users/operator" with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false
  end

let user_operator_delete_not_found () =
  "DELETE on /users/operator fails (not found)"
  @? begin
  match request ~hsm_state:(operational_mock ()) ~meth:`DELETE ~headers:admin_headers "/users/operator2" with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false
  end

let user_operator_delete_invalid_id () =
  "DELETE on /users/operator fails (invalid ID)"
  @? begin
  match request ~hsm_state:(operational_mock ()) ~meth:`DELETE ~headers:admin_headers "/users//" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false
  end

let user_operator_delete_fails () =
  "DELETE on /users/operator fails (requires administrator privileges)"
  @? begin
    let headers = auth_header "operator" "test2Passphrase" in
  match request ~hsm_state:(operational_mock ()) ~meth:`DELETE ~headers "/users/operator" with
  | _, Some (`Forbidden, _, _, _) -> true
  | _ -> false
  end

let user_op_delete_fails () =
  "DELETE on /users/op fails (user does not exist)"
  @? begin
  match request ~hsm_state:(operational_mock ()) ~meth:`DELETE ~headers:admin_headers "/users/op" with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false
  end

let user_operator_get () =
  "GET on /users/operator succeeds"
  @? begin
  match request ~hsm_state:(operational_mock ()) ~headers:admin_headers "/users/operator" with
  | _, Some (`OK, _, `String data, _) -> String.equal data {|{"realName":"operator","role":"Operator"}|}
  | _ -> false
  end

let user_operator_get_not_found () =
  "GET on /users/op returns not found"
  @? begin
  match request ~hsm_state:(operational_mock ()) ~headers:admin_headers "/users/op" with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false
  end

let user_operator_get_invalid_id () =
  "GET on /users// returns bad request"
  @? begin
  match request ~hsm_state:(operational_mock ()) ~headers:admin_headers "/users//" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false
  end

let user_version_get_bad_request () =
  "GET on /users/.version returns bad request"
  @? begin
  match request ~hsm_state:(operational_mock ()) ~headers:admin_headers "/users/.version" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false
  end

let user_version_delete_fails_invalid_id () =
  "DELETE on /users/.version fails"
  @? begin
  match request ~hsm_state:(operational_mock ()) ~meth:`DELETE ~headers:admin_headers "/users/.version" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false
  end

let user_passphrase_post () =
  "POST on /users/admin/passphrase succeeds"
  @? begin
    let new_passphrase = "my super new passphrase" in
    match admin_post_request ~body:(`String ("{\"passphrase\":\"" ^ new_passphrase ^ "\"}")) "/users/admin/passphrase" with
  | hsm_state, Some (`No_content, _, _, _) ->
     begin
       match request ~hsm_state ~meth:`GET ~headers:admin_headers "/users/admin" with
       | _, Some (`Unauthorized, _, _, _) ->
          begin
            let headers = auth_header "admin" new_passphrase in
            match request ~hsm_state ~headers "/users/admin" with
            | _, Some (`OK, _, _, _) -> true
            | _ -> false
          end
       | _ -> false
     end
  | _ -> false
  end

let user_passphrase_operator_post () =
  "POST on /users/operator/passphrase succeeds"
  @? begin
    let headers = auth_header "operator" "test2Passphrase" in
    let new_passphrase = "my super new passphrase" in
    match request ~hsm_state:(operational_mock ()) ~body:(`String ("{\"passphrase\":\"" ^ new_passphrase ^ "\"}")) ~meth:`POST ~headers "/users/operator/passphrase" with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false
  end

let user_passphrase_administrator_post () =
  "POST on /users/admin/passphrase fails as operator"
  @? begin
    let headers = auth_header "operator" "test2Passphrase" in
    let new_passphrase = "my super new passphrase" in
    match request ~hsm_state:(operational_mock ()) ~body:(`String ("{\"passphrase\":\"" ^ new_passphrase ^ "\"}")) ~meth:`POST ~headers "/users/admin/passphrase" with
  | _, Some (`Forbidden, _, _, _) -> true
  | _ -> false
  end

let user_passphrase_post_fails_not_found () =
  "POST on /users/foobar/passphrase fails (not found)"
  @? begin
    let new_passphrase = "my super new passphrase" in
    match admin_post_request ~body:(`String ("{\"passphrase\":\"" ^ new_passphrase ^ "\"}")) "/users/foobar/passphrase" with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false
  end

let user_passphrase_post_fails_invalid_id () =
  "POST on /users//passphrase fails (invalid ID)"
  @? begin
    let new_passphrase = "my super new passphrase" in
    match admin_post_request ~body:(`String ("{\"passphrase\":\"" ^ new_passphrase ^ "\"}")) "/users//passphrase" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false
  end

let keys_get () =
  "GET on /keys succeeds"
  @? begin match request ~headers:admin_headers ~hsm_state:(operational_mock ()) "/keys" with
  | _, Some (`OK, _, `String body, _) -> String.equal body "[]"
  | _ -> false
  end

let key_json = {| { mechanisms: [ "RSA_Signature_PKCS1" ], type: "RSA", key: { primeP: "+hsFcOCzFRwQMwuLaFjpv6pMv6BcqmcRBBWbVaWzpaq6+ag4dRpy0tIF1852zyCYqkGu5uTkHt6ndJPfKnJISQ==", primeQ : "wxq55QRL62Z+1IrsBM6h/YBcfTHnbiojepFPAakJAU0P0j+9gsHBbPgb2iFMhQyEj0bIKdfWhaAS1oqj6awsMw==", publicExponent : "AQAB" } } |}

let keys_post_json () =
  "POST on /keys succeeds"
  @? begin
  match admin_post_request ~body:(`String key_json) "/keys" with
  | _, Some (`Created, _, _, _) -> true
  | _ -> false
  end

let key_pem = {|-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAL6csYDN7EOaO+QN
mn92flj6m93rK9hz82MPHuxqiBVhqIYeZaAqIoxoly69jEN+/OJWx5JQhsIkWKR8
GVuLfIXoP5+7Sbbj1+9WU54lybyPj9oplNq+WY5U6lXgFLR8rbRpq8mJw31hZ/X6
rjQnJDrtBDsNmj0bRA33uc8bPPKLAgMBAAECgYBU6mF5TEOQ6kj8E8NcPWGUKjD9
8CKcTyuCWd4g3GS7gcId3bTQYXT6sC2JuQ+fkhb+jkJiQFWIb8C9pjt1uPJDvxir
SwBPm4sRWIKTmXVH4rMJ1K/rhPd4biei5E+tVRuxc4Ml4b3zqnIxfCa7BIDqTmc4
rJHR6S+HU0Hr4NAIwQJBAPobBXDgsxUcEDMLi2hY6b+qTL+gXKpnEQQVm1Wls6Wq
uvmoOHUactLSBdfOds8gmKpBrubk5B7ep3ST3ypySEkCQQDDGrnlBEvrZn7UiuwE
zqH9gFx9MeduKiN6kU8BqQkBTQ/SP72CwcFs+BvaIUyFDISPRsgp19aFoBLWiqPp
rCwzAkEAjXnbig6RPs+xGi7dnRkuoIzk/UDpKjtDFNxkEf65sGzzd2YBCbz8VuUX
CQxxiJkXwreFCHdR02R/tSIwiwI6gQJBAMK+gp9eUol9nUt5/2ws9PSck7VDgsYr
uY42TK5Tk3GBAjHS/c7up6ulW+e3JTII9Kgu9s0NbEulJCiR6lrsSJECQQC5PtvX
Md8AsPjClPZa3yUjpRaBeOvFmYMVH/scXXy+hxJJwz/tl+Gtde1Gf/CeDw5TEcQy
+7ZxYTUvsOssyznW
-----END PRIVATE KEY-----|}

let keys_post_pem () =
  let query = [ ("mechanisms", [ "RSA_Signature_PKCS1" ]) ] in
  "POST on /keys succeeds"
  @? begin
  match admin_post_request ~content_type:"application/x-pem-file" ~query ~body:(`String key_pem) "/keys" with
  | _, Some (`Created, _, _, _) -> true
  | _ -> false
  end

let keys_generate () =
  let generate_json = {|{ mechanisms: [ "RSA_Decryption_PKCS1" ], type: "RSA", length: 2048 }|} in
  "POST on /keys/generate succeeds"
  @? begin
  match admin_post_request ~body:(`String generate_json) "/keys/generate" with
  | _, Some (`Created, headers, _, _) ->
    begin match Cohttp.Header.get headers "location" with
    | None -> false
    | Some loc -> (* /api/v1/keys/<keyid> *) List.length (Astring.String.cuts ~empty:false ~sep:"/" loc) = 4
    end
  | _ -> false
  end

let keys_generate_invalid_id () =
  let generate_json = {|{ mechanisms: [ "RSA_Decryption_PKCS1" ], type: "RSA", length: 2048, id: "&*&*&*" }|} in
  "POST on /keys/generate with invalid ID fails"
  @? begin
  match admin_post_request ~body:(`String generate_json) "/keys/generate" with
  | _, Some (`Bad_request, _, `String reply, _) ->
    let expected = {|{"message":"ID may only contain alphanumeric characters."}|} in
    String.equal reply expected
  | _ -> false
  end

let keys_generate_invalid_id_length () =
  let generate_json = {|{ mechanisms: [ "RSA_Decryption_PKCS1" ], type: "RSA", length: 2048, id: "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890" }|} in
  "POST on /keys/generate with invalid ID fails"
  @? begin
  match admin_post_request ~body:(`String generate_json) "/keys/generate" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false
  end

let keys_generate_invalid_mech () =
  let generate_json = {|{ mechanisms: [ "EdDSA_Signature" ], type: "RSA", length: 2048, id: "1234" }|} in
  "POST on /keys/generate with invalid mechanism fails"
  @? begin
  match admin_post_request ~body:(`String generate_json) "/keys/generate" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false
  end

let keys_generate_no_mech () =
  let generate_json = {|{ mechanisms: [ ], type: "RSA", length: 2048, id: "1234" }|} in
  "POST on /keys/generate with no mechanism fails"
  @? begin
  match admin_post_request ~body:(`String generate_json) "/keys/generate" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false
  end

let keys_generate_ed25519 () =
  "POST on /keys/generate with ED25519 succeeds"
  @? begin
  let generate_ed25519 = {|{ mechanisms: [ "EdDSA_Signature" ], type: "Curve25519" }|} in
  match admin_post_request ~body:(`String generate_ed25519) "/keys/generate" with
  | _, Some (`Created, headers, _, _) ->
    begin match Cohttp.Header.get headers "location" with
    | None -> false
    | Some loc -> (* /api/v1/keys/<keyid> *)
      List.length (Astring.String.cuts ~empty:false ~sep:"/" loc) = 4
    end
  | _ -> false
  end

let keys_generate_ed25519_explicit_keyid () =
  "POST on /keys/generate with ED25519 succeeds (with explicit key ID)"
  @? begin
  let generate_ed25519 = {|{ mechanisms: [ "EdDSA_Signature" ], type: "Curve25519", "id": "mynewkey" }|} in
  match admin_post_request ~body:(`String generate_ed25519) "/keys/generate" with
  | _, Some (`Created, headers, _, _) ->
    begin match Cohttp.Header.get headers "location" with
    | None -> false
    | Some loc -> String.equal loc "/api/v1/keys/mynewkey"
    end
  | _ -> false
  end

let keys_generate_ed25519_fail () =
  let generate_ed25519 = {|{ mechanisms: [ "RSA_Decryption_PKCS1" ], type: "Curve25519" }|} in
  "POST on /keys/generate with ED25519 fails (wrong mechanism)"
  @? begin
  match admin_post_request ~body:(`String generate_ed25519) "/keys/generate" with
  | _, Some (`Bad_request, headers, _, _) ->
    begin match Cohttp.Header.get headers "location" with
      | None -> true
      | Some _ -> false
    end
  | _ -> false
  end

  let keys_generate_generic () =
    "POST on /keys/generate with Generic succeeds"
    @? begin
    let generate_generic = {|{ mechanisms: [ "AES_Encryption_CBC" ], type: "Generic", length: 256 }|} in
    match admin_post_request ~body:(`String generate_generic) "/keys/generate" with
    | _, Some (`Created, headers, _, _) ->
      begin match Cohttp.Header.get headers "location" with
      | None -> false
      | Some loc -> (* /api/v1/keys/<keyid> *)
        List.length (Astring.String.cuts ~empty:false ~sep:"/" loc) = 4
      end
    | _ -> false
    end

    let keys_generate_generic_fail () =
      let generate_generic = {|{ mechanisms: [ "EdDSA_Signature" ], type: "Generic", length: 256 }|} in
      "POST on /keys/generate with Generic fails (wrong mechanism)"
      @? begin
      match admin_post_request ~body:(`String generate_generic) "/keys/generate" with
      | _, Some (`Bad_request, headers, _, _) ->
        begin match Cohttp.Header.get headers "location" with
          | None -> true
          | Some _ -> false
        end
      | _ -> false
      end

let test_key_pem = {|
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCwMWUcsAEksFrhssoZK09w9iTMe77qJrks542+InrqD8qj31gw
Wagnrd/x9RAvqxkmLqkiuTYOQq7ly5Vrswvwub0TleCtvhnDWg1mZQ5obSBZ8BbS
o6K8oI/pjLaVgshx8e3Dx73ekDtlQNEmYiXB4Zlhv5VZnGC+nhcw0KHj2wIDAQAB
AoGAKNvrlNGEElwLV1e84kVW8N1D/1+bEHXWb4FrL3KTioALACGlM+E2y6zYyCWK
kWNeO6qKcpD85iW0pXmmtwkYdWHFsG6fthZCsPUdVchoYDQQmCjZLNk+l4jnV66p
KowVbScx/oWDgIFw/dajFR+bDybuTjCr8QJ10LuelzRwueECQQDqBswdI669i0sW
eBMRnGD7uFYR8/pyExIkQJ+WgyYEKG+Q8rJbAVDJdhbqATtSXJb9g43aVh5ecnd9
9tR4IBgJAkEAwLx5ddawRbTJdPdG5jDDjY5716U5g1U8mgrBn6yX3cMgLsyMf2ZP
gQKQaKbSdRWgxIc0bkGpkMHbKbSTrcYtwwJBAJs5SPdm7IciNfrAR/2dWKJ9oPEl
f49cYOMUzgVaFcQaQe3FXFGKbNhDcG1jxcIaUbfzIwqXpmsEx4cQSdsnhmkCQQCw
wWjGuBBKrSUAXvKnktsUjDJpLz7Sgi4ku26dCETyfMub/71t7R9Gmlpjj3J9LEuX
UMO1xgRDHHXpBpFVEeXPAkA1JUjkAwT934dsaE5UJKw6UbSuO/aJtC3zzwlJxJ/+
q0PSmuPXlTzxujJ39G0gDqfeyhEn/ynw0ElbqB2sg4eA
-----END RSA PRIVATE KEY-----
|}

let test_key =
  match X509.Private_key.decode_pem (Cstruct.of_string test_key_pem) with
  | Ok `RSA key -> key
  | _ -> assert false

let hsm_with_key ?(mechanisms = Keyfender.Json.(MS.singleton RSA_Decryption_PKCS1)) () =
  let state = operational_mock () in
  Lwt_main.run (Hsm.Key.add_pem state mechanisms ~id:"keyID" test_key_pem >|= function
  | Ok () -> state
  | Error _ -> assert false)

let keys_key_get () =
  "GET on /keys/keyID succeeds"
  @? begin
  match request ~headers:admin_headers ~hsm_state:(hsm_with_key ()) "/keys/keyID" with
  | _, Some (`OK, _, `String data, _) ->
    let json_data = Yojson.Safe.from_string data in
    begin match json_data with
      | `Assoc xs ->
        begin
          List.exists (fun (k, v) -> k = "mechanisms" && match v with `List _ -> true | _ -> false) xs &&
          List.exists (fun (k, v) -> k = "type" && match v with `String a -> a = "RSA" | _ -> false) xs &&
          List.exists (fun (k, v) -> k = "operations" && match v with `Int _ -> true | _ -> false) xs &&
          List.exists (fun (k, v) ->
              k = "key" &&
              match v with
              | `Assoc a ->
                List.exists (fun (k, v) -> k = "modulus" && match v with `String _ -> true | _ -> false) a &&
                List.exists (fun (k, v) -> k = "publicExponent" && match v with `String _ -> true | _ -> false) a &&
                List.length a = 2
              | _ -> false)
            xs &&
          List.length xs = 4
        end
      | _ -> false
    end
  | _ -> false
  end

let keys_key_get_not_found () =
  "GET on /keys/keyID fails (ID not found)"
  @? begin
  match request ~headers:admin_headers ~hsm_state:(hsm_with_key ()) "/keys/keyID2" with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false
  end

let keys_key_get_invalid_id () =
  "GET on /keys/keyID fails (invalid ID)"
  @? begin
  match request ~headers:admin_headers ~hsm_state:(hsm_with_key ()) "/keys//" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false
  end

let keys_key_get_invalid_id2 () =
  "GET on /keys/keyID fails (invalid ID)"
  @? begin
  match request ~headers:admin_headers ~hsm_state:(hsm_with_key ()) "/keys/--" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false
  end

let keys_key_put () =
  "PUT on /keys/keyID succeeds"
  @? begin
  match admin_put_request ~body:(`String key_json) "/keys/keyID" with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false
  end

let keys_key_put_already_there () =
  "PUT on /keys/keyID succeeds"
  @? begin
  match admin_put_request ~hsm_state:(hsm_with_key ()) ~body:(`String key_json) "/keys/keyID" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false
  end

let keys_key_put_invalid_id () =
  "PUT on /keys/keyID fails (invalid ID)"
  @? begin
  match admin_put_request ~body:(`String key_json) "/keys//" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false
  end

let keys_key_delete () =
  "DELETE on /keys/keyID succeeds"
  @? begin
  match request ~meth:`DELETE ~headers:admin_headers ~hsm_state:(hsm_with_key ()) "/keys/keyID" with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false
  end

let keys_key_delete_not_found () =
  "DELETE on /keys/keyID fails (ID not found)"
  @? begin
  match request ~meth:`DELETE ~headers:admin_headers ~hsm_state:(hsm_with_key ()) "/keys/keyID2" with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false
  end

let keys_key_delete_invalid_id () =
  "DELETE on /keys/keyID fails (invalid ID)"
  @? begin
  match request ~meth:`DELETE ~headers:admin_headers ~hsm_state:(hsm_with_key ()) "/keys//" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false
  end

let admin_keys_key_public_pem () =
  "GET on /keys/keyID/public.pem succeeds"
  @? begin
  match request ~headers:admin_headers ~hsm_state:(hsm_with_key ()) "/keys/keyID/public.pem" with
  | _, Some (`OK, _, _, _) -> true
  | _ -> false
  end

let operator_keys_key_public_pem () =
  "GET on /keys/keyID/public.pem succeeds"
  @? begin
  match request ~headers:operator_headers ~hsm_state:(hsm_with_key ()) "/keys/keyID/public.pem" with
  | _, Some (`OK, _, _, _) -> true
  | _ -> false
  end

let operator_keys_key_public_pem_not_found () =
  "GET on /keys/keyID/public.pem fails (ID not found)"
  @? begin
  match request ~headers:operator_headers ~hsm_state:(hsm_with_key ()) "/keys/keyID2/public.pem" with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false
  end

let operator_keys_key_public_pem_invalid_id () =
  "GET on /keys/keyID/public.pem fails (invalid ID)"
  @? begin
  match request ~headers:operator_headers ~hsm_state:(hsm_with_key ()) "/keys//public.pem" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false
  end

let admin_keys_key_csr_pem () =
  "POST on /keys/keyID/csr.pem succeeds"
  @? begin
  match admin_post_request ~body:(`String subject) ~hsm_state:(hsm_with_key ()) "/keys/keyID/csr.pem" with
  | _, Some (`OK, headers, _, _) ->
    begin match Cohttp.Header.get headers "content-type" with
      | None -> false
      | Some ct -> String.equal ct "application/x-pem-file"
    end
  | _ -> false
  end

let operator_keys_key_csr_pem () =
  "POST on /keys/keyID/csr.pem succeeds"
  @? begin
  match request ~meth:`POST ~headers:operator_headers ~body:(`String subject) ~hsm_state:(hsm_with_key ()) "/keys/keyID/csr.pem" with
  | _, Some (`OK, _, _, _) -> true
  | _ -> false
  end

let operator_keys_key_csr_pem_not_found () =
  "POST on /keys/keyID/csr.pem fails (ID not found)"
  @? begin
  match request ~meth:`POST ~headers:operator_headers ~body:(`String subject) ~hsm_state:(hsm_with_key ()) "/keys/keyID2/csr.pem" with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false
  end

let operator_keys_key_csr_pem_invalid_id () =
  "POST on /keys/keyID/csr.pem fails (invalid ID)"
  @? begin
  match request ~meth:`POST ~headers:operator_headers ~body:(`String subject) ~hsm_state:(hsm_with_key ()) "/keys//csr.pem" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false
  end


let message = "Hi Alice! Please bring malacpörkölt for dinner!"

let encrypted_message = {|
WiugdWUSZAqia2lIJbPm1N3KHcnbZAyLklnNqKnlzDjvTR9UNgmlG2FC4jdnfvn9w9TUt5H9z7Z5
9jnWww+v9AQebiUpnps0RqwN87XDWCHhE9AdqWFnNjCA4NsoKXUFB4RhrRrBInqVKD0SFYSXVu4g
hufwzgzFoWeqJnQN6uE=
|}

let encrypted =
  Printf.sprintf {|{ mode: "PKCS1", encrypted: "%s"}|} encrypted_message

let operator_keys_key_decrypt () =
  "POST on /keys/keyID/decrypt succeeds"
  @? begin
  match request ~meth:`POST ~headers:operator_headers ~body:(`String encrypted) ~hsm_state:(hsm_with_key ()) "/keys/keyID/decrypt" with
    | _, Some (`OK, _, `String data, _) ->
      begin match Yojson.Safe.from_string data with
        | `Assoc [ "decrypted", `String decrypted ] ->
          begin match Base64.decode decrypted with
            | Error _ -> false
            | Ok decoded -> String.equal message decoded
          end
        | _ -> false
      end
    | _ -> false
  end

let operator_keys_key_decrypt_fails () =
  "POST on /keys/keyID/decrypt fails"
  @? begin
  let hsm_state = hsm_with_key ~mechanisms:Keyfender.Json.(MS.singleton RSA_Signature_PKCS1) () in
  match request ~meth:`POST ~headers:operator_headers ~body:(`String encrypted) ~hsm_state "/keys/keyID/decrypt" with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  end

let operator_keys_key_decrypt_fails_wrong_mech () =
  "POST on /keys/keyID/decrypt fails (wrong mechanism)"
  @? begin
  let hsm_state = hsm_with_key ~mechanisms:Keyfender.Json.(MS.singleton RSA_Decryption_RAW) () in
  match request ~meth:`POST ~headers:operator_headers ~body:(`String encrypted) ~hsm_state "/keys/keyID/decrypt" with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  end

let operator_keys_key_decrypt_fails_invalid_id () =
  "POST on /keys/keyID/decrypt fails (invalid ID)"
  @? begin
  match request ~meth:`POST ~headers:operator_headers ~body:(`String encrypted) ~hsm_state:(hsm_with_key ()) "/keys//decrypt" with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  end

let operator_keys_key_decrypt_fails_not_found () =
  "POST on /keys/keyID/decrypt fails (ID not found)"
  @? begin
  match request ~meth:`POST ~headers:operator_headers ~body:(`String encrypted) ~hsm_state:(hsm_with_key ()) "/keys/keyID2/decrypt" with
    | _, Some (`Not_found, _, _, _) -> true
    | _ -> false
  end

let sign_request =
  Printf.sprintf {|{ mode: "PKCS1", message: "%s"}|}
    (Base64.encode_string message)

let operator_keys_key_sign () =
  "POST on /keys/keyID/sign succeeds"
  @? begin
    let hsm_state = hsm_with_key ~mechanisms:Keyfender.Json.(MS.singleton RSA_Signature_PKCS1) () in
  match request ~meth:`POST ~headers:operator_headers ~body:(`String sign_request) ~hsm_state "/keys/keyID/sign" with
    | _, Some (`OK, _, `String data, _) ->
      begin match Yojson.Safe.from_string data with
        | `Assoc [ "signature", `String signature ] ->
          begin match Base64.decode signature with
            | Error _ -> false
            | Ok decoded ->
              let key = Mirage_crypto_pk.Rsa.pub_of_priv test_key in
              match Mirage_crypto_pk.Rsa.PKCS1.sig_decode ~key @@ Cstruct.of_string decoded with
              | Some msg -> String.equal (Cstruct.to_string msg) message
              | None -> false
          end
        | _ -> false
      end
    | _ -> false
  end

let operator_keys_key_sign_fails () =
  "POST on /keys/keyID/sign fails"
  @? begin
    let hsm_state = hsm_with_key () in
  match request ~meth:`POST ~headers:operator_headers ~body:(`String sign_request) ~hsm_state "/keys/keyID/sign" with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  end

let operator_keys_key_sign_fails_bad_data () =
  "POST on /keys/keyID/sign fails (msg too short)"
  @? begin
    let hsm_state = hsm_with_key ~mechanisms:Keyfender.Json.(MS.singleton RSA_Signature_PSS_SHA256) () in
    let sign_request =
      {|{ mode: "PSS_SHA256", message: "nhrfotu32409ru0rgert45z54z099u23r03498uhtr=="}|}
    in
    match request ~meth:`POST ~headers:operator_headers ~body:(`String sign_request) ~hsm_state "/keys/keyID/sign" with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  end

let operator_keys_key_sign_fails_wrong_mech () =
  "POST on /keys/keyID/sign fails (wrong mechanism)"
  @? begin
    let mechanisms = Keyfender.Json.(MS.singleton RSA_Signature_PSS_MD5) in
    let hsm_state = hsm_with_key ~mechanisms () in
    match request ~meth:`POST ~headers:operator_headers ~body:(`String sign_request) ~hsm_state "/keys/keyID/sign" with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  end

let operator_keys_key_sign_fails_invalid_id () =
  "POST on /keys/keyID/sign fails (invalid ID)"
  @? begin
    let hsm_state = hsm_with_key ~mechanisms:Keyfender.Json.(MS.singleton RSA_Signature_PKCS1) () in
    match request ~meth:`POST ~headers:operator_headers ~body:(`String sign_request) ~hsm_state "/keys//sign" with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  end

let operator_keys_key_sign_fails_not_found () =
  "POST on /keys/keyID/sign fails (ID not found)"
  @? begin
    let hsm_state = hsm_with_key ~mechanisms:Keyfender.Json.(MS.singleton RSA_Signature_PKCS1) () in
    match request ~meth:`POST ~headers:operator_headers ~body:(`String sign_request) ~hsm_state "/keys/keyID2/sign" with
    | _, Some (`Not_found, _, _, _) -> true
    | _ -> false
  end

let operator_keys_key_sign_and_decrypt () =
  "POST on /keys/keyID/decrypt succeeds with sign and decrypt key"
  @? begin
  let mechanisms = Keyfender.Json.(MS.add RSA_Decryption_PKCS1 (MS.singleton RSA_Signature_PKCS1)) in
  let hsm_state = hsm_with_key ~mechanisms () in
  match request ~meth:`POST ~headers:operator_headers ~body:(`String encrypted) ~hsm_state "/keys/keyID/decrypt" with
    | _, Some (`OK, _, `String data, _) ->
      begin match Yojson.Safe.from_string data with
        | `Assoc [ "decrypted", `String decrypted ] ->
          begin match Base64.decode decrypted with
            | Error _ -> false
            | Ok decoded ->
              String.equal message decoded &&
              (match request ~meth:`POST ~headers:operator_headers ~body:(`String sign_request) ~hsm_state "/keys/keyID/sign" with
               | _, Some (`OK, _, `String data, _) ->
                 begin match Yojson.Safe.from_string data with
                   | `Assoc [ "signature", `String signature ] ->
                     begin match Base64.decode signature with
                       | Error _ -> false
                       | Ok decoded ->
                         let key = Mirage_crypto_pk.Rsa.pub_of_priv test_key in
                         match Mirage_crypto_pk.Rsa.PKCS1.sig_decode ~key @@ Cstruct.of_string decoded with
                         | Some msg -> String.equal (Cstruct.to_string msg) message
                         | None -> false
                     end
                   | _ -> false
                 end
               | _ -> false)
          end
        | _ -> false
      end
    | _ -> false
  end

let ed25519_priv_pem =
  {|-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
-----END PRIVATE KEY-----
|}

let hsm_with_ed25519_key () =
  let hsm_state = operational_mock () in
  Lwt_main.run (Hsm.Key.add_pem hsm_state Keyfender.Json.(MS.singleton EdDSA_Signature) ~id:"keyID" ed25519_priv_pem >|= function
    | Ok () -> hsm_state
    | Error _ -> assert false)

let ed25519_priv = match X509.Private_key.decode_pem (Cstruct.of_string ed25519_priv_pem) with
  | Ok `ED25519 priv -> priv
  | _ -> assert false

let ed25519_pub = Mirage_crypto_ec.Ed25519.pub_of_priv ed25519_priv

let operator_sign_ed25519_succeeds () =
  "POST on /keys/keyID/sign succeeds with ed25519 sign key"
  @? begin
    let hsm_state = hsm_with_ed25519_key () in
    let sign_request =
      Printf.sprintf {|{ mode: "EdDSA", message: "%s"}|}
        (Base64.encode_string message)
    in
    match request ~meth:`POST ~headers:operator_headers ~body:(`String sign_request) ~hsm_state "/keys/keyID/sign" with
    | _, Some (`OK, _, `String data, _) ->
      begin match Yojson.Safe.from_string data with
        | `Assoc [ "signature", `String signature ] ->
          begin match Base64.decode signature with
            | Error _ -> false
            | Ok signature ->
              let signature = Cstruct.of_string signature in
              Mirage_crypto_ec.Ed25519.verify ~key:ed25519_pub signature ~msg:(Cstruct.of_string message)
          end
        | _ -> false
      end
    | _ -> false
  end

let operator_sign_ed25519_fails () =
  "POST on /keys/keyID/sign fails with ed25519 sign key (bad mode)"
  @? begin
    let hsm_state = hsm_with_ed25519_key () in
    let sign_request =
      Printf.sprintf {|{ mode: "PKCS1", message: "%s"}|}
        (Base64.encode_string message)
    in
    match request ~meth:`POST ~headers:operator_headers ~body:(`String sign_request) ~hsm_state "/keys/keyID/sign" with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  end

let keys_key_get_ed25519 () =
  "GET on /keys/keyID succeeds with ED25519 key"
  @? begin
  match request ~headers:admin_headers ~hsm_state:(hsm_with_ed25519_key ()) "/keys/keyID" with
  | _, Some (`OK, _, _, _) -> true
  | _ -> false
  end

let ed25519_json =
  let b64 = Base64.encode_string (Cstruct.to_string (Mirage_crypto_ec.Ed25519.priv_to_cstruct ed25519_priv)) in
  Printf.sprintf {| { mechanisms: [ "EdDSA_Signature" ], type: "Curve25519", key: { data: "%s" } } |} b64

let keys_key_put_ed25519 () =
  "PUT on /keys/keyID succeeds with ED25519 key"
  @? begin
  match admin_put_request ~body:(`String ed25519_json) "/keys/keyID" with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false
  end

let operator_keys_key_public_pem_ed25519 () =
  "GET on /keys/keyID/public.pem succeeds"
  @? begin
  match request ~headers:operator_headers ~hsm_state:(hsm_with_ed25519_key ()) "/keys/keyID/public.pem" with
  | _, Some (`OK, _, `String body, _) -> String.equal body (Cstruct.to_string (X509.Public_key.encode_pem (`ED25519 ed25519_pub)))
  | _ -> false
  end

let generic_key = "secretsecretsecretsecretsecretse"
let aes_message = "messagemessagemessagemessagemess"
let aes_cbc_iv = "iviviviviviviviv"
let aes_cbc_encrypted = "bx4qzXVP7jEUogLTcsaMcOOe1TZFS2zQTwebJNzTS90="

let add_generic state ~id ms key =
  let json_key = { Keyfender.Json.data = Base64.encode_string key ; 
    primeP = ""; primeQ = ""; publicExponent = "" } in
  match Lwt_main.run (Hsm.Key.add_json ~id state ms Generic json_key) with
  | Ok () -> ()
  | Error _ -> assert false

let hsm_with_generic_key () =
  let hsm_state = operational_mock () in
  add_generic hsm_state Keyfender.Json.(MS.of_list [ AES_Decryption_CBC; AES_Encryption_CBC ]) ~id:"keyID" generic_key;
  hsm_state

let operator_decrypt_aes_cbc_succeeds () =
  "POST on /keys/keyID/decrypt succeeds with AES CBC"
  @? begin
    let hsm_state = hsm_with_generic_key () in
    let decrypt_request =
      Printf.sprintf {|{ mode: "AES_CBC", iv: "%s", encrypted: "%s"}|}
        (Base64.encode_string aes_cbc_iv) aes_cbc_encrypted
    in
    match request ~meth:`POST ~headers:operator_headers ~body:(`String decrypt_request) ~hsm_state "/keys/keyID/decrypt" with
    | _, Some (`OK, _, `String data, _) ->
      begin match Yojson.Safe.from_string data with
        | `Assoc [ "decrypted", `String decrypted ] ->
          begin match Base64.decode decrypted with
            | Error _ -> false
            | Ok m -> String.equal aes_message m
          end
        | _ -> false
      end
    | _ -> false
  end

let operator_decrypt_aes_cbc_no_iv_fails () =
  "POST on /keys/keyID/decrypt succeeds with AES CBC"
  @? begin
    let hsm_state = hsm_with_generic_key () in
    let decrypt_request =
      Printf.sprintf {|{ mode: "AES_CBC", encrypted: "%s"}|}
        aes_cbc_encrypted
    in
    match request ~meth:`POST ~headers:operator_headers ~body:(`String decrypt_request) ~hsm_state "/keys/keyID/decrypt" with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  end

let operator_encrypt_aes_cbc_succeeds () =
  "POST on /keys/keyID/decrypt succeeds with AES CBC"
  @? begin
    let hsm_state = hsm_with_generic_key () in
    let encrypt_request =
      Printf.sprintf {|{ mode: "AES_CBC", iv: "%s", message: "%s"}|}
        (Base64.encode_string aes_cbc_iv) (Base64.encode_string aes_message)
    in
    Printf.eprintf "request: %s" encrypt_request;
    match request ~meth:`POST ~headers:operator_headers ~body:(`String encrypt_request) ~hsm_state "/keys/keyID/encrypt" with
    | _, Some (`OK, _, `String data, _) ->
      Printf.eprintf "response: %s" data;
      begin match Yojson.Safe.from_string data with
        | `Assoc [ "encrypted", `String encrypted; "iv", `String iv ] ->
          begin match Base64.decode encrypted with
            | Error _ -> false
            | Ok _ -> String.equal aes_cbc_encrypted encrypted && String.equal iv (Base64.encode_string aes_cbc_iv)
          end
        | _ -> false
      end
    | _ -> false
  end

let operator_encrypt_aes_cbc_no_iv_succeeds () =
  "POST on /keys/keyID/decrypt succeeds with AES CBC"
  @? begin
    let hsm_state = hsm_with_generic_key () in
    let encrypt_request =
      Printf.sprintf {|{ mode: "AES_CBC", message: "%s"}|}
        (Base64.encode_string aes_message)
    in
    Printf.eprintf "request: %s" encrypt_request;
    match request ~meth:`POST ~headers:operator_headers ~body:(`String encrypt_request) ~hsm_state "/keys/keyID/encrypt" with
    | _, Some (`OK, _, `String data, _) ->
      Printf.eprintf "response: %s" data;
      begin match Yojson.Safe.from_string data with
        | `Assoc [ "encrypted", `String encrypted_b64; "iv", `String iv ] ->
          begin match Base64.decode encrypted_b64 with
            | Error _ -> false
            | Ok encrypted ->
              let iv = Base64.decode_exn iv |> Cstruct.of_string in
              let key = Cstruct.of_string generic_key |> Mirage_crypto.Cipher_block.AES.CBC.of_secret in
              let encrypted_cs = Cstruct.of_string encrypted in
              let m = Mirage_crypto.Cipher_block.AES.CBC.decrypt ~key ~iv encrypted_cs |> Cstruct.to_string in
              String.equal m aes_message
          end
        | _ -> false
      end
    | _ -> false
  end

let keys_key_get_generic () =
  "GET on /keys/keyID succeeds with Generic key"
  @? begin
  match request ~headers:admin_headers ~hsm_state:(hsm_with_generic_key ()) "/keys/keyID" with
  | _, Some (`OK, _, _, _) -> true
  | _ -> false
  end

let generic_json =
  let b64 = Base64.encode_string generic_key in
  Printf.sprintf {| { mechanisms: [ "AES_Encryption_CBC" ], type: "Generic", key: { data: "%s" } } |} b64

let keys_key_put_generic () =
  "PUT on /keys/keyID succeeds with Generic key"
  @? begin
  match admin_put_request ~body:(`String generic_json) "/keys/keyID" with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false
  end

let keys_key_cert_get () =
  "GET on /keys/keyID/cert succeeds"
  @? begin
    let hsm_state = hsm_with_key () in
    let _ = Lwt_main.run (Hsm.Key.set_cert hsm_state ~id:"keyID" ~content_type:"foo/bar" "data") in
    match request ~headers:operator_headers ~hsm_state "/keys/keyID/cert" with
    | _, Some (`OK, headers, `String data, _) ->
      begin match Cohttp.Header.get headers "content-type" with
        | Some "foo/bar" -> String.equal data "data"
        | _ -> false
      end
    | _ -> false
  end

let keys_key_cert_get_not_found () =
  "GET on /keys/keyID/cert fails (ID not found)"
  @? begin
    let hsm_state = hsm_with_key () in
    match request ~headers:operator_headers ~hsm_state "/keys/keyID2/cert" with
    | _, Some (`Not_found, _, _, _) -> true
    | _ -> false
  end

let keys_key_cert_get_invalid_id () =
  "GET on /keys/keyID/cert fails (invalid ID)"
  @? begin
    let hsm_state = hsm_with_key () in
    match request ~headers:operator_headers ~hsm_state "/keys//cert" with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  end

let keys_key_cert_put () =
  "PUT on /keys/keyID/cert succeeds"
  @? begin
    let hsm_state = hsm_with_key () in
    match admin_put_request ~body:(`String "data") ~hsm_state "/keys/keyID/cert" with
    | _, Some (`Created, _, _, _) -> true
    | _ -> false
  end

let keys_key_cert_put_fails () =
  "PUT on /keys/keyID/cert fails (wrong content type)"
  @? begin
    let hsm_state = hsm_with_key () in
    match admin_put_request ~content_type:"text/html" ~body:(`String "data") ~hsm_state "/keys/keyID/cert" with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  end

let keys_key_cert_put_not_found () =
  "PUT on /keys/keyID/cert fails (ID not found)"
  @? begin
    let hsm_state = hsm_with_key () in
    match admin_put_request ~body:(`String "data") ~hsm_state "/keys/keyID2/cert" with
    | _, Some (`Not_found, _, _, _) -> true
    | _ -> false
  end

let keys_key_cert_put_invalid_id () =
  "PUT on /keys/keyID/cert fails (invalid ID)"
  @? begin
    let hsm_state = hsm_with_key () in
    match admin_put_request ~body:(`String "data") ~hsm_state "/keys//cert" with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  end

let keys_key_cert_delete () =
  "DELETE on /keys/keyID/cert succeeds"
  @? begin
    let hsm_state = hsm_with_key () in
    let _ = Lwt_main.run (Hsm.Key.set_cert hsm_state ~id:"keyID" ~content_type:"text/plain" "data") in
    match request ~meth:`DELETE ~headers:admin_headers ~hsm_state "/keys/keyID/cert" with
    | _, Some (`No_content, _, _, _) -> true
    | _ -> false
  end

let keys_key_cert_delete_not_found () =
  "DELETE on /keys/keyID/cert fails (ID not found)"
  @? begin
    let hsm_state = hsm_with_key () in
    match request ~meth:`DELETE ~headers:admin_headers ~hsm_state "/keys/keyID2/cert" with
    | _, Some (`Not_found, _, _, _) -> true
    | _ -> false
  end

let keys_key_cert_delete_invalid_id () =
  "DELETE on /keys/keyID/cert fails (invalid ID)"
  @? begin
    let hsm_state = hsm_with_key () in
    match request ~meth:`DELETE ~headers:admin_headers ~hsm_state "/keys//cert" with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  end

let keys_key_version_get_fails () =
  "GET on /keys/.version fails"
  @? begin
  match request ~headers:admin_headers ~hsm_state:(hsm_with_key ()) "/keys/.version" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false
  end

let keys_key_version_delete_fails () =
  "DELETE on /keys/.version fails"
  @? begin
  match request ~meth:`DELETE ~headers:admin_headers ~hsm_state:(hsm_with_key ()) "/keys/.version" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false
  end

let keys_key_version_cert_get_fails () =
  "GET on /keys/.version/cert fails"
  @? begin
    let hsm_state = hsm_with_key () in
    let _ = Lwt_main.run (Hsm.Key.set_cert hsm_state ~id:".version" ~content_type:"foo/bar" "data") in
    match request ~headers:operator_headers ~hsm_state "/keys/.version/cert" with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  end

let keys_key_version_cert_put_fails () =
  "PUT on /keys/.version/cert fails"
  @? begin
    let hsm_state = hsm_with_key () in
    match admin_put_request ~body:(`String "data") ~hsm_state "/keys/.version/cert" with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  end

let keys_key_version_cert_delete_fails () =
  "DELETE on /keys/.version/cert fails"
  @? begin
    let hsm_state = hsm_with_key () in
    let _ = Lwt_main.run (Hsm.Key.set_cert hsm_state ~id:".version" ~content_type:"foo/bar" "data") in
    match request ~meth:`DELETE ~headers:admin_headers ~hsm_state "/keys/.version/cert" with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  end

let unlock_rate_limit = 10

let rate_limit_for_unlock () =
  let path = "/unlock" in
  "rate limit for unlock"
  @? begin
    let hsm_state = locked_mock () in
    for _ = 1 to unlock_rate_limit do
      ignore (request ~hsm_state path)
    done;
    match request ~hsm_state path with
    | _, Some (`Too_many_requests, _, _, _) -> true
    | _ -> false
  end

let rate_limit = 10

let rate_limit_for_get () =
  let path = "/system/info" in
  "rate limit for get"
  @? begin
    let hsm_state = operational_mock () in
    let headers = auth_header "not a valid user" "no valid password" in
    for _ = 0 to rate_limit do
      ignore (request ~hsm_state ~headers path)
    done;
    match request ~hsm_state ~headers path with
    | _, Some (`Too_many_requests, _, _, _) ->
     begin match request ~hsm_state ~headers:admin_headers ~ip:Ipaddr.V4.localhost path with
     | _, Some (`OK, _, _, _) -> true
     | _ -> false
     end
    | _ -> false
  end

let reset_rate_limit_after_successful_login () =
  let path = "/system/info" in
  "rate limit is reset after successful login"
  @? begin
    let hsm_state = operational_mock () in
    let headers = auth_header "not a valid user" "no valid password" in
    for _ = 1 to rate_limit - 1 do
      ignore (request ~hsm_state ~headers ~ip:Ipaddr.V4.localhost path)
    done;
    (* one request left before the rate limit returns Too_many_requests *)
    (* reset the rate limit by a successful request *)
    begin match request ~hsm_state ~headers:admin_headers ~ip:Ipaddr.V4.localhost path with
      | _, Some (`OK, _, _, _) ->
        (* test rate_limit requests again *)
        begin match request ~hsm_state ~headers ~ip:Ipaddr.V4.localhost path with
          | _, Some (`Unauthorized, _, _, _) ->
            begin
              for _ = 1 to rate_limit - 1 do
                ignore (request ~hsm_state ~headers ~ip:Ipaddr.V4.localhost path)
              done;
              match request ~hsm_state ~headers ~ip:Ipaddr.V4.localhost path with
              | _, Some (`Unauthorized, _, _, _) ->
                begin match request ~hsm_state ~headers ~ip:Ipaddr.V4.localhost path with
                  | _, Some (`Too_many_requests, _, _, _) -> true
                  | _ -> false
                end
              | _ -> false
            end
        | _ -> false
        end ;
      | _ -> false
    end
  end

let auth_decode_invalid_base64 () =
  let auth_header user pass =
    let base64 = "wrong" ^ Base64.encode_string (user ^ ":" ^ pass) in
    Header.init_with "authorization" ("Basic " ^ base64)
  in
  let admin_headers = auth_header "admin" "test1Passphrase" in
  "a request for /system/info with wrong base64 in user authentication returns 401"
   @? begin match request ~hsm_state:(operational_mock ()) ~headers:admin_headers "/system/info" with
      | _hsm_state, Some (`Unauthorized, _, _, _) -> true
      | _ -> false
   end

let rsa2048_priv_pem = {|-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx1CQY/rCAyoh2vJ6aNQi2W3jxx8yynoo1L433lhGcDtaPQaq
+jDlucORkb190MlqbBslXPGDyCUPq5c3GLV7u2dp5Xe2NsMQ23+ijqssKo290La9
Lvcmz34+StCB6HcoPXyw8vni4TZwmNwDTvaxBLXV/wg7s96cLu6+gexjSsgcXFkJ
zVF9PFi4ijyyxzhRLxWzVDwSXgtL7gcl/VXrnJwKepGBj7O9MT87M1fCLkrpnE2l
Z7XQ5wKFWWLVQScqLEn7NZYqyQAZ8lvKNt2uItSZuVCVvuuM9HjDdHuqprf0dDbP
o7IJuuaDv+1ehcxcW2pmbgjk6lnrlOSBga7klQIDAQABAoIBAQCtqJ81zUzvTu1S
hARtg6+dfCaC3sb1LbyXp+irnIQ60yvLkhy0gpgV47TYo56UpHlKGdjTA0cLwmbF
3anOqIlW/kKBAW3MhucQKEPtRGzl4ruotx9cZVD2ZotFyif18KQp9pOCEIFCMpmm
RcPIMB6J+Rir7XN/Q40XQ0LPlrPoearBW999Lc5zbg715F7cfctTEsOL3+RKncsx
Fj9XkbYXBVWpL5Six0eJAK/0yRSxHfAVfFs4RzRJokyBK6oDt+41U7saZkyOn3ER
Q9fm8b4MsxrOAiQ/yVCOPX7sGbVB+n6y5XNyWYYavERydM/h3DMon3OltqwlxKQn
EMm+rCR9AoGBAOOKVIoovynxEeNmhiCjx2bLr9jaHiJoKfLqB9CVbxw9lUkvE/3s
j4U/bNW8+AGqrDylSCmYa3dI8lYTtFb2VXUQF5CU7903mgxrYNl0zjfhk/cwk1Xa
ILNBku8ykfUiNcfMB8pdcK7OFdSZ32Hu9aEgyAACnbCFjSKvv9H4sY0bAoGBAOA+
eEoACKLrrEBt38lq/u7yyCfWc+PfCsK7Y34kTWp/njKElFAAbhaUKRuTZOfYWLn+
9Zd6S1/LztqG7RRCyQ4X3KPw9hwxo+M/KbRw3qXg+3N6IgmB4AqVAeqKjFtEGk18
fk94HTDjfP+VoQOzgAP+WEyU6iP4MX48fKYIcOAPAoGBAKUWTyHyUEgg5MalMvlp
epoFfG8MScLS6mSZEdRvJy9JKw/u/UVFJhgaHV+x/ApRhyd1D7dGI+pm3ZRANZ7G
mNgXNdGrjaBl3/nUym7bhWcb3lwBPVSTrxf/opizixxclsKAMMLNKp1ZXpNilKUc
V9Bw1UrUmw5gxzZ8ZuLz2fYzAoGAU8WipGp8z3hhgjRJzPImyNd0BMXtx2wUlgjx
MzeWoDmKvO6ghX6ToeW5sa6PnLlK9DkWQH+UVvZJkYOkX9RPTe+GIsyq9H9q7UM0
bk9YLfntlgdDXe/h5bIi5B7cLmAzv0zJ1yBVL2Vc1hJs83gEU/mZvQpIqiVXQASS
wGgY2usCgYBNTWTUeE9Ua9rmG2SJk5mr6jCwAX9BHpl1cue+7mqKNtc+Ma98OmF8
6f5wf5MawPcuM8H/lFVgCfouD3u0AA6v39+t/qGJzv3Dr9MMTHYWOTUsMuf+JVOJ
g4nEL7yCJH4hBR0mqM/f6pnqgsQDE3c5nP4vQRmndFtMWk1dRHNqRg==
-----END RSA PRIVATE KEY-----|}

let rsa2048_pub =
  match X509.Private_key.decode_pem (Cstruct.of_string rsa2048_priv_pem) with
  | Ok `RSA k -> Mirage_crypto_pk.Rsa.pub_of_priv k
  | _ -> assert false

let add_pem state ~id ms key =
  match Lwt_main.run (Hsm.Key.add_pem ~id state ms key) with
  | Ok () -> ()
  | Error _ -> assert false

module Oaep_md5 = Mirage_crypto_pk.Rsa.OAEP(Mirage_crypto.Hash.MD5)
module Oaep_sha1 = Mirage_crypto_pk.Rsa.OAEP(Mirage_crypto.Hash.SHA1)
module Oaep_sha224 = Mirage_crypto_pk.Rsa.OAEP(Mirage_crypto.Hash.SHA224)
module Oaep_sha256 = Mirage_crypto_pk.Rsa.OAEP(Mirage_crypto.Hash.SHA256)
module Oaep_sha384 = Mirage_crypto_pk.Rsa.OAEP(Mirage_crypto.Hash.SHA384)
module Oaep_sha512 = Mirage_crypto_pk.Rsa.OAEP(Mirage_crypto.Hash.SHA512)

let enc_test_data =
  Cstruct.of_string "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd"

let crypto_rsa_decrypt () =
  let algos =
    Keyfender.Json.[
      256, "fvIOfN3+AOt3wvaRVMT6+SjlYfyeqP/llAl93KBEPcmb4eoKKAhEhoPdL6NkCr26lFKL0QuPqHA1mS8jw9nVBHFoBhBwU2dlNfa7NNlSE2Ph/FwJVF7NAXtw4LXTECYL5aPBj1Svo8IfWUQXJVPNF1HA3Uw4jxDusFNbjvT0Xk7SsPJnLT1DAQlsoV9xWjonnd53LjuHjJ1BAvq/wYnjOjvsAZu7Zp730Kg4HuBAoj3FE3wlq3/ABxS13+lEuL2RT+tJEROAWVK6J/D7ya2kCVXY+9OhIQgndUS7KRO7LhW2uhbPKs2jG/sjNgSw5NM/d0S9fcUN5IPpiPaGOzy9cw==", RAW, "RAW" ;
      245, "s0bvjV8/3BJYdtYsAGtD3yCWeGXIxreSFi0Vsw3juMyxpDOcBCl6xMjJhnHuxhdJ+HqiKSRZkgOVab9JXUUIZpr4ja1U42kOo9Zs2MYLhMrBFdkiXli6/UjHWT93GlcxIavYMOblh16FOaKlZH5cZrzfiQTeqDLBnWgZxmtKnXaNaeAZ5L8y7lT1hldS7nz0+vOSHEeW1BfbJwAuijb/hv/tSta2+78gkuRQTXAfwcePi5D7PRaRc72keX0TzHGBQulN/JuxHR2m3trEgKb3SNsZW3zLLiAWxNQqYqgCe2xuiREnQYifAdMFGF9EeT23KBFh5I2mNknLLSppR2WRwA==", PKCS1, "PKCS1" ;
      222, "fG1U6k+ZwNKxSOlTG0oUp+uz9YqWh51et7YX6/0xMGxNJrg+fB4tIhayPVE4BKY1mp/3GPYeBwiYxAI5+hG2zdMC3Z2JioghSkVrI2Ne7dt+7x6PY3UIrgPW0prx8qfQu9WGkv1RYc4tUpoAboGGO14aumwwYstMzSpsPOlt+7RFmcV4MmsfiOU7p0n4p+Fvs9T6yaczVAjx6AQLpdGFKg3u834I8S38z9fJU8MnwcYJAUrgiUVcbP4qCtQZYFL9Sx9SqS+gm9nWiTgq3pPjgvBCsRtnX8Gozd4HlCERmFqyfjjMyni+OQE4MrGcvRKcwZrm+QQxNQuTKE14ldtLiQ==", OAEP_MD5, "OAEP_MD5" ;
      214, "wS+bLk7xSUIlVSPWIm8tWr/HTEKrcr7wwN5EG96s8BiFBh4/RbsNrpAp0kxHGMyPsXBREaqObYli9hxO/YsoCNcU5PG2b/VLBPgKGZ+t9gODXu/r0ANj/tdnTrgEy2+ukOdjE5y+wRZ3R0wwj0ZzWsKfBGhPtwwjXp6yjuEnwXprt4JdINI7IJG3/JUiP79qWCrupY6e9G/Raa9B2moFdyJwNrvu7siULIJ40yutzdG6yEs2s6bh8TQQz08i5X5YPlPq73hjvr71sEnRXMcjHZAJXgtofLiGv1d8YrF6O8SABM99Y0Pj1TYO/wGb4MjIjBsgnHm/Y7wXTe6Xb/gPGg==", OAEP_SHA1, "OAEP_SHA1" ;
      198, "PMXEPfP+oaIFAJvOklA5ZRUCeoUfJHOwj2V3Oh8SQww9affvW3G40jCOg1SLFh5CiFRk3QdU4sanuuQQUiHoYeV5L6iwm/HK/B7LrS6BRrYjk7KnQR/mVgPn6hLHpAtwRWYuaUJHZQawTZHrod4XVti2vO23Cn+4S9pXAJnoJIHsb8AQAlTn01QjOMd4AhxSsT5AKeG5GRWgP1sFaTnaGQ4KKVS3cJW+MGrC6boZGN/Tjr4x5efIVp5dMnNXAU3aXb0G9C4S/WNIwp8ayoNrbL3TD/WY8GW3ypQZ78+YYb8vbYyn/gQJdqqckx9YH/AgdIXeZGrCVOSmNDxj7hrisQ==", OAEP_SHA224, "OAEP_SHA224" ;
      190, "Fj0g5jxcZJMxQChCsw2QKVLK99VAVUOhB1XPOLatEh/2NXstdMNUVOT1MBqZ+jdm1T9VYitxhsa1qxjPkDG+mMWulp7BWNo9vBIAFJgCAantNUf4j3TWAms4QVYwBOwvgyhRBL4M9abC1KvEJWnMhzy2NFtHN4p0oOKgXC6LarUkX67o+Q2e62K2VtDONrBoOqWqaPQ0aphOvd9KM32cllC95gthBzg7MVUVcQbJSVXUvm8MIAttKxTmrw/vPIfmlkKIZenEkg8eYPk3cVuyuiwJyctqQCNFJbYtDqb0/hp72I3KfJFaZViLHS8/dEwqCxuUvkqmZZft1lDjzACHWA==", OAEP_SHA256, "OAEP_SHA256" ;
      158, "nnhUPjJxUxcv2obRvC6IouLauuXxUe9ihtLTd92OThlMOIQqPaBZFKiY0cWujVyEC1aYM1+kPDQL3g2VKGD4RndwnUy9uE9FapWNn52VZq1MMMDAa5gDYQ92H9dmE4UYnym46IieZPt0hX54csqS6elwepcZPXSpdhk9D0C4Xc0+m56B8JS2/bvoHzxWHwrfL5ALutN01yiMrYkXzSuiXjdwG76SWCOZpsoj6HcP+gTglOAGIm6M80ENQfMWjNWYdF2nHhzNX2e4oVU8Nhp3/2U7ATlb2xwdwp7viMjBm6ExoqsI0fkguqLrUJ7Y5rWNWK2JmL8WQYIlUmniOvc8MA==", OAEP_SHA384, "OAEP_SHA384" ;
      126, "CZah2t+0Gq63qOi1t5QkjyX0Ja+PVVshr7AGHj72yNnDKlQJsUIAl9QFvauuzirf1d83djBXaGz5wYEv4RQ/v/RqDFnl73SI5COiSlkxKp96V3nhRoT7B5a0IGegQJLHauAIpeOprGQMYfCOKliXz2s4dSOKosM7QpnACC6qc+AONcuDFfvsX9minQByrSqUHo+iQl780HMxtnCQnJMhZIv96Om8IfoxK7AzXU/tEtkoaStLiQeLsspfu9WOHO9kwQLVYV0KldYvFWZYeYrUmsqo4/FwngFUh8Rso5Bqwp3IpGdjY4uisfyovrg0rT/V+q4vPc7/LKnUaLxsI08Oxg==", OAEP_SHA512, "OAEP_SHA512" ;
    ] in
  let hsm = operational_mock () in
  let mechs =
    List.fold_right Keyfender.Json.MS.add
      [ Keyfender.Json.RSA_Decryption_RAW ; RSA_Decryption_PKCS1 ;
        RSA_Decryption_OAEP_MD5 ; RSA_Decryption_OAEP_SHA1 ;
        RSA_Decryption_OAEP_SHA224 ; RSA_Decryption_OAEP_SHA256 ;
        RSA_Decryption_OAEP_SHA384 ; RSA_Decryption_OAEP_SHA512 ]
      Keyfender.Json.MS.empty
  in
  add_pem hsm ~id:"test" mechs rsa2048_priv_pem;
  List.iter (fun (idx, enc_data, dec_mode, txt) ->
      ("decryption with RSA " ^ txt ^ " succeeds")
      @? begin
        match Lwt_main.run (Hsm.Key.decrypt hsm ~id:"test" ~iv:None dec_mode enc_data) with
     | Ok data ->
       let b64_dec = Base64.decode_exn data in
       String.equal b64_dec Cstruct.(to_string (sub enc_test_data 0 idx))
     | Error _ -> false
      end)
    algos

let sign_test_data = Cstruct.of_string "hello"

let b64_and_hash h d =
  Base64.encode_exn (Cstruct.to_string (Mirage_crypto.Hash.digest h d))

let crypto_rsa_pkcs1_sign () =
  let hsm = operational_mock () in
  add_pem hsm ~id:"test" Keyfender.Json.(MS.singleton RSA_Signature_PKCS1) rsa2048_priv_pem;
  let signature_hc = "iGIgswYW3f1hGYutuI6T/511p41aBF0gNV1N/MdqG1Wofaj8onUDJd/LD4h7s5s8wsXJ/EoH0zMck2XovWi3TLwCoghH3nL+Dv9b9fn6YMEnYOk4Uv0klFclwvLDmpiW+8An+7WPti2zlSkCkl2diwfA6N1hBRqKpnYYWCxMHxQOXCnXfDu1fxm6+MsUP8YZ5WUtVG6BV9lm+lzktHXBAkXmCYswtUbiol5NRbOH9P1PhG37UylT22ekszC8Ime5K2PSt5+WvlzM2Ry+peCMjSS7fMnsgasnkqLrTnZrZLMD7J6jG6I4Jxq+nPAgj9sXkJ+ozqllab+4mRIJEiaPOg==" in
  "signing with RSA PKCS1 succeeds"
   @? begin match Lwt_main.run (Hsm.Key.sign hsm ~id:"test" Keyfender.Json.PKCS1 (b64_and_hash `SHA1 sign_test_data)) with
     | Ok signature ->
       assert (signature = signature_hc);
       let b64_dec = Base64.decode_exn signature in
       (match Mirage_crypto_pk.Rsa.PKCS1.sig_decode ~key:rsa2048_pub (Cstruct.of_string b64_dec) with
        | None -> false
        | Some raw -> Cstruct.equal raw (Mirage_crypto.Hash.SHA1.digest sign_test_data))
      | _ -> false
   end

let crypto_rsa_pss_sign () =
  let algos =
    Keyfender.Json.[
      `MD5, PSS_MD5, "PSS_MD5" ;
      `SHA1, PSS_SHA1, "PSS_SHA1" ;
      `SHA224, PSS_SHA224, "PSS_SHA224" ;
      `SHA256, PSS_SHA256, "PSS_SHA256" ;
      `SHA384, PSS_SHA384, "PSS_SHA384" ;
      `SHA512, PSS_SHA512, "PSS_SHA512" ;
    ] in
  let hsm = operational_mock () in
  let mechs =
    List.fold_right Keyfender.Json.MS.add
      [ Keyfender.Json.RSA_Signature_PSS_MD5 ; RSA_Signature_PSS_SHA1 ;
        RSA_Signature_PSS_SHA224 ; RSA_Signature_PSS_SHA256 ;
        RSA_Signature_PSS_SHA384 ; RSA_Signature_PSS_SHA512 ]
      Keyfender.Json.MS.empty
  in
  add_pem hsm ~id:"test" mechs rsa2048_priv_pem;
  List.iter (fun (hash, sign_mode, txt) ->
      ("signing with RSA " ^ txt ^ " succeeds")
      @? begin match Lwt_main.run (Hsm.Key.sign hsm ~id:"test" sign_mode (b64_and_hash hash sign_test_data)) with
     | Ok signature ->
       let b64_dec = Base64.decode_exn signature in
       (match X509.Public_key.verify hash ~scheme:`RSA_PSS ~signature:(Cstruct.of_string b64_dec) (`RSA rsa2048_pub) (`Message sign_test_data) with
        | Ok () -> true
        | Error _ -> false)
     | Error _ -> false
      end)
    algos

let ed25519_priv_pem = {|-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIIHCCOimH9qZePG/EZcb3trtpCVUy92dmaBpU1gWY5r7
-----END PRIVATE KEY-----|}

let ed25519_pub =
  match X509.Private_key.decode_pem (Cstruct.of_string ed25519_priv_pem) with
  | Ok k -> X509.Private_key.public k
  | _ -> assert false

let crypto_ed25519_sign () =
  let hsm = operational_mock () in
  let mechs = Keyfender.Json.MS.singleton Keyfender.Json.EdDSA_Signature in
  add_pem hsm ~id:"test" mechs ed25519_priv_pem;
  "signing with ED25519 succeeds"
  @? begin match Lwt_main.run (Hsm.Key.sign hsm ~id:"test" Keyfender.Json.EdDSA (Base64.encode_exn (Cstruct.to_string sign_test_data))) with
     | Ok signature ->
       let exp_sig = "MXXfyOqswfWDcXAoE2zU2Cf2VW5GajdqZge8hh3is2uVcHW5bbewE/zlb9hvoUjAqSO7ObIm29D4Krb8CjlpCQ==" in
       assert (exp_sig = signature);
       let b64_dec = Base64.decode_exn signature in
       (match X509.Public_key.verify `SHA512 ~scheme:`ED25519 ~signature:(Cstruct.of_string b64_dec) ed25519_pub (`Message sign_test_data) with
        | Ok () -> true
        | Error _ -> false)
     | Error _ -> false
  end

let crypto_ecdsa_sign () =
  let mechs = Keyfender.Json.MS.singleton Keyfender.Json.ECDSA_Signature in
  let seed = Cstruct.create 16 in
  let algos = [
    `SHA224, X509.Private_key.generate ~seed `P224, "MDwCHFn8JgXlX/0M0hIYcmjNc5MPZrACrnoV0UWCkAMCHCqDX5Rm9xCodXSJ9mKZhjjjfjpNT69JOTPKLGk=", "P224" ;
    `SHA256, X509.Private_key.generate ~seed `P256, "MEUCIQC3LKyNLNwZ+UhQ4tXzlbQdsnBzJuN/a6EbHl+N7J42XgIgRdacwWqGIatrRSdn9AEQ3RXRkNhiKHYmTmn8e3MKAYg=", "P256" ;
    `SHA384, X509.Private_key.generate ~seed `P384, "MGUCMQDO9eNxo4+IAoZpxqMvQvAeitP+D+5h1WiWBFRECdAN75uhGdGa9I9B0Ei3fv1uAE8CMH25z78MU+VqU1a+i1M2AEoVd7Jpj3CRnaYne78KgwXNnUr4nGDkvjcDyTutXhInjA==", "P384" ;
    `SHA512, X509.Private_key.generate ~seed `P521, "MIGIAkIBuBsgXU417z6tOTUKmUbemf/TbHt43MK7qPmq4QQKstcBCPzGavagjOU2arQPrKR3QCGffDGNG2C4jhx5m2HxQ9YCQgDx5HLLjbJGEAaz9mePAo+u/TPScLOHbEpO7vYloCSipEc6GjoimPvl4xTd6zeRpMD97jmhmLVeUbQWNi6Jthvftg==", "P521" ;
  ] in
  List.iter (fun (hash, priv, sign, txt) ->
      let hsm = operational_mock () in
      add_pem hsm ~id:"test" mechs (Cstruct.to_string (X509.Private_key.encode_pem priv));
      let pub = X509.Private_key.public priv in
      ("signing with ECDSA " ^ txt ^ " succeeds")
      @? begin match Lwt_main.run (Hsm.Key.sign hsm ~id:"test" Keyfender.Json.ECDSA (b64_and_hash hash sign_test_data)) with
     | Ok signature ->
       assert (sign = signature);
       let b64_dec = Base64.decode_exn signature in
       (match X509.Public_key.verify hash ~scheme:`ECDSA ~signature:(Cstruct.of_string b64_dec) pub (`Message sign_test_data) with
        | Ok () -> true
        | Error _ -> false)
     | Error _ -> false
      end)
    algos

let crypto_aes_cbc_encrypt () =
  let mechs = Keyfender.Json.MS.singleton Keyfender.Json.AES_Encryption_CBC in
  let sizes = [ 128; 192; 256 ] in
  List.iter (fun size ->
      let hsm = operational_mock () in
      let secret = Mirage_crypto_rng.generate (size/8) in
      add_generic hsm ~id:"test" mechs (secret |> Cstruct.to_string);
      ("encryption with AES-CBC succeeds")
      @? begin match Lwt_main.run (Hsm.Key.encrypt hsm ~id:"test" ~iv:None AES_CBC (Base64.encode_string aes_message)) with
      | Ok (cipher_b64, Some iv_b64) ->
          let iv = Base64.decode_exn iv_b64 |> Cstruct.of_string in
          let key = Mirage_crypto.Cipher_block.AES.CBC.of_secret secret in
          let encrypted_cs = Base64.decode_exn cipher_b64 |> Cstruct.of_string in
          let m = Mirage_crypto.Cipher_block.AES.CBC.decrypt ~key ~iv encrypted_cs |> Cstruct.to_string in
          String.equal m aes_message
      | Ok (_, None)
      | Error _ -> assert false
      end)
    sizes

let crypto_aes_cbc_decrypt () =
  let mechs = Keyfender.Json.MS.singleton Keyfender.Json.AES_Decryption_CBC in
  let sizes = [ 128; 192; 256 ] in
  List.iter (fun size ->
      let hsm = operational_mock () in
      let secret = Mirage_crypto_rng.generate (size/8) in
      add_generic hsm ~id:"test" mechs (secret |> Cstruct.to_string);
      let iv = Mirage_crypto_rng.generate Mirage_crypto.Cipher_block.AES.CBC.block_size in
      let key = Mirage_crypto.Cipher_block.AES.CBC.of_secret secret in
      let encrypted = Mirage_crypto.Cipher_block.AES.CBC.encrypt ~key ~iv (Cstruct.of_string aes_message)
        |> Cstruct.to_string |> Base64.encode_string
      in
      let iv = Some (Cstruct.to_string iv |> Base64.encode_string) in
      ("decryption with AES-CBC succeeds")
      @? begin match Lwt_main.run (Hsm.Key.decrypt hsm ~id:"test" ~iv AES_CBC encrypted) with
      | Ok m ->
          String.equal m (Base64.encode_string aes_message)
      | Error _ -> assert false
      end)
    sizes

(* translate from ounit into boolean *)
let rec ounit_success =
  function
    | [] -> true
    | RSuccess _::t
    | RSkip _::t ->
        ounit_success t
    | RFailure _::_
    | RError _::_
    | RTodo _::_ ->
        false

let () =
  Printexc.record_backtrace true;
  Fmt_tty.setup_std_outputs ();
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level (Some Debug);
  Mirage_crypto_rng_unix.initialize ();
  let tests = [
    "/" >:: empty;
    "/health/alive" >:: health_alive_ok;
    "/health/ready" >:: health_ready_ok;
    "/health/ready" >:: health_ready_error_precondition_failed;
    "/health/state" >:: health_state_ok;
    "/random" >:: random_ok;
    "/random" >:: random_error_bad_length;
    "/provision" >:: provision_ok;
    "/provision" >:: provision_error_malformed_request;
    "/provision" >:: provision_error_precondition_failed;
    "/system/info" >:: system_info_ok;
    "/system/info" >:: system_info_error_authentication_required;
    "/system/info" >:: system_info_error_precondition_failed;
    "/system/info" >:: system_info_error_forbidden;
    "/system/reboot" >:: system_reboot_ok;
    "/system/shutdown" >:: system_shutdown_ok;
    "/system/reset" >:: system_reset_ok;
    "/system/update" >:: system_update_ok;
    "/system/update" >:: system_update_signature_mismatch;
    "/system/update" >:: system_update_too_much_data;
    "/system/update" >:: system_update_too_few_data;
    "/system/update" >:: system_update_invalid_data;
    "/system/update" >:: system_update_platform_bad;
    (*"/system/update" >:: system_update_version_downgrade;*)
    "/system/commit-update" >:: system_update_commit_ok;
    "/system/commit-update" >:: system_update_commit_fail;
    "/system/cancel-update" >:: system_update_cancel_ok;
    "/system/update from binary file" >:: system_update_from_file_ok;
    "/system/update signing" >:: sign_update_ok;
    "/system/backup" >:: system_backup_and_restore_ok;
    "/unlock" >:: unlock_ok;
    "/unlock" >:: unlock_failed;
    "/unlock" >:: unlock_failed_two;
    "/unlock" >:: unlock_twice;
    "/lock" >:: lock_ok;
    "/lock" >:: lock_failed;
    "/config/unattended_boot" >:: get_unattended_boot_ok;
    "/config/unattended_boot" >:: unattended_boot_succeeds;
    "/config/unattended_boot" >:: unattended_boot_failed_wrong_device_id;
    "/config/unattended_boot" >:: unattended_boot_failed;
    "/config/unlock-passphrase" >:: change_unlock_passphrase;
    "/config/unlock-passphrase" >:: change_unlock_passphrase_empty;
    "/config/tls/public.pem" >:: get_config_tls_public_pem;
    "/config/tls/cert.pem" >:: get_config_tls_cert_pem;
    "/config/tls/cert.pem" >:: put_config_tls_cert_pem;
    "/config/tls/cert.pem" >:: put_config_tls_cert_pem_fail;
    "/config/tls/csr.pem" >:: post_config_tls_csr_pem;
    "/config/network" >:: config_network_ok;
    "/config/network" >:: config_network_set_ok;
    "/config/network" >:: config_network_set_fail;
    "/config/logging" >:: config_logging_ok;
    "/config/logging" >:: config_logging_set_ok;
    "/config/logging" >:: config_logging_set_fail;
    "/config/time" >:: config_time_ok;
    "/config/time" >:: config_time_set_ok;
    "/config/time" >:: config_time_set_fail;
    "/config/backup-passphrase" >:: set_backup_passphrase;
    "/config/backup-passphrase" >:: set_backup_passphrase_empty;
    "invalid config version" >:: invalid_config_version;
    "config version but no unlock salt" >:: config_version_but_no_salt;
    "/users" >:: users_get;
    "/users" >:: users_post;
    "/users/operator" >:: user_operator_add;
    "/users/operator" >:: user_operator_add_empty_passphrase;
    "/users/operator" >:: user_operator_add_invalid_id;
    "/users/operator" >:: user_operator_delete;
    "/users/operator" >:: user_operator_delete_not_found;
    "/users/operator" >:: user_operator_delete_invalid_id;
    "/users/operator" >:: user_operator_delete_fails;
    "/users/operator" >:: user_op_delete_fails;
    "/users/operator" >:: user_operator_get;
    "/users/operator" >:: user_operator_get_not_found;
    "/users/operator" >:: user_operator_get_invalid_id;
    "/users/.version" >:: user_version_get_bad_request;
    "/users/.version" >:: user_version_delete_fails_invalid_id;
    "/users/admin/passphrase" >:: user_passphrase_post;
    "/users/operator/passphrase" >:: user_passphrase_operator_post;
    "/users/admin/passphrase" >:: user_passphrase_administrator_post;
    "/users/admin/passphrase" >:: user_passphrase_post_fails_not_found;
    "/users/admin/passphrase" >:: user_passphrase_post_fails_invalid_id;
    "/keys" >:: keys_get;
    "/keys" >:: keys_post_json;
    "/keys" >:: keys_post_pem;
    "/keys/generate" >:: keys_generate;
    "/keys/generate" >:: keys_generate_invalid_id;
    "/keys/generate" >:: keys_generate_invalid_id_length;
    "/keys/generate" >:: keys_generate_invalid_mech;
    "/keys/generate" >:: keys_generate_no_mech;
    "/keys/generate" >:: keys_generate_ed25519;
    "/keys/generate" >:: keys_generate_ed25519_explicit_keyid;
    "/keys/generate" >:: keys_generate_ed25519_fail;
    "/keys/generate" >:: keys_generate_generic;
    "/keys/generate" >:: keys_generate_generic_fail;
    "/keys/keyID" >:: keys_key_get;
    "/keys/keyID" >:: keys_key_get_not_found;
    "/keys/keyID" >:: keys_key_get_invalid_id;
    "/keys/keyID" >:: keys_key_put;
    "/keys/keyID" >:: keys_key_put_already_there;
    "/keys/keyID" >:: keys_key_put_invalid_id;
    "/keys/keyID" >:: keys_key_delete;
    "/keys/keyID" >:: keys_key_delete_not_found;
    "/keys/keyID" >:: keys_key_delete_invalid_id;
    "/keys/keyID/public.pem" >:: admin_keys_key_public_pem;
    "/keys/keyID/public.pem" >:: operator_keys_key_public_pem;
    "/keys/keyID/public.pem" >:: operator_keys_key_public_pem_not_found;
    "/keys/keyID/public.pem" >:: operator_keys_key_public_pem_invalid_id;
    "/keys/keyID/csr.pem" >:: admin_keys_key_csr_pem;
    "/keys/keyID/csr.pem" >:: operator_keys_key_csr_pem;
    "/keys/keyID/csr.pem" >:: operator_keys_key_csr_pem_not_found;
    "/keys/keyID/csr.pem" >:: operator_keys_key_csr_pem_invalid_id;
    "/keys/keyID/decrypt" >:: operator_keys_key_decrypt;
    "/keys/keyID/decrypt" >:: operator_keys_key_decrypt_fails;
    "/keys/keyID/decrypt" >:: operator_keys_key_decrypt_fails_wrong_mech;
    "/keys/keyID/decrypt" >:: operator_keys_key_decrypt_fails_invalid_id;
    "/keys/keyID/decrypt" >:: operator_keys_key_decrypt_fails_not_found;
    "/keys/keyID/decrypt" >:: operator_decrypt_aes_cbc_succeeds;
    "/keys/keyID/decrypt" >:: operator_decrypt_aes_cbc_no_iv_fails;
    "/keys/keyID/encrypt" >:: operator_encrypt_aes_cbc_succeeds;
    "/keys/keyID/encrypt" >:: operator_encrypt_aes_cbc_no_iv_succeeds;
    "/keys/keyID/sign" >:: operator_keys_key_sign;
    "/keys/keyID/sign" >:: operator_keys_key_sign_fails;
    "/keys/keyID/sign" >:: operator_keys_key_sign_fails_bad_data;
    "/keys/keyID/sign" >:: operator_keys_key_sign_fails_wrong_mech;
    "/keys/keyID/sign" >:: operator_keys_key_sign_fails_invalid_id;
    "/keys/keyID/sign" >:: operator_keys_key_sign_fails_not_found;
    "/keys/keyID/decrypt and /sign" >:: operator_keys_key_sign_and_decrypt;
    "/keys/keyID/sign" >:: operator_sign_ed25519_succeeds;
    "/keys/keyID/sign" >:: operator_sign_ed25519_fails;
    "/keys/keyID" >:: keys_key_get_ed25519;
    "/keys/keyID" >:: keys_key_put_ed25519;
    "/keys/keyID" >:: keys_key_get_generic;
    "/keys/keyID" >:: keys_key_put_generic;
    "/keys/keyID/public.pem" >:: operator_keys_key_public_pem_ed25519;
    "/keys/keyID/cert" >:: keys_key_cert_get;
    "/keys/keyID/cert" >:: keys_key_cert_get_not_found;
    "/keys/keyID/cert" >:: keys_key_cert_get_invalid_id;
    "/keys/keyID/cert" >:: keys_key_cert_put;
    "/keys/keyID/cert" >:: keys_key_cert_put_fails;
    "/keys/keyID/cert" >:: keys_key_cert_put_not_found;
    "/keys/keyID/cert" >:: keys_key_cert_put_invalid_id;
    "/keys/keyID/cert" >:: keys_key_cert_delete;
    "/keys/keyID/cert" >:: keys_key_cert_delete_not_found;
    "/keys/keyID/cert" >:: keys_key_cert_delete_invalid_id;
    "/keys/version" >:: keys_key_version_get_fails;
    "/keys/version" >:: keys_key_version_delete_fails;
    "/keys/version/cert" >:: keys_key_version_cert_get_fails;
    "/keys/version/cert" >:: keys_key_version_cert_put_fails;
    "/keys/version/cert" >:: keys_key_version_cert_delete_fails;
    "/unlock" >:: rate_limit_for_unlock;
    "/system/info" >:: rate_limit_for_get;
    "rate limit reset after successful login" >:: reset_rate_limit_after_successful_login;
    "access.ml: decode auth" >:: auth_decode_invalid_base64;
    "RSA decrypt" >:: crypto_rsa_decrypt;
    "RSA PKCS1 sign" >:: crypto_rsa_pkcs1_sign;
    "RSA PSS sign" >:: crypto_rsa_pss_sign;
    "ED25519 sign" >:: crypto_ed25519_sign;
    "ECDSA sign" >:: crypto_ecdsa_sign;
    "AES-CBC encrypt" >:: crypto_aes_cbc_encrypt;
    "AES-CBC decrypt" >:: crypto_aes_cbc_decrypt;
  ] in
  let suite = "test dispatch" >::: tests in
  let verbose = ref false in
  let set_verbose _ = verbose := true in
  Arg.parse
    [("-verbose", Arg.Unit set_verbose, "Run the test in verbose mode.");]
    (fun x -> raise (Arg.Bad ("Bad argument : " ^ x)))
    ("Usage: " ^ Sys.argv.(0) ^ " [-verbose]");
  if not (ounit_success (run_test_tt ~verbose:!verbose suite))
  then exit 1
