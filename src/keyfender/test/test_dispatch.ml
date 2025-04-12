(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Cohttp
open Lwt.Infix
open Test_dispatch_helpers
open Test_utils

let () =
  Printexc.record_backtrace true;
  Fmt_tty.setup_std_outputs ();
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level (Some Debug);
  Keyfender.Crypto.set_test_params ()

let ( @? ) name fn =
  Alcotest.test_case name `Quick (fun () ->
      Alcotest.(check bool) "OK" true (fn ()))

let get_ok_result topic = function
  | Ok x -> x
  | Error (`Msg err) -> Alcotest.failf "%s: %s" topic err

let empty =
  "a request for / will produce no result" @? fun () ->
  match request "/" with _, None -> true | _ -> false

let health_alive_ok =
  "a request for /health/alive will produce a HTTP 200" @? fun () ->
  match request "/health/alive" with
  | _, Some (`OK, _, _, _) -> true
  | _ -> false

let health_ready_ok =
  "a request for /health/ready in operational state will produce an HTTP 200"
  @? fun () ->
  match request ~hsm_state:(operational_mock ()) "/health/ready" with
  | _, Some (`OK, _, _, _) -> true
  | _ -> false

let health_ready_error_precondition_failed =
  "a request for /health/ready in unprovisioned state will produce an HTTP 412"
  @? fun () ->
  match request "/health/ready" with
  | _, Some (`Precondition_failed, _, _, _) -> true
  | _ -> false

let health_state_ok =
  "a request for /health/state will produce an HTTP 200 and returns the state \
   as json"
  @? fun () ->
  let hsm_state = operational_mock () in
  match request ~hsm_state "/health/state" with
  | _, Some (`OK, _, `String body, _) ->
      String.equal body @@ Yojson.Safe.to_string
      @@ Keyfender.Json.state_to_yojson @@ Hsm.state hsm_state
  | _ -> false

let random_ok =
  "a request for /random will produce an HTTP 200 and returns random data"
  @? fun () ->
  let body = `String {| { "length": 10 } |} in
  let hsm_state = operational_mock () in
  let headers = operator_headers in
  match request ~meth:`POST ~hsm_state ~headers ~body "/random" with
  | _, Some (`OK, _, _, _) -> true
  | _ -> false

let random_error_bad_length =
  "a request for /random will produce an HTTP 400" @? fun () ->
  let body = `String {| { "length": 10000 } |} in
  let hsm_state = operational_mock () in
  let headers = operator_headers in
  match request ~meth:`POST ~hsm_state ~headers ~body "/random" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let provision_json =
  {| {
  "unlockPassphrase": "UnlockPassphrase",
  "adminPassphrase": "Administrator",
  "systemTime": "2018-10-30T11:20:50Z"
} |}

let provision_ok =
  "an initial provision request is successful (state transition to \
   operational, HTTP response 204)"
  @? fun () ->
  let body = `String provision_json in
  match request ~body ~meth:`POST "/provision" with
  | hsm_state, Some (`No_content, _, _, _) -> Hsm.state hsm_state = `Operational
  | _ -> false

let provision_error_malformed_request =
  "an initial provision request with invalid json returns a malformed request \
   with 400"
  @? fun () ->
  let body = `String ("hallo" ^ provision_json) in
  match request ~body ~meth:`POST "/provision" with
  | hsm_state, Some (`Bad_request, _, _, _) ->
      Hsm.state hsm_state = `Unprovisioned
  | _ -> false

let provision_error_precondition_failed =
  "an initial provision request is successful, a subsequent provision fails \
   with 412"
  @? fun () ->
  let body = `String provision_json in
  match request ~body ~meth:`POST "/provision" with
  | hsm_state, Some (`No_content, _, _, _) -> (
      match request ~hsm_state ~body ~meth:`POST "/provision" with
      | _, Some (`Precondition_failed, _, _, _) -> true
      | _ -> false)
  | _ -> false

let system_info_ok =
  "a request for /system/info with authenticated user returns 200" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~headers:admin_headers
      "/system/info"
  with
  | hsm_state, Some (`OK, _, `String body, _) ->
      String.equal body @@ Yojson.Safe.to_string
      @@ Keyfender.Json.system_info_to_yojson
      @@ Hsm.System.system_info hsm_state
  | _ -> false

let system_info_error_authentication_required =
  "a request for /system/info without authenticated user returns 401"
  @? fun () ->
  match request ~hsm_state:(operational_mock ()) "/system/info" with
  | _, Some (`Unauthorized, _, _, _) -> true
  | _ -> false

let system_info_error_precondition_failed =
  "a request for /system/info in unprovisioned state fails with 412"
  @? fun () ->
  match request "/system/info" with
  | _, Some (`Precondition_failed, _, _, _) -> true
  | _ -> false

let system_info_error_forbidden =
  "a request for /system/info with authenticated operator returns 403"
  @? fun () ->
  match
    request ~hsm_state:(operational_mock ())
      ~headers:(auth_header "operator" "test2Passphrase")
      "/system/info"
  with
  | _, Some (`Forbidden, _, _, _) -> true
  | _ -> false

let system_reboot_ok =
  "a request for /system/reboot with authenticated user returns 200"
  @? fun () ->
  match admin_post_request "/system/reboot" with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false

let system_reboot_namespaced_fails =
  "a request for /system/reboot with namespaced user returns 403" @? fun () ->
  match
    request ~meth:`POST ~hsm_state:(operational_mock ())
      ~headers:subadmin_headers "/system/reboot"
  with
  | _, Some (`Forbidden, _, _, _) -> true
  | _ -> false

let system_shutdown_ok =
  "a request for /system/shutdown with authenticated user returns 200"
  @? fun () ->
  match admin_post_request "/system/shutdown" with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false

let system_shutdown_namespaced_fails =
  "a request for /system/shutdown with namespaced user returns 403" @? fun () ->
  match
    request ~meth:`POST ~hsm_state:(operational_mock ())
      ~headers:subadmin_headers "/system/shutdown"
  with
  | _, Some (`Forbidden, _, _, _) -> true
  | _ -> false

let system_factory_reset_ok =
  "a request for /system/factory-reset with authenticated user returns 200"
  @? fun () ->
  match admin_post_request "/system/factory-reset" with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false

let system_factory_reset_namespaced_fails =
  "a request for /system/factory-reset with namespaced user returns 403"
  @? fun () ->
  match
    request ~meth:`POST ~hsm_state:(operational_mock ())
      ~headers:subadmin_headers "/system/factory-reset"
  with
  | _, Some (`Forbidden, _, _, _) -> true
  | _ -> false

let update_key =
  {|-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----|}
  |> X509.Private_key.decode_pem
  |> function
  | Ok (`RSA key) -> key
  | Ok _ -> invalid_arg "not an RSA key"
  | Error (`Msg m) -> invalid_arg m

let prefix_and_pad s =
  let pad = String.make (512 - String.length s) '\000' in
  String.concat "" [ "\000\000\000\001"; s; pad ]

let sign_update u =
  let signature =
    Mirage_crypto_pk.Rsa.PKCS1.sign ~hash:`SHA256 ~key:update_key (`Message u)
  in
  let length = String.length signature in
  let len_buf = Bytes.create 3 in
  Bytes.set_uint8 len_buf 0 (length lsr 16);
  Bytes.set_uint16_be len_buf 1 (length land 0xffff);
  "_NETHSM_UPDATE_\x00" ^ Bytes.unsafe_to_string len_buf ^ signature

let system_update_ok =
  "a request for /system/update with authenticated user returns 200"
  @? fun () ->
  let body =
    let data = prefix_and_pad "binary data is here" in
    let update = "\000\000\018A new system image\000\000\0032.0" ^ data in
    `String (sign_update update ^ update)
  in
  match admin_post_request ~body "/system/update" with
  | hsm_state, Some (`OK, _, `String release_notes, _) ->
      String.equal "{\"releaseNotes\":\"A new system image\"}" release_notes
      && Hsm.state hsm_state = `Operational
  | _ -> false

let system_update_namespaced_fails =
  "a request for /system/update with namespaced user returns 403" @? fun () ->
  let body =
    let data = prefix_and_pad "binary data is here" in
    let update = "\000\000\018A new system image\000\000\0032.0" ^ data in
    `String (sign_update update ^ update)
  in
  match
    request ~body ~meth:`POST ~hsm_state:(operational_mock ())
      ~headers:subadmin_headers "/system/update"
  with
  | _, Some (`Forbidden, _, _, _) -> true
  | _ -> false

let system_update_signature_mismatch =
  "a request for /system/update with authenticated user and bad signature \
   returns 400"
  @? fun () ->
  let body =
    let data = prefix_and_pad "binary data is here" in
    let update = "\000\000\018A new system image\000\000\0032.0" ^ data in
    let signature = sign_update (update ^ "\000") in
    `String (signature ^ update)
  in
  match admin_post_request ~body "/system/update" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let system_update_too_much_data =
  "a request for /system/update with authenticated user and too much data \
   returns 400"
  @? fun () ->
  let body =
    let data = prefix_and_pad "binary data is here" ^ "\000" in
    let update = "\000\000\018A new system image\000\000\0032.0" ^ data in
    let signature = sign_update update in
    `String (signature ^ update)
  in
  match admin_post_request ~body "/system/update" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let system_update_too_few_data =
  "a request for /system/update with authenticated user and too few data \
   returns 400"
  @? fun () ->
  let body =
    let data =
      let d = prefix_and_pad "binary data is here" in
      String.sub d 0 (pred (String.length d))
    in
    let update = "\000\000\018A new system image\000\000\0032.0" ^ data in
    let signature = sign_update update in
    `String (signature ^ update)
  in
  match admin_post_request ~body "/system/update" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let system_update_invalid_data =
  "a request for /system/update with invalid data fails." @? fun () ->
  let body =
    `String
      "\000\000\003signature too long\000\000\018A new system \
       image\000\000\0032.0binary data is here"
  in
  match admin_post_request ~body "/system/update" with
  | hsm_state, Some (`Bad_request, _, `String body, _) ->
      Logs.info (fun m -> m "Update with invalid data returned %s" body);
      Hsm.state hsm_state = `Operational
  | _ -> false

let system_update_platform_bad =
  "a request for /system/update with bad platform." @? fun () ->
  let expect = warning "during update, platform reported platform bad" in
  let body =
    let data = prefix_and_pad "binary data is here" in
    let update = "\000\000\018A new system image\000\000\0032.0" ^ data in
    `String (sign_update update ^ update)
  in
  let hsm_state =
    operational_mock
      ~mbox:(fun mbox -> Lwt_mvar.put mbox (Error "platform bad"))
      ()
  in
  match admin_post_request ~expect ~hsm_state ~body "/system/update" with
  | hsm_state, Some (`Bad_request, _, _, _) ->
      Hsm.state hsm_state = `Operational
  | _ -> false

let system_update_version_downgrade =
  "a request for /system/update trying to send an older software fails."
  @? fun () ->
  let body =
    let data = prefix_and_pad "binary data is here" in
    let update = "\000\000\018A new system image\000\000\004-1.5" ^ data in
    let signature = sign_update update in
    `String (signature ^ update)
  in
  match admin_post_request ~body "/system/update" with
  | hsm_state, Some (`Conflict, _, `String body, _) ->
      Logs.info (fun m ->
          m "Update with older software version returned %s" body);
      Hsm.state hsm_state = `Operational
  | _ -> false

let operational_mock_with_mbox () =
  Lwt_main.run
    ( Kv_mem.connect () >>= Hsm.boot ~platform software_update_key
    >>= fun (state, o, m) ->
      Lwt.async (fun () ->
          let rec go () = Lwt_mvar.take o >>= fun _ -> go () in
          go ());
      Lwt.async (fun () ->
          let rec go () = Lwt_mvar.put m (Ok ()) >>= fun () -> go () in
          go ());
      Hsm.provision state ~unlock:"unlockPassphrase" ~admin:"test1Passphrase"
        Ptime.epoch
      >>= fun _ ->
      Hsm.User.add state (user "operator") ~role:`Operator
        ~passphrase:"test2Passphrase" ~name:"operator"
      >>= fun _ ->
      Hsm.User.add_tag state (user "operator") ~tag:"berlin" >>= fun _ ->
      Hsm.User.add state (user "backup") ~role:`Backup
        ~passphrase:"backupUserPassphrase" ~name:"backup"
      >|= fun _ -> state )

let multipart_log =
  {|test_dispatch.exe: [DEBUG] Partial state of the multipart/form stream.
test_dispatch.exe: [DEBUG] Capacity of the internal queue: 4096 byte(s).
test_dispatch.exe: [DEBUG] Length of the internal queue: 0 byte(s).
test_dispatch.exe: [DEBUG] Decode a 8-bit part.
test_dispatch.exe: [DEBUG] Decode a 8-bit part.
test_dispatch.exe: [DEBUG] Partial state of the multipart/form stream.
test_dispatch.exe: [DEBUG] End of input.
test_dispatch.exe: [DEBUG] Remain one payload: "\r\n--------------------------eb790219f130e103--\r\n"
|}

let system_update_commit_ok =
  "a request for /system/commit-update with authenticated user returns 200"
  @? fun () ->
  let body =
    let data = prefix_and_pad "binary data is here" in
    let update = "\000\000\018A new system image\000\000\0032.0" ^ data in
    let signature = sign_update update in
    `String (signature ^ update)
  and hsm_state = operational_mock_with_mbox () in
  match admin_post_request ~hsm_state ~body "/system/update" with
  | hsm_state, Some (`OK, _, _, _) -> (
      match admin_post_request ~hsm_state "/system/commit-update" with
      | _, Some (`No_content, _, _, _) -> true
      | _ -> false)
  | _ -> false

let system_update_commit_namespaced_fails =
  "a request for /system/commit-update with namespaced user returns 403"
  @? fun () ->
  match
    request ~meth:`POST ~hsm_state:(operational_mock ())
      ~headers:subadmin_headers "/system/commit-update"
  with
  | _, Some (`Forbidden, _, _, _) -> true
  | _ -> false

let system_update_commit_fail =
  "a request for /system/commit-update without an image previously uploaded \
   fails."
  @? fun () ->
  match admin_post_request "/system/commit-update" with
  | _, Some (`Precondition_failed, _, _, _) -> true
  | _ -> false

let system_update_cancel_ok =
  "a request for /system/cancel-update with authenticated user returns 200"
  @? fun () ->
  let body =
    let data = prefix_and_pad "binary data is here" in
    let update = "\000\000\018A new system image\000\000\0032.0" ^ data in
    let signature = sign_update update in
    `String (signature ^ update)
  in
  match admin_post_request ~body "/system/update" with
  | hsm_state, Some (`OK, _, _, _) -> (
      match admin_post_request ~hsm_state "/system/cancel-update" with
      | _, Some (`No_content, _, _, _) -> true
      | _ -> false)
  | _ -> false

let system_update_cancel_namespaced_fails =
  "a request for /system/cancel-update with namespaced user returns 403"
  @? fun () ->
  let body =
    let data = prefix_and_pad "binary data is here" in
    let update = "\000\000\018A new system image\000\000\0032.0" ^ data in
    let signature = sign_update update in
    `String (signature ^ update)
  in
  match
    request ~body ~meth:`POST ~hsm_state:(operational_mock ())
      ~headers:subadmin_headers "/system/cancel-update"
  with
  | _, Some (`Forbidden, _, _, _) -> true
  | _ -> false

let system_backup_and_restore_ok =
  "a request for /system/restore succeeds" @? fun () ->
  let backup_passphrase = "backup passphrase" in
  let passphrase =
    Printf.sprintf "{ \"newPassphrase\" : %S, \"currentPassphrase\":\"\" }"
      backup_passphrase
  in
  let hsm_state = hsm_with_key ~and_namespace:"namespace1" () in
  match
    admin_put_request ~hsm_state ~body:(`String passphrase)
      "/config/backup-passphrase"
  with
  | hsm_state, Some (`No_content, _, _, _) -> (
      let headers = auth_header "backup" "backupUserPassphrase" in
      match request ~meth:`POST ~hsm_state ~headers "/system/backup" with
      | _hsm_state, Some (`OK, _, `Stream s, _) -> (
          let arguments =
            Yojson.Safe.to_string
              (Keyfender.Json.restore_req_to_yojson
                 ({
                    backupPassphrase = backup_passphrase;
                    systemTime = Some (Ptime.to_rfc3339 Ptime.epoch);
                  }
                   : Keyfender.Json.restore_req))
          in
          let backup_data =
            String.concat "" (Lwt_main.run (Lwt_stream.to_list s))
          in
          let content_type, body =
            create_multipart_request
              [ ("arguments", arguments); ("backup_data", backup_data) ]
          in
          let expect = multipart_log in
          match
            request ~expect ~meth:`POST ~content_type ~body:(`String body)
              "/system/restore"
          with
          | hsm_state', Some (`No_content, _, _, _) -> (
              assert (Hsm.state hsm_state' = `Locked);
              let unlock_json = {|{ "passphrase": "unlockPassphrase" }|} in
              match
                request ~meth:`POST ~body:(`String unlock_json)
                  ~hsm_state:hsm_state' "/unlock"
              with
              | _, Some (`No_content, _, _, _) ->
                  Hsm.state hsm_state' = `Operational
                  && Lwt_main.run (Hsm.equal hsm_state hsm_state')
              | _ -> false)
          | _ -> false)
      | _ -> false)
  | _ -> false

let system_backup_and_restore_changed_devkey =
  "/system/restore with changed device key and unlock -> operational"
  @? fun () ->
  let backup_passphrase = "backup passphrase" in
  let passphrase =
    Printf.sprintf "{ \"newPassphrase\" : %S, \"currentPassphrase\":\"\" }"
      backup_passphrase
  in
  match
    admin_put_request ~body:(`String passphrase) "/config/backup-passphrase"
  with
  | hsm_state, Some (`No_content, _, _, _) -> (
      let headers = auth_header "backup" "backupUserPassphrase" in
      match request ~meth:`POST ~hsm_state ~headers "/system/backup" with
      | _hsm_state, Some (`OK, _, `Stream s, _) -> (
          let arguments =
            Yojson.Safe.to_string
              (Keyfender.Json.restore_req_to_yojson
                 ({
                    backupPassphrase = backup_passphrase;
                    systemTime = Some (Ptime.to_rfc3339 Ptime.epoch);
                  }
                   : Keyfender.Json.restore_req))
          in
          let backup_data =
            String.concat "" (Lwt_main.run (Lwt_stream.to_list s))
          in
          let content_type, body =
            create_multipart_request
              [ ("arguments", arguments); ("backup_data", backup_data) ]
          in
          let platform =
            {
              platform with
              deviceKey = "//////////////////////////////////////////8=";
            }
          in
          let hsm_state_2 =
            Lwt_main.run
              ( Kv_mem.connect () >>= Hsm.boot ~platform software_update_key
              >|= fun (y, _, _) -> y )
          in
          let expect =
            multipart_log ^ info "Device Key changed."
            ^ info "Rewriting stored Domain Key."
          in
          match
            request ~expect ~meth:`POST ~content_type ~body:(`String body)
              ~hsm_state:hsm_state_2 "/system/restore"
          with
          | hsm_state', Some (`No_content, _, _, _) -> (
              assert (Hsm.state hsm_state' = `Locked);
              let unlock_json = {|{ "passphrase": "unlockPassphrase" }|} in
              match
                request ~meth:`POST ~body:(`String unlock_json)
                  ~hsm_state:hsm_state' "/unlock"
              with
              | _, Some (`No_content, _, _, _) ->
                  Hsm.state hsm_state' = `Operational
                  && not (Lwt_main.run (Hsm.equal hsm_state hsm_state'))
              | _ -> false)
          | _ -> false)
      | _ -> false)
  | _ -> false

let system_backup_and_restore_unattended =
  Alcotest.test_case "/system/restore with unattended mode -> operational"
    `Quick
  @@ fun () ->
  let hsm_state = hsm_with_key () in
  let* hsm_state =
    admin_put_request ~body:(`String {|{"status":"on"}|}) ~hsm_state
      "/config/unattended-boot"
    |> Expect.no_content
  in
  let backup_passphrase = "backup passphrase" in
  let passphrase =
    Printf.sprintf "{ \"newPassphrase\" : %S, \"currentPassphrase\":\"\" }"
      backup_passphrase
  in
  let* hsm_state =
    admin_put_request ~hsm_state ~body:(`String passphrase)
      "/config/backup-passphrase"
    |> Expect.no_content
  in
  let headers = auth_header "backup" "backupUserPassphrase" in
  let* _hsm_state, s =
    request ~meth:`POST ~hsm_state ~headers "/system/backup" |> Expect.stream
  in
  (* restore *)
  let hsm_state, store =
    Lwt_main.run
      ( Kv_mem.connect () >>= fun store ->
        Hsm.boot ~platform software_update_key store >|= fun (y, _, _) ->
        (y, store) )
  in
  let* hsm_state =
    let arguments =
      Yojson.Safe.to_string
        (Keyfender.Json.restore_req_to_yojson
           ({
              backupPassphrase = backup_passphrase;
              systemTime = Some (Ptime.to_rfc3339 Ptime.epoch);
            }
             : Keyfender.Json.restore_req))
    in
    let backup_data = String.concat "" (Lwt_main.run (Lwt_stream.to_list s)) in
    let content_type, body =
      create_multipart_request
        [ ("arguments", arguments); ("backup_data", backup_data) ]
    in
    let expect = multipart_log in
    request ~expect ~meth:`POST ~content_type ~body:(`String body) ~hsm_state
      "/system/restore"
    |> Expect.no_content
  in
  Alcotest.(check string)
    "state" "operational"
    (Fmt.to_to_string Hsm.pp_state (Hsm.state hsm_state));
  let hsm_state =
    Lwt_main.run
      (Hsm.boot ~platform software_update_key store >|= fun (x, _, _) -> x)
  in
  Alcotest.(check string)
    "state" "operational"
    (Fmt.to_to_string Hsm.pp_state (Hsm.state hsm_state))

let system_backup_and_restore_unattended_changed_devkey =
  Alcotest.test_case
    "/system/restore with unattended mode and new device key -> locked" `Quick
  @@ fun () ->
  let hsm_state = hsm_with_key () in
  let* hsm_state =
    admin_put_request ~body:(`String {|{"status":"on"}|}) ~hsm_state
      "/config/unattended-boot"
    |> Expect.no_content
  in
  let backup_passphrase = "backup passphrase" in
  let passphrase =
    Printf.sprintf "{ \"newPassphrase\" : %S, \"currentPassphrase\":\"\" }"
      backup_passphrase
  in
  let* hsm_state =
    admin_put_request ~hsm_state ~body:(`String passphrase)
      "/config/backup-passphrase"
    |> Expect.no_content
  in
  let headers = auth_header "backup" "backupUserPassphrase" in
  let* _hsm_state, s =
    request ~meth:`POST ~hsm_state ~headers "/system/backup" |> Expect.stream
  in
  (* restore *)
  let platform =
    { platform with deviceKey = "//////////////////////////////////////////8=" }
  in
  let hsm_state, store =
    Lwt_main.run
      ( Kv_mem.connect () >>= fun store ->
        Hsm.boot ~platform software_update_key store >|= fun (y, _, _) ->
        (y, store) )
  in
  let* hsm_state =
    let expect =
      multipart_log ^ info "Device Key changed."
      ^ info "Rewriting stored Domain Key."
      ^ error "unattended boot failed with not authenticated"
    in
    let arguments =
      Yojson.Safe.to_string
        (Keyfender.Json.restore_req_to_yojson
           ({
              backupPassphrase = backup_passphrase;
              systemTime = Some (Ptime.to_rfc3339 Ptime.epoch);
            }
             : Keyfender.Json.restore_req))
    in
    let backup_data = String.concat "" (Lwt_main.run (Lwt_stream.to_list s)) in
    let content_type, body =
      create_multipart_request
        [ ("arguments", arguments); ("backup_data", backup_data) ]
    in
    request ~expect ~meth:`POST ~content_type ~body:(`String body) ~hsm_state
      "/system/restore"
    |> Expect.no_content
  in
  Alcotest.(check string)
    "state" "locked"
    (Fmt.to_to_string Hsm.pp_state (Hsm.state hsm_state));
  let hsm_state =
    Lwt_main.run
      (Hsm.boot ~platform software_update_key store >|= fun (x, _, _) -> x)
  in
  Alcotest.(check string)
    "state" "locked"
    (Fmt.to_to_string Hsm.pp_state (Hsm.state hsm_state))

let system_backup_and_restore_operational =
  Alcotest.test_case "a request for /system/restore succeeds while operational"
    `Quick
  @@ fun () ->
  let backup_passphrase = "backup passphrase" in
  let passphrase =
    Printf.sprintf "{ \"newPassphrase\" : %S, \"currentPassphrase\":\"\" }"
      backup_passphrase
  in
  let hsm_state = hsm_with_key ~and_namespace:"namespace1" () in
  let* hsm_state =
    admin_put_request ~hsm_state ~body:(`String passphrase)
      "/config/backup-passphrase"
    |> Expect.no_content
  in
  let headers = auth_header "backup" "backupUserPassphrase" in
  let* _hsm_state, s =
    request ~meth:`POST ~hsm_state ~headers "/system/backup" |> Expect.stream
  in
  let backup_data = String.concat "" (Lwt_main.run (Lwt_stream.to_list s)) in
  (* backup is done, let's remove a key and try to restore it *)
  let* hsm_state =
    let expect = info "removed (keyID)" in
    request ~expect ~meth:`DELETE ~hsm_state ~headers:admin_headers
      "/keys/keyID"
    |> Expect.no_content
  in
  (* add key, we'll check that it's removed after restore *)
  Lwt_main.run
    (let mechanisms = Keyfender.Json.(MS.singleton RSA_Decryption_PKCS1) in
     Hsm.Key.add_pem hsm_state mechanisms ~id:"newKeyID" test_key_pem
       no_restrictions)
  |> Result.get_ok;
  (* do the same with namespaces *)
  let expect_ns = info "removed (namespace1)" ^ info "removed (subKeyID)" in
  let* hsm_state =
    request ~expect:expect_ns ~meth:`DELETE ~hsm_state ~headers:admin_headers
      "/namespaces/namespace1"
    |> Expect.no_content
  in
  let expect = info "created (namespace3)" in
  let* hsm_state =
    request ~expect ~meth:`PUT ~hsm_state ~headers:admin_headers
      "/namespaces/namespace3"
    |> Expect.no_content
  in
  (* the unlock passphrase is changed, must be restored *)
  Lwt_main.run
    (Hsm.Config.change_unlock_passphrase hsm_state ~new_passphrase:"i am secure"
       ~current_passphrase:"unlockPassphrase")
  |> Result.get_ok;
  (* the removed key is indeed removed *)
  let* _ =
    request ~headers:admin_headers ~hsm_state "/keys/keyID" |> Expect.not_found
  in
  (* restore *)
  let* hsm_state =
    let expect =
      multipart_log ^ info "Domain Key changed."
      ^ info "Rewriting stored Domain Key."
      ^ info "removing: /key/newKeyID\n"
      ^ info "removing: /namespace/namespace3\n"
    in
    let arguments =
      Yojson.Safe.to_string
        (Keyfender.Json.restore_req_to_yojson
           ({
              backupPassphrase = backup_passphrase;
              systemTime = Some (Ptime.to_rfc3339 Ptime.epoch);
            }
             : Keyfender.Json.restore_req))
    in
    let content_type, body =
      create_multipart_request
        [ ("arguments", arguments); ("backup_data", backup_data) ]
    in
    request ~expect ~meth:`POST ~hsm_state ~headers:admin_headers ~content_type
      ~body:(`String body) "/system/restore"
    |> Expect.no_content
  in
  (* after first restore it should be locked *)
  assert (Hsm.state hsm_state = `Locked);
  let unlock_json = {|{ "passphrase": "unlockPassphrase" }|} in
  let* hsm_state =
    request ~meth:`POST ~body:(`String unlock_json) ~hsm_state "/unlock"
    |> Expect.no_content
  in
  assert (Hsm.state hsm_state = `Operational);
  (* check that deleted keys are restored *)
  let* _ =
    request ~headers:admin_headers ~hsm_state "/keys/keyID" |> Expect.ok
  in
  (* check that new keys are deleted *)
  let* _ =
    request ~headers:admin_headers ~hsm_state "/keys/newKeyID"
    |> Expect.not_found
  in
  (* same for namespaces and related keys *)
  let* _ =
    request ~expect:expect_ns ~headers:admin_headers ~meth:`DELETE ~hsm_state
      "/namespaces/namespace1"
    |> Expect.no_content
  in
  let* _ =
    request ~headers:admin_headers ~meth:`DELETE ~hsm_state
      "/namespaces/namespace3"
    |> Expect.not_found
  in
  (* second restore *)
  let* hsm_state =
    let expect = multipart_log in
    let arguments =
      Yojson.Safe.to_string
        (Keyfender.Json.restore_req_to_yojson
           ({
              backupPassphrase = backup_passphrase;
              systemTime = Some (Ptime.to_rfc3339 Ptime.epoch);
            }
             : Keyfender.Json.restore_req))
    in
    let content_type, body =
      create_multipart_request
        [ ("arguments", arguments); ("backup_data", backup_data) ]
    in
    request ~expect ~meth:`POST ~hsm_state ~headers:admin_headers ~content_type
      ~body:(`String body) "/system/restore"
    |> Expect.no_content
  in
  (* after second restore it should be operational *)
  assert (Hsm.state hsm_state = `Operational);
  ()

let system_backup_post_accept_header =
  "a request for /system/backup using 'Accept: application/octet-stream' \
   succeeds"
  @? fun () ->
  let backup_passphrase = "backup passphrase" in
  let passphrase =
    Printf.sprintf "{ \"newPassphrase\" : %S, \"currentPassphrase\":\"\" }"
      backup_passphrase
  in
  match
    admin_put_request ~body:(`String passphrase) "/config/backup-passphrase"
  with
  | hsm_state, Some (`No_content, _, _, _) -> (
      let headers =
        Header.add
          (auth_header "backup" "backupUserPassphrase")
          "Accept" "application/octet-stream"
      in
      match request ~meth:`POST ~hsm_state ~headers "/system/backup" with
      | _hsm_state, Some (`OK, _, `Stream _, _) -> true
      | _ -> false)
  | _ -> false

let readfile filename =
  let fd = Unix.openfile filename [ Unix.O_RDONLY ] 0 in
  let filesize = (Unix.stat filename).Unix.st_size in
  let buf = Bytes.create filesize in
  let rec read off =
    if off = filesize then ()
    else
      let bytes_read = Unix.read fd buf off (filesize - off) in
      read (bytes_read + off)
  in
  read 0;
  Unix.close fd;
  `String (Bytes.to_string buf)

let system_update_from_file_ok =
  "a request for /system/update with authenticated user and update read from \
   disk returns 200"
  @? fun () ->
  let body = readfile "update.bin" in
  match admin_post_request ~body "/system/update" with
  | hsm_state, Some (`OK, _, `String _, _) -> Hsm.state hsm_state = `Operational
  | _ -> false

let sign_update_ok =
  "a request for /system/update with authenticated user returns 200"
  @? fun () ->
  let returncode =
    Sys.command
      "../bin/sign_update.exe key.pem changes version update.bin \
       --output=signed_update.bin"
  in
  assert (returncode = 0);
  let body = readfile "signed_update.bin" in
  match admin_post_request ~body "/system/update" with
  | hsm_state, Some (`OK, _, `String _, _) -> Hsm.state hsm_state = `Operational
  | _ -> false

let unlock_json = {|{ "passphrase": "test1234Passphrase" }|}

let unlock_ok =
  "a request for /unlock unlocks the HSM" @? fun () ->
  match
    request ~meth:`POST ~body:(`String unlock_json) ~hsm_state:(locked_mock ())
      "/unlock"
  with
  | hsm_state, Some (`No_content, _, _, _) -> Hsm.state hsm_state = `Operational
  | _ -> false

let unlock_failed =
  "a request for /unlock with the wrong passphrase fails" @? fun () ->
  let wrong_passphrase = {|{ "passphrase": "wrong" }|} in
  match
    request ~meth:`POST ~body:(`String wrong_passphrase)
      ~hsm_state:(locked_mock ()) "/unlock"
  with
  | hsm_state, Some (`Bad_request, _, _, _) -> Hsm.state hsm_state = `Locked
  | _ -> false

let unlock_failed_two =
  "a request for /unlock with the wrong passphrase fails" @? fun () ->
  let wrong_passphrase = {|{ "passphrase": "wrongwrongwrong" }|} in
  match
    request ~meth:`POST ~body:(`String wrong_passphrase)
      ~hsm_state:(locked_mock ()) "/unlock"
  with
  | hsm_state, Some (`Forbidden, _, _, _) -> Hsm.state hsm_state = `Locked
  | _ -> false

let unlock_twice =
  "the first request for /unlock unlocks the HSM, the second fails" @? fun () ->
  match
    request ~meth:`POST ~body:(`String unlock_json) ~hsm_state:(locked_mock ())
      "/unlock"
  with
  | hsm_state, Some (`No_content, _, _, _) -> (
      match
        request ~meth:`POST ~body:(`String unlock_json) ~hsm_state "/unlock"
      with
      | hsm', Some (`Precondition_failed, _, _, _) ->
          Hsm.state hsm' = `Operational
      | _ -> false)
  | _ -> false

let unlock_fails_wrong_device_key =
  "a request for /unlock with the wrong device key fails" @? fun () ->
  let kv =
    Lwt_main.run
      ( Kv_mem.connect () >>= fun kv ->
        Hsm.boot ~platform software_update_key kv >>= fun (state, _, _) ->
        Hsm.provision state ~unlock:"test1234Passphrase"
          ~admin:"test1Passphrase" Ptime.epoch
        >|= fun r ->
        assert (r = Ok ());
        kv )
  in
  let hsm_state =
    Lwt_main.run
      (Hsm.boot ~platform software_update_key kv >|= fun (y, _, _) -> y)
  in
  match
    request ~meth:`POST ~body:(`String unlock_json) ~hsm_state "/unlock"
  with
  | hsm_state, Some (`No_content, _, _, _)
    when Hsm.state hsm_state = `Operational -> (
      let platform =
        {
          platform with
          deviceKey = "//////////////////////////////////////////8=";
        }
      in
      let hsm_state =
        Lwt_main.run
          (Hsm.boot ~platform software_update_key kv >|= fun (y, _, _) -> y)
      in
      match
        request ~meth:`POST ~body:(`String unlock_json) ~hsm_state "/unlock"
      with
      | hsm_state, Some (`Forbidden, _, _, _) -> Hsm.state hsm_state = `Locked
      | _ -> false)
  | _ -> false

let lock_ok =
  "a request for /lock locks the HSM" @? fun () ->
  match admin_post_request ~hsm_state:(operational_mock ()) "/lock" with
  | hsm_state, Some (`No_content, _, _, _) -> Hsm.state hsm_state = `Locked
  | _ -> false

let lock_failed =
  "a request for /lock with the wrong passphrase fails" @? fun () ->
  let headers = operator_headers in
  let hsm_state = operational_mock () in
  match request ~meth:`POST ~hsm_state ~headers "/lock" with
  | hsm_state, Some (`Forbidden, _, _, _) -> Hsm.state hsm_state = `Operational
  | _ -> false

let lock_nonroot_fails =
  "a request for /lock as a namespaced user fails fails" @? fun () ->
  let headers = subadmin_headers in
  let hsm_state = operational_mock () in
  match request ~meth:`POST ~hsm_state ~headers "/lock" with
  | hsm_state, Some (`Forbidden, _, _, _) -> Hsm.state hsm_state = `Operational
  | _ -> false

(* /config *)

let change_unlock_passphrase =
  "change unlock passphrase succeeds" @? fun () ->
  let change_passphrase =
    {|{ "newPassphrase" : "new passphrase", "currentPassphrase" : "unlockPassphrase" }|}
  in
  let unlock_passphrase = {|{ "passphrase" : "new passphrase" }|} in
  match
    admin_put_request ~body:(`String change_passphrase)
      "/config/unlock-passphrase"
  with
  | hsm_state, Some (`No_content, _, _, _) -> (
      Hsm.lock hsm_state;
      match
        request ~meth:`POST ~body:(`String unlock_passphrase) ~hsm_state
          "/unlock"
      with
      | hsm_state, Some (`No_content, _, _, _) ->
          Hsm.state hsm_state = `Operational
      | _ -> false)
  | _ -> false

let change_unlock_passphrase_empty =
  "change to empty unlock passphrase fails" @? fun () ->
  let passphrase = {|{ "passphrase" : "" }|} in
  match
    admin_put_request ~body:(`String passphrase) "/config/unlock-passphrase"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let get_unattended_boot_ok =
  "GET /config/unattended-boot succeeds" @? fun () ->
  let headers = admin_headers in
  match
    request ~headers ~hsm_state:(operational_mock ()) "/config/unattended-boot"
  with
  | _hsm_state', Some (`OK, _, `String body, _) -> body = {|{"status":"off"}|}
  | _ -> false

let unattended_boot_succeeds =
  "unattended boot succeeds" @? fun () ->
  let store, hsm_state =
    Lwt_main.run
      ( Kv_mem.connect () >>= fun store ->
        Hsm.boot ~platform software_update_key store >>= fun (state, _, _) ->
        Hsm.provision state ~unlock:"unlockPassphrase" ~admin:"test1Passphrase"
          Ptime.epoch
        >|= fun _ -> (store, state) )
  in
  match
    admin_put_request ~body:(`String {|{ "status" : "on" }|}) ~hsm_state
      "/config/unattended-boot"
  with
  | _hsm_state', Some (`No_content, _, _, _) ->
      Lwt_main.run
        ( Hsm.boot ~platform software_update_key store
        >|= fun (hsm_state, _, _) -> Hsm.state hsm_state = `Operational )
  | _ -> false

let unattended_boot_failed_wrong_device_key =
  "unattended boot failed (wrong Device Key)" @? fun () ->
  let store, hsm_state =
    Lwt_main.run
      ( Kv_mem.connect () >>= fun store ->
        Hsm.boot ~platform software_update_key store >>= fun (state, _, _) ->
        Hsm.provision state ~unlock:"unlockPassphrase" ~admin:"test1Passphrase"
          Ptime.epoch
        >|= fun _ -> (store, state) )
  in
  match
    admin_put_request ~body:(`String {|{ "status" : "on" }|}) ~hsm_state
      "/config/unattended-boot"
  with
  | _hsm_state', Some (`No_content, _, _, _) ->
      let platform =
        {
          platform with
          deviceKey = "//////////////////////////////////////////8=";
        }
      in
      Lwt_main.run
        ( Hsm.boot ~platform software_update_key store
        >|= fun (hsm_state, _, _) -> Hsm.state hsm_state = `Locked )
  | _ -> false

let get_config_tls_public_pem =
  "get tls public pem file succeeds" @? fun () ->
  let headers = admin_headers in
  match
    request ~hsm_state:(operational_mock ()) ~meth:`GET ~headers
      "/config/tls/public.pem"
  with
  | _, Some (`OK, _, _, _) -> true
  | _ -> false

let get_config_tls_cert_pem =
  "get tls cert pem file succeeds" @? fun () ->
  let headers = admin_headers in
  match
    request ~hsm_state:(operational_mock ()) ~meth:`GET ~headers
      "/config/tls/cert.pem"
  with
  | _, Some (`OK, _, _, _) -> true
  | _ -> false

let put_config_tls_cert_pem =
  "put tls cert pem file succeeds" @? fun () ->
  let headers = admin_headers in
  match
    request ~hsm_state:(operational_mock ()) ~meth:`GET ~headers
      "/config/tls/cert.pem"
  with
  | hsm_state, Some (`OK, _, `String body, _) -> (
      let content_type = "application/x-pem-file" in
      match
        request ~hsm_state ~meth:`PUT ~headers ~content_type
          ~body:(`String body) "/config/tls/cert.pem"
      with
      | _, Some (`Created, headers, _, _) -> (
          match Cohttp.Header.get headers "location" with
          | None -> false
          | Some loc -> String.equal loc "/api/v1/config/tls/cert.pem")
      | _ -> false)
  | _ -> false

let put_config_tls_cert_pem_fail =
  "post tls cert pem file fail" @? fun () ->
  let headers = admin_headers in
  let content_type = "application/x-pem-file" in
  let not_a_pem = "hello this is not pem format" in
  match
    request ~hsm_state:(operational_mock ()) ~meth:`PUT ~headers ~content_type
      ~body:(`String not_a_pem) "/config/tls/cert.pem"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let subject =
  {|{
    "countryName": "DE",
    "stateOrProvinceName": "",
    "localityName": "Berlin",
    "organizationName": "Nitrokey",
    "organizationalUnitName": "",
    "commonName": "nethsm.local",
    "emailAddress": "info@nitrokey.com"
  }|}

let common_name_only = {|{ "commonName": "nethsm.local" }|}

let post_config_tls_csr_pem =
  "post tls csr pem file succeeds" @? fun () ->
  match admin_post_request ~body:(`String subject) "/config/tls/csr.pem" with
  | _, Some (`OK, _, `String body, _) -> (
      match X509.Signing_request.decode_pem body with
      | Ok _ -> true
      | Error _ -> false)
  | _ -> false

let post_config_tls_csr_pem2 =
  "post tls csr pem with only commonName succeeds" @? fun () ->
  match
    admin_post_request ~body:(`String common_name_only) "/config/tls/csr.pem"
  with
  | _, Some (`OK, _, `String body, _) -> (
      match X509.Signing_request.decode_pem body with
      | Ok _ -> true
      | Error _ -> false)
  | _ -> false

let bad_subject =
  {|{
    "countryName": "DE",
    "stateOrProvinceName": "",
    "localityName": "Berlin",
    "organizationName": "Nitrokey",
    "organizationalUnitName": "",
    "emailAddress": "info@nitrokey.com"
  }|}

let post_config_tls_csr_pem_fails =
  "post tls csr pem without commonName fails" @? fun () ->
  match
    admin_post_request ~body:(`String bad_subject) "/config/tls/csr.pem"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let post_config_tls_generate =
  let generate_json = {|{ type: "RSA", length: 2048 }|} in
  let decode_key pem_data =
    match X509.Public_key.decode_pem pem_data with
    | Ok v -> v
    | Error _ -> raise (Failure "decode_key")
  in
  let get_public_key ~hsm_state =
    match
      request ~hsm_state ~meth:`GET ~headers:admin_headers
        "/config/tls/public.pem"
    with
    | _, Some (`OK, _, `String body, _) -> decode_key body
    | _ -> raise (Failure "get_public_key")
  in
  "post tls generate" @? fun () ->
  let hsm_state = operational_mock () in
  try
    (* obtain generated key at provision *)
    let initial_key = get_public_key ~hsm_state in
    (* call the generate endpoint to generate an RSA key *)
    match
      admin_post_request ~hsm_state ~body:(`String generate_json)
        "/config/tls/generate"
    with
    | _, Some (`No_content, _, _, _) ->
        (* check that the tls key is different from the initial key *)
        let new_key = get_public_key ~hsm_state in
        not
          (String.equal
             (X509.Public_key.fingerprint new_key)
             (X509.Public_key.fingerprint initial_key))
    | _ -> false
  with Failure _ -> false

let post_config_tls_generate_generic_key =
  "post tls generate fail generic key" @? fun () ->
  let hsm_state = operational_mock () in
  try
    match
      admin_post_request ~hsm_state
        ~body:(`String {|{ type: "Generic", length: 2048 }|})
        "/config/tls/generate"
    with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  with Failure _ -> false

let post_config_tls_generate_bad_length =
  "post tls generate fail bad length" @? fun () ->
  let hsm_state = operational_mock () in
  try
    match
      admin_post_request ~hsm_state
        ~body:(`String {|{ type: "RSA", length: 100 }|}) "/config/tls/generate"
    with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  with Failure _ -> false

let config_network_ok =
  "GET on /config/network succeeds" @? fun () ->
  let expect =
    warning
      "error Cannot find the key /config/ip-config while retrieving IP, using \
       default"
  in
  let headers = admin_headers in
  match
    request ~expect ~hsm_state:(operational_mock ()) ~meth:`GET ~headers
      "/config/network"
  with
  | _, Some (`OK, _, `String body, _) ->
      String.equal body
        {|{"ipAddress":"192.168.1.1","netmask":"255.255.255.0","gateway":"0.0.0.0"}|}
  | _ -> false

let config_network_set_ok =
  "PUT on /config/network succeeds" @? fun () ->
  let new_network =
    {|{"ipAddress":"6.6.6.6","netmask":"255.255.255.0","gateway":"0.0.0.0"}|}
  in
  match admin_put_request ~body:(`String new_network) "/config/network" with
  | hsm_state, Some (`No_content, _, _, _) -> (
      match
        request ~hsm_state ~meth:`GET ~headers:admin_headers "/config/network"
      with
      | _, Some (`OK, _, `String body, _) -> String.equal body new_network
      | _ -> false)
  | _ -> false

let config_network_set_fail =
  "PUT with invalid IP address on /config/network fails" @? fun () ->
  let new_network =
    {|{"ipAddress":"6.6.6.666","netmask":"255.255.255.0","gateway":"0.0.0.0"}|}
  in
  match admin_put_request ~body:(`String new_network) "/config/network" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let config_logging_ok =
  "GET on /config/logging succeeds" @? fun () ->
  let headers = admin_headers in
  match
    request ~hsm_state:(operational_mock ()) ~meth:`GET ~headers
      "/config/logging"
  with
  | _, Some (`OK, _, `String body, _) ->
      String.equal body {|{"ipAddress":"0.0.0.0","port":514,"logLevel":"info"}|}
  | _ -> false

let config_logging_set_ok =
  "PUT on /config/logging succeeds" @? fun () ->
  let new_logging = {|{"ipAddress":"6.6.6.6","port":514,"logLevel":"error"}|} in
  match admin_put_request ~body:(`String new_logging) "/config/logging" with
  | hsm_state, Some (`No_content, _, _, _) -> (
      match
        request ~hsm_state ~meth:`GET ~headers:admin_headers "/config/logging"
      with
      | _, Some (`OK, _, `String body, _) -> String.equal body new_logging
      | _ -> false)
  | _ -> false

let config_logging_set_fail =
  "PUT with invalid logLevel on /config/logging fails" @? fun () ->
  let new_logging =
    {|{"ipAddress":"6.6.6.6","port":514,"logLevel":"nonexisting"}|}
  in
  match admin_put_request ~body:(`String new_logging) "/config/logging" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let config_time_ok =
  "GET on /config/time succeeds" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~headers:admin_headers
      "/config/time"
  with
  | _, Some (`OK, _, `String body, _) -> (
      match Yojson.Safe.from_string body with
      | `Assoc [ ("time", `String time) ] -> (
          match Ptime.of_rfc3339 time with Ok _ -> true | _ -> false)
      | _ -> false)
  | _ -> false

let config_time_set_ok =
  "PUT on /config/time succeeds" @? fun () ->
  let new_time = {|{time: "1970-01-01T00:00:00-00:00"}|} in
  match admin_put_request ~body:(`String new_time) "/config/time" with
  | hsm_state, Some (`No_content, _, _, _) -> (
      match request ~hsm_state ~headers:admin_headers "/config/time" with
      | _, Some (`OK, _, `String body, _) -> (
          match Yojson.Safe.from_string body with
          | `Assoc [ ("time", `String time) ] -> (
              match Ptime.of_rfc3339 time with Ok _ -> true | _ -> false)
          | _ -> false)
      | _ -> false)
  | _ -> false

let config_time_set_fail =
  "PUT with invalid timestamp on /config/time fails" @? fun () ->
  let new_time = {|{time: "1234"}|} in
  match admin_put_request ~body:(`String new_time) "/config/time" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let change_backup_passphrase =
  "set backup passphrase succeeds" @? fun () ->
  let passphrase =
    {|{ "newPassphrase" : "my backup passphrase", "currentPassphrase" : "" }|}
  in
  match
    admin_put_request ~body:(`String passphrase) "/config/backup-passphrase"
  with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false

let change_backup_passphrase_empty =
  "change to empty backup passphrase fails" @? fun () ->
  let passphrase = {|{ "newPassphrase" : "", "currentPassphrase" : ""}|} in
  match
    admin_put_request ~body:(`String passphrase) "/config/backup-passphrase"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let invalid_config_version =
  Alcotest.test_case "invalid config/version field" `Quick @@ fun () ->
  Alcotest.check_raises "invalid version breaks HSM"
    (Invalid_argument "broken NetHSM") (fun () ->
      Lwt_main.run
        ( Kv_mem.connect () >>= fun data ->
          Kv_mem.set data (Mirage_kv.Key.v "config/version") "abcdef"
          >>= fun _ -> Hsm.boot ~platform software_update_key data )
      |> ignore);
  Alcotest.check_raises "no version breaks HSM"
    (Invalid_argument "broken NetHSM") (fun () ->
      Lwt_main.run
        ( Kv_mem.connect () >>= fun data ->
          Kv_mem.set data (Mirage_kv.Key.v "config/version") "" >>= fun _ ->
          Hsm.boot ~platform software_update_key data )
      |> ignore)

let config_version_but_no_salt =
  Alcotest.test_case "config/version but no salt" `Quick @@ fun () ->
  Alcotest.check_raises "breaks HSM" (Invalid_argument "fatal!") (fun () ->
      Lwt_main.run
        ( Kv_mem.connect () >>= fun data ->
          Kv_mem.set data (Mirage_kv.Key.v "config/version") "0" >>= fun _ ->
          Hsm.boot ~platform software_update_key data )
      |> ignore)

let namespaces_get =
  "GET on /namespaces/ succeeds" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~headers:admin_headers
      "/namespaces"
  with
  | _, Some (`OK, _, `String data, _) ->
      let expected = {|[{"id":"namespace1"},{"id":"namespace2"}]|} in
      String.equal expected data
  | _ -> false

let namespaces_get_nuser =
  "GET on /namespaces/ fails when called by N-Admins" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~headers:subadmin_headers
      "/namespaces"
  with
  | _, Some (`Forbidden, _, _, _) -> true
  | _ -> false

let namespaces_seq =
  "GET on /namespaces/ succeeds after creating and deleting a namespace"
  @? fun () ->
  let hsm_state = operational_mock () in
  let hsm_state, _ =
    request
      ~expect:(info "created (namespace3)")
      ~meth:`PUT ~hsm_state ~headers:admin_headers "/namespaces/namespace3"
  in
  let hsm_state, _ =
    request
      ~expect:(info "removed (namespace3)")
      ~meth:`DELETE ~hsm_state ~headers:admin_headers "/namespaces/namespace3"
  in
  match request ~hsm_state ~headers:admin_headers "/namespaces" with
  | _, Some (`OK, _, `String data, _) ->
      let expected = {|[{"id":"namespace1"},{"id":"namespace2"}]|} in
      String.equal expected data
  | _ -> false

let namespaces_existing_create =
  "PUT on /namespaces/namespace1 fails (already exists)" @? fun () ->
  match
    request ~meth:`PUT ~hsm_state:(operational_mock ()) ~headers:admin_headers
      "/namespaces/namespace1"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let namespaces_existing_delete =
  "DELETE on /namespaces/namespace1 succeeds with no keys" @? fun () ->
  let expect = info "removed (namespace1)" in
  match
    request ~meth:`DELETE ~expect ~hsm_state:(operational_mock ())
      ~headers:admin_headers "/namespaces/namespace1"
  with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false

let namespaces_existing_delete_keys =
  "DELETE on /namespaces/namespace1 succeeds and deletes keys" @? fun () ->
  let expect = info "removed (namespace1)" ^ info "removed (subKeyID)" in
  match
    request ~meth:`DELETE ~expect
      ~hsm_state:(hsm_with_key ~and_namespace:"namespace1" ())
      ~headers:admin_headers "/namespaces/namespace1"
  with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false

let namespaces_new_delete =
  "DELETE on /namespaces/namespace3 fails (does not exist)" @? fun () ->
  match
    request ~meth:`DELETE ~hsm_state:(operational_mock ())
      ~headers:admin_headers "/namespaces/namespace3"
  with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false

let namespaces_new_create =
  "PUT on /namespaces/namespace3 succeeds" @? fun () ->
  let expect = info "created (namespace3)" in
  match
    request ~expect ~meth:`PUT ~hsm_state:(operational_mock ())
      ~headers:admin_headers "/namespaces/namespace3"
  with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false

let namespaces_shared_prefix =
  "Deleting a namespace does not delete namespaces that share suffix"
  @? fun () ->
  let expect = info "created (namespace11)" in
  let hsm_state =
    match
      request ~expect ~meth:`PUT
        ~hsm_state:(hsm_with_key ~and_namespace:"namespace1" ())
        ~headers:admin_headers "/namespaces/namespace11"
    with
    | hsm_state, Some (`No_content, _, _, _) -> hsm_state
    | _ -> Alcotest.fail "couldn't create namespace11"
  in
  let expect = info "removed (namespace1)" ^ info "removed (subKeyID)" in
  let hsm_state =
    match
      request ~meth:`DELETE ~expect ~hsm_state ~headers:admin_headers
        "/namespaces/namespace1"
    with
    | _, Some (`No_content, _, _, _) -> hsm_state
    | _ -> Alcotest.fail "couldn't delete namespace1"
  in
  match request ~hsm_state ~headers:admin_headers "/namespaces" with
  | _, Some (`OK, _, `String data, _) ->
      let expected = {|[{"id":"namespace11"},{"id":"namespace2"}]|} in
      Alcotest.(check string "namespace list" expected data);
      true
  | _ -> false

let users_get =
  "GET on /users/ succeeds" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~headers:admin_headers "/users"
  with
  | _, Some (`OK, _, `String data, _) ->
      let expected =
        {|[{"user":"admin"},{"user":"backup"},{"user":"namespace1~subadmin"},{"user":"namespace1~suboperator"},{"user":"namespace2~suboperator2"},{"user":"operator"},{"user":"operator2"}]|}
      in
      Alcotest.(check string "user list same" expected data);
      true
  | _ -> false

let users_get_namespace =
  "GET on /users/ succeeds partially when namespaced" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~headers:subadmin_headers "/users"
  with
  | _, Some (`OK, _, `String data, _) ->
      let expected =
        {|[{"user":"namespace1~subadmin"},{"user":"namespace1~suboperator"}]|}
      in
      Alcotest.(check string "user list same" expected data);
      true
  | _ -> false

let operator_json =
  {| { realName: "Jane User", role: "Operator", passphrase: "Very secret" } |}

let users_post =
  "POST on /users/ succeeds" @? fun () ->
  let expect = info "added Jane User (xxxx): R-Operator" in
  match admin_post_request ~expect ~body:(`String operator_json) "/users" with
  | _, Some (`Created, headers, body, _) -> (
      match Cohttp.Header.get headers "location" with
      | None -> false
      | Some loc ->
          let header_check =
            List.length (Astring.String.cuts ~empty:false ~sep:"/" loc) = 4
          in
          header_check && check_body_id body (extract_location_id loc))
  | _ -> false

let users_post_namespace =
  "POST on /users/ as N-Admin succeeds" @? fun () ->
  let expect = info "added Jane User (xxxx): R-Operator" in
  match
    request ~hsm_state:(operational_mock ()) ~meth:`POST
      ~headers:subadmin_headers ~expect ~body:(`String operator_json) "/users"
  with
  | _, Some (`Created, headers, body, _) -> (
      match Cohttp.Header.get headers "location" with
      | None -> false
      | Some loc ->
          let header_check =
            List.length (Astring.String.cuts ~empty:false ~sep:"/" loc) = 4
          in
          header_check && check_body_id body (extract_location_id loc))
  | _ -> false

let user_operator_add_root_root =
  "PUT on /users/op succeeds" @? fun () ->
  let expect = info "added Jane User (op): R-Operator" in
  match admin_put_request ~expect ~body:(`String operator_json) "/users/op" with
  | _, Some (`Created, headers, _, _) -> (
      match Cohttp.Header.get headers "location" with
      | None -> false
      | Some loc -> String.equal loc "/api/v1/users/op")
  | _ -> false

let user_operator_add_root_ns =
  "PUT on /users/namespace3~op from R-Admin succeeds with non-existing \
   namespace"
  @? fun () ->
  let expect = info "added Jane User (namespace3~op): R-Operator" in
  match
    admin_put_request ~expect ~body:(`String operator_json)
      "/users/namespace3~op"
  with
  | _, Some (`Created, headers, _, _) -> (
      match Cohttp.Header.get headers "location" with
      | None -> false
      | Some loc -> String.equal loc "/api/v1/users/namespace3~op")
  | _ -> false

let user_operator_add_ns_root =
  "PUT on /users/op fails from N-Admin" @? fun () ->
  match
    request ~meth:`PUT ~hsm_state:(operational_mock ())
      ~headers:subadmin_headers ~body:(`String operator_json) "/users/op"
  with
  | _, Some (`Forbidden, _, _, _) -> true
  | _ -> false

let user_operator_add_ns_ns =
  "PUT on /users/namespace1~op from N-Admin succeeds" @? fun () ->
  let expect = info "added Jane User (namespace1~op): R-Operator" in
  match
    request ~meth:`PUT ~hsm_state:(operational_mock ()) ~expect
      ~headers:subadmin_headers ~body:(`String operator_json)
      "/users/namespace1~op"
  with
  | _, Some (`Created, headers, _, _) -> (
      match Cohttp.Header.get headers "location" with
      | None -> false
      | Some loc -> String.equal loc "/api/v1/users/namespace1~op")
  | _ -> false

let user_operator_add_ns_ns_mismatch =
  "PUT on /users/namespace2~op fails from N-Admin from different namespace"
  @? fun () ->
  match
    request ~meth:`PUT ~hsm_state:(operational_mock ())
      ~headers:subadmin_headers ~body:(`String operator_json)
      "/users/namespace2~op"
  with
  | _, Some (`Forbidden, _, _, _) -> true
  | _ -> false

let user_operator_add_root_ns_existing =
  "PUT on /users/namespace1~op with namespace fails when namespace exists"
  @? fun () ->
  match
    request ~meth:`PUT ~hsm_state:(operational_mock ()) ~headers:admin_headers
      ~body:(`String operator_json) "/users/namespace1~op"
  with
  | _, Some (`Forbidden, _, _, _) -> true
  | _ -> false

let users_post_root_invalid1 =
  "POST on /users/~ as R-Admin fails" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~meth:`POST ~headers:admin_headers
      ~body:(`String operator_json) "/users/~"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let users_post_root_invalid2 =
  "POST on /users/~name as R-Admin fails" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~meth:`POST ~headers:admin_headers
      ~body:(`String operator_json) "/users/~name"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let users_post_root_invalid3 =
  "POST on /users/namespace1 as R-Admin fails" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~meth:`POST ~headers:admin_headers
      ~body:(`String operator_json) "/users/namespace1"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let users_post_ns_root =
  "POST on /users/ as R-Admin fails" @? fun () ->
  let expect = info "added Jane User (xxxx): R-Operator" in
  match
    request ~hsm_state:(operational_mock ()) ~meth:`POST
      ~headers:subadmin_headers ~expect ~body:(`String operator_json) "/users/"
  with
  | _, Some (`Created, _, _, _) -> true
  | _ -> false

let users_post_ns_ns =
  "POST on /users/namespace1~ as N-Admin succeeds" @? fun () ->
  let expect = info "added Jane User (xxxx): R-Operator" in
  match
    request ~hsm_state:(operational_mock ()) ~meth:`POST ~expect
      ~headers:subadmin_headers ~body:(`String operator_json)
      "/users/namespace1~"
  with
  | _, Some (`Created, headers, body, _) -> (
      match Cohttp.Header.get headers "location" with
      | None -> Alcotest.fail "no location headers"
      | Some loc ->
          Alcotest.(
            check int
              ("header segments: " ^ loc)
              4
              (List.length @@ Astring.String.cuts ~empty:false ~sep:"/" loc));
          check_body_id body (extract_location_id loc))
  | _ -> false

let users_post_ns_ns_mismatch =
  "POST on /users/namespace2~ as N-Admin from namespace1 fails" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~meth:`POST
      ~headers:subadmin_headers ~body:(`String operator_json)
      "/users/namespace2~"
  with
  | _, Some (`Forbidden, _, _, _) -> true
  | _ -> false

let user_operator_add_empty_passphrase =
  let operator_json =
    {| { realName: "Jane User", role: "Operator", passphrase: "" } |}
  in
  "PUT on /users/op fails (empty passphrase)" @? fun () ->
  match admin_put_request ~body:(`String operator_json) "/users/op" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let user_operator_add_invalid_id =
  "PUT on /users// fails (invalid id)" @? fun () ->
  match admin_put_request ~body:(`String operator_json) "/users//" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let user_operator_add_invalid_id2 =
  "PUT on /users/<long id>/ fails (ID too long)" @? fun () ->
  let id =
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
  in
  match
    admin_put_request ~body:(`String operator_json) ("/users/" ^ id ^ "/")
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let user_operator_add_invalid_id3 =
  "PUT on /users/test-user/ fails (not alphanum)" @? fun () ->
  let id = "test-user" in
  match
    admin_put_request ~body:(`String operator_json) ("/users/" ^ id ^ "/")
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let user_operator_add_invalid_id4 =
  "PUT on /users/~user/ fails (empty ns)" @? fun () ->
  match admin_put_request ~body:(`String operator_json) "/users/~user/" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let user_operator_add_invalid_id5 =
  "PUT on /users/user~/ fails (empty user id)" @? fun () ->
  match admin_put_request ~body:(`String operator_json) "/users/user~/" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let user_operator_delete_root_root =
  "DELETE on /users/operator succeeds" @? fun () ->
  let expect = info "removed (operator)" in
  match
    request ~expect ~hsm_state:(operational_mock ()) ~meth:`DELETE
      ~headers:admin_headers "/users/operator"
  with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false

let user_operator_delete_self =
  "DELETE on /users/namespace1~subadmin fails by self" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~meth:`DELETE
      ~headers:subadmin_headers "/users/namespace1~subadmin"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let user_operator_delete_not_found =
  "DELETE on /users/operator fails (not found)" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~meth:`DELETE
      ~headers:admin_headers "/users/op"
  with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false

let user_operator_delete_invalid_id =
  "DELETE on /users/operator fails (invalid ID)" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~meth:`DELETE
      ~headers:admin_headers "/users//"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let user_operator_delete_fails =
  "DELETE on /users/operator fails (requires administrator privileges)"
  @? fun () ->
  let headers = auth_header "operator" "test2Passphrase" in
  match
    request ~hsm_state:(operational_mock ()) ~meth:`DELETE ~headers
      "/users/operator"
  with
  | _, Some (`Forbidden, _, _, _) -> true
  | _ -> false

let user_operator_delete_root_ns =
  "DELETE on /users/namespace1~suboperator fails as R-Admin" @? fun () ->
  let headers = admin_headers in
  match
    request
      ~hsm_state:(hsm_with_key ~and_namespace:"namespace1" ())
      ~meth:`DELETE ~headers "/users/namespace1~suboperator"
  with
  | _, Some (`Forbidden, _, _, _) -> true
  | _ -> false

let user_operator_delete_ns_ns =
  "DELETE on /users/namespace1~suboperator succeeds as N-Admin" @? fun () ->
  let headers = subadmin_headers in
  let expect = info {|removed (namespace1~suboperator)|} in
  match
    request ~expect
      ~hsm_state:(hsm_with_key ~and_namespace:"namespace1" ())
      ~meth:`DELETE ~headers "/users/namespace1~suboperator"
  with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false

let user_operator_delete_ns_ns_mismatch =
  "DELETE on /users/namespace2~suboperator fails as N-Admin from different \
   namespace"
  @? fun () ->
  let headers = subadmin_headers in
  match
    request
      ~hsm_state:(hsm_with_key ~and_namespace:"namespace1" ())
      ~meth:`DELETE ~headers "/users/namespace2~suboperator"
  with
  | _, Some (`Forbidden, _, _, _) -> true
  | _ -> false

let user_operator_delete_ns_root =
  "DELETE on /users/operator fails as an N-Admin" @? fun () ->
  let headers = subadmin_headers in
  match
    request
      ~hsm_state:(hsm_with_key ~and_namespace:"namespace1" ())
      ~meth:`DELETE ~headers "/users/operator"
  with
  | _, Some (`Forbidden, _, _, _) -> true
  | _ -> false

let user_op_delete_fails =
  "DELETE on /users/op fails (user does not exist)" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~meth:`DELETE
      ~headers:admin_headers "/users/op"
  with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false

let user_operator_get =
  "GET on /users/operator succeeds" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~headers:admin_headers
      "/users/operator"
  with
  | _, Some (`OK, _, `String data, _) ->
      String.equal data {|{"realName":"operator","role":"Operator"}|}
  | _ -> false

let user_operator_get_not_found =
  "GET on /users/op returns not found" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~headers:admin_headers "/users/op"
  with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false

let user_operator_get_invalid_id =
  "GET on /users// returns bad request" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~headers:admin_headers "/users//"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let user_operator_get_invalid_id2 =
  "GET on /users/<LONG ID>/ returns bad request" @? fun () ->
  let id =
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
  in
  match
    request ~hsm_state:(operational_mock ()) ~headers:admin_headers
      ("/users/" ^ id ^ "/")
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let user_operator_get_forbidden =
  "GET on /users/operator2/ returns forbidden" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~headers:operator_headers
      "/users/operator2/"
  with
  | _, Some (`Forbidden, _, _, _) -> true
  | _ -> false

let user_operator_tags_get =
  "GET on /users/operator/tags succeeds" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~headers:admin_headers
      "/users/operator/tags"
  with
  | _, Some (`OK, _, `String data, _) -> String.equal data {|["berlin"]|}
  | _ -> false

let user_operator_tags_get_invalid_id =
  "GET on /users/op/tags returns not found" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~headers:admin_headers
      "/users/op/tags"
  with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false

let user_operator_tags_put =
  "PUT on /users/operator/tags/frankfurt returns 204 no content" @? fun () ->
  let expect = info "added a tag to operator (operator): \"frankfurt\"" in
  match
    request ~expect ~hsm_state:(operational_mock ()) ~meth:`PUT
      ~headers:admin_headers "/users/operator/tags/frankfurt"
  with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false

let user_operator_tags_put_twice =
  "PUT on /users/operator/tags/berlin returns 304 not modified" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~meth:`PUT ~headers:admin_headers
      "/users/operator/tags/berlin"
  with
  | _, Some (`Not_modified, _, _, _) -> true
  | _ -> false

let user_operator_tags_put_invalid_id =
  "PUT on /users/operator/tags/+=< returns bad request" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~meth:`PUT ~headers:admin_headers
      "/users/operator/tags/+=<"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let user_operator_tags_delete =
  "DELETE on /users/operator/tags/berlin returns no content" @? fun () ->
  let expect = info "removed a tag from operator (operator): \"berlin\"" in
  match
    request ~expect ~hsm_state:(operational_mock ()) ~meth:`DELETE
      ~headers:admin_headers "/users/operator/tags/berlin"
  with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false

let user_operator_tags_delete_not_found =
  "DELETE on /users/operator/tags/frankfurt returns not found" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~meth:`DELETE
      ~headers:admin_headers "/users/operator/tags/frankfurt"
  with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false

let user_backup_tags_get_not_operator =
  "GET on /users/backup/tags returns not found" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~headers:admin_headers
      "/users/backup/tags"
  with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false

let user_backup_tags_put_not_operator =
  "PUT on /users/backup/tags returns bad request" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~meth:`PUT ~headers:admin_headers
      "/users/backup/tags/frankfurt"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let user_version_get_bad_request =
  "GET on /users/.version returns bad request" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~headers:admin_headers
      "/users/.version"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let user_version_delete_fails_invalid_id =
  "DELETE on /users/.version fails" @? fun () ->
  match
    request ~hsm_state:(operational_mock ()) ~meth:`DELETE
      ~headers:admin_headers "/users/.version"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let user_passphrase_post =
  "POST on /users/admin/passphrase succeeds" @? fun () ->
  let new_passphrase = "my super new passphrase" in
  let expect = info "changed admin (admin) passphrase" in
  match
    admin_post_request ~expect
      ~body:(`String ("{\"passphrase\":\"" ^ new_passphrase ^ "\"}"))
      "/users/admin/passphrase"
  with
  | hsm_state, Some (`No_content, _, _, _) -> (
      let headers = auth_header "admin" new_passphrase in
      match request ~hsm_state ~headers "/users/admin" with
      | _, Some (`OK, _, _, _) -> (
          match
            request ~hsm_state ~meth:`GET ~headers:admin_headers "/users/admin"
          with
          | _, Some (`Unauthorized, _, _, _) -> true
          | _ -> false)
      | _ -> false)
  | _ -> false

let user_passphrase_operator_post =
  "POST on /users/operator/passphrase succeeds" @? fun () ->
  let headers = auth_header "operator" "test2Passphrase" in
  let new_passphrase = "my super new passphrase" in
  let expect = info "changed operator (operator) passphrase" in
  match
    request ~expect ~hsm_state:(operational_mock ())
      ~body:(`String ("{\"passphrase\":\"" ^ new_passphrase ^ "\"}"))
      ~meth:`POST ~headers "/users/operator/passphrase"
  with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false

let user_passphrase_suboperator_post_root_ns_existing =
  "POST on /users/namespace1~suboperator/passphrase from R-Admin fails if \
   namespace exists"
  @? fun () ->
  let new_passphrase = "my super new passphrase" in
  match
    request ~hsm_state:(operational_mock ())
      ~body:(`String ("{\"passphrase\":\"" ^ new_passphrase ^ "\"}"))
      ~meth:`POST ~headers:admin_headers
      "/users/namespace1~suboperator/passphrase"
  with
  | _, Some (`Forbidden, _, _, _) -> true
  | _ -> false

let user_passphrase_suboperator_post_root_ns =
  "POST on /users/namespace1~suboperator/passphrase from R-Admin succeeds if \
   namespace does not exists"
  @? fun () ->
  let new_passphrase = "my super new passphrase" in
  let hsm_state =
    let expect = info "removed (namespace1)" in
    match
      request ~expect ~hsm_state:(operational_mock ()) ~meth:`DELETE
        ~headers:admin_headers "/namespaces/namespace1"
    with
    | hsm_state, Some (`No_content, _, _, _) -> hsm_state
    | _ -> assert false
  in
  let expect = info "changed namespace1~suboperator (suboperator) passphrase" in
  match
    request ~expect ~hsm_state
      ~body:(`String ("{\"passphrase\":\"" ^ new_passphrase ^ "\"}"))
      ~meth:`POST ~headers:admin_headers
      "/users/namespace1~suboperator/passphrase"
  with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false

let user_passphrase_suboperator_post_ns_ns =
  "POST on /users/namespace1~suboperator/passphrase from N-Admin succeeds"
  @? fun () ->
  let new_passphrase = "my super new passphrase" in
  let expect = info "changed namespace1~suboperator (suboperator) passphrase" in
  match
    request ~expect ~hsm_state:(operational_mock ())
      ~body:(`String ("{\"passphrase\":\"" ^ new_passphrase ^ "\"}"))
      ~meth:`POST ~headers:subadmin_headers
      "/users/namespace1~suboperator/passphrase"
  with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false

let user_passphrase_suboperator_post_ns_ns_mismatch =
  "POST on /users/namespace2~suboperator/passphrase fails as  N-Admin from \
   different namespace"
  @? fun () ->
  let new_passphrase = "my super new passphrase" in
  match
    request ~hsm_state:(operational_mock ())
      ~body:(`String ("{\"passphrase\":\"" ^ new_passphrase ^ "\"}"))
      ~meth:`POST ~headers:subadmin_headers
      "/users/namespace2~suboperator/passphrase"
  with
  | _, Some (`Forbidden, _, _, _) -> true
  | _ -> false

let user_passphrase_suboperator_post_ns_root =
  "POST on /users/operator/passphrase from N-Admin fails" @? fun () ->
  let new_passphrase = "my super new passphrase" in
  match
    request ~hsm_state:(operational_mock ())
      ~body:(`String ("{\"passphrase\":\"" ^ new_passphrase ^ "\"}"))
      ~meth:`POST ~headers:subadmin_headers "/users/operator/passphrase"
  with
  | _, Some (`Forbidden, _, _, _) -> true
  | _ -> false

let user_passphrase_administrator_post =
  "POST on /users/admin/passphrase fails as operator" @? fun () ->
  let headers = auth_header "operator" "test2Passphrase" in
  let new_passphrase = "my super new passphrase" in
  match
    request ~hsm_state:(operational_mock ())
      ~body:(`String ("{\"passphrase\":\"" ^ new_passphrase ^ "\"}"))
      ~meth:`POST ~headers "/users/admin/passphrase"
  with
  | _, Some (`Forbidden, _, _, _) -> true
  | _ -> false

let user_passphrase_post_fails_not_found =
  "POST on /users/foobar/passphrase fails (not found)" @? fun () ->
  let new_passphrase = "my super new passphrase" in
  match
    admin_post_request
      ~body:(`String ("{\"passphrase\":\"" ^ new_passphrase ^ "\"}"))
      "/users/foobar/passphrase"
  with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false

let user_passphrase_post_fails_invalid_id =
  "POST on /users//passphrase fails (invalid ID)" @? fun () ->
  let new_passphrase = "my super new passphrase" in
  match
    admin_post_request
      ~body:(`String ("{\"passphrase\":\"" ^ new_passphrase ^ "\"}"))
      "/users//passphrase"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let keys_get =
  "GET on /keys succeeds" @? fun () ->
  match
    request ~headers:admin_headers ~hsm_state:(operational_mock ()) "/keys"
  with
  | _, Some (`OK, _, `String body, _) -> String.equal body "[]"
  | _ -> false

let keys_get_namespace =
  "GET on /keys lists only key in caller's namespace" @? fun () ->
  let n1 =
    match
      request ~headers:subadmin_headers
        ~hsm_state:(hsm_with_key ~and_namespace:"namespace1" ())
        "/keys"
    with
    | _, Some (`OK, _, `String body, _) ->
        String.equal body {|[{"id":"subKeyID"}]|}
    | _ -> false
  in
  let n2 =
    match
      request ~headers:admin_headers
        ~hsm_state:(hsm_with_key ~and_namespace:"namespace1" ())
        "/keys"
    with
    | _, Some (`OK, _, `String body, _) ->
        String.equal body {|[{"id":"keyID"}]|}
    | _ -> false
  in
  let n3 =
    match
      request ~headers:subadmin_headers ~hsm_state:(hsm_with_key ()) "/keys"
    with
    | _, Some (`OK, _, `String body, _) -> String.equal body "[]"
    | _ -> false
  in
  let n4 =
    match
      request ~headers:admin_headers ~hsm_state:(hsm_with_key ()) "/keys"
    with
    | _, Some (`OK, _, `String body, _) ->
        String.equal body {|[{"id":"keyID"}]|}
    | _ -> false
  in
  n1 && n2 && n3 && n4

let key_json =
  {| { mechanisms: [ "RSA_Signature_PKCS1" ], type: "RSA", private: { primeP: "+hsFcOCzFRwQMwuLaFjpv6pMv6BcqmcRBBWbVaWzpaq6+ag4dRpy0tIF1852zyCYqkGu5uTkHt6ndJPfKnJISQ==", primeQ : "wxq55QRL62Z+1IrsBM6h/YBcfTHnbiojepFPAakJAU0P0j+9gsHBbPgb2iFMhQyEj0bIKdfWhaAS1oqj6awsMw==", publicExponent : "AQAB" } } |}

let keys_get_namespace_seq =
  "GET on /keys behaves as intended w.r.t. namespace creation/deletion"
  @? fun () ->
  (* Create user in non-existing namespace *)
  let sa3_json =
    {| { realName: "N-Admin", role: "Administrator", passphrase: "ppppppppp3" } |}
  in
  let headers = auth_header "namespace3~subadmin3" "ppppppppp3" in
  let hsm_state = operational_mock () in
  let hsm_state =
    let expect = info "added N-Admin (namespace3~subadmin3): R-Administrator" in
    match
      admin_put_request ~expect ~hsm_state ~body:(`String sa3_json)
        "/users/namespace3~subadmin3"
    with
    | state, Some (`Created, _, _, _) -> state
    | _ -> Alcotest.fail "user creation failed"
  in
  (* User cannot list its namespace keys *)
  let () =
    match request ~meth:`GET ~headers ~hsm_state "/keys" with
    | _, Some (`Forbidden, _, _, _) -> ()
    | _ -> Alcotest.fail "GET /keys/ did not return 403"
  in
  (* Create the namespace *)
  let hsm_state =
    let expect = info "created (namespace3)" in
    match admin_put_request ~expect ~hsm_state "/namespaces/namespace3" with
    | state, Some (`No_content, _, _, _) -> state
    | _ -> Alcotest.fail "namespace creation failed"
  in
  (* Create a key *)
  let hsm_state =
    let expect = info "created (keyID)" in
    match
      request ~meth:`PUT ~headers ~hsm_state ~expect ~body:(`String key_json)
        "/keys/keyID"
    with
    | state, Some (`No_content, _, _, _) -> state
    | _ -> Alcotest.fail "key creation failed"
  in
  (* User can now list the keys *)
  let () =
    match request ~meth:`GET ~headers ~hsm_state "/keys" with
    | _, Some (`OK, _, `String body, _) ->
        let expect = {|[{"id":"keyID"}]|} in
        Alcotest.(check string "key list is the same" body expect)
    | _ -> Alcotest.fail "GET /keys/ did not return 403"
  in
  (* User deletion by admin forbidden *)
  let () =
    match
      request ~meth:`DELETE ~headers:admin_headers ~hsm_state
        "/users/namespace3~subadmin3"
    with
    | _, Some (`Forbidden, _, _, _) -> ()
    | _ -> Alcotest.fail "user deletion succeeded"
  in
  (* Delete namespace *)
  let hsm_state =
    let expect = info "removed (namespace3)" ^ info "removed (keyID)" in
    match
      request ~meth:`DELETE ~headers:admin_headers ~expect ~hsm_state
        "/namespaces/namespace3"
    with
    | state, Some (`No_content, _, _, _) -> state
    | _ -> Alcotest.fail "namespace deletion failed"
  in
  (* User cannot list its namespace keys, again *)
  let () =
    match request ~meth:`GET ~headers ~hsm_state "/keys" with
    | _, Some (`Forbidden, _, _, _) -> ()
    | _ -> Alcotest.fail "GET /keys/ did not return 403"
  in
  (* User deletion by admin succeeds *)
  let () =
    let expect = info "removed (namespace3~subadmin3)" in
    match
      request ~meth:`DELETE ~headers:admin_headers ~expect ~hsm_state
        "/users/namespace3~subadmin3"
    with
    | _, Some (`No_content, _, _, _) -> ()
    | _ -> Alcotest.fail "user deletion failed"
  in
  true

let keys_post_json =
  "POST on /keys succeeds" @? fun () ->
  let expect = info "created (xxxx)" in
  match admin_post_request ~expect ~body:(`String key_json) "/keys" with
  | _, Some (`Created, headers, body, _) -> (
      match Cohttp.Header.get headers "location" with
      | None -> false
      | Some loc ->
          (* /api/v1/keys/<keyid> *)
          let header_check =
            List.length (Astring.String.cuts ~empty:false ~sep:"/" loc) = 4
          in
          header_check && check_body_id body (extract_location_id loc))
  | _ -> false

let key_pem =
  {|-----BEGIN PRIVATE KEY-----
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

let keys_post_pem =
  "POST on /keys succeeds" @? fun () ->
  let params =
    {|{ mechanisms: [ "RSA_Signature_PKCS1" ], restrictions: { tags: [ "munich" ] } }|}
  in
  let expect =
    multipart_log ^ info "created (xxxx)" ^ info "tags (xxxx): [\"munich\"]"
  in
  let content_type, body =
    create_multipart_request [ ("arguments", params); ("backup_data", key_pem) ]
  in
  match
    admin_post_request ~expect ~content_type ~body:(`String body) "/keys"
  with
  | _, Some (`Created, headers, body, _) -> (
      match Cohttp.Header.get headers "location" with
      | None -> false
      | Some loc ->
          (* /api/v1/keys/<keyid> *)
          let header_check =
            List.length (Astring.String.cuts ~empty:false ~sep:"/" loc) = 4
          in
          header_check && check_body_id body (extract_location_id loc))
  | _ -> false

let keys_generate =
  let generate_json =
    {|{ mechanisms: [ "RSA_Decryption_PKCS1" ], type: "RSA", length: 2048 }|}
  in
  "POST on /keys/generate succeeds" @? fun () ->
  let expect = info "created (xxxx)" in
  match
    admin_post_request ~expect ~body:(`String generate_json) "/keys/generate"
  with
  | _, Some (`Created, headers, body, _) -> (
      match Cohttp.Header.get headers "location" with
      | None -> false
      | Some loc ->
          (* /api/v1/keys/<keyid> *)
          let header_check =
            List.length (Astring.String.cuts ~empty:false ~sep:"/" loc) = 4
          in
          header_check && check_body_id body (extract_location_id loc))
  | _ -> false

let keys_generate_invalid_id =
  let generate_json =
    {|{ mechanisms: [ "RSA_Decryption_PKCS1" ], type: "RSA", length: 2048, id: "&*&*&*" }|}
  in
  "POST on /keys/generate with invalid ID fails" @? fun () ->
  match admin_post_request ~body:(`String generate_json) "/keys/generate" with
  | _, Some (`Bad_request, _, `String reply, _) ->
      let expected =
        {|{"message":"ID may only contain alphanumeric characters."}|}
      in
      String.equal reply expected
  | _ -> false

let keys_generate_invalid_id_length =
  let generate_json =
    {|{ mechanisms: [ "RSA_Decryption_PKCS1" ], type: "RSA", length: 2048, id: "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890" }|}
  in
  "POST on /keys/generate with invalid ID fails" @? fun () ->
  match admin_post_request ~body:(`String generate_json) "/keys/generate" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let keys_generate_invalid_mech =
  let generate_json =
    {|{ mechanisms: [ "EdDSA_Signature" ], type: "RSA", length: 2048, id: "1234" }|}
  in
  "POST on /keys/generate with invalid mechanism fails" @? fun () ->
  match admin_post_request ~body:(`String generate_json) "/keys/generate" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let keys_generate_no_mech =
  let generate_json =
    {|{ mechanisms: [ ], type: "RSA", length: 2048, id: "1234" }|}
  in
  "POST on /keys/generate with no mechanism fails" @? fun () ->
  match admin_post_request ~body:(`String generate_json) "/keys/generate" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let keys_generate_ed25519 =
  "POST on /keys/generate with ED25519 succeeds" @? fun () ->
  let generate_ed25519 =
    {|{ mechanisms: [ "EdDSA_Signature" ], type: "Curve25519" }|}
  in
  let expect = info "created (xxxx)" in
  match
    admin_post_request ~expect ~body:(`String generate_ed25519) "/keys/generate"
  with
  | _, Some (`Created, headers, body, _) -> (
      match Cohttp.Header.get headers "location" with
      | None -> false
      | Some loc ->
          (* /api/v1/keys/<keyid> *)
          let header_check =
            List.length (Astring.String.cuts ~empty:false ~sep:"/" loc) = 4
          in
          header_check && check_body_id body (extract_location_id loc))
  | _ -> false

let keys_generate_ed25519_explicit_keyid =
  "POST on /keys/generate with ED25519 succeeds (with explicit key ID)"
  @? fun () ->
  let generate_ed25519 =
    {|{ mechanisms: [ "EdDSA_Signature" ], type: "Curve25519", "id": "mynewkey" }|}
  in
  let expect = info "created (mynewkey)" in
  match
    admin_post_request ~expect ~body:(`String generate_ed25519) "/keys/generate"
  with
  | _, Some (`Created, headers, body, _) -> (
      match Cohttp.Header.get headers "location" with
      | None -> false
      | Some loc ->
          let header_check = String.equal loc "/api/v1/keys/mynewkey" in
          header_check && check_body_id body "mynewkey")
  | _ -> false

let keys_generate_ed25519_fail =
  let generate_ed25519 =
    {|{ mechanisms: [ "RSA_Decryption_PKCS1" ], type: "Curve25519" }|}
  in
  "POST on /keys/generate with ED25519 fails (wrong mechanism)" @? fun () ->
  match
    admin_post_request ~body:(`String generate_ed25519) "/keys/generate"
  with
  | _, Some (`Bad_request, headers, _, _) -> (
      match Cohttp.Header.get headers "location" with
      | None -> true
      | Some _ -> false)
  | _ -> false

let keys_generate_generic =
  "POST on /keys/generate with Generic succeeds" @? fun () ->
  let generate_generic =
    {|{ mechanisms: [ "AES_Encryption_CBC" ], type: "Generic", length: 256 }|}
  in
  let expect = info "created (xxxx)" in
  match
    admin_post_request ~expect ~body:(`String generate_generic) "/keys/generate"
  with
  | _, Some (`Created, headers, body, _) -> (
      match Cohttp.Header.get headers "location" with
      | None -> false
      | Some loc ->
          (* /api/v1/keys/<keyid> *)
          let header_check =
            List.length (Astring.String.cuts ~empty:false ~sep:"/" loc) = 4
          in
          header_check && check_body_id body (extract_location_id loc))
  | _ -> false

let keys_generate_generic_fail =
  let generate_generic =
    {|{ mechanisms: [ "EdDSA_Signature" ], type: "Generic", length: 256 }|}
  in
  "POST on /keys/generate with Generic fails (wrong mechanism)" @? fun () ->
  match
    admin_post_request ~body:(`String generate_generic) "/keys/generate"
  with
  | _, Some (`Bad_request, headers, _, _) -> (
      match Cohttp.Header.get headers "location" with
      | None -> true
      | Some _ -> false)
  | _ -> false

let keys_key_get =
  "GET on /keys/keyID succeeds" @? fun () ->
  match
    request ~headers:admin_headers ~hsm_state:(hsm_with_key ()) "/keys/keyID"
  with
  | _, Some (`OK, _, `String data, _) -> (
      let json_data = Yojson.Safe.from_string data in
      match json_data with
      | `Assoc xs ->
          List.exists
            (fun (k, v) ->
              k = "mechanisms" && match v with `List _ -> true | _ -> false)
            xs
          && List.exists
               (fun (k, v) ->
                 k = "type"
                 && match v with `String a -> a = "RSA" | _ -> false)
               xs
          && List.exists
               (fun (k, v) ->
                 k = "operations" && match v with `Int _ -> true | _ -> false)
               xs
          && List.exists
               (fun (k, v) ->
                 k = "public"
                 &&
                 match v with
                 | `Assoc a ->
                     List.exists
                       (fun (k, v) ->
                         k = "modulus"
                         && match v with `String _ -> true | _ -> false)
                       a
                     && List.exists
                          (fun (k, v) ->
                            k = "publicExponent"
                            && match v with `String _ -> true | _ -> false)
                          a
                     && List.length a = 2
                 | _ -> false)
               xs
          && List.length xs = 5
      | _ -> false)
  | _ -> false

let keys_key_get_not_found =
  "GET on /keys/keyID fails (ID not found)" @? fun () ->
  match
    request ~headers:admin_headers ~hsm_state:(hsm_with_key ()) "/keys/keyID2"
  with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false

let keys_key_get_invalid_id =
  "GET on /keys/keyID fails (invalid ID)" @? fun () ->
  match
    request ~headers:admin_headers ~hsm_state:(hsm_with_key ()) "/keys//"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let keys_key_get_invalid_id2 =
  "GET on /keys/keyID fails (invalid ID)" @? fun () ->
  match
    request ~headers:admin_headers ~hsm_state:(hsm_with_key ()) "/keys/--"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let keys_key_put_json =
  "PUT on /keys/keyID succeeds" @? fun () ->
  let expect = info "created (keyID)" in
  match admin_put_request ~expect ~body:(`String key_json) "/keys/keyID" with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false

let keys_key_put_pem =
  "PUT on /keys/keyID succeeds" @? fun () ->
  let expect =
    multipart_log ^ info "created (keyID)" ^ info "tags (keyID): [\"munich\"]"
  in
  let params =
    {|{ mechanisms: [ "RSA_Signature_PKCS1" ], restrictions: { tags: [ "munich" ] } }|}
  in
  let content_type, body =
    create_multipart_request [ ("arguments", params); ("backup_data", key_pem) ]
  in
  match
    admin_put_request ~expect ~content_type ~body:(`String body) "/keys/keyID"
  with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false

let keys_key_put_already_there =
  "PUT on /keys/keyID succeeds" @? fun () ->
  match
    admin_put_request ~hsm_state:(hsm_with_key ()) ~body:(`String key_json)
      "/keys/keyID"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let keys_key_put_invalid_id =
  "PUT on /keys/keyID fails (invalid ID)" @? fun () ->
  match admin_put_request ~body:(`String key_json) "/keys//" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let keys_key_delete =
  "DELETE on /keys/keyID succeeds" @? fun () ->
  let expect = info "removed (keyID)" in
  match
    request ~expect ~meth:`DELETE ~headers:admin_headers
      ~hsm_state:(hsm_with_key ()) "/keys/keyID"
  with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false

let keys_key_delete_not_found =
  "DELETE on /keys/keyID fails (ID not found)" @? fun () ->
  match
    request ~meth:`DELETE ~headers:admin_headers ~hsm_state:(hsm_with_key ())
      "/keys/keyID2"
  with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false

let keys_key_delete_invalid_id =
  "DELETE on /keys/keyID fails (invalid ID)" @? fun () ->
  match
    request ~meth:`DELETE ~headers:admin_headers ~hsm_state:(hsm_with_key ())
      "/keys//"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let admin_keys_key_public_pem =
  "GET on /keys/keyID/public.pem succeeds" @? fun () ->
  match
    request ~headers:admin_headers ~hsm_state:(hsm_with_key ())
      "/keys/keyID/public.pem"
  with
  | _, Some (`OK, _, _, _) -> true
  | _ -> false

let operator_keys_key_public_pem =
  "GET on /keys/keyID/public.pem succeeds" @? fun () ->
  match
    request ~headers:operator_headers ~hsm_state:(hsm_with_key ())
      "/keys/keyID/public.pem"
  with
  | _, Some (`OK, _, _, _) -> true
  | _ -> false

let operator_keys_key_public_pem_not_found =
  "GET on /keys/keyID/public.pem fails (ID not found)" @? fun () ->
  match
    request ~headers:operator_headers ~hsm_state:(hsm_with_key ())
      "/keys/keyID2/public.pem"
  with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false

let operator_keys_key_public_pem_invalid_id =
  "GET on /keys/keyID/public.pem fails (invalid ID)" @? fun () ->
  match
    request ~headers:operator_headers ~hsm_state:(hsm_with_key ())
      "/keys//public.pem"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let admin_keys_key_csr_pem =
  "POST on /keys/keyID/csr.pem succeeds" @? fun () ->
  match
    admin_post_request ~body:(`String subject) ~hsm_state:(hsm_with_key ())
      "/keys/keyID/csr.pem"
  with
  | _, Some (`OK, headers, `String body, _) -> (
      match Cohttp.Header.get headers "content-type" with
      | None -> false
      | Some ct -> (
          String.equal ct "application/x-pem-file"
          &&
          match X509.Signing_request.decode_pem body with
          | Ok _ -> true
          | Error _ -> false))
  | _ -> false

let operator_keys_key_csr_pem =
  "POST on /keys/keyID/csr.pem succeeds" @? fun () ->
  match
    request ~meth:`POST ~headers:operator_headers ~body:(`String subject)
      ~hsm_state:(hsm_with_key ()) "/keys/keyID/csr.pem"
  with
  | _, Some (`OK, _, _, _) -> true
  | _ -> false

let operator_keys_key_csr_pem_common_name_only =
  "POST on /keys/keyID/csr.pem succeeds with only common name" @? fun () ->
  match
    request ~meth:`POST ~headers:operator_headers
      ~body:(`String common_name_only) ~hsm_state:(hsm_with_key ())
      "/keys/keyID/csr.pem"
  with
  | _, Some (`OK, _, _, _) -> true
  | _ -> false

let operator_keys_key_csr_pem_no_common_name =
  "POST on /keys/keyID/csr.pem fails (no common name)" @? fun () ->
  match
    request ~meth:`POST ~headers:operator_headers ~body:(`String bad_subject)
      ~hsm_state:(hsm_with_key ()) "/keys/keyID/csr.pem"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let operator_keys_key_csr_pem_not_found =
  "POST on /keys/keyID/csr.pem fails (ID not found)" @? fun () ->
  match
    request ~meth:`POST ~headers:operator_headers ~body:(`String subject)
      ~hsm_state:(hsm_with_key ()) "/keys/keyID2/csr.pem"
  with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false

let operator_keys_key_csr_pem_invalid_id =
  "POST on /keys/keyID/csr.pem fails (invalid ID)" @? fun () ->
  match
    request ~meth:`POST ~headers:operator_headers ~body:(`String subject)
      ~hsm_state:(hsm_with_key ()) "/keys//csr.pem"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let message = "Hi Alice! Please bring malacpörkölt for dinner!"

let encrypted_message =
  {|
WiugdWUSZAqia2lIJbPm1N3KHcnbZAyLklnNqKnlzDjvTR9UNgmlG2FC4jdnfvn9w9TUt5H9z7Z5
9jnWww+v9AQebiUpnps0RqwN87XDWCHhE9AdqWFnNjCA4NsoKXUFB4RhrRrBInqVKD0SFYSXVu4g
hufwzgzFoWeqJnQN6uE=
|}

let encrypted =
  Printf.sprintf {|{ mode: "PKCS1", encrypted: "%s"}|} encrypted_message

let operator_keys_key_decrypt =
  "POST on /keys/keyID/decrypt succeeds" @? fun () ->
  match
    request ~meth:`POST ~headers:operator_headers ~body:(`String encrypted)
      ~hsm_state:(hsm_with_key ()) "/keys/keyID/decrypt"
  with
  | _, Some (`OK, _, `String data, _) -> (
      match Yojson.Safe.from_string data with
      | `Assoc [ ("decrypted", `String decrypted) ] -> (
          match Base64.decode decrypted with
          | Error _ -> false
          | Ok decoded -> String.equal message decoded)
      | _ -> false)
  | _ -> false

let operator_keys_key_decrypt_fails =
  "POST on /keys/keyID/decrypt fails" @? fun () ->
  let hsm_state =
    hsm_with_key
      ~mechanisms:Keyfender.Json.(MS.singleton RSA_Signature_PKCS1)
      ()
  in
  match
    request ~meth:`POST ~headers:operator_headers ~body:(`String encrypted)
      ~hsm_state "/keys/keyID/decrypt"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let operator_keys_key_decrypt_fails_wrong_mech =
  "POST on /keys/keyID/decrypt fails (wrong mechanism)" @? fun () ->
  let hsm_state =
    hsm_with_key ~mechanisms:Keyfender.Json.(MS.singleton RSA_Decryption_RAW) ()
  in
  match
    request ~meth:`POST ~headers:operator_headers ~body:(`String encrypted)
      ~hsm_state "/keys/keyID/decrypt"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let operator_keys_key_decrypt_fails_invalid_id =
  "POST on /keys/keyID/decrypt fails (invalid ID)" @? fun () ->
  match
    request ~meth:`POST ~headers:operator_headers ~body:(`String encrypted)
      ~hsm_state:(hsm_with_key ()) "/keys//decrypt"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let operator_keys_key_decrypt_fails_not_found =
  "POST on /keys/keyID/decrypt fails (ID not found)" @? fun () ->
  match
    request ~meth:`POST ~headers:operator_headers ~body:(`String encrypted)
      ~hsm_state:(hsm_with_key ()) "/keys/keyID2/decrypt"
  with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false

let sign_request =
  Printf.sprintf {|{ mode: "PKCS1", message: "%s"}|}
    (Base64.encode_string message)

let operator_keys_key_sign =
  "POST on /keys/keyID/sign succeeds" @? fun () ->
  let hsm_state =
    hsm_with_key
      ~mechanisms:Keyfender.Json.(MS.singleton RSA_Signature_PKCS1)
      ()
  in
  match
    request ~meth:`POST ~headers:operator_headers ~body:(`String sign_request)
      ~hsm_state "/keys/keyID/sign"
  with
  | _, Some (`OK, _, `String data, _) -> (
      match Yojson.Safe.from_string data with
      | `Assoc [ ("signature", `String signature) ] -> (
          match Base64.decode signature with
          | Error _ -> false
          | Ok decoded -> (
              let key = Mirage_crypto_pk.Rsa.pub_of_priv test_key in
              match Mirage_crypto_pk.Rsa.PKCS1.sig_decode ~key decoded with
              | Some msg -> String.equal msg message
              | None -> false))
      | _ -> false)
  | _ -> false

let operator_keys_key_sign_fails =
  "POST on /keys/keyID/sign fails" @? fun () ->
  let hsm_state = hsm_with_key () in
  match
    request ~meth:`POST ~headers:operator_headers ~body:(`String sign_request)
      ~hsm_state "/keys/keyID/sign"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let operator_keys_key_sign_fails_bad_data =
  "POST on /keys/keyID/sign fails (msg too short)" @? fun () ->
  let hsm_state =
    hsm_with_key
      ~mechanisms:Keyfender.Json.(MS.singleton RSA_Signature_PSS_SHA256)
      ()
  in
  let sign_request =
    {|{ mode: "PSS_SHA256", message: "nhrfotu32409ru0rgert45z54z099u23r03498uhtr=="}|}
  in
  match
    request ~meth:`POST ~headers:operator_headers ~body:(`String sign_request)
      ~hsm_state "/keys/keyID/sign"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let operator_keys_key_sign_fails_wrong_mech =
  "POST on /keys/keyID/sign fails (wrong mechanism)" @? fun () ->
  let mechanisms = Keyfender.Json.(MS.singleton RSA_Signature_PSS_MD5) in
  let hsm_state = hsm_with_key ~mechanisms () in
  match
    request ~meth:`POST ~headers:operator_headers ~body:(`String sign_request)
      ~hsm_state "/keys/keyID/sign"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let operator_keys_key_sign_fails_invalid_id =
  "POST on /keys/keyID/sign fails (invalid ID)" @? fun () ->
  let hsm_state =
    hsm_with_key
      ~mechanisms:Keyfender.Json.(MS.singleton RSA_Signature_PKCS1)
      ()
  in
  match
    request ~meth:`POST ~headers:operator_headers ~body:(`String sign_request)
      ~hsm_state "/keys//sign"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let operator_keys_key_sign_fails_not_found =
  "POST on /keys/keyID/sign fails (ID not found)" @? fun () ->
  let hsm_state =
    hsm_with_key
      ~mechanisms:Keyfender.Json.(MS.singleton RSA_Signature_PKCS1)
      ()
  in
  match
    request ~meth:`POST ~headers:operator_headers ~body:(`String sign_request)
      ~hsm_state "/keys/keyID2/sign"
  with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false

let operator_keys_key_sign_and_decrypt =
  "POST on /keys/keyID/decrypt succeeds with sign and decrypt key" @? fun () ->
  let mechanisms =
    Keyfender.Json.(
      MS.add RSA_Decryption_PKCS1 (MS.singleton RSA_Signature_PKCS1))
  in
  let hsm_state = hsm_with_key ~mechanisms () in
  match
    request ~meth:`POST ~headers:operator_headers ~body:(`String encrypted)
      ~hsm_state "/keys/keyID/decrypt"
  with
  | _, Some (`OK, _, `String data, _) -> (
      match Yojson.Safe.from_string data with
      | `Assoc [ ("decrypted", `String decrypted) ] -> (
          match Base64.decode decrypted with
          | Error _ -> false
          | Ok decoded -> (
              String.equal message decoded
              &&
              match
                request ~meth:`POST ~headers:operator_headers
                  ~body:(`String sign_request) ~hsm_state "/keys/keyID/sign"
              with
              | _, Some (`OK, _, `String data, _) -> (
                  match Yojson.Safe.from_string data with
                  | `Assoc [ ("signature", `String signature) ] -> (
                      match Base64.decode signature with
                      | Error _ -> false
                      | Ok decoded -> (
                          let key = Mirage_crypto_pk.Rsa.pub_of_priv test_key in
                          match
                            Mirage_crypto_pk.Rsa.PKCS1.sig_decode ~key decoded
                          with
                          | Some msg -> String.equal msg message
                          | None -> false))
                  | _ -> false)
              | _ -> false))
      | _ -> false)
  | _ -> false

let ed25519_priv_pem =
  {|-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
-----END PRIVATE KEY-----
|}

let hsm_with_ed25519_key () =
  let hsm_state = operational_mock () in
  Lwt_main.run
    ( Hsm.Key.add_pem hsm_state
        Keyfender.Json.(MS.singleton EdDSA_Signature)
        ~id:"keyID" ed25519_priv_pem no_restrictions
    >|= function
      | Ok () -> hsm_state
      | Error _ -> assert false )

let ed25519_priv =
  match X509.Private_key.decode_pem ed25519_priv_pem with
  | Ok (`ED25519 priv) -> priv
  | _ -> assert false

let ed25519_pub = Mirage_crypto_ec.Ed25519.pub_of_priv ed25519_priv

let operator_sign_ed25519_succeeds =
  "POST on /keys/keyID/sign succeeds with ed25519 sign key" @? fun () ->
  let hsm_state = hsm_with_ed25519_key () in
  let sign_request =
    Printf.sprintf {|{ mode: "EdDSA", message: "%s"}|}
      (Base64.encode_string message)
  in
  match
    request ~meth:`POST ~headers:operator_headers ~body:(`String sign_request)
      ~hsm_state "/keys/keyID/sign"
  with
  | _, Some (`OK, _, `String data, _) -> (
      match Yojson.Safe.from_string data with
      | `Assoc [ ("signature", `String signature) ] -> (
          match Base64.decode signature with
          | Error _ -> false
          | Ok signature ->
              Mirage_crypto_ec.Ed25519.verify ~key:ed25519_pub signature
                ~msg:message)
      | _ -> false)
  | _ -> false

let operator_sign_ed25519_fails =
  "POST on /keys/keyID/sign fails with ed25519 sign key (bad mode)" @? fun () ->
  let hsm_state = hsm_with_ed25519_key () in
  let sign_request =
    Printf.sprintf {|{ mode: "PKCS1", message: "%s"}|}
      (Base64.encode_string message)
  in
  match
    request ~meth:`POST ~headers:operator_headers ~body:(`String sign_request)
      ~hsm_state "/keys/keyID/sign"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let keys_key_get_ed25519 =
  "GET on /keys/keyID succeeds with ED25519 key" @? fun () ->
  match
    request ~headers:admin_headers ~hsm_state:(hsm_with_ed25519_key ())
      "/keys/keyID"
  with
  | _, Some (`OK, _, _, _) -> true
  | _ -> false

let ed25519_json =
  let b64 =
    Base64.encode_string (Mirage_crypto_ec.Ed25519.priv_to_octets ed25519_priv)
  in
  Printf.sprintf
    {| { mechanisms: [ "EdDSA_Signature" ], type: "Curve25519", private: { data: "%s" } } |}
    b64

let keys_key_put_ed25519 =
  "PUT on /keys/keyID succeeds with ED25519 key" @? fun () ->
  let expect = info "created (keyID)" in
  match
    admin_put_request ~expect ~body:(`String ed25519_json) "/keys/keyID"
  with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false

let operator_keys_key_public_pem_ed25519 =
  "GET on /keys/keyID/public.pem succeeds" @? fun () ->
  match
    request ~headers:operator_headers ~hsm_state:(hsm_with_ed25519_key ())
      "/keys/keyID/public.pem"
  with
  | _, Some (`OK, _, `String body, _) ->
      String.equal body (X509.Public_key.encode_pem (`ED25519 ed25519_pub))
  | _ -> false

let generic_key = "secretsecretsecretsecretsecretse"
let aes_message = "messagemessagemessagemessagemess"
let aes_cbc_iv = "iviviviviviviviv"
let aes_cbc_encrypted = "bx4qzXVP7jEUogLTcsaMcOOe1TZFS2zQTwebJNzTS90="

let add_generic state ~id ms key =
  let json_key =
    {
      Keyfender.Json.data = Base64.encode_string key;
      primeP = "";
      primeQ = "";
      publicExponent = "";
    }
  in
  match
    Lwt_main.run
      (Hsm.Key.add_json ~id state ms Generic json_key no_restrictions)
  with
  | Ok () -> ()
  | Error _ -> assert false

let hsm_with_generic_key () =
  let hsm_state = operational_mock () in
  add_generic hsm_state
    Keyfender.Json.(MS.of_list [ AES_Decryption_CBC; AES_Encryption_CBC ])
    ~id:"keyID" generic_key;
  hsm_state

let operator_decrypt_aes_cbc_succeeds =
  "POST on /keys/keyID/decrypt succeeds with AES CBC" @? fun () ->
  let hsm_state = hsm_with_generic_key () in
  let decrypt_request =
    Printf.sprintf {|{ mode: "AES_CBC", iv: "%s", encrypted: "%s"}|}
      (Base64.encode_string aes_cbc_iv)
      aes_cbc_encrypted
  in
  match
    request ~meth:`POST ~headers:operator_headers
      ~body:(`String decrypt_request) ~hsm_state "/keys/keyID/decrypt"
  with
  | _, Some (`OK, _, `String data, _) -> (
      match Yojson.Safe.from_string data with
      | `Assoc [ ("decrypted", `String decrypted) ] -> (
          match Base64.decode decrypted with
          | Error _ -> false
          | Ok m -> String.equal aes_message m)
      | _ -> false)
  | _ -> false

let operator_decrypt_aes_cbc_no_iv_fails =
  "POST on /keys/keyID/decrypt succeeds with AES CBC" @? fun () ->
  let hsm_state = hsm_with_generic_key () in
  let decrypt_request =
    Printf.sprintf {|{ mode: "AES_CBC", encrypted: "%s"}|} aes_cbc_encrypted
  in
  match
    request ~meth:`POST ~headers:operator_headers
      ~body:(`String decrypt_request) ~hsm_state "/keys/keyID/decrypt"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let operator_encrypt_aes_cbc_succeeds =
  "POST on /keys/keyID/decrypt succeeds with AES CBC" @? fun () ->
  let hsm_state = hsm_with_generic_key () in
  let encrypt_request =
    Printf.sprintf {|{ mode: "AES_CBC", iv: "%s", message: "%s"}|}
      (Base64.encode_string aes_cbc_iv)
      (Base64.encode_string aes_message)
  in
  Printf.eprintf "request: %s" encrypt_request;
  match
    request ~meth:`POST ~headers:operator_headers
      ~body:(`String encrypt_request) ~hsm_state "/keys/keyID/encrypt"
  with
  | _, Some (`OK, _, `String data, _) -> (
      Printf.eprintf "response: %s" data;
      match Yojson.Safe.from_string data with
      | `Assoc [ ("encrypted", `String encrypted); ("iv", `String iv) ] -> (
          match Base64.decode encrypted with
          | Error _ -> false
          | Ok _ ->
              String.equal aes_cbc_encrypted encrypted
              && String.equal iv (Base64.encode_string aes_cbc_iv))
      | _ -> false)
  | _ -> false

let operator_encrypt_aes_cbc_no_iv_succeeds =
  "POST on /keys/keyID/decrypt succeeds with AES CBC" @? fun () ->
  let hsm_state = hsm_with_generic_key () in
  let encrypt_request =
    Printf.sprintf {|{ mode: "AES_CBC", message: "%s"}|}
      (Base64.encode_string aes_message)
  in
  Printf.eprintf "request: %s" encrypt_request;
  match
    request ~meth:`POST ~headers:operator_headers
      ~body:(`String encrypt_request) ~hsm_state "/keys/keyID/encrypt"
  with
  | _, Some (`OK, _, `String data, _) -> (
      Printf.eprintf "response: %s" data;
      match Yojson.Safe.from_string data with
      | `Assoc [ ("encrypted", `String encrypted_b64); ("iv", `String iv) ] -> (
          match Base64.decode encrypted_b64 with
          | Error _ -> false
          | Ok encrypted ->
              let iv = Base64.decode_exn iv in
              let key = Mirage_crypto.AES.CBC.of_secret generic_key in
              let m = Mirage_crypto.AES.CBC.decrypt ~key ~iv encrypted in
              String.equal m aes_message)
      | _ -> false)
  | _ -> false

let keys_key_get_generic =
  "GET on /keys/keyID succeeds with Generic key" @? fun () ->
  match
    request ~headers:admin_headers ~hsm_state:(hsm_with_generic_key ())
      "/keys/keyID"
  with
  | _, Some (`OK, _, _, _) -> true
  | _ -> false

let generic_json =
  let b64 = Base64.encode_string generic_key in
  Printf.sprintf
    {| { mechanisms: [ "AES_Encryption_CBC" ], type: "Generic", private: { data: "%s" } } |}
    b64

let keys_key_put_generic =
  "PUT on /keys/keyID succeeds with Generic key" @? fun () ->
  let expect = info "created (keyID)" in
  match
    admin_put_request ~expect ~body:(`String generic_json) "/keys/keyID"
  with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false

let hsm_with_tags () =
  let hsm_state = operational_mock () in
  let ms =
    Keyfender.Json.(MS.of_list [ RSA_Decryption_RAW; RSA_Signature_PKCS1 ])
  in
  let tags = Keyfender.Json.TagSet.singleton "berlin" in
  Lwt_main.run
    (Hsm.Key.generate ~id:"keyID" hsm_state RSA ms ~length:1024 { tags })
  |> Result.get_ok;
  hsm_state

let keys_key_get_with_restrictions =
  "GET on /keys/keyID with restrictions" @? fun () ->
  match
    request ~headers:admin_headers ~hsm_state:(hsm_with_tags ()) "/keys/keyID"
  with
  | _, Some (`OK, _, `String body, _) ->
      let open Yojson.Safe.Util in
      body |> Yojson.Safe.from_string |> member "restrictions" |> member "tags"
      |> convert_each to_string
      |> List.exists (String.equal "berlin")
  | _ -> false
  | exception Yojson.Safe.Util.Type_error _ -> false

let keys_key_restrictions_tags_put =
  "PUT on /keys/keyID/restrictions/tags/frankfurt succeeds" @? fun () ->
  let expect = info "update (keyID): added tag \"frankfurt\"" in
  match
    admin_put_request ~expect ~hsm_state:(hsm_with_tags ())
      "/keys/keyID/restrictions/tags/frankfurt"
  with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false

let keys_key_restrictions_tags_delete =
  "DELETE on /keys/keyID/restrictions/tags/berlin succeeds" @? fun () ->
  let expect = info "update (keyID): removed tag \"berlin\"" in
  match
    request ~expect ~headers:admin_headers ~hsm_state:(hsm_with_tags ())
      ~meth:`DELETE "/keys/keyID/restrictions/tags/berlin"
  with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false

let keys_key_restrictions_tags_sign_ok =
  "POST on /keys/keyID/sign with an user matching the tag succeeds" @? fun () ->
  match
    request ~headers:operator_headers ~hsm_state:(hsm_with_tags ()) ~meth:`POST
      ~body:(`String sign_request) "/keys/keyID/sign"
  with
  | _, Some (`OK, _, _, _) -> true
  | _ -> false

let keys_key_restrictions_tags_sign_fail =
  "POST on /keys/keyID/sign with an user that doesn't have the tag fails"
  @? fun () ->
  let hsm_state = hsm_with_tags () in
  Lwt_main.run (Hsm.User.remove_tag hsm_state (user "operator") ~tag:"berlin")
  |> Result.get_ok |> ignore;
  match
    request ~headers:operator_headers ~hsm_state ~meth:`POST
      ~body:(`String sign_request) "/keys/keyID/sign"
  with
  | _, Some (`Forbidden, _, _, _) -> true
  | _ -> false

let keys_get_restrictions_filtered =
  Alcotest.test_case "GET on /keys?filter list is filtered by restrictions"
    `Quick
  @@ fun () ->
  let hsm_state = hsm_with_tags () in
  (match
     request ~headers:operator_headers ~hsm_state "/keys"
       ~query:[ ("filter", []) ]
   with
  | _, Some (`OK, _, `String body, _) ->
      Alcotest.(check (neg string))
        "when operator has tag: list isn't empty" body "[]"
  | _ -> Alcotest.fail "when operator has tag: didn't return OK");
  Lwt_main.run (Hsm.User.remove_tag hsm_state (user "operator") ~tag:"berlin")
  |> Result.get_ok |> ignore;
  match
    request ~headers:operator_headers ~hsm_state "/keys"
      ~query:[ ("filter", []) ]
  with
  | _, Some (`OK, _, `String body, _) ->
      Alcotest.(check string)
        "when operator doesn't have tag: list is empty" body "[]"
  | _ -> Alcotest.fail "when operator doesn't have tag: didn't return OK"

let keys_get_restrictions_unfiltered =
  Alcotest.test_case "GET on /keys list is not filtered by restrictions" `Quick
  @@ fun () ->
  let hsm_state = hsm_with_tags () in
  (match request ~headers:operator_headers ~hsm_state "/keys" with
  | _, Some (`OK, _, `String body, _) ->
      Alcotest.(check (neg string))
        "when operator has tag: list isn't empty" body "[]"
  | _ -> Alcotest.fail "when operator has tag: didn't return OK");
  Lwt_main.run (Hsm.User.remove_tag hsm_state (user "operator") ~tag:"berlin")
  |> Result.get_ok |> ignore;
  match request ~headers:operator_headers ~hsm_state "/keys" with
  | _, Some (`OK, _, `String body, _) ->
      Alcotest.(check (neg string))
        "when operator doesn't have tag: list is also not empty" body "[]"
  | _ -> Alcotest.fail "when operator doesn't have tag: didn't return OK"

let keys_key_cert_get =
  "GET on /keys/keyID/cert succeeds" @? fun () ->
  let hsm_state = hsm_with_key () in
  let _ =
    Lwt_main.run
      (Hsm.Key.set_cert hsm_state ~id:"keyID"
         ~content_type:"application/octet-stream" "data")
  in
  match request ~headers:operator_headers ~hsm_state "/keys/keyID/cert" with
  | _, Some (`OK, headers, `String data, _) -> (
      match Cohttp.Header.get headers "content-type" with
      | Some "application/octet-stream" -> String.equal data "data"
      | _ -> false)
  | _ -> false

let keys_key_cert_get_not_found =
  "GET on /keys/keyID/cert fails (ID not found)" @? fun () ->
  let hsm_state = hsm_with_key () in
  match request ~headers:operator_headers ~hsm_state "/keys/keyID2/cert" with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false

let keys_key_cert_get_invalid_id =
  "GET on /keys/keyID/cert fails (invalid ID)" @? fun () ->
  let hsm_state = hsm_with_key () in
  match request ~headers:operator_headers ~hsm_state "/keys//cert" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let keys_key_cert_get_accept_header =
  Alcotest.test_case
    "GET on /keys/keyID/cert with an Accept header works as expected" `Quick
  @@ fun () ->
  let hsm_state = hsm_with_key () in
  let _ =
    Lwt_main.run
      (Hsm.Key.set_cert hsm_state ~id:"keyID"
         ~content_type:"application/octet-stream" "data")
  in
  let headers_with_accept accept =
    Header.add operator_headers "Accept" accept
  in
  Alcotest.(check bool)
    "application/octet-stream is OK" true
    (match
       request
         ~headers:(headers_with_accept "application/octet-stream")
         ~hsm_state "/keys/keyID/cert"
     with
    | _, Some (`OK, _, _, _) -> true
    | _ -> false);
  Alcotest.(check bool)
    "application/json fails" true
    (match
       request
         ~headers:(headers_with_accept "application/json")
         ~hsm_state "/keys/keyID/cert"
     with
    | _, Some (`Not_acceptable, _, _, _) -> true
    | _ -> false)

let keys_key_cert_put =
  "PUT on /keys/keyID/cert succeeds" @? fun () ->
  let hsm_state = hsm_with_key () in
  match
    admin_put_request ~content_type:"application/octet-stream"
      ~body:(`String "data") ~hsm_state "/keys/keyID/cert"
  with
  | _, Some (`Created, _, _, _) -> true
  | _ -> false

let keys_key_cert_put_fails =
  "PUT on /keys/keyID/cert fails (wrong content type)" @? fun () ->
  let hsm_state = hsm_with_key () in
  match
    admin_put_request ~content_type:"text/html" ~body:(`String "data")
      ~hsm_state "/keys/keyID/cert"
  with
  | _, Some (`Unsupported_media_type, _, _, _) -> true
  | _ -> false

let keys_key_cert_put_not_found =
  "PUT on /keys/keyID/cert fails (ID not found)" @? fun () ->
  let hsm_state = hsm_with_key () in
  match
    admin_put_request ~content_type:"application/octet-stream"
      ~body:(`String "data") ~hsm_state "/keys/keyID2/cert"
  with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false

let keys_key_cert_put_invalid_id =
  "PUT on /keys/keyID/cert fails (invalid ID)" @? fun () ->
  let hsm_state = hsm_with_key () in
  match
    admin_put_request ~content_type:"application/octet-stream"
      ~body:(`String "data") ~hsm_state "/keys//cert"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let keys_key_cert_delete =
  "DELETE on /keys/keyID/cert succeeds" @? fun () ->
  let hsm_state = hsm_with_key () in
  let _ =
    Lwt_main.run
      (Hsm.Key.set_cert hsm_state ~id:"keyID"
         ~content_type:"application/octet-stream" "data")
  in
  match
    request ~meth:`DELETE ~headers:admin_headers ~hsm_state "/keys/keyID/cert"
  with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false

let keys_key_cert_delete_not_found =
  "DELETE on /keys/keyID/cert fails (ID not found)" @? fun () ->
  let hsm_state = hsm_with_key () in
  match
    request ~meth:`DELETE ~headers:admin_headers ~hsm_state "/keys/keyID2/cert"
  with
  | _, Some (`Not_found, _, _, _) -> true
  | _ -> false

let keys_key_cert_delete_invalid_id =
  "DELETE on /keys/keyID/cert fails (invalid ID)" @? fun () ->
  let hsm_state = hsm_with_key () in
  match
    request ~meth:`DELETE ~headers:admin_headers ~hsm_state "/keys//cert"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let keys_key_version_get_fails =
  "GET on /keys/.version fails" @? fun () ->
  match
    request ~headers:admin_headers ~hsm_state:(hsm_with_key ()) "/keys/.version"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let keys_key_version_delete_fails =
  "DELETE on /keys/.version fails" @? fun () ->
  match
    request ~meth:`DELETE ~headers:admin_headers ~hsm_state:(hsm_with_key ())
      "/keys/.version"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let keys_key_version_cert_get_fails =
  "GET on /keys/.version/cert fails" @? fun () ->
  let hsm_state = hsm_with_key () in
  let _ =
    Lwt_main.run
      (Hsm.Key.set_cert hsm_state ~id:".version"
         ~content_type:"application/octet-stream" "data")
  in
  match request ~headers:operator_headers ~hsm_state "/keys/.version/cert" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let keys_key_version_cert_put_fails =
  "PUT on /keys/.version/cert fails" @? fun () ->
  let hsm_state = hsm_with_key () in
  match
    admin_put_request ~content_type:"application/octet-stream"
      ~body:(`String "data") ~hsm_state "/keys/.version/cert"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let keys_key_version_cert_delete_fails =
  "DELETE on /keys/.version/cert fails" @? fun () ->
  let hsm_state = hsm_with_key () in
  let _ =
    Lwt_main.run
      (Hsm.Key.set_cert hsm_state ~id:".version"
         ~content_type:"application/octet-stream" "data")
  in
  match
    request ~meth:`DELETE ~headers:admin_headers ~hsm_state
      "/keys/.version/cert"
  with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false

let rate_limit_for_unlock =
  let path = "/unlock" in
  "rate limit for unlock" @? fun () ->
  let body = `String {| { "passphrase" : "notUnlock1234" } |} in
  let hsm_state = locked_mock () in
  ignore (request ~meth:`POST ~body ~hsm_state path);
  (* returns Bad_request *)
  match request ~meth:`POST ~body ~hsm_state path with
  | _, Some (`Too_many_requests, _, _, _) -> true
  | _ -> false

let rate_limit_for_unlock2 =
  let path = "/unlock" in
  "rate limit for unlock" @? fun () ->
  let body = `String {| { "passphrase" : "notUnlock" } |} in
  let hsm_state = locked_mock () in
  ignore (request ~meth:`POST ~body ~hsm_state path);
  (* returns Bad_request *)
  match request ~meth:`POST ~body ~hsm_state path with
  | _, Some (`Too_many_requests, _, _, _) -> true
  | _ -> false

let rate_limit_for_get =
  let path = "/system/info" in
  "rate limit for get" @? fun () ->
  let hsm_state = operational_mock () in
  let headers = auth_header "notavaliduser" "no valid password" in
  let expect =
    warning
      "notavaliduser unauthenticated: Cannot find the key \
       /authentication/notavaliduser"
  in
  ignore (request ~expect ~hsm_state ~headers path);
  match request ~hsm_state ~headers path with
  | _, Some (`Too_many_requests, _, _, _) -> (
      match
        request ~hsm_state ~headers:admin_headers ~ip:Ipaddr.V4.localhost path
      with
      | _, Some (`OK, _, _, _) -> true
      | _ -> false)
  | _ -> false

let reset_rate_limit_after_successful_login =
  let path = "/system/info" in
  "rate limit is reset after successful login" @? fun () ->
  let hsm_state = operational_mock () in
  let headers = auth_header "admin" "no valid password" in
  (* one request left before the rate limit returns Too_many_requests *)
  (* reset the rate limit by a successful request *)
  match
    request ~hsm_state ~headers:admin_headers ~ip:Ipaddr.V4.localhost path
  with
  | _, Some (`OK, _, _, _) -> (
      (* test rate_limit requests again *)
      match request ~hsm_state ~headers ~ip:Ipaddr.V4.localhost path with
      | _, Some (`Unauthorized, _, _, _) -> (
          match request ~hsm_state ~headers ~ip:Ipaddr.V4.localhost path with
          | _, Some (`Too_many_requests, _, _, _) -> true
          | _ -> false)
      | _ -> false)
  | _ -> false

let reset_rate_limit_after_successful_login_2 =
  let path = "/system/info" in
  "rate limit is reset after successful login (i.e. two consecutive requests \
   are fine)"
  @? fun () ->
  let hsm_state = operational_mock () in
  match
    request ~hsm_state ~headers:admin_headers ~ip:Ipaddr.V4.localhost path
  with
  | _, Some (`OK, _, _, _) -> (
      match
        request ~hsm_state ~headers:admin_headers ~ip:Ipaddr.V4.localhost path
      with
      | _, Some (`OK, _, _, _) -> true
      | _ -> false)
  | _ -> false

let rate_limit_time_for_get =
  let path = "/system/info" in
  "rate limit time for get after a second" @? fun () ->
  let hsm_state = operational_mock () in
  let headers = auth_header "notavaliduser" "no valid password" in
  let expect =
    warning
      "notavaliduser unauthenticated: Cannot find the key \
       /authentication/notavaliduser"
  in
  ignore (request ~hsm_state ~expect ~headers path);
  match request ~hsm_state ~headers path with
  | _, Some (`Too_many_requests, _, _, _) -> (
      Mock_clock.one_second_later ();
      match request ~hsm_state ~expect ~headers path with
      | _, Some (`Unauthorized, _, _, _) -> true
      | _ -> false)
  | _ -> false

let rate_limit_time_for_unlock =
  let path = "/unlock" in
  "rate limit time for unlock" @? fun () ->
  let body = `String {| { "passphrase" : "notUnlock1234" } |} in
  let hsm_state = locked_mock () in
  ignore (request ~meth:`POST ~body ~hsm_state path);
  (* returns Forbidden *)
  match request ~meth:`POST ~body ~hsm_state path with
  | _, Some (`Too_many_requests, _, _, _) -> (
      Mock_clock.one_second_later ();
      match request ~meth:`POST ~body ~hsm_state path with
      | _, Some (`Forbidden, _, _, _) -> true
      | _ -> false)
  | _ -> false

let rate_limit_time_for_unlock2 =
  let path = "/unlock" in
  "rate limit time for unlock" @? fun () ->
  let body = `String {| { "passphrase" : "notUnlock" } |} in
  let hsm_state = locked_mock () in
  ignore (request ~meth:`POST ~body ~hsm_state path);
  (* returns Bad_request *)
  match request ~meth:`POST ~body ~hsm_state path with
  | _, Some (`Too_many_requests, _, _, _) -> (
      Mock_clock.one_second_later ();
      match request ~meth:`POST ~body ~hsm_state path with
      | _, Some (`Bad_request, _, _, _) -> true
      | _ -> false)
  | _ -> false

let auth_decode_invalid_base64 =
  "a request for /system/info with wrong base64 in user authentication returns \
   401"
  @? fun () ->
  let auth_header user pass =
    let base64 = "wrong" ^ Base64.encode_string (user ^ ":" ^ pass) in
    Header.init_with "authorization" ("Basic " ^ base64)
  in
  let expect =
    warning
      "is_authorized failed with message invalid base64 encoding: Wrong padding"
  in
  let admin_headers = auth_header "admin" "test1Passphrase" in
  match
    request ~expect ~hsm_state:(operational_mock ()) ~headers:admin_headers
      "/system/info"
  with
  | _hsm_state, Some (`Unauthorized, _, _, _) -> true
  | _ -> false

let rsa2048_priv_pem =
  {|-----BEGIN RSA PRIVATE KEY-----
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
  match X509.Private_key.decode_pem rsa2048_priv_pem with
  | Ok (`RSA k) -> Mirage_crypto_pk.Rsa.pub_of_priv k
  | _ -> assert false

let add_pem state ~id ms key =
  match Lwt_main.run (Hsm.Key.add_pem ~id state ms key no_restrictions) with
  | Ok () -> ()
  | Error _ -> assert false

module Oaep_md5 = Mirage_crypto_pk.Rsa.OAEP (Digestif.MD5)
module Oaep_sha1 = Mirage_crypto_pk.Rsa.OAEP (Digestif.SHA1)
module Oaep_sha224 = Mirage_crypto_pk.Rsa.OAEP (Digestif.SHA224)
module Oaep_sha256 = Mirage_crypto_pk.Rsa.OAEP (Digestif.SHA256)
module Oaep_sha384 = Mirage_crypto_pk.Rsa.OAEP (Digestif.SHA384)
module Oaep_sha512 = Mirage_crypto_pk.Rsa.OAEP (Digestif.SHA512)

let enc_test_data =
  "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd"

let crypto_rsa_decrypt () =
  let algos =
    Keyfender.Json.
      [
        ( 256,
          "fvIOfN3+AOt3wvaRVMT6+SjlYfyeqP/llAl93KBEPcmb4eoKKAhEhoPdL6NkCr26lFKL0QuPqHA1mS8jw9nVBHFoBhBwU2dlNfa7NNlSE2Ph/FwJVF7NAXtw4LXTECYL5aPBj1Svo8IfWUQXJVPNF1HA3Uw4jxDusFNbjvT0Xk7SsPJnLT1DAQlsoV9xWjonnd53LjuHjJ1BAvq/wYnjOjvsAZu7Zp730Kg4HuBAoj3FE3wlq3/ABxS13+lEuL2RT+tJEROAWVK6J/D7ya2kCVXY+9OhIQgndUS7KRO7LhW2uhbPKs2jG/sjNgSw5NM/d0S9fcUN5IPpiPaGOzy9cw==",
          RAW,
          "RAW" );
        ( 245,
          "s0bvjV8/3BJYdtYsAGtD3yCWeGXIxreSFi0Vsw3juMyxpDOcBCl6xMjJhnHuxhdJ+HqiKSRZkgOVab9JXUUIZpr4ja1U42kOo9Zs2MYLhMrBFdkiXli6/UjHWT93GlcxIavYMOblh16FOaKlZH5cZrzfiQTeqDLBnWgZxmtKnXaNaeAZ5L8y7lT1hldS7nz0+vOSHEeW1BfbJwAuijb/hv/tSta2+78gkuRQTXAfwcePi5D7PRaRc72keX0TzHGBQulN/JuxHR2m3trEgKb3SNsZW3zLLiAWxNQqYqgCe2xuiREnQYifAdMFGF9EeT23KBFh5I2mNknLLSppR2WRwA==",
          PKCS1,
          "PKCS1" );
        ( 222,
          "fG1U6k+ZwNKxSOlTG0oUp+uz9YqWh51et7YX6/0xMGxNJrg+fB4tIhayPVE4BKY1mp/3GPYeBwiYxAI5+hG2zdMC3Z2JioghSkVrI2Ne7dt+7x6PY3UIrgPW0prx8qfQu9WGkv1RYc4tUpoAboGGO14aumwwYstMzSpsPOlt+7RFmcV4MmsfiOU7p0n4p+Fvs9T6yaczVAjx6AQLpdGFKg3u834I8S38z9fJU8MnwcYJAUrgiUVcbP4qCtQZYFL9Sx9SqS+gm9nWiTgq3pPjgvBCsRtnX8Gozd4HlCERmFqyfjjMyni+OQE4MrGcvRKcwZrm+QQxNQuTKE14ldtLiQ==",
          OAEP_MD5,
          "OAEP_MD5" );
        ( 214,
          "wS+bLk7xSUIlVSPWIm8tWr/HTEKrcr7wwN5EG96s8BiFBh4/RbsNrpAp0kxHGMyPsXBREaqObYli9hxO/YsoCNcU5PG2b/VLBPgKGZ+t9gODXu/r0ANj/tdnTrgEy2+ukOdjE5y+wRZ3R0wwj0ZzWsKfBGhPtwwjXp6yjuEnwXprt4JdINI7IJG3/JUiP79qWCrupY6e9G/Raa9B2moFdyJwNrvu7siULIJ40yutzdG6yEs2s6bh8TQQz08i5X5YPlPq73hjvr71sEnRXMcjHZAJXgtofLiGv1d8YrF6O8SABM99Y0Pj1TYO/wGb4MjIjBsgnHm/Y7wXTe6Xb/gPGg==",
          OAEP_SHA1,
          "OAEP_SHA1" );
        ( 198,
          "PMXEPfP+oaIFAJvOklA5ZRUCeoUfJHOwj2V3Oh8SQww9affvW3G40jCOg1SLFh5CiFRk3QdU4sanuuQQUiHoYeV5L6iwm/HK/B7LrS6BRrYjk7KnQR/mVgPn6hLHpAtwRWYuaUJHZQawTZHrod4XVti2vO23Cn+4S9pXAJnoJIHsb8AQAlTn01QjOMd4AhxSsT5AKeG5GRWgP1sFaTnaGQ4KKVS3cJW+MGrC6boZGN/Tjr4x5efIVp5dMnNXAU3aXb0G9C4S/WNIwp8ayoNrbL3TD/WY8GW3ypQZ78+YYb8vbYyn/gQJdqqckx9YH/AgdIXeZGrCVOSmNDxj7hrisQ==",
          OAEP_SHA224,
          "OAEP_SHA224" );
        ( 190,
          "Fj0g5jxcZJMxQChCsw2QKVLK99VAVUOhB1XPOLatEh/2NXstdMNUVOT1MBqZ+jdm1T9VYitxhsa1qxjPkDG+mMWulp7BWNo9vBIAFJgCAantNUf4j3TWAms4QVYwBOwvgyhRBL4M9abC1KvEJWnMhzy2NFtHN4p0oOKgXC6LarUkX67o+Q2e62K2VtDONrBoOqWqaPQ0aphOvd9KM32cllC95gthBzg7MVUVcQbJSVXUvm8MIAttKxTmrw/vPIfmlkKIZenEkg8eYPk3cVuyuiwJyctqQCNFJbYtDqb0/hp72I3KfJFaZViLHS8/dEwqCxuUvkqmZZft1lDjzACHWA==",
          OAEP_SHA256,
          "OAEP_SHA256" );
        ( 158,
          "nnhUPjJxUxcv2obRvC6IouLauuXxUe9ihtLTd92OThlMOIQqPaBZFKiY0cWujVyEC1aYM1+kPDQL3g2VKGD4RndwnUy9uE9FapWNn52VZq1MMMDAa5gDYQ92H9dmE4UYnym46IieZPt0hX54csqS6elwepcZPXSpdhk9D0C4Xc0+m56B8JS2/bvoHzxWHwrfL5ALutN01yiMrYkXzSuiXjdwG76SWCOZpsoj6HcP+gTglOAGIm6M80ENQfMWjNWYdF2nHhzNX2e4oVU8Nhp3/2U7ATlb2xwdwp7viMjBm6ExoqsI0fkguqLrUJ7Y5rWNWK2JmL8WQYIlUmniOvc8MA==",
          OAEP_SHA384,
          "OAEP_SHA384" );
        ( 126,
          "CZah2t+0Gq63qOi1t5QkjyX0Ja+PVVshr7AGHj72yNnDKlQJsUIAl9QFvauuzirf1d83djBXaGz5wYEv4RQ/v/RqDFnl73SI5COiSlkxKp96V3nhRoT7B5a0IGegQJLHauAIpeOprGQMYfCOKliXz2s4dSOKosM7QpnACC6qc+AONcuDFfvsX9minQByrSqUHo+iQl780HMxtnCQnJMhZIv96Om8IfoxK7AzXU/tEtkoaStLiQeLsspfu9WOHO9kwQLVYV0KldYvFWZYeYrUmsqo4/FwngFUh8Rso5Bqwp3IpGdjY4uisfyovrg0rT/V+q4vPc7/LKnUaLxsI08Oxg==",
          OAEP_SHA512,
          "OAEP_SHA512" );
      ]
  in
  List.map
    (fun (idx, enc_data, dec_mode, txt) ->
      ("decryption with RSA " ^ txt ^ " succeeds") @? fun () ->
      let hsm = operational_mock () in
      let mechs =
        List.fold_right Keyfender.Json.MS.add
          [
            Keyfender.Json.RSA_Decryption_RAW;
            RSA_Decryption_PKCS1;
            RSA_Decryption_OAEP_MD5;
            RSA_Decryption_OAEP_SHA1;
            RSA_Decryption_OAEP_SHA224;
            RSA_Decryption_OAEP_SHA256;
            RSA_Decryption_OAEP_SHA384;
            RSA_Decryption_OAEP_SHA512;
          ]
          Keyfender.Json.MS.empty
      in
      add_pem hsm ~id:"test" mechs rsa2048_priv_pem;
      match
        Lwt_main.run
          (Hsm.Key.decrypt hsm ~id:"test" ~iv:None ~user_nid:(user "operator")
             dec_mode enc_data)
      with
      | Ok data ->
          let b64_dec = Base64.decode_exn data in
          String.equal b64_dec (String.sub enc_test_data 0 idx)
      | Error _ -> false)
    algos

let sign_test_data = "hello"

let b64_and_hash h d =
  let (module H) = Digestif.module_of_hash' h in
  Base64.encode_exn H.(digest_string d |> to_raw_string)

let crypto_rsa_pkcs1_sign () =
  "signing with RSA PKCS1 succeeds" @? fun () ->
  let hsm = operational_mock () in
  add_pem hsm ~id:"test"
    Keyfender.Json.(MS.singleton RSA_Signature_PKCS1)
    rsa2048_priv_pem;
  let signature_hc =
    "iGIgswYW3f1hGYutuI6T/511p41aBF0gNV1N/MdqG1Wofaj8onUDJd/LD4h7s5s8wsXJ/EoH0zMck2XovWi3TLwCoghH3nL+Dv9b9fn6YMEnYOk4Uv0klFclwvLDmpiW+8An+7WPti2zlSkCkl2diwfA6N1hBRqKpnYYWCxMHxQOXCnXfDu1fxm6+MsUP8YZ5WUtVG6BV9lm+lzktHXBAkXmCYswtUbiol5NRbOH9P1PhG37UylT22ekszC8Ime5K2PSt5+WvlzM2Ry+peCMjSS7fMnsgasnkqLrTnZrZLMD7J6jG6I4Jxq+nPAgj9sXkJ+ozqllab+4mRIJEiaPOg=="
  in
  match
    Lwt_main.run
      (Hsm.Key.sign hsm ~id:"test" ~user_nid:(user "operator")
         Keyfender.Json.PKCS1
         (b64_and_hash `SHA1 sign_test_data))
  with
  | Ok signature -> (
      assert (signature = signature_hc);
      let b64_dec = Base64.decode_exn signature in
      match Mirage_crypto_pk.Rsa.PKCS1.sig_decode ~key:rsa2048_pub b64_dec with
      | None -> false
      | Some raw ->
          String.equal raw
            Digestif.SHA1.(digest_string sign_test_data |> to_raw_string))
  | _ -> false

let crypto_rsa_pss_sign () =
  let algos =
    Keyfender.Json.
      [
        (`MD5, PSS_MD5, "PSS_MD5");
        (`SHA1, PSS_SHA1, "PSS_SHA1");
        (`SHA224, PSS_SHA224, "PSS_SHA224");
        (`SHA256, PSS_SHA256, "PSS_SHA256");
        (`SHA384, PSS_SHA384, "PSS_SHA384");
        (`SHA512, PSS_SHA512, "PSS_SHA512");
      ]
  in
  List.map
    (fun (hash, sign_mode, txt) ->
      ("signing with RSA " ^ txt ^ " succeeds") @? fun () ->
      let hsm = operational_mock () in
      let mechs =
        List.fold_right Keyfender.Json.MS.add
          [
            Keyfender.Json.RSA_Signature_PSS_MD5;
            RSA_Signature_PSS_SHA1;
            RSA_Signature_PSS_SHA224;
            RSA_Signature_PSS_SHA256;
            RSA_Signature_PSS_SHA384;
            RSA_Signature_PSS_SHA512;
          ]
          Keyfender.Json.MS.empty
      in
      add_pem hsm ~id:"test" mechs rsa2048_priv_pem;
      match
        Lwt_main.run
          (Hsm.Key.sign hsm ~id:"test" ~user_nid:(user "operator") sign_mode
             (b64_and_hash hash sign_test_data))
      with
      | Ok signature -> (
          let b64_dec = Base64.decode_exn signature in
          match
            X509.Public_key.verify hash ~scheme:`RSA_PSS ~signature:b64_dec
              (`RSA rsa2048_pub) (`Message sign_test_data)
          with
          | Ok () -> true
          | Error _ -> false)
      | Error _ -> false)
    algos

let ed25519_priv_pem =
  {|-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIIHCCOimH9qZePG/EZcb3trtpCVUy92dmaBpU1gWY5r7
-----END PRIVATE KEY-----|}

let ed25519_pub =
  match X509.Private_key.decode_pem ed25519_priv_pem with
  | Ok k -> X509.Private_key.public k
  | _ -> assert false

let crypto_ed25519_sign () =
  "signing with ED25519 succeeds" @? fun () ->
  let hsm = operational_mock () in
  let mechs = Keyfender.Json.MS.singleton Keyfender.Json.EdDSA_Signature in
  add_pem hsm ~id:"test" mechs ed25519_priv_pem;
  match
    Lwt_main.run
      (Hsm.Key.sign hsm ~id:"test" ~user_nid:(user "operator")
         Keyfender.Json.EdDSA
         (Base64.encode_exn sign_test_data))
  with
  | Ok signature -> (
      let exp_sig =
        "MXXfyOqswfWDcXAoE2zU2Cf2VW5GajdqZge8hh3is2uVcHW5bbewE/zlb9hvoUjAqSO7ObIm29D4Krb8CjlpCQ=="
      in
      assert (exp_sig = signature);
      let b64_dec = Base64.decode_exn signature in
      match
        X509.Public_key.verify `SHA512 ~scheme:`ED25519 ~signature:b64_dec
          ed25519_pub (`Message sign_test_data)
      with
      | Ok () -> true
      | Error _ -> false)
  | Error _ -> false

let crypto_ecdsa_sign () =
  let mechs = Keyfender.Json.MS.singleton Keyfender.Json.ECDSA_Signature in
  let seed = String.make 16 '\000' in
  let algos =
    [
      ( `SHA256,
        X509.Private_key.generate ~seed `P256,
        "MEUCIQC3LKyNLNwZ+UhQ4tXzlbQdsnBzJuN/a6EbHl+N7J42XgIgRdacwWqGIatrRSdn9AEQ3RXRkNhiKHYmTmn8e3MKAYg=",
        "P256" );
      ( `SHA384,
        X509.Private_key.generate ~seed `P384,
        "MGUCMQDO9eNxo4+IAoZpxqMvQvAeitP+D+5h1WiWBFRECdAN75uhGdGa9I9B0Ei3fv1uAE8CMH25z78MU+VqU1a+i1M2AEoVd7Jpj3CRnaYne78KgwXNnUr4nGDkvjcDyTutXhInjA==",
        "P384" );
      ( `SHA512,
        X509.Private_key.generate ~seed `P521,
        "MIGIAkIAxUNirK+/g6PtdsTFjXqcc+B7S4OCw0ZAwUWYvYa+IQtitW0LTK8nUkbOytEW/UZJq+d7+fPDBdI3O/kHOkFTu4ECQgDltV5EgDZnpjcsdH15Jm5kxzstOvgFUCi0EWhLn6mUeMSq2rZZUZZI3/6o5SgEwL4p6kkRLRPXo/btBJqY5BJUrw==",
        "P521" );
    ]
  in
  List.map
    (fun (hash, priv, sign, txt) ->
      Alcotest.test_case
        ("signing with ECDSA " ^ txt ^ " succeeds")
        `Quick
        (fun () ->
          let hsm = operational_mock () in
          add_pem hsm ~id:"test" mechs (X509.Private_key.encode_pem priv);
          let pub = X509.Private_key.public priv in
          let signature =
            Lwt_main.run
              (Hsm.Key.sign hsm ~id:"test" ~user_nid:(user "operator")
                 Keyfender.Json.ECDSA
                 (b64_and_hash hash sign_test_data))
            |> Result.map_error (fun (_, s) -> `Msg s)
            |> get_ok_result "sign"
          in
          Alcotest.(check string) ("same signature for " ^ txt) sign signature;
          let b64_dec = Base64.decode signature |> get_ok_result "base64" in
          X509.Public_key.verify hash ~scheme:`ECDSA ~signature:b64_dec pub
            (`Message sign_test_data)
          |> get_ok_result "verify"))
    algos

let crypto_aes_cbc_encrypt () =
  let mechs = Keyfender.Json.MS.singleton Keyfender.Json.AES_Encryption_CBC in
  let sizes = [ 128; 192; 256 ] in
  List.map
    (fun size ->
      "encryption with AES-CBC succeeds" @? fun () ->
      let hsm = operational_mock () in
      let secret = Mirage_crypto_rng.generate (size / 8) in
      add_generic hsm ~id:"test" mechs secret;
      match
        Lwt_main.run
          (Hsm.Key.encrypt hsm ~id:"test" ~user_nid:(user "operator") ~iv:None
             AES_CBC
             (Base64.encode_string aes_message))
      with
      | Ok (cipher_b64, Some iv_b64) ->
          let iv = Base64.decode_exn iv_b64 in
          let key = Mirage_crypto.AES.CBC.of_secret secret in
          let encrypted = Base64.decode_exn cipher_b64 in
          let m = Mirage_crypto.AES.CBC.decrypt ~key ~iv encrypted in
          String.equal m aes_message
      | Ok (_, None) | Error _ -> assert false)
    sizes

let crypto_aes_cbc_decrypt () =
  let mechs = Keyfender.Json.MS.singleton Keyfender.Json.AES_Decryption_CBC in
  let sizes = [ 128; 192; 256 ] in
  List.map
    (fun size ->
      "decryption with AES-CBC succeeds" @? fun () ->
      let hsm = operational_mock () in
      let secret = Mirage_crypto_rng.generate (size / 8) in
      add_generic hsm ~id:"test" mechs secret;
      let iv = Mirage_crypto_rng.generate Mirage_crypto.AES.CBC.block_size in
      let key = Mirage_crypto.AES.CBC.of_secret secret in
      let encrypted =
        Mirage_crypto.AES.CBC.encrypt ~key ~iv aes_message
        |> Base64.encode_string
      in
      let iv = Some (Base64.encode_string iv) in
      match
        Lwt_main.run
          (Hsm.Key.decrypt hsm ~id:"test" ~user_nid:(user "operator") ~iv
             AES_CBC encrypted)
      with
      | Ok m -> String.equal m (Base64.encode_string aes_message)
      | Error _ -> assert false)
    sizes

let () =
  let open Alcotest in
  let tests =
    [
      (* the spaces trigger alcotest to do long line output*)
      ("/                                               ", [ empty ]);
      ("/health/alive", [ health_alive_ok ]);
      ( "/health/ready",
        [ health_ready_ok; health_ready_error_precondition_failed ] );
      ("/health/state", [ health_state_ok ]);
      ("/random", [ random_ok; random_error_bad_length ]);
      ( "/provision",
        [
          provision_ok;
          provision_error_malformed_request;
          provision_error_precondition_failed;
        ] );
      ( "/system/info",
        [
          system_info_ok;
          system_info_error_authentication_required;
          system_info_error_precondition_failed;
          system_info_error_forbidden;
        ] );
      ("/system/reboot", [ system_reboot_ok; system_reboot_namespaced_fails ]);
      ( "/system/shutdown",
        [ system_shutdown_ok; system_shutdown_namespaced_fails ] );
      ( "/system/factory-reset",
        [ system_factory_reset_ok; system_factory_reset_namespaced_fails ] );
      ( "/system/update",
        [
          system_update_ok;
          system_update_namespaced_fails;
          system_update_signature_mismatch;
          system_update_too_much_data;
          system_update_too_few_data;
          system_update_invalid_data;
          system_update_platform_bad;
          system_update_version_downgrade;
        ] );
      ( "/system/commit-update",
        [
          system_update_commit_ok;
          system_update_commit_namespaced_fails;
          system_update_commit_fail;
          system_update_cancel_ok;
          system_update_cancel_namespaced_fails;
        ] );
      ("/system/update from binary file", [ system_update_from_file_ok ]);
      ("/system/update signing", [ sign_update_ok ]);
      ( "/system/backup",
        [
          system_backup_and_restore_ok;
          system_backup_and_restore_unattended;
          system_backup_and_restore_unattended_changed_devkey;
          system_backup_and_restore_changed_devkey;
          system_backup_and_restore_operational;
          system_backup_post_accept_header;
        ] );
      ( "/unlock",
        [
          unlock_ok;
          unlock_failed;
          unlock_failed_two;
          unlock_twice;
          unlock_fails_wrong_device_key;
        ] );
      ("/lock", [ lock_ok; lock_failed; lock_nonroot_fails ]);
      ( "/config/unattended_boot",
        [
          get_unattended_boot_ok;
          unattended_boot_succeeds;
          unattended_boot_failed_wrong_device_key;
        ] );
      ( "/config/unlock-passphrase",
        [ change_unlock_passphrase; change_unlock_passphrase_empty ] );
      ("/config/tls/public.pem", [ get_config_tls_public_pem ]);
      ( "/config/tls/cert.pem",
        [
          get_config_tls_cert_pem;
          put_config_tls_cert_pem;
          put_config_tls_cert_pem_fail;
        ] );
      ( "/config/tls/csr",
        [
          post_config_tls_csr_pem;
          post_config_tls_csr_pem2;
          post_config_tls_csr_pem_fails;
        ] );
      ( "/config/tls/generate",
        [
          post_config_tls_generate;
          post_config_tls_generate_generic_key;
          post_config_tls_generate_bad_length;
        ] );
      ( "/config/network",
        [ config_network_ok; config_network_set_ok; config_network_set_fail ] );
      ( "/config/logging",
        [ config_logging_ok; config_logging_set_ok; config_logging_set_fail ] );
      ( "/config/time",
        [ config_time_ok; config_time_set_ok; config_time_set_fail ] );
      ( "/config/backup-passphrase",
        [ change_backup_passphrase; change_backup_passphrase_empty ] );
      ("invalid config version", [ invalid_config_version ]);
      ("config version but no unlock salt", [ config_version_but_no_salt ]);
      ("/namespaces", [ namespaces_get; namespaces_get_nuser; namespaces_seq ]);
      ( "/namespaces/namespace1",
        [
          namespaces_existing_delete;
          namespaces_existing_delete_keys;
          namespaces_existing_create;
        ] );
      ( "/namespaces/namespace3",
        [
          namespaces_new_create; namespaces_new_delete; namespaces_shared_prefix;
        ] );
      ( "/users",
        [ users_get; users_get_namespace; users_post; users_post_namespace ] );
      ( "/users/operator",
        [
          user_operator_add_empty_passphrase;
          user_operator_add_invalid_id;
          user_operator_add_invalid_id2;
          user_operator_add_invalid_id3;
          user_operator_add_invalid_id4;
          user_operator_add_invalid_id5;
          user_operator_add_root_root;
          user_operator_add_ns_root;
          user_operator_add_root_ns;
          user_operator_add_root_ns_existing;
          user_operator_add_ns_ns;
          user_operator_add_ns_ns_mismatch;
          users_post_ns_root;
          users_post_ns_ns;
          users_post_ns_ns_mismatch;
          users_post_root_invalid1;
          users_post_root_invalid2;
          users_post_root_invalid3;
          user_operator_delete_root_root;
          user_operator_delete_self;
          user_operator_delete_root_ns;
          user_operator_delete_ns_root;
          user_operator_delete_ns_ns;
          user_operator_delete_ns_ns_mismatch;
          user_operator_delete_not_found;
          user_operator_delete_invalid_id;
          user_operator_delete_fails;
          user_op_delete_fails;
          user_operator_get;
          user_operator_get_not_found;
          user_operator_get_invalid_id;
          user_operator_get_invalid_id2;
          user_operator_get_forbidden;
        ] );
      ( "/users/operator/tags",
        [
          user_operator_tags_get;
          user_operator_tags_get_invalid_id;
          user_operator_tags_put;
          user_operator_tags_put_twice;
          user_operator_tags_put_invalid_id;
          user_operator_tags_delete;
          user_operator_tags_delete_not_found;
        ] );
      ( "/users/backup/tags",
        [ user_backup_tags_get_not_operator; user_backup_tags_put_not_operator ]
      );
      ( "/users/.version",
        [ user_version_get_bad_request; user_version_delete_fails_invalid_id ]
      );
      ( "/users/admin/passphrase",
        [
          user_passphrase_post;
          user_passphrase_administrator_post;
          user_passphrase_post_fails_not_found;
          user_passphrase_post_fails_invalid_id;
        ] );
      ("/users/operator/passphrase", [ user_passphrase_operator_post ]);
      ( "/users/suboperator/passphrase",
        [
          user_passphrase_suboperator_post_root_ns;
          user_passphrase_suboperator_post_root_ns_existing;
          user_passphrase_suboperator_post_ns_root;
          user_passphrase_suboperator_post_ns_ns;
          user_passphrase_suboperator_post_ns_ns_mismatch;
        ] );
      ( "/keys",
        [
          keys_get;
          keys_get_namespace;
          keys_get_namespace_seq;
          keys_get_restrictions_filtered;
          keys_get_restrictions_unfiltered;
          keys_post_json;
          keys_post_pem;
        ] );
      ( "/keys/generate",
        [
          keys_generate;
          keys_generate_invalid_id;
          keys_generate_invalid_id_length;
          keys_generate_invalid_mech;
          keys_generate_no_mech;
          keys_generate_ed25519;
          keys_generate_ed25519_explicit_keyid;
          keys_generate_ed25519_fail;
          keys_generate_generic;
          keys_generate_generic_fail;
        ] );
      ( "/keys/keyID",
        [
          keys_key_get;
          keys_key_get_not_found;
          keys_key_get_invalid_id;
          keys_key_get_invalid_id2;
          keys_key_put_json;
          keys_key_put_pem;
          keys_key_put_already_there;
          keys_key_put_invalid_id;
          keys_key_delete;
          keys_key_delete_not_found;
          keys_key_delete_invalid_id;
          keys_key_get_ed25519;
          keys_key_put_ed25519;
          keys_key_get_generic;
          keys_key_put_generic;
          keys_key_get_with_restrictions;
        ] );
      ( "/keys/keyID/restrictions/tags",
        [
          keys_key_restrictions_tags_put;
          keys_key_restrictions_tags_delete;
          keys_key_restrictions_tags_sign_ok;
          keys_key_restrictions_tags_sign_fail;
        ] );
      ( "/keys/keyID/public.pem",
        [
          admin_keys_key_public_pem;
          operator_keys_key_public_pem;
          operator_keys_key_public_pem_not_found;
          operator_keys_key_public_pem_invalid_id;
          operator_keys_key_public_pem_ed25519;
        ] );
      ( "/keys/keyID/csr.pem",
        [
          admin_keys_key_csr_pem;
          operator_keys_key_csr_pem;
          operator_keys_key_csr_pem_common_name_only;
          operator_keys_key_csr_pem_no_common_name;
          operator_keys_key_csr_pem_not_found;
          operator_keys_key_csr_pem_invalid_id;
        ] );
      ( "/keys/keyID/decrypt",
        [
          operator_keys_key_decrypt;
          operator_keys_key_decrypt_fails;
          operator_keys_key_decrypt_fails_wrong_mech;
          operator_keys_key_decrypt_fails_invalid_id;
          operator_keys_key_decrypt_fails_not_found;
          operator_decrypt_aes_cbc_succeeds;
          operator_decrypt_aes_cbc_no_iv_fails;
          operator_encrypt_aes_cbc_succeeds;
          operator_encrypt_aes_cbc_no_iv_succeeds;
        ] );
      ( "/keys/keyID/sign",
        [
          operator_keys_key_sign;
          operator_keys_key_sign_fails;
          operator_keys_key_sign_fails_bad_data;
          operator_keys_key_sign_fails_wrong_mech;
          operator_keys_key_sign_fails_invalid_id;
          operator_keys_key_sign_fails_not_found;
          operator_sign_ed25519_succeeds;
          operator_sign_ed25519_fails;
        ] );
      ("/keys/keyID/decrypt and /sign", [ operator_keys_key_sign_and_decrypt ]);
      ( "/keys/keyID/cert",
        [
          keys_key_cert_get;
          keys_key_cert_get_not_found;
          keys_key_cert_get_invalid_id;
          keys_key_cert_get_accept_header;
          keys_key_cert_put;
          keys_key_cert_put_fails;
          keys_key_cert_put_not_found;
          keys_key_cert_put_invalid_id;
          keys_key_cert_delete;
          keys_key_cert_delete_not_found;
          keys_key_cert_delete_invalid_id;
        ] );
      ( "/keys/version",
        [ keys_key_version_get_fails; keys_key_version_delete_fails ] );
      ( "/keys/version/cert",
        [
          keys_key_version_cert_get_fails;
          keys_key_version_cert_put_fails;
          keys_key_version_cert_delete_fails;
        ] );
      ( "rate limit",
        [
          rate_limit_for_get;
          reset_rate_limit_after_successful_login;
          reset_rate_limit_after_successful_login_2;
          rate_limit_for_unlock;
          rate_limit_for_unlock2;
          rate_limit_time_for_get;
          rate_limit_time_for_unlock;
          rate_limit_time_for_unlock2;
        ] );
      ("access.ml: decode auth", [ auth_decode_invalid_base64 ]);
      ("RSA decrypt", crypto_rsa_decrypt ());
      ("RSA PKCS1 sign", [ crypto_rsa_pkcs1_sign () ]);
      ("RSA PSS sign", crypto_rsa_pss_sign ());
      ("ED25519 sign", [ crypto_ed25519_sign () ]);
      ("ECDSA sign", crypto_ecdsa_sign ());
      ("AES-CBC encrypt", crypto_aes_cbc_encrypt ());
      ("AES-CBC decrypt", crypto_aes_cbc_decrypt ());
    ]
  in
  run ~argv:Sys.argv "dispatch" tests
