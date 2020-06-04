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
    | None -> Lwt_main.run (Kv_mem.connect () >>= Hsm.boot)
    | Some x -> x
  in
  let path = "/api/v1" ^ endpoint in
  let uri = Uri.make ~scheme:"http" ~host:"localhost" ~path ?query () in
  let request = Request.make ~meth ~headers uri in
  let resp = Lwt_main.run @@ Handlers.Wm.dispatch' (Handlers.routes hsm_state' ip) ~body ~request in
  hsm_state', resp

let operational_mock () =
  Lwt_main.run (
    Kv_mem.connect () >>= Hsm.boot >>= fun state ->
    Hsm.provision state ~unlock:"unlockPassphrase" ~admin:"test1Passphrase" Ptime.epoch >>= fun _ ->
    Hsm.User.add state ~id:"operator" ~role:`Operator ~passphrase:"test2Passphrase" ~name:"operator" >>= fun _ ->
    Hsm.User.add state ~id:"backup" ~role:`Backup ~passphrase:"test3Passphrase" ~name:"backup" >|= fun _ ->
    state)

let locked_mock () =
  Lwt_main.run (
    (* create an empty in memory key-value store, and a HSM state (unprovisioned) *)
    Kv_mem.connect () >>= fun kv ->
    Hsm.boot kv >>= fun state ->
    (* provision HSM, leading to state operational (and writes to the kv store) *)
    Hsm.provision state ~unlock:"test1234Passphrase" ~admin:"test1Passphrase" Ptime.epoch >>= fun r ->
    (* create a new HSM state, using the provisioned kv store, with a `Locked state *)
    assert (r = Ok ());
    Hsm.boot kv)

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

let provision_json = {| {
  "unlockPassphrase": "UnlockPassphrase",
  "adminPassphrase": "Administrator",
  "systemTime": "2018-10-30T11:20:50Z"
} |}

let provision_ok () =
  let body = `String provision_json in
  "an initial provision request is successful (state transition to operational, HTTP response 204)"
    @? begin match request ~body ~meth:`PUT "/provision" with
       | hsm_state, Some (`No_content, _, _, _) -> Hsm.state hsm_state = `Operational
       | _ -> false
    end

let provision_error_malformed_request () =
  let body = `String ("hallo" ^ provision_json) in
  "an initial provision request with invalid json returns a malformed request with 400"
    @? begin match request ~body ~meth:`PUT "/provision" with
       | hsm_state, Some (`Bad_request, _, _, _) -> Hsm.state hsm_state = `Unprovisioned
       | _ -> false
    end

let provision_error_precondition_failed () =
  let body = `String provision_json in
  "an initial provision request is successful, a subsequent provision fails with 412"
    @? begin match request ~body ~meth:`PUT "/provision" with
       | hsm_state, Some (`No_content, _, _, _) ->
         begin match request ~hsm_state ~body ~meth:`PUT "/provision" with
          | _, Some (`Precondition_failed, _, _, _) -> true
          | _ -> false
         end
       | _ -> false
    end

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
      | hsm_state, Some (`No_content, _, _, _) -> Hsm.state hsm_state = `Busy
      | _ -> false
   end

let system_shutdown_ok () =
  "a request for /system/shutdown with authenticated user returns 200"
   @? begin match admin_post_request "/system/shutdown" with
      | hsm_state, Some (`No_content, _, _, _) -> Hsm.state hsm_state = `Busy
      | _ -> false
   end

let system_reset_ok () =
  "a request for /system/reset with authenticated user returns 200"
   @? begin match admin_post_request "/system/reset" with
      | hsm_state, Some (`No_content, _, _, _) -> Hsm.state hsm_state = `Unprovisioned
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
  | Error `Msg m -> invalid_arg m

module Pss_sha256 = Mirage_crypto_pk.Rsa.PSS(Mirage_crypto.Hash.SHA256)

let sign_update u =
  let signature = Pss_sha256.sign ~key:update_key (`Message (Cstruct.of_string u)) in
  let length = Cstruct.len signature in
  let len_buf = Cstruct.create 3 in
  Cstruct.set_uint8 len_buf 0 (length lsr 16);
  Cstruct.BE.set_uint16 len_buf 1 (length land 0xffff);
  Cstruct.to_string (Cstruct.append len_buf signature)

let system_update_ok () =
  let body =
    let update = "\000\000\018A new system image\000\000\0032.0binary data is here" in
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
    let update = "\000\000\018A new system image\000\000\0032.0binary data is here" in
    let signature = sign_update update in
    `String (signature ^ update ^ "BOGUS CONTENT")
  in
  "a request for /system/update with authenticated user returns 200"
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

let system_update_version_downgrade () =
  let body =
    let update = "\000\000\018A new system image\000\000\0030.5binary data is here" in
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

let system_update_commit_ok () =
  let body =
    let update = "\000\000\018A new system image\000\000\0032.0binary data is here" in 
    let signature = sign_update update in
    `String (signature ^ update)
  in
  "a request for /system/commit-update with authenticated user returns 200"
   @? begin match admin_post_request ~body "/system/update" with
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
    let update = "\000\000\018A new system image\000\000\0032.0binary data is here" in
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
    match admin_post_request ~body:(`String passphrase) "/config/backup-passphrase" with
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
              begin match request ~meth:`PUT ~body:(`String unlock_json) ~hsm_state:hsm_state' "/unlock" with
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
  let returncode = Sys.command "../bin/sign_update.exe key.pem changes 2.0 update.bin --output=signed_update.bin" in
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
  @? begin match request ~meth:`PUT ~body:(`String unlock_json) ~hsm_state:(locked_mock ()) "/unlock" with
  | hsm_state, Some (`No_content, _, _, _) -> Hsm.state hsm_state = `Operational
  | _ -> false
  end

let unlock_failed () =
  "a request for /unlock with the wrong passphrase fails"
  @? begin
    let wrong_passphrase = {|{ "passphrase": "wrong" }|} in
    match request ~meth:`PUT ~body:(`String wrong_passphrase) ~hsm_state:(locked_mock ()) "/unlock" with
  | hsm_state, Some (`Bad_request, _, _, _) -> Hsm.state hsm_state = `Locked
  | _ -> false
  end

let unlock_twice () =
  "the first request for /unlock unlocks the HSM, the second fails"
  @? begin match request ~meth:`PUT ~body:(`String unlock_json) ~hsm_state:(locked_mock ()) "/unlock" with
  | hsm_state, Some (`No_content, _, _, _) ->
    begin
      match request ~meth:`PUT ~body:(`String unlock_json) ~hsm_state "/unlock" with
      | hsm', Some (`Precondition_failed, _, _, _) -> Hsm.state hsm' = `Operational
      | _ -> false
    end
  | _ -> false
  end

(* /config *)

let change_unlock_passphrase () =
  "change unlock passphrase succeeds"
  @? begin
  let passphrase = {|{ "passphrase" : "new passphrase" }|} in
  match admin_post_request ~body:(`String passphrase) "/config/unlock-passphrase" with
  | hsm_state, Some (`No_content, _, _, _) ->
    Hsm.lock hsm_state;
    begin match admin_put_request ~body:(`String passphrase) ~hsm_state "/unlock" with
    | hsm_state, Some (`No_content, _, _, _) -> Hsm.state hsm_state = `Operational
    | _ -> false
    end
  | _ -> false
  end

let change_unlock_passphrase_empty () =
  "change to empty unlock passphrase fails"
  @? begin
  let passphrase = {|{ "passphrase" : "" }|} in
  match admin_post_request ~body:(`String passphrase) "/config/unlock-passphrase" with
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
        Hsm.boot store >>= fun state ->
        Hsm.provision state ~unlock:"unlockPassphrase" ~admin:"test1Passphrase" Ptime.epoch >|= fun _ ->
        store, state)
    in
    match admin_post_request ~body:(`String {|{ "status" : "on" }|}) ~hsm_state "/config/unattended-boot" with
    | _hsm_state', Some (`No_content, _, _, _) ->
      Lwt_main.run (Hsm.boot store >|= fun hsm_state -> Hsm.state hsm_state = `Operational)
    | _ -> false
  end

let unattended_boot_failed () =
  "unattended boot fails to unlock"
  @? begin
    let store, hsm_state =
      Lwt_main.run (
        Kv_mem.connect () >>= fun store ->
        Hsm.boot store >>= fun state ->
        Hsm.provision state ~unlock:"unlockPassphrase" ~admin:"test1Passphrase" Ptime.epoch >|= fun _ ->
        store, state)
    in
    match admin_post_request ~body:(`String {|{ "status" : "on" }|}) ~hsm_state "/config/unattended-boot" with
    | _hsm_state', Some (`No_content, _, _, _) ->
      Lwt_main.run (
        Kv_mem.remove store (Mirage_kv.Key.v "/config/device-id-salt") >>= fun _ ->
        Hsm.boot store >|= fun hsm_state ->
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
      | _, Some (`Created, _, _, _) -> true
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
    "commonName": "nitrohsm.local",
    "emailAddress": "info@nitrokey.com"
  }|}

let post_config_tls_csr_pem () =
  "post tls csr pem file succeeds"
  @? begin
  match admin_post_request ~body:(`String subject) "/config/tls/csr.pem" with
  | _, Some (`OK, _, _, _) -> true
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
  match admin_post_request ~body:(`String passphrase) "/config/backup-passphrase" with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false
  end

let set_backup_passphrase_empty () =
  "set empty backup passphrase fails"
  @? begin
  let passphrase = {|{ "passphrase" : "" }|} in
  match admin_post_request ~body:(`String passphrase) "/config/backup-passphrase" with
  | _, Some (`Bad_request, _, _, _) -> true
  | _ -> false
  end

let invalid_config_version () =
  assert_raises (Invalid_argument "broken NitroHSM")
    (fun () ->
       Lwt_main.run (
         Kv_mem.connect () >>= fun data ->
         Kv_mem.set data (Mirage_kv.Key.v "config/version") "abcdef" >>= fun _ ->
         Hsm.boot data)) ;
  assert_raises (Invalid_argument "broken NitroHSM")
    (fun () ->
       Lwt_main.run (
         Kv_mem.connect () >>= fun data ->
         Kv_mem.set data (Mirage_kv.Key.v "config/version") "" >>= fun _ ->
         Hsm.boot data))

let config_version_but_no_salt () =
  Lwt_main.run (
    Kv_mem.connect () >>= fun data ->
    Kv_mem.set data (Mirage_kv.Key.v "config/version") "0" >>= fun _ ->
    Hsm.boot data >|= fun hsm ->
    assert_bool "hsm state is unprovisioned if only config/version is present"
      (Hsm.state hsm = `Unprovisioned))

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
  | _, Some (`Created, _, _, _) -> true
  | _ -> false
  end

let user_operator_add () =
  "PUT on /users/op succeeds"
  @? begin
  match admin_put_request ~body:(`String operator_json) "/users/op" with
  | _, Some (`Created, _, _, _) -> true
  | _ -> false
  end

let user_operator_add_empty_passphrase () =
  let operator_json = {| { realName: "Jane User", role: "Operator", passphrase: "" } |} in
  "PUT on /users/op succeeds"
  @? begin
  match admin_put_request ~body:(`String operator_json) "/users/op" with
  | _, Some (`Bad_request, _, _, _) ->
    true
  | _ -> false
  end

let user_operator_delete () =
  "DELETE on /users/operator succeeds"
  @? begin
  match request ~hsm_state:(operational_mock ()) ~meth:`DELETE ~headers:admin_headers "/users/operator" with
  | _, Some (`No_content, _, _, _) -> true
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

let keys_get () =
  "GET on /keys succeeds"
  @? begin match request ~headers:admin_headers ~hsm_state:(operational_mock ()) "/keys" with
  | _, Some (`OK, _, `String body, _) -> String.equal body "[]"
  | _ -> false
  end

let key_json = {| { purpose: "Sign", algorithm: "RSA", key: { primeP: "+hsFcOCzFRwQMwuLaFjpv6pMv6BcqmcRBBWbVaWzpaq6+ag4dRpy0tIF1852zyCYqkGu5uTkHt6ndJPfKnJISQ==", primeQ : "wxq55QRL62Z+1IrsBM6h/YBcfTHnbiojepFPAakJAU0P0j+9gsHBbPgb2iFMhQyEj0bIKdfWhaAS1oqj6awsMw==", publicExponent : "AQAB" } } |}

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
  let query = [ ("purpose", [ "sign" ]) ] in
  "POST on /keys succeeds"
  @? begin
  match admin_post_request ~content_type:"application/x-pem-file" ~query ~body:(`String key_pem) "/keys" with
  | _, Some (`Created, _, _, _) -> true
  | _ -> false
  end

let generate_json = {|{ purpose: "Decrypt", algorithm: "RSA", length: 2048 }|}

let keys_generate () =
  "POST on /keys/generate succeeds"
  @? begin
  match admin_post_request ~body:(`String generate_json) "/keys/generate" with
  | _, Some (`Created, _, _, _) -> true
  | _ -> false
  end

let keys_generate_invalid_id () =
  let generate_json = {|{ purpose: "Decrypt", algorithm: "RSA", length: 2048, id: "&*&*&*" }|} in
  "POST on /keys/generate with invalid ID fails"
  @? begin
  match admin_post_request ~body:(`String generate_json) "/keys/generate" with
  | _, Some (`Bad_request, _, `String reply, _) ->
    let expected = {|{"message":"ID may only contain alphanumeric characters."}|} in
    String.equal reply expected
  | _ -> false
  end

let keys_generate_invalid_id_length () =
  let generate_json = {|{ purpose: "Decrypt", algorithm: "RSA", length: 2048, id: "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890" }|} in
  "POST on /keys/generate with invalid ID fails"
  @? begin
  match admin_post_request ~body:(`String generate_json) "/keys/generate" with
  | _, Some (`Bad_request, _, _, _) -> true
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

let hsm_with_key ?(mode = Keyfender.Json.Decrypt) () =
  let state = operational_mock () in
  Lwt_main.run (Hsm.Key.add_pem state mode ~id:"keyID" test_key_pem >|= function
  | Ok () -> state
  | Error _ -> assert false)

let keys_key_get () =
  "GET on /keys/keyID succeeds"
  @? begin
  match request ~headers:admin_headers ~hsm_state:(hsm_with_key ()) "/keys/keyID" with
  | _, Some (`OK, _, _, _) -> true
  | _ -> false
  end

let keys_key_put () =
  "PUT on /keys/keyID succeeds"
  @? begin
  match admin_put_request ~body:(`String key_json) "/keys/keyID" with
  | _, Some (`No_content, _, _, _) -> true
  | _ -> false
  end

let keys_key_delete () =
  "DELETE on /keys/keyID succeeds"
  @? begin
  match request ~meth:`DELETE ~headers:admin_headers ~hsm_state:(hsm_with_key ()) "/keys/keyID" with
  | _, Some (`No_content, _, _, _) -> true
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

let admin_keys_key_csr_pem () =
  "POST on /keys/keyID/csr.pem succeeds"
  @? begin
  match admin_post_request ~body:(`String subject) ~hsm_state:(hsm_with_key ()) "/keys/keyID/csr.pem" with
  | _, Some (`OK, _, _, _) -> true
  | _ -> false
  end

let operator_keys_key_csr_pem () =
  "POST on /keys/keyID/csr.pem succeeds"
  @? begin
  match request ~meth:`POST ~headers:operator_headers ~body:(`String subject) ~hsm_state:(hsm_with_key ()) "/keys/keyID/csr.pem" with
  | _, Some (`OK, _, _, _) -> true
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

let sign_request =
  Printf.sprintf {|{ mode: "PKCS1", message: "%s"}|}
    (Base64.encode_string message)

let operator_keys_key_sign () =
  "POST on /keys/keyID/sign succeeds"
  @? begin
    let hsm_state = hsm_with_key ~mode:Keyfender.Json.Sign () in
  match request ~meth:`POST ~headers:operator_headers ~body:(`String sign_request) ~hsm_state "/keys/keyID/sign" with
    | _, Some (`OK, _, `String data, _) ->
      begin match Yojson.Safe.from_string data with
        | `Assoc [ "signature", `String signature ] ->
          begin match Base64.decode signature with
            | Error _ -> false
            | Ok decoded ->
              match X509.Private_key.decode_pem (Cstruct.of_string test_key_pem) with
              | Error _ -> false
              | Ok `RSA private_key ->
                let key = Mirage_crypto_pk.Rsa.pub_of_priv private_key in
                match Mirage_crypto_pk.Rsa.PKCS1.sig_decode ~key @@ Cstruct.of_string decoded with
                | Some msg -> String.equal (Cstruct.to_string msg) message
                | None -> false
          end
        | _ -> false
      end
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

let keys_key_cert_put () =
  "PUT on /keys/keyID/cert succeeds"
  @? begin
    let hsm_state = hsm_with_key () in
    match admin_put_request ~body:(`String "data") ~hsm_state "/keys/keyID/cert" with
    | _, Some (`Created, _, _, _) -> true
    | _ -> false
  end

let keys_key_cert_delete () =
  "DELETE on /keys/keyID/cert succeeds"
  @? begin
    let hsm_state = hsm_with_key () in
    let _ = Lwt_main.run (Hsm.Key.set_cert hsm_state ~id:"keyID" ~content_type:"foo/bar" "data") in
    match request ~meth:`DELETE ~headers:admin_headers ~hsm_state "/keys/keyID/cert" with
    | _, Some (`No_content, _, _, _) -> true
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
    "/system/update" >:: system_update_invalid_data;
    "/system/update" >:: system_update_version_downgrade;
    "/system/commit-update" >:: system_update_commit_ok;
    "/system/commit-update" >:: system_update_commit_fail;
    "/system/cancel-update" >:: system_update_cancel_ok;
    "/system/update from binary file" >:: system_update_from_file_ok;
    "/system/update signing" >:: sign_update_ok;
    "/system/backup" >:: system_backup_and_restore_ok;
    "/unlock" >:: unlock_ok;
    "/unlock" >:: unlock_failed;
    "/unlock" >:: unlock_twice;
    "/config/unattended_boot" >:: get_unattended_boot_ok;
    "/config/unattended_boot" >:: unattended_boot_succeeds;
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
    "/users/operator" >:: user_operator_delete;
    "/users/operator" >:: user_operator_delete_fails;
    "/users/operator" >:: user_op_delete_fails;
    "/users/operator" >:: user_operator_get;
    "/users/operator" >:: user_operator_get_not_found;
    "/users/admin/passphrase" >:: user_passphrase_post;
    "/users/operator/passphrase" >:: user_passphrase_operator_post;
    "/users/admin/passphrase" >:: user_passphrase_administrator_post;
    "/keys" >:: keys_get;
    "/keys" >:: keys_post_json;
    "/keys" >:: keys_post_pem;
    "/keys/generate" >:: keys_generate;
    "/keys/generate" >:: keys_generate_invalid_id;
    "/keys/generate" >:: keys_generate_invalid_id_length;
    "/keys/keyID" >:: keys_key_get;
    "/keys/keyID" >:: keys_key_put;
    "/keys/keyID" >:: keys_key_delete;
    "/keys/keyID/public.pem" >:: admin_keys_key_public_pem;
    "/keys/keyID/public.pem" >:: operator_keys_key_public_pem;
    "/keys/keyID/csr.pem" >:: admin_keys_key_csr_pem;
    "/keys/keyID/csr.pem" >:: operator_keys_key_csr_pem;
    "/keys/keyID/decrypt" >:: operator_keys_key_decrypt;
    "/keys/keyID/sign" >:: operator_keys_key_sign;
    "/keys/keyID/cert" >:: keys_key_cert_get;
    "/keys/keyID/cert" >:: keys_key_cert_put;
    "/keys/keyID/cert" >:: keys_key_cert_delete;
    "/unlock" >:: rate_limit_for_unlock;
    "/system/info" >:: rate_limit_for_get;
    "rate limit reset after successful login" >:: reset_rate_limit_after_successful_login;
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
