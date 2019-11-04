open OUnit
open Cohttp
open Lwt.Infix

module Kv_mem = Mirage_kv_mem.Make(Pclock)
module Hsm = Keyfender.Hsm.Make(Mirage_random_test)(Kv_mem)(Pclock)
module Handlers = Keyfender.Server.Make_handlers(Mirage_random_test)(Pclock)(Hsm)

let now () = Ptime.v (Pclock.now_d_ps ())

let request ?hsm_state ?(body = `Empty) ?(meth = `GET) ?(headers = Header.init_with "accept" "application/json") path =
  let hsm_state' = match hsm_state with
    | None -> Lwt_main.run (Kv_mem.connect () >>= Hsm.boot)
    | Some x -> x
  in
  let uri = Uri.make ~scheme:"http" ~host:"localhost" ~path () in
  let request = Request.make ~meth ~headers uri in
  match Lwt_main.run @@ Handlers.Wm.dispatch' (Handlers.routes hsm_state' now) ~body ~request with
  | None -> hsm_state', None
  | Some (status, _, _, _) as r ->
    Printf.printf "got HTTP status %d\n%!" (Code.code_of_status status) ;
    hsm_state', r

let operational_mock () =
  Lwt_main.run (
    Kv_mem.connect () >>= Hsm.boot >>= fun state ->
    Hsm.provision state ~unlock:"" ~admin:"test1" Ptime.epoch >>= fun _ ->
    Hsm.User.add state ~id:"operator" ~role:`Operator ~passphrase:"test2" ~name:"operator" >|= fun _ ->
    state)

let locked_mock () =
  Lwt_main.run (
    (* create an empty in memory key-value store, and a HSM state (unprovisioned) *)
    Kv_mem.connect () >>= fun kv ->
    Hsm.boot kv >>= fun state ->
    (* provision HSM, leading to state operational (and writes to the kv store) *)
    Hsm.provision state ~unlock:"test1234" ~admin:"test1" Ptime.epoch >>= fun r ->
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
  "a request for /health/state will produce an HTTP 200"
    @? begin match request ~hsm_state "/health/state" with
       | _, Some (`OK, _, `String body, _) -> String.equal body @@ Yojson.Safe.to_string @@ Hsm.state_to_yojson @@ Hsm.state hsm_state 
       | _ -> false
    end

let provision_json = {| {
  "unlockPassphrase": "Unlock",
  "adminPassphrase": "Administrator",
  "time": "2018-10-30T11:20:50Z"
} |}

let provision_ok () =
  let body = `String provision_json in
  "an initial provision request is successful (state transition to operational, HTTP response 204)"
    @? begin match request ~body ~meth:`PUT ~headers:(Header.init_with "content-type" "application/json") "/provision" with
       | hsm_state, Some (`No_content, _, _, _) -> Hsm.state hsm_state = `Operational
       | _ -> false
    end

let provision_error_malformed_request () =
  let body = `String ("hallo" ^ provision_json) in
  "an initial provision request with invalid json returns a malformed request with 400"
    @? begin match request ~body ~meth:`PUT ~headers:(Header.init_with "content-type" "application/json") "/provision" with
       | hsm_state, Some (`Bad_request, _, _, _) -> Hsm.state hsm_state = `Unprovisioned
       | _ -> false
    end

let provision_error_precondition_failed () =
  let body = `String provision_json in
  "an initial provision request is successful, a subsequent provision fails with 412"
    @? begin match request ~body ~meth:`PUT ~headers:(Header.init_with "content-type" "application/json") "/provision" with
       | hsm_state, Some (`No_content, _, _, _) ->
         begin match request ~hsm_state ~body ~meth:`PUT ~headers:(Header.init_with "content-type" "application/json") "/provision" with
          | _, Some (`Precondition_failed, _, _, _) -> true
          | _ -> false
         end
       | _ -> false
    end

let authorization_header user pass =
  let base64 = Cstruct.to_string (Nocrypto.Base64.encode (Cstruct.of_string (user ^ ":" ^ pass))) in
  Header.init_with "authorization" ("Basic " ^ base64)

let system_info_ok () =
  "a request for /system/info with authenticated user returns 200"
   @? begin match request ~hsm_state:(operational_mock ()) ~headers:(authorization_header "admin" "test1") "/system/info" with
      | hsm_state, Some (`OK, _, `String body, _) -> String.equal body @@ Yojson.Safe.to_string @@ Hsm.system_info_to_yojson @@ Hsm.System.system_info hsm_state
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
   @? begin match request ~hsm_state:(operational_mock ()) ~headers:(authorization_header "operator" "test2") "/system/info" with
      | _, Some (`Forbidden, _, _, _) -> true
      | _ -> false
   end

let system_reboot_ok () =
  "a request for /system/reboot with authenticated user returns 200"
   @? begin match request ~meth:`POST ~hsm_state:(operational_mock ()) ~headers:(authorization_header "admin" "test1") "/system/reboot" with
      | hsm_state, Some (`No_content, _, _, _) -> Hsm.state hsm_state = `Busy
      | _ -> false
   end

let system_shutdown_ok () =
  "a request for /system/shutdown with authenticated user returns 200"
   @? begin match request ~meth:`POST ~hsm_state:(operational_mock ()) ~headers:(authorization_header "admin" "test1") "/system/shutdown" with
      | hsm_state, Some (`No_content, _, _, _) -> Hsm.state hsm_state = `Busy
      | _ -> false
   end

let system_reset_ok () =
  "a request for /system/reset with authenticated user returns 200"
   @? begin match request ~meth:`POST ~hsm_state:(operational_mock ()) ~headers:(authorization_header "admin" "test1") "/system/reset" with
      | hsm_state, Some (`No_content, _, _, _) -> Hsm.state hsm_state = `Unprovisioned
      | _ -> false
   end

let system_update_ok () =
  let body = `String "\000\003sig\000\018A new system image\000\0032.0binary data is here" in
  "a request for /system/update with authenticated user returns 200"
   @? begin match request ~meth:`POST ~hsm_state:(operational_mock ()) ~headers:(authorization_header "admin" "test1") ~body "/system/update" with
      | hsm_state, Some (`OK, _, _, _) -> Hsm.state hsm_state = `Operational
      | _ -> false
   end

let system_update_invalid_data () =
  let body = `String "\000\003signature too long\000\018A new system image\000\0032.0binary data is here" in
  "a request for /system/update with invalid data fails."
   @? begin match request ~meth:`POST ~hsm_state:(operational_mock ()) ~headers:(authorization_header "admin" "test1") ~body "/system/update" with
      | hsm_state, Some (`Bad_request, _, `String body, _) -> 
        Logs.info (fun m -> m "Update with invalid data returned %s" body); 
        Hsm.state hsm_state = `Operational
      | _ -> false
   end

let system_update_version_downgrade () =
  let body = `String "\000\003sig\000\018A new system image\000\0030.5binary data is here" in
  "a request for /system/update trying to send an older software fails."
   @? begin match request ~meth:`POST ~hsm_state:(operational_mock ()) ~headers:(authorization_header "admin" "test1") ~body "/system/update" with
      | hsm_state, Some (`Bad_request, _, `String body, _) -> 
        Logs.info (fun m -> m "Update with older software version returned %s" body); 
        Hsm.state hsm_state = `Operational
      | _ -> false
   end

let system_update_commit_ok () =
  let headers = authorization_header "admin" "test1" in
  let body = `String "\000\003sig\000\018A new system image\000\0032.0binary data is here" in
  "a request for /system/update-commit with authenticated user returns 200"
   @? begin match request ~meth:`POST ~hsm_state:(operational_mock ()) ~headers ~body "/system/update" with
      | hsm_state, Some (`OK, _, _, _) -> 
        begin match request ~meth:`POST ~hsm_state ~headers "/system/commit-update" with
        | _ , Some (`No_content, _, _, _) -> true
        | _ -> false
        end
      | _ -> false
   end

let system_update_cancel_ok () =
  let headers = authorization_header "admin" "test1" in
  let body = `String "\000\003sig\000\018A new system image\000\0032.0binary data is here" in
  "a request for /system/update-cancel with authenticated user returns 200"
   @? begin match request ~meth:`POST ~hsm_state:(operational_mock ()) ~headers ~body "/system/update" with
      | hsm_state, Some (`OK, _, _, _) -> 
        begin match request ~meth:`POST ~hsm_state ~headers "/system/cancel-update" with
        | _ , Some (`No_content, _, _, _) -> true
        | _ -> false
        end
      | _ -> false
   end

let unlock_json = {|{ "passphrase": "test1234" }|}

let unlock_ok () =
  "a request for /unlock unlocks the HSM"
  @? begin match request ~body:(`String unlock_json) ~hsm_state:(locked_mock ())
                   ~meth:`PUT ~headers:(Header.init_with "content-type" "application/json") "/unlock" with
  | hsm_state, Some (`No_content, _, _, _) -> Hsm.state hsm_state = `Operational
  | _ -> false
  end

let unlock_failed () =
  "a request for /unlock with the wrong passphrase fails"
  @? begin
    let wrong_passphrase = {|{ "passphrase": "wrong" }|} in
    match request ~body:(`String wrong_passphrase) ~hsm_state:(locked_mock ())
                   ~meth:`PUT ~headers:(Header.init_with "content-type" "application/json") "/unlock" with
  | hsm_state, Some (`Bad_request, _, _, _) -> Hsm.state hsm_state = `Locked
  | _ -> false
  end

let unlock_twice () =
  "the first request for /unlock unlocks the HSM, the second fails"
  @? begin match request ~body:(`String unlock_json) ~hsm_state:(locked_mock ())
                   ~meth:`PUT ~headers:(Header.init_with "content-type" "application/json") "/unlock" with
  | hsm_state, Some (`No_content, _, _, _) ->
    begin
      match request ~body:(`String unlock_json) ~hsm_state
              ~meth:`PUT ~headers:(Header.init_with "content-type" "application/json") "/unlock" with
      | hsm', Some (`Precondition_failed, _, _, _) -> Hsm.state hsm' = `Operational
      | _ -> false
    end
  | _ -> false
  end

let get_unattended_boot_ok () =
  "GET /config/unattended-boot succeeds"
  @? begin
    let headers = authorization_header "admin" "test1" in
    match request ~hsm_state:(operational_mock ()) ~meth:`GET ~headers "/config/unattended-boot" with
    | _hsm_state', Some (`OK, _, `String body, _) -> body = {|{"status":"off"}|}
    | _ -> false
  end

let unattended_boot_succeeds () =
  "unattended boot succeeds"
  @? begin
    let headers = Header.add (authorization_header "admin" "test1") "content-type" "application/json" in
    let store, hsm_state =
      Lwt_main.run (
        Kv_mem.connect () >>= fun store ->
        Hsm.boot store >>= fun state ->
        Hsm.provision state ~unlock:"" ~admin:"test1" Ptime.epoch >|= fun _ ->
        store, state)
    in
    match request ~body:(`String {|{ "status" : "on" }|}) ~hsm_state ~meth:`POST ~headers "/config/unattended-boot" with
    | _hsm_state', Some (`No_content, _, _, _) ->
      Lwt_main.run (Hsm.boot store >|= fun hsm_state -> Hsm.state hsm_state = `Operational)
    | _ -> false
  end

let unattended_boot_failed () =
  "unattended boot fails to unlock"
  @? begin
    let headers = Header.add (authorization_header "admin" "test1") "content-type" "application/json" in
    let store, hsm_state =
      Lwt_main.run (
        Kv_mem.connect () >>= fun store ->
        Hsm.boot store >>= fun state ->
        Hsm.provision state ~unlock:"" ~admin:"test1" Ptime.epoch >|= fun _ ->
        store, state)
    in
    match request ~body:(`String {|{ "status" : "on" }|}) ~hsm_state ~meth:`POST ~headers "/config/unattended-boot" with
    | _hsm_state', Some (`No_content, _, _, _) ->
      Lwt_main.run (
        Kv_mem.remove store (Mirage_kv.Key.v "/config/device-id-salt") >>= fun _ ->
        Hsm.boot store >|= fun hsm_state ->
        Hsm.state hsm_state = `Locked)
    | _ -> false
  end

(* /config *)

let change_unlock_passphrase () =
  "change unlock passphrase succeeds"
  @? begin 
  let headers = Header.add (authorization_header "admin" "test1") "content-type" "application/json" in 
  let passphrase = {|{ "passphrase" : "new passphrase" }|} in
  match request ~body:(`String passphrase) ~hsm_state:(operational_mock ())
                   ~meth:`PUT ~headers "/config/unlock-passphrase" with
  | hsm_state, Some (`No_content, _, _, _) -> 
    Hsm.lock hsm_state;
    begin match request ~body:(`String passphrase) ~hsm_state
                     ~meth:`PUT ~headers:(Header.init_with "content-type" "application/json") "/unlock" with
    | hsm_state, Some (`No_content, _, _, _) -> Hsm.state hsm_state = `Operational
    | _ -> false
    end
  | _ -> false
  end

let change_unlock_passphrase_empty () =
  "change to empty unlock passphrase fails"
  @? begin 
  let headers = Header.add (authorization_header "admin" "test1") "content-type" "application/json" in 
  let passphrase = {|{ "passphrase" : "" }|} in
  match request ~body:(`String passphrase) ~hsm_state:(operational_mock ())
                   ~meth:`PUT ~headers "/config/unlock-passphrase" with
  | _, Some (`Bad_request, _, _, _) -> true 
  | _ -> false
  end

let get_config_tls_public_pem () =
  "get tls public pem file succeeds"
  @? begin 
  let headers = authorization_header "admin" "test1" in 
  match request ~hsm_state:(operational_mock ())
                   ~meth:`GET ~headers "/config/tls/public.pem" with
  | _, Some (`OK, _, _, _) -> true 
  | _ -> false
  end

let get_config_tls_cert_pem () =
  "get tls cert pem file succeeds"
  @? begin 
  let headers = authorization_header "admin" "test1" in 
  match request ~hsm_state:(operational_mock ())
                   ~meth:`GET ~headers "/config/tls/cert.pem" with
  | _, Some (`OK, _, _, _) -> true 
  | _ -> false
  end

let post_config_tls_cert_pem () =
  "post tls cert pem file succeeds"
  @? begin 
  let headers = authorization_header "admin" "test1" in 
  match request ~hsm_state:(operational_mock ())
                   ~meth:`GET ~headers "/config/tls/cert.pem" with
  | hsm_state, Some (`OK, _, `String body, _) -> 
    begin
      let headers = Header.add headers "content-type" "application/x-pem-file" in 
      match request ~hsm_state ~meth:`PUT ~headers ~body:(`String body) "/config/tls/cert.pem" with
      | _, Some (`No_content, _, _, _) -> true 
      | _ -> false
    end
  | _ -> false
  end

let post_config_tls_cert_pem_fail () =
  "post tls cert pem file fail"
  @? begin 
    let headers = authorization_header "admin" "test1" in 
    let headers = Header.add headers "content-type" "application/x-pem-file" in 
    let not_a_pem = "hello this is not pem format" in
    match request ~hsm_state:(operational_mock ()) ~meth:`PUT ~headers ~body:(`String not_a_pem) "/config/tls/cert.pem" with
    | _, Some (`Bad_request, _, _, _) -> true 
    | _ -> false
  end

let post_config_tls_csr_pem () =
  "post tls csr pem file succeeds"
  @? begin 
  let subject = {|{ 
    "countryName": "DE",
    "stateOrProvinceName": "",
    "localityName": "Berlin",
    "organizationName": "Nitrokey",
    "organizationalUnitName": "",
    "commonName": "nitrohsm.local",
    "emailAddress": "info@nitrokey.com"
  }|} in
  let headers = Header.add (authorization_header "admin" "test1") "content-type" "application/json" in 
  match request ~hsm_state:(operational_mock ())
                   ~meth:`PUT ~headers ~body:(`String subject) "/config/tls/csr.pem" with
  | _, Some (`OK, _, _, _) -> true 
  | _ -> false
  end

let config_network_ok () =
  "GET on /config/network succeeds"
  @? begin
    let headers = authorization_header "admin" "test1" in
  match request ~hsm_state:(operational_mock ()) ~meth:`GET ~headers "/config/network" with
  | _, Some (`OK, _, `String body, _) ->
    body = {|{"ipAddress":"192.168.1.1","netmask":"255.255.255.0","gateway":"0.0.0.0"}|}
  | _ -> false
  end

let config_network_set_ok () =
  "PUT on /config/network succeeds"
  @? begin
    let new_network = {|{"ipAddress":"6.6.6.6","netmask":"255.255.255.0","gateway":"0.0.0.0"}|} in
    let headers = Header.add (authorization_header "admin" "test1") "content-type" "application/json" in 
    match request ~body:(`String new_network) ~hsm_state:(operational_mock ()) ~meth:`PUT ~headers "/config/network" with
    | hsm_state, Some (`No_content, _, _, _) ->
      begin match request ~hsm_state ~meth:`GET ~headers "/config/network" with
        | _, Some (`OK, _, `String body, _) -> body = new_network
        | _ -> false
      end
  | _ -> false
  end

let config_network_set_fail () =
  "PUT with invalid IP address on /config/network fails"
  @? begin
    let new_network = {|{"ipAddress":"6.6.6.666","netmask":"255.255.255.0","gateway":"0.0.0.0"}|} in
    let headers = Header.add (authorization_header "admin" "test1") "content-type" "application/json" in 
    match request ~body:(`String new_network) ~hsm_state:(operational_mock ()) ~meth:`PUT ~headers "/config/network" with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  end

let config_logging_ok () =
  "GET on /config/logging succeeds"
  @? begin
    let headers = authorization_header "admin" "test1" in
  match request ~hsm_state:(operational_mock ()) ~meth:`GET ~headers "/config/logging" with
  | _, Some (`OK, _, `String body, _) ->
    body = {|{"ipAddress":"0.0.0.0","port":514,"logLevel":"info"}|}
  | _ -> false
  end

let config_logging_set_ok () =
  "PUT on /config/logging succeeds"
  @? begin
    let new_logging = {|{"ipAddress":"6.6.6.6","port":514,"logLevel":"error"}|} in
    let headers = Header.add (authorization_header "admin" "test1") "content-type" "application/json" in 
    match request ~body:(`String new_logging) ~hsm_state:(operational_mock ()) ~meth:`PUT ~headers "/config/logging" with
    | hsm_state, Some (`No_content, _, _, _) ->
      begin match request ~hsm_state ~meth:`GET ~headers "/config/logging" with
        | _, Some (`OK, _, `String body, _) -> body = new_logging
        | _ -> false
      end
  | _ -> false
  end

let config_logging_set_fail () =
  "PUT with invalid logLevel on /config/logging fails"
  @? begin
    let new_logging = {|{"ipAddress":"6.6.6.6","port":514,"logLevel":"nonexisting"}|} in
    let headers = Header.add (authorization_header "admin" "test1") "content-type" "application/json" in 
    match request ~body:(`String new_logging) ~hsm_state:(operational_mock ()) ~meth:`PUT ~headers "/config/logging" with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  end

let config_time_ok () =
  "GET on /config/time succeeds"
  @? begin
    let headers = authorization_header "admin" "test1" in
  match request ~hsm_state:(operational_mock ()) ~meth:`GET ~headers "/config/time" with
  | _, Some (`OK, _, `String body, _) ->
    let without_ticks = String.sub body 1 (String.length body - 2) in
    begin match Ptime.of_rfc3339 without_ticks with Ok _ -> true | _ -> false end
  | _ -> false
  end

let config_time_set_ok () =
  "PUT on /config/time succeeds"
  @? begin
    let new_time = {|"1970-01-01T00:00:00-00:00"|} in
    let headers = Header.add (authorization_header "admin" "test1") "content-type" "application/json" in 
    match request ~body:(`String new_time) ~hsm_state:(operational_mock ()) ~meth:`PUT ~headers "/config/time" with
    | hsm_state, Some (`No_content, _, _, _) ->
      begin match request ~hsm_state ~meth:`GET ~headers "/config/time" with
        | _, Some (`OK, _, `String body, _) ->
          let without_ticks = String.sub body 1 (String.length body - 2) in
          begin match Ptime.of_rfc3339 without_ticks with Ok _ -> true | _ -> false end
        | _ -> false
      end
  | _ -> false
  end

let config_time_set_fail () =
  "PUT with invalid logLevel on /config/time fails"
  @? begin
    let new_time = {|"1234"|} in
    let headers = Header.add (authorization_header "admin" "test1") "content-type" "application/json" in 
    match request ~body:(`String new_time) ~hsm_state:(operational_mock ()) ~meth:`PUT ~headers "/config/time" with
    | _, Some (`Bad_request, _, _, _) -> true
    | _ -> false
  end

let set_backup_passphrase () =
  "set backup passphrase succeeds"
  @? begin
  let headers = Header.add (authorization_header "admin" "test1") "content-type" "application/json" in 
  let passphrase = {|{ "passphrase" : "my backup passphrase" }|} in
  match request ~body:(`String passphrase) ~hsm_state:(operational_mock ())
                   ~meth:`PUT ~headers "/config/backup-passphrase" with
  | _, Some (`No_content, _, _, _) -> true 
  | _ -> false
  end

let set_backup_passphrase_empty () =
  "set empty backup passphrase fails"
  @? begin
  let headers = Header.add (authorization_header "admin" "test1") "content-type" "application/json" in 
  let passphrase = {|{ "passphrase" : "" }|} in
  match request ~body:(`String passphrase) ~hsm_state:(operational_mock ())
                   ~meth:`PUT ~headers "/config/backup-passphrase" with
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
  Lwt_main.run @@ Nocrypto_entropy_lwt.initialize ();
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
    "/system/update" >:: system_update_invalid_data;
    "/system/update" >:: system_update_version_downgrade;
    "/system/update" >:: system_update_commit_ok;
    "/system/update" >:: system_update_cancel_ok;
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
    "/config/tls/cert.pem" >:: post_config_tls_cert_pem;
    "/config/tls/cert.pem" >:: post_config_tls_cert_pem_fail;
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
