open Cohttp
open Lwt.Infix

let () = Mirage_crypto_rng_unix.initialize ()

module Test_logs = struct
  let buffer = Buffer.create 1000
  let fmt = Format.formatter_of_buffer buffer
  let reporter = Logs.format_reporter ~app:fmt ~dst:fmt ()
  let tag_regex = Str.regexp {|([a-f0-9]+)|}
  let sanitize s = Str.global_substitute tag_regex (fun _ -> "(xxxx)") s

  let check ~expect fn =
    let backup = Logs.reporter () in
    Fun.protect ~finally:(fun () ->
        Buffer.clear buffer;
        Logs.set_reporter backup)
    @@ fun () ->
    Logs.set_reporter reporter;
    let result = fn () in
    Format.pp_print_flush fmt ();
    Alcotest.(check string) "logs" expect (sanitize (Buffer.contents buffer));
    result
end

let info msg = Fmt.str "test_dispatch.exe: [INFO] %s\n" msg
let warning msg = Fmt.str "test_dispatch.exe: [WARNING] %s\n" msg
let error msg = Fmt.str "test_dispatch.exe: [ERROR] %s\n" msg

module Mock_clock = struct
  let _now = ref (1000, 0L)
  let now_d_ps () = !_now
  let current_tz_offset_s () = None
  let period_d_ps () = None

  let one_second_later () =
    _now := (fst !_now, Int64.add (snd !_now) 1_000_000_000_000L)
end

module Hsm_clock = Keyfender.Hsm_clock.Make (Mock_clock)

module Time = struct
  let sleep_ns duration = Lwt_unix.sleep (Duration.to_f duration)
end

module Kv_mem = Mirage_kv_mem.Make (Hsm_clock)

module Hsm =
  Keyfender.Hsm.Make (Mirage_random_test) (Kv_mem) (Time) (Mclock) (Hsm_clock)

module Handlers = Keyfender.Server.Make_handlers (Mirage_random_test) (Hsm)

let software_update_key =
  match
    X509.Public_key.decode_pem ([%blob "public.pem"] |> Cstruct.of_string)
  with
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

let request ?(expect = "") ?hsm_state ?(body = `Empty) ?(meth = `GET)
    ?(headers = Header.init ()) ?(content_type = "application/json") ?query
    ?(ip = Ipaddr.V4.any) endpoint =
  let headers = Header.replace headers "content-type" content_type in
  let hsm_state' =
    match hsm_state with
    | None ->
        Lwt_main.run
          ( Kv_mem.connect () >>= Hsm.boot ~platform software_update_key
          >|= fun (y, _, _) -> y )
    | Some x -> x
  in
  let path = "/api/v1" ^ endpoint in
  let uri = Uri.make ~scheme:"http" ~host:"localhost" ~path ?query () in
  let request = Request.make ~meth ~headers uri in
  Logs.info (fun f ->
      f "[REQ] %s %a" (Cohttp.Code.string_of_method meth) Uri.pp uri);
  let resp =
    Test_logs.check ~expect (fun () ->
        Lwt_main.run
        @@ Handlers.Wm.dispatch' (Handlers.routes hsm_state' ip) ~body ~request)
  in
  Option.iter
    (fun (code, _, _, _) ->
      Logs.info (fun f -> f "[RESP] %s" (Cohttp.Code.string_of_status code)))
    resp;
  (hsm_state', resp)

let good_platform mbox = Lwt_mvar.put mbox (Ok ())

let copy t =
  let v = Marshal.to_string t [] in
  Marshal.from_string v 0

let create_operational_mock mbox =
  Lwt_main.run
    ( Kv_mem.connect () >>= Hsm.boot ~platform software_update_key
    >>= fun (state, _, m) ->
      mbox m >>= fun () ->
      Hsm.provision state ~unlock:"unlockPassphrase" ~admin:"test1Passphrase"
        Ptime.epoch
      >>= fun _ ->
      Hsm.User.add state ~id:"operator" ~role:`Operator
        ~passphrase:"test2Passphrase" ~name:"operator"
      >>= fun _ ->
      Hsm.User.add_tag state ~id:"operator" ~tag:"berlin" >>= fun _ ->
      Hsm.User.add state ~id:"backup" ~role:`Backup
        ~passphrase:"test3Passphrase" ~name:"backup"
      >>= fun _ ->
      Hsm.User.add state ~id:"operator2" ~role:`Operator
        ~passphrase:"test4Passphrase" ~name:"operator2"
      >|= fun _ -> state )

let operational_mock = lazy (create_operational_mock good_platform)

let operational_mock ?(mbox = good_platform) () =
  let t =
    if mbox == good_platform then copy (Lazy.force operational_mock)
    else create_operational_mock mbox
  in
  Hsm.reset_rate_limit ();
  t

let create_locked_mock () =
  Lwt_main.run
    ( (* create an empty in memory key-value store, and a HSM state (unprovisioned) *)
      Kv_mem.connect ()
    >>= fun kv ->
      Hsm.boot ~platform software_update_key kv >>= fun (state, _, _) ->
      (* provision HSM, leading to state operational (and writes to the kv store) *)
      Hsm.provision state ~unlock:"test1234Passphrase" ~admin:"test1Passphrase"
        Ptime.epoch
      >>= fun r ->
      (* create a new HSM state, using the provisioned kv store, with a `Locked state *)
      assert (r = Ok ());
      Hsm.boot ~platform software_update_key kv >|= fun (y, _, _) -> y )

let locked_mock = lazy (create_locked_mock ())

let locked_mock () =
  let t = copy (Lazy.force locked_mock) in
  Hsm.reset_rate_limit ();
  t

let test_key_pem =
  {|
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
  | Ok (`RSA key) -> key
  | _ -> assert false

let no_restrictions = Keyfender.Json.{ tags = TagSet.empty }

let hsm_with_key
    ?(mechanisms = Keyfender.Json.(MS.singleton RSA_Decryption_PKCS1)) () =
  let state = operational_mock () in
  Lwt_main.run
    (Hsm.Key.add_pem state mechanisms ~id:"keyID" test_key_pem no_restrictions
     >|= function
     | Ok () -> state
     | Error _ -> assert false)

let auth_header user pass =
  let base64 = Base64.encode_string (user ^ ":" ^ pass) in
  Header.init_with "authorization" ("Basic " ^ base64)

let admin_headers = auth_header "admin" "test1Passphrase"
let operator_headers = auth_header "operator" "test2Passphrase"

let admin_put_request ?expect ?(hsm_state = operational_mock ())
    ?(body = `Empty) ?content_type ?query path =
  let headers = admin_headers in
  request ?expect ~meth:`PUT ~hsm_state ~headers ~body ?content_type ?query path

let admin_post_request ?expect ?(hsm_state = operational_mock ())
    ?(body = `Empty) ?content_type ?query path =
  let headers = admin_headers in
  request ?expect ~meth:`POST ~hsm_state ~headers ~body ?content_type ?query
    path
