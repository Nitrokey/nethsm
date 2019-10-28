open OUnit
open Cohttp
open Lwt.Infix

module Kv_mem = Mirage_kv_mem.Make(Pclock)
module Hsm = Keyfender.Hsm.Make(Mirage_random_test)(Kv_mem)
module Handlers = Keyfender.Server.Make_handlers(Mirage_random_test)(Pclock)(Hsm)

let now () = Ptime.v (Pclock.now_d_ps ())

let request ?hsm_state ?(body = `Empty) ?(meth = `GET) ?(headers = Header.init_with "accept" "application/json") path =
  let hsm_state' = match hsm_state with
    | None -> Lwt_main.run (Kv_mem.connect () >>= Hsm.make)
    | Some x -> x
  in
  let uri = Uri.make ~scheme:"http" ~host:"localhost" ~path () in
  let request = Request.make ~meth ~headers uri in
  match Lwt_main.run @@ Handlers.Wm.dispatch' (Handlers.routes hsm_state' now) ~body ~request with
  | None -> hsm_state', None
  | Some (status, _, _, _) as r -> Printf.printf "got HTTP status %d\n%!" (Code.code_of_status status) ; hsm_state', r

let operational_mock () =
  Lwt_main.run (
    Kv_mem.connect () >>= Hsm.make >>= fun state ->
    Hsm.provision state ~unlock:"" ~admin:"test1" Ptime.epoch >>= fun _ ->
    Hsm.User.add state ~id:"operator" ~role:`Operator ~passphrase:"test2" ~name:"operator" >|= fun _ ->
    state)

let locked_mock () =
  Lwt_main.run (
    (* create an empty in memory key-value store, and a HSM state (unprovisioned) *)
    Kv_mem.connect () >>= fun kv ->
    Hsm.make kv >>= fun state ->
    (* provision HSM, leading to state operational (and writes to the kv store) *)
    Hsm.provision state ~unlock:"test1234" ~admin:"test1" Ptime.epoch >>= fun r ->
    (* create a new HSM state, using the provisioned kv store, with a `Locked state *)
    assert (r = Ok ());
    Hsm.make kv)

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

let unlock_json = {|{ "passphrase": "test1234" }|}

let unlock_ok () =
  "a request for /unlock unlocks the HSM"
  @? begin match request ~body:(`String unlock_json) ~hsm_state:(locked_mock ())
                   ~meth:`PUT ~headers:(Header.init_with "content-type" "application/json") "/unlock" with
  | hsm_state, Some (`No_content, _, _, _) -> Hsm.state hsm_state = `Operational
  | _ -> false
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
    "/unlock" >:: unlock_ok;
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
