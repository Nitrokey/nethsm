(*
  To call:
    dune exec ./generate_raml_tests.exe
*)

(* TODO

- Negative test cases we want to cover:
  - non-allowed http methods (=> 405 method not allowed)
  - invalid state (=> 412 precondition failed)

- minimize skip_endpoints: add a reason, split by HTTP method

- raml / code: should alive and ready be 204?

- add set -e to setup.sh to pass on error from provision_..sh

- comapre response header (create headers.expected)
  - content types -> different header
  - check location header

- use common-functions.sh in generate_raml_tests.exe for command.sh

- setup could use an argument "desired state", and execute the HTTP requests required to get into that state
--> one script, not per-test

LATER:

- gitlab pages code coverage
- improve code coverage of unit tests

*)

let host = "localhost"
let port = "8080"
let prefix = "api/v1"
let keyid = "myKey1"
let userid = "operator"
let cmd path meth = Printf.sprintf "curl http://%s:%s/%s%s -X %s " host port prefix path (String.uppercase_ascii meth)
let raml = "../../docs/nitrohsm-api.raml"
let allowed_methods = ["get" ; "put" ; "post"]
let allowed_request_types = [
  "application/json" ;
  "application/x-pem-file" ;
  "application/octet-stream" ;
  "application/x-x509-ca-cert" ;
  "application/pgp-keys";
]
let all_states = ["Unprovisioned"; "Locked"; "Operational"]
let skip_endpoints = ["/system/update"; "/system/cancel-update"; "/system/commit-update"; "/system/backup"; "/system/restore"; "/keys/{KeyID}/cert"; "/config/tls/cert.pem"]
let skip_body_endpoints = ["/random"; "/config/tls/csr.pem"; "/config/tls/cert.pem"; "/config/tls/public.pem"; "/health/state"; "/metrics"; "/config/time" ]

let is_quoted s =
  let l = String.length s in
  l >= 2 && String.get s 0 = '"' && String.get s (l-1) = '"'

let unquote s =
  let l = String.length s in
  if is_quoted s
  (* if its not a JSON object *)
  then String.sub s 1 (l-2)
  else s

let escape s =
  if is_quoted s
  (* if its not a JSON object *)
  then s
  else
    let s' = Str.global_replace (Str.regexp_string "\"") "\\\"" s in
    "\"" ^ s' ^ "\""

let get_endpoints meta = 
  Ezjsonm.get_dict meta |> List.partition (fun (key, _v) -> CCString.prefix ~pre:"/" key)

let get_meth meth meta = (* e.g. met is "get", "put", "post" *)
  Ezjsonm.get_dict meta |> List.partition (fun (key, _v) -> key = meth)

let write file content =
  let oc = open_out file in
  Printf.fprintf oc "%s" content;
  close_out oc;
  ()

let write_cmd outdir file content =
  write (outdir ^ "/" ^ file) content;
  let _ = Sys.command("chmod u+x " ^ outdir ^ "/" ^ file) in
  ()

let path_to_filename state meth path =
  let path = Str.global_replace (Str.regexp_string "/") "_" path in
  let path = Str.global_replace (Str.regexp_string ".") "_" path in
  let path = Str.global_replace (Str.regexp_string "{") "" path in
  let path = Str.global_replace (Str.regexp_string "}") "" path in
  let path = String.sub path 1 (String.length path -1) in (* remove leading / *)
  let outdir = Printf.sprintf "generated/%s_%s_%s" state path meth in
  let outfile = Printf.sprintf "%s/command.sh" outdir in
  (outdir, outfile)

let auth_header (user, pass) =
  let base64 = Base64.encode_string (user ^ ":" ^ pass) in
  " -H \"Authorization: Basic " ^ base64 ^ "\" "

(* TODO Metrics and Backup passphrase are different in RAML *)
let passphrase = function
  | "Administrator" -> ("admin", "Administrator")
  | "Operator" -> ("operator", "OperatorOperator")
  | "Metrics" -> ("metrics", "MetricsMetrics")
  | "Backup" -> ("backup", "BackupBackup")
  | _ -> assert false

let prepare_setup _meth _path _cmd (state, role, _req) =
  (* 1. prepare server state *)
  let provision = "NITROHSM_URL=\"http://localhost:8080/api\" ../../provision_test.sh"
  in
  let lock =
    let header = auth_header (passphrase "Administrator") in
    cmd "/lock" "POST" ^ header
  in
  let prepare_state = match state with
  | "Unprovisioned" -> ""
  | "Locked" -> provision ^ "\n" ^ lock
  | "Operational" -> provision
  | s -> Printf.printf "Error: Unknown prerequisite state in raml: %s\n" s; ""
  in
  (* 2. prepare role *)
  let add_user role =
    let user, pass = passphrase role in
    let header = auth_header (passphrase "Administrator") in
    let data = Printf.sprintf "{ realName: %S , role: %S , passphrase: %S }" user role pass in
    cmd ("/users/" ^ user) "PUT" ^ header ^ "-H \"Content-Type: application/json\" --data " ^ escape data
  in
  let prepare_role = match role with
    | Some "Metrics" -> add_user "Metrics"
    | Some "Backup" -> add_user "Backup"
    | _ -> ""
  in
  prepare_state ^ "\n" ^ prepare_role

let req_states req =
  Ezjsonm.get_strings @@ Ezjsonm.find req ["state"]

let req_roles req =
  Ezjsonm.get_strings @@ Ezjsonm.find req ["role"]

let make_post_data req = 
  match Ezjsonm.get_dict @@ Ezjsonm.find req ["body"] with
  | exception Not_found -> [""]
  | mediatypes ->
    let f (mediatype, req') =
      if not @@ List.mem mediatype allowed_request_types
      then Printf.printf "Request type %s found but not supported, raml malformed?" mediatype;
      let header = "-H \"Content-Type: " ^ mediatype ^ "\" " in
      header ^ "--data " ^ escape @@ Ezjsonm.(value_to_string @@ find req' ["example"])
    in
    List.map f mediatypes

let make_req_data req meth =
  let roles = req_roles req in
  let role, auth_header = match roles with
  | ["Public"] -> None, ""
  | "Administrator" :: _ -> Some "Administrator", auth_header (passphrase "Administrator")
  | "Operator" :: _ -> Some "Operator", auth_header (passphrase "Operator")
  | [ "Metrics" ] -> Some "Metrics", auth_header (passphrase "Metrics")
  | [ "Backup" ] -> Some "Backup", auth_header (passphrase "Backup")
  | x :: _ -> Printf.printf "unknown role %s" x; None, "" (*assert false*)
  | _ -> assert false
  in
  let states = req_states req in
  let states_and_data_for_mediatype = match meth with
  | "get" -> [(states, role, auth_header)]
  | "post" 
  | "put" -> List.map (fun d -> (states, role, auth_header ^ d)) (make_post_data req)
  | m -> Printf.printf "Error: Method %s not allowed" m; [(states, role, auth_header)]
  in
  (* TODO unroll roles? *)
  let unroll_states (states, role, data) =
    List.map (fun s -> (s, role, data)) states
  in
  List.concat_map unroll_states states_and_data_for_mediatype

let make_resp_data raml =
  let response_codes = Ezjsonm.get_dict @@ Ezjsonm.find raml ["responses"] in
  let get_example (code, meta) = match code with
  | "200" -> 
    begin
      match Ezjsonm.get_dict @@ Ezjsonm.find meta ["body"] with
      | exception Not_found -> [("200", None)]
      | mediatypes ->
        List.map (fun (typ, example) ->
          let subtree = Ezjsonm.find example ["example"] in
          ("200", Some (typ, subtree))) mediatypes
    end
  | somecode  -> [(somecode, None)]; 
  in
  let codes_and_examples = List.concat_map get_example response_codes in
  codes_and_examples

let tests_for_states meth path cmd (response_code, response_body) (state, role, req) =
  let (outdir, test_file) = path_to_filename state meth path in
  let _ = Sys.command("mkdir -p " ^ outdir) in

  let cmd' = Str.global_replace (Str.regexp_string "{KeyID}") keyid cmd in
  let cmd'' = Str.global_replace (Str.regexp_string "{UserID}") userid cmd' in
  let test_cmd = Printf.sprintf "%s %s  -D headers.out -o body.out \n\n" cmd'' req in

  (* if keyid was set, prepare a wrong one *)
  if cmd <> cmd' then
    begin
      let wrong_key = Str.global_replace (Str.regexp_string "{KeyID}") "bogus" cmd in
      let wrong_key_cmd = Printf.sprintf "%s %s  -D 404_wrong_key_headers.out -o /dev/null \n\n" wrong_key req in
      write_cmd outdir "404_wrong_key_cmd.sh" wrong_key_cmd
    end;

  (* if userid was set, prepare a wrong one *)
  if cmd' <> cmd'' then
    begin
      let wrong_user = Str.global_replace (Str.regexp_string "{UserID}") "bogus" cmd in
      let wrong_user_cmd = Printf.sprintf "%s %s  -D 404_wrong_user_headers.out -o /dev/null \n\n" wrong_user req in
      write_cmd outdir "404_wrong_user_cmd.sh" wrong_user_cmd
    end;

  (* if request contains --data json, prepare a wrong example *)
  let args = Str.split (Str.regexp "--data") req in
  if List.length args == 2 then
    begin
      (* prepare wrong json *)
      let headers = List.hd args in
      let wrong_json = "{}}}" in
      let wrong_req = Printf.sprintf " %s--data %s " headers (escape wrong_json) in
      let wrong_json_cmd = Printf.sprintf "%s %s  -D 400_wrong_json_headers.out -o /dev/null \n\n" cmd'' wrong_req in
      write_cmd outdir "400_wrong_json_cmd.sh" wrong_json_cmd;

      (* prepare wrong auth header *)
      let someone_else = match role with
      | Some "Administrator" -> auth_header (passphrase "Backup")
      | Some "Operator" -> auth_header (passphrase "Metrics")
      | Some "Metrics" -> auth_header (passphrase "Backup")
      | Some "Backup" -> auth_header (passphrase "Metrics")
      | _ -> ""
      in
      let wrong_auth = Str.global_replace (Str.regexp_string {|-H "Authorization: Basic YWRtaW46QWRtaW5pc3RyYXRvcg=="|}) someone_else req in
      if req <> wrong_auth then
        begin
          let wrong_auth_cmd = Printf.sprintf "%s %s  -D 403_wrong_auth_headers.out -o /dev/null \n\n" cmd'' wrong_auth in
          write_cmd outdir "403_wrong_auth_cmd.sh" wrong_auth_cmd;
        end;
    end;


  write test_file test_cmd;
  let _ = Sys.command("chmod u+x " ^ test_file) in

  (* prepare required state and role *)
  let setup_file = outdir ^ "/setup.sh" in
  let setup_cmd = prepare_setup meth path cmd (state, role, req) in
  write setup_file setup_cmd;
  let _ = Sys.command("chmod u+x " ^ setup_file) in

  let shutdown_file = outdir ^ "/shutdown.sh" in
  let shutdown_cmd =
    if path = "/system/shutdown" then "" else
    {|NITROHSM_URL="http://localhost:8080/api" ../../shutdown_from_any_state.sh|}
  in
  write shutdown_file shutdown_cmd;
  let _ = Sys.command("chmod u+x " ^ shutdown_file) in

  let expected_body =
    match response_body with
    | None -> ""
    | Some (_typ, example) ->
      let escaped = unquote @@ Ezjsonm.value_to_string example in
      Str.global_replace (Str.regexp_string {|\n|}) "\n" escaped
  in
  write (outdir ^ "/body.expected") expected_body;

  let reply =
   let status = Cohttp.Code.(reason_phrase_of_code (int_of_string response_code)) in
   Printf.sprintf "HTTP/1.1 %s %s" response_code status
  in
  write (outdir ^ "/headers.expected") reply;

  if List.mem path skip_body_endpoints then
    let _ = Sys.command("touch " ^ outdir ^ "/body.skip") in
    ();

  ()

let print_method path (meth, req) =
  if List.mem meth allowed_methods (* skips descriptions *)
  then begin 
    let reqs = make_req_data req meth in
    let responses = make_resp_data req in
    let success_response = List.find (fun (c, _) -> String.get c 0 = '2') responses in
    List.iter (tests_for_states meth path (cmd path meth) success_response) reqs;
  end

let print_methods (path, methods) =
  Printf.printf "generating tests for %s.." path;
  if not (List.mem path skip_endpoints)
  then begin
    List.iter (print_method path) methods;
    Printf.printf "done\n"
  end
  else Printf.printf "(skipped endpoint)\n"

let rec subpaths (path, meta) =
  let (endpoints, _) = get_endpoints meta in
  if endpoints = [] 
  then [ (path, Ezjsonm.get_dict meta) ]
  else List.concat_map (fun (subpath, m) -> subpaths (path ^ subpath, m)) endpoints

let example = CCIO.with_in raml CCIO.read_all
  |> Yaml.of_string
  |> Stdlib.Result.get_ok

(* all paths, start from empty root *)
let () = 
  let paths = subpaths ("", example) in
  (*let paths = [List.nth paths 1] in*)
  List.iter print_methods paths;
