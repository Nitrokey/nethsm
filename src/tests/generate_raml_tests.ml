(*
  To call:
    dune exec ./generate_raml_tests.exe
*)

(* TODO
- UserID: braucht ein beispiel (im setup)
- header vergleichen (headers.expected erzeugen)
  - zuerst die status zeile (HTTP code)
- curl in setup.sh failed --> exit code? -- curl exit codes beruecksichtigen
- auffaechern von rollen (Operator, Administrator)
- unterschiedliche content types -> setzen der header
- test code generierung: aktuell nur success, auch failures programmatisch erzeugen
  - fuer nicht authorisierte rollen sollten endpunkte nicht verfuegbar sein
- minimiere skip_endpoints

--> evaluate test coverage
- standalone tests vs vermeidung von resets

DONE
- exclude spezial-endpoints (zB /random)
- keyID setup command
- endpunkte durchtesten (mit abgeschaltetem header vergleich)
*)

(*
cat 2020-09-01
1) shutdown in generated tests
multiple cases:
- operational
 --> script verwenden, wenn der user (admin) das gleiche passwort hat
- locked
 --> script verwenden, dass zuerst unlock macht und dann shutdown
- unprovisioned
 --> script verwenden, dass zuerst provisioned und dann shutdown

unprovisioned_provisioned -> im RAML sind admin + unlock passphrase anders ~> RAML an scripte anpassen

--> script anpassen, um zu schauen in welchem state wir sind, und je nachdem handeln

2) measure code coverage of generated tests (Makefile)
--> yes, generate_raml_tests.exe ausfuehren und dependencies
< bisect-ppx-report fehlt noch

3) use common-functions.sh in generate_raml_tests.exe for command.sh, use provision_test.sh for setup.sh
setup could use an argument "desired state", and execute the HTTP requests required to get into that state
--> one script, not per-test

4) gitlab pages code coverage
5) improve code coverage of unit tests
*)

let host = "localhost"
let port = "8080"
let prefix = "api/v1"
let keyid = "mykey"
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
let skip_endpoints = ["/system/update"; "/system/cancel-update"; "/system/commit-update"; "/system/backup"; "/system/restore"; "/keys/{KeyID}/cert"]
let skip_body_endpoints = ["/random"; "/config/tls/csr.pem"; "/config/tls/cert.pem"; "/config/tls/public.pem"; "/health/state"; "/metrics" ]

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

let passphrase = function
  | "Administrator" -> ("admin", "Administrator")
  | "Operator" -> ("operator", "This is my operator passphrase")
  | "Metrics" -> ("metrics", "This is my metrics passphrase")
  | "Backup" -> ("backup", "This is my backup passphrase")
  | _ -> assert false

let prepare_setup _meth path _cmd (state, role, _req) =
  (* 1. prepare server state *)
  let provision = cmd "/provision" "PUT" ^ "-H \"Content-Type: application/json\" --data @../../provision.json"

  (* TODO NITROHSM_URL="http://localhost:8080/api" ../../provision_test.sh || (kill $PID ; exit 5) *)
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
    | Some "Operator" -> add_user "Operator"
    | Some "Metrics" -> add_user "Metrics"
    | Some "Backup" -> add_user "Backup"
    | _ -> ""
  in
  let prepare_data =
    let keyid_path = "/keys/{KeyID}" in
    if String.length path >= String.length keyid_path && String.sub path 0 (String.length keyid_path) = keyid_path
    then cmd ("/keys/" ^ keyid) "PUT" ^ (auth_header (passphrase "Administrator")) ^ "-H \"Content-Type: application/json\" --data @../../key.json"
    else ""
  in
  prepare_state ^ "\n" ^ prepare_role ^ "\n" ^ prepare_data

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

let tests_for_states meth path cmd responses (state, role, req) =
  let (outdir, test_file) = path_to_filename state meth path in
  let _ = Sys.command("mkdir -p " ^ outdir) in

  let cmd' =
    Str.global_replace (Str.regexp_string "{KeyID}") keyid cmd
  in
  let test_cmd = Printf.sprintf "%s %s  -D headers.out -o body.out \n\n" cmd' req in
  write test_file test_cmd;
  let _ = Sys.command("chmod u+x " ^ test_file) in

  (* prepare required state and role *)
  let setup_file = outdir ^ "/setup.sh" in
  let setup_cmd = prepare_setup meth path cmd (state, role, req) in
  write setup_file setup_cmd;
  let _ = Sys.command("chmod u+x " ^ setup_file) in

  let expected_body =
    match List.find_opt (fun (c, _) -> c = "200") responses with
    | None -> ""
    | Some (_, Some (_typ, example)) ->
      let escaped = unquote @@ Ezjsonm.value_to_string example in
      Str.global_replace (Str.regexp_string {|\n|}) "\n" escaped
    | Some (_, _) -> ""
  in
  write (outdir ^ "/body.expected") expected_body;

  if List.mem path skip_body_endpoints then
    let _ = Sys.command("touch " ^ outdir ^ "/body.skip") in
    ();

  let _ = Sys.command("touch " ^ outdir ^ "/headers.expected") in
  ()

let print_method path (meth, req) =
  if List.mem meth allowed_methods (* skips descriptions *)
  then begin 
    let reqs = make_req_data req meth in
    let responses = make_resp_data req in
    List.iter (tests_for_states meth path (cmd path meth) responses) reqs;
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
