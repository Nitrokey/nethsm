(*
  To call:
    dune exec ./generate_raml_tests.exe
*)

let host = "localhost"
let port = "8080"
let prefix = "api/v1"
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

let escape s =
  let s' = Str.global_replace (Str.regexp_string "\"") "\\\"" s in
  let l = String.length s' in
  let s'' =
    if l > 4 && String.sub s' 0 2 = {|\"|} && String.sub s' (l-2) 2 = {|\"|}
    (* if its a JSON string, remove escapes *)
    then String.sub s' 2 (l-4)
    else s'
  in
  "\"" ^ s'' ^ "\""

let get_endpoints meta = 
  Ezjsonm.get_dict meta |> List.partition (fun (key, _v) -> CCString.prefix ~pre:"/" key)

let get_meth meth meta = (* e.g. met is "get", "put", "post" *)
  Ezjsonm.get_dict meta |> List.partition (fun (key, _v) -> key = meth)

let write file content =
  let oc = open_out file in
  Printf.fprintf oc "%s\n" content;
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

let auth_header user pass =
  let base64 = Base64.encode_string (user ^ ":" ^ pass) in
  " -H \"Authorization: Basic " ^ base64 ^ "\" "

let prepare_setup _meth _path _cmd (prereq_state, _req) =
  (* 1. prepare server state *)
  let provision = cmd "provision" "PUT" ^ "-H \"Content-Type: application/json\" --data @../../provision.json"
  in
  let lock =
    let header = auth_header "admin" "Administrator" in
    cmd "lock" "POST" ^ header
  in
  let prepare_state = match prereq_state with
  | "Unprovisioned" -> ""
  | "Locked" -> provision ^ "\n" ^ lock
  | "Operational" -> provision
  | s -> Printf.printf "Error: Unknown prerequisite state in raml: %s\n" s; ""
  in
  (* 2. prepare role *)
  let prepare_role = "" in
  prepare_state ^ "\n" ^ prepare_role

let req_states req =
  Ezjsonm.get_strings @@ Ezjsonm.find req ["state"]

let req_roles req =
  Ezjsonm.get_strings @@ Ezjsonm.find req ["role"]

let make_post_data req = 
  let states = req_states req in
  let roles = req_roles req in
  let mediatypes = Ezjsonm.get_dict @@ Ezjsonm.find req ["body"] in
  let f (mediatype, req') =
    if not @@ List.mem mediatype allowed_request_types
    then Printf.printf "Request type %s found but not supported, raml malformed?" mediatype;
    let header = "-H \"Content-Type: " ^ mediatype ^ "\" " in
    states, roles, header ^ "--data " ^ escape @@ Ezjsonm.(value_to_string @@ find req' ["example"])
  in
  List.map f mediatypes

let make_req_data req meth =
  let roles = req_roles req in
  let auth_header = match roles with
  | ["Public"] -> ""
  | "Administrator" :: _ -> auth_header "admin" "Administrator"
  | "Operator" :: _ -> auth_header "operator" "This is my operator passphrase"
  | [ "Metrics" ] -> auth_header "metrics" "This is my metrics passphrase"
  | [ "Backup" ] -> auth_header "backup" "This is my backup passphrase"
  | x :: _ -> Printf.printf "unknown role %s" x; "" (*assert false*)
  | _ -> assert false
  in
  let states_and_data_for_mediatype = match meth with
  | "get" -> [(req_states req, req_roles req, auth_header)]
  | "post" 
  | "put" -> List.map (fun (s, r, d) -> (s, r, auth_header ^ d)) (make_post_data req)
  | m -> Printf.printf "Error: Method %s not allowed" m; [(req_states req, req_roles req, auth_header)]
  in
  (* TODO unroll roles? *)
  let unroll_states (states, _roles, data) =
    List.map (fun s -> (s, data)) states
  in
  List.concat_map unroll_states states_and_data_for_mediatype

let make_resp_data raml =
  let response_codes = Ezjsonm.get_dict @@ Ezjsonm.find raml ["responses"] in
  let get_example (code, meta) = match code with
  | "200"     -> 
    begin (* TODO do we need loop? should be just JSON *)
      let mediatypes = Ezjsonm.get_dict @@ Ezjsonm.find meta ["body"] in
      List.map (fun example -> ("200", Some example)) mediatypes
    end
  | somecode  -> [(somecode, None)]; 
  in
  let codes_and_examples = List.concat_map get_example response_codes in
  codes_and_examples

let tests_for_states meth path cmd (prereq_state, req) =
  let (outdir, test_file) = path_to_filename prereq_state meth path in
  let _ = Sys.command("mkdir -p " ^ outdir) in

  let test_cmd = Printf.sprintf "%s %s  -D headers.out -o body.out \n\n" cmd req in
  write test_file test_cmd;
  let _ = Sys.command("chmod u+x " ^ test_file) in

  (* prepare required state and role *)
  let setup_file = outdir ^ "/setup.sh" in
  let setup_cmd = prepare_setup meth path cmd (prereq_state, req) in
  write setup_file setup_cmd;
  let _ = Sys.command("chmod u+x " ^ setup_file) in

  let _ = Sys.command("touch " ^ outdir ^ "/body.expected") in
  let _ = Sys.command("touch " ^ outdir ^ "/headers.expected") in
  ()

let print_method path (meth, req) =
  if List.mem meth allowed_methods (* skips descriptions *)
  then begin 
    let reqs = make_req_data req meth in
    let _responses = make_resp_data req in
    List.iter (tests_for_states meth path (cmd path meth)) reqs;
  end

let print_methods (path, methods) =
  Printf.printf "generating tests for %s\n" path;
  List.iter (print_method path) methods

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
