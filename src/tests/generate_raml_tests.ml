(*
  To call:
    dune exec ./generate_raml_tests.exe
*)

let host = "localhost"
let port = "8080"
let prefix = "api/v1"
let raml = "../../docs/nitrohsm-api.raml"
let allowed_methods = ["get" ; "put" ; "post"]
let allowed_request_types = [
  "application/json" ;
  "application/x-pem-file" ;
  "application/octet-stream" ;
  "application/x-x509-ca-cert" ;
  "application/pgp-keys";
]
(* TODO what's the diff beween the last two? *)
let all_states = ["Unprovisioned"; "Locked"; "Unlocked"; "Operational"]

let escape s =
  let s' = Str.global_replace (Str.regexp_string "\"") "\\\"" s in
  let l = String.length s' in
  (* second part triggers Fatal error: exception (Invalid_argument "String.sub / Bytes.sub") *)
  if l > 4 && String.sub s' 0 2 = "\\\"" (*&& String.sub s' (l-4) l = "\\\""*)
  (* if its a string, remove escapes *)
  then begin
    let s' = String.sub s' 2 (l-4) in
    "\"" ^ s' ^ "\""
  end
  else
    "\"" ^ s' ^ "\""
  ;;

let get_endpoints meta = 
  Ezjsonm.get_dict meta |> List.partition (fun (key, _v) -> CCString.prefix ~pre:"/" key)

let get_meth meth meta = (* e.g. met is "get", "put", "post" *)
  Ezjsonm.get_dict meta |> List.partition (fun (key, _v) -> key = meth)

let write file content =
  let oc = open_out file in
  Printf.fprintf oc "%s\n" content;
  close_out oc;
  ()

let make_post_data req = 
  let states = Ezjsonm.get_strings @@ Ezjsonm.find req ["state"] in
  let mediatypes = Ezjsonm.get_dict @@ Ezjsonm.find req ["body"] in
  let f (mediatype, req') =
    if not @@ List.mem mediatype allowed_request_types
    then Printf.printf "Request type %s found but not supported, raml malformed?" mediatype;
    let header = "-H \"Content-Type: " ^ mediatype ^ "\" " in
    states, header ^ "--data " ^ escape @@ Ezjsonm.(value_to_string @@ find req' ["example"])
  in
  List.map f mediatypes

let make_req_data req meth =
  let states_and_data_for_mediatype = match meth with
  | "get" -> [(all_states, "")]
  | "post" 
  | "put" -> make_post_data req
  | m -> Printf.printf "Error: Method %s not allowed" m; [(all_states,"")]
  in
  let unroll_states (states, data) =
    List.map (fun s -> (s, data)) states
  in
  List.concat_map unroll_states states_and_data_for_mediatype

let path_to_filename meth path =
  let path = Str.global_replace (Str.regexp_string "/") "_" path in
  let path = Str.global_replace (Str.regexp_string ".") "_" path in
  let path = Str.global_replace (Str.regexp_string "{") "_" path in
  let path = Str.global_replace (Str.regexp_string "}") "_" path in
  let path = String.sub path 1 (String.length path -1) in (* remove leading / *)
  let outdir = Printf.sprintf "generated/%s_%s" path meth in
  let outfile = Printf.sprintf "%s/command.sh" outdir in
  (outdir, outfile)

let prepare_setup _meth _path _cmd (prereq_state, _req) =
  (* 1. prepare server state *)
  let provision = "curl -X PUT http://localhost:8080/api/v1/provision -H \"Content-Type: application/json\" -v --data @../../../keyfender/test/provision.json" in
  let unlock = "do the unlock" in
  let prepare_state = match prereq_state with
  | "Unprovisioned" -> "";
  | "Locked" -> provision
  | "Operational"
  | "Unlocked" -> provision ^ "\n" ^ unlock
  | s -> Printf.printf "Error: Unknown prerequisite state in raml: %s\n" s; ""
  in
  (* 2. prepare role *)
  let prepare_role = "" in
  prepare_state ^ "\n" ^ prepare_role

let tests_for_states meth path cmd (prereq_state, req) =
  let (outdir, test_file) = path_to_filename meth path in
  let _ = Sys.command("mkdir -p " ^ outdir) in

  let test_cmd = Printf.sprintf "%s %s  -D headers.out -o body.out \n\n" cmd req in
  write test_file test_cmd;
  let _ = Sys.command("chmod u+x " ^ test_file) in

  (* Which state can the server be in before the test? *)
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
    let cmd = Printf.sprintf "curl http://%s:%s/%s%s -X %s" host port prefix path (String.uppercase_ascii meth) in
    List.iter (tests_for_states meth path cmd) reqs;
  end

let print_methods (path, methods) =
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
  List.iter (fun (a, _b) -> Printf.printf "%s\n" a ) paths;
  List.iter print_methods paths;
