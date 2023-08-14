(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

(*
  To call:
    dune exec ./generate_api_tests.exe
*)

let host = "localhost"
let port = "8443"
let prefix = "api/v1"
let cmd path meth = Printf.sprintf "curl --insecure https://%s:%s/%s%s -X %s " host port prefix path (String.uppercase_ascii meth)
let api_file = "../../docs/nethsm-api.yaml"
let allowed_methods = ["get" ; "put" ; "post"]
let all_states = ["Unprovisioned"; "Locked"; "Operational"]
let skip_endpoints = ["/system/update"; "/system/cancel-update"; "/system/commit-update"; "/system/backup"; "/system/restore"; "/keys/{KeyID}/cert"; "/config/tls/cert.pem"]
let skip_body_endpoints = ["/random"; "/config/tls/csr.pem"; "/config/tls/cert.pem"; "/config/tls/public.pem"; "/health/state"; "/metrics"; "/config/time"; "/system/info"; "/keys/{KeyID}"; "/keys"; "/users/{UserID}"; "/users"]

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

let api = CCIO.with_in api_file CCIO.read_all
  |> Yaml.of_string
  |> Stdlib.Result.get_ok

(* refs are in the form #/components/schemas/PemCert, so basically a path *)
let json_ref_resolve ref =
  assert (ref.[0] = '#' && ref.[1] = '/');
  let path = List.tl (String.split_on_char '/' ref) in
  Ezjsonm.find api path

let example_of_type json =
  match Ezjsonm.find_opt json ["schema"; "$ref"] with
  | Some (`String ref) ->
    begin
    let type_json = json_ref_resolve ref in
    try Ezjsonm.find type_json ["example"] with
    | Not_found -> failwith ("Couldn't find example for type " ^ ref)
    end
  | _ -> failwith "Inline type definitions not allowed"

let write file content =
  let oc = open_out file in
  Printf.fprintf oc "%s" content;
  close_out oc

let write_cmd file content =
  let oc = open_out file in
  Printf.fprintf oc "#!/bin/sh\n";
  Printf.fprintf oc "%s" content;
  close_out oc;
  ignore (Sys.command("chmod u+x " ^ file))

let path_to_filename state meth path =
  let path = Str.global_replace (Str.regexp_string "/") "_" path in
  let path = Str.global_replace (Str.regexp_string ".") "_" path in
  let path = Str.global_replace (Str.regexp_string "{") "" path in
  let path = Str.global_replace (Str.regexp_string "}") "" path in
  let path = String.sub path 1 (String.length path - 1) in (* remove leading / *)
  let outdir = Printf.sprintf "generated/%s_%s_%s" state path meth in
  let outfile = "cmd.sh" in
  (outdir, outfile)

let auth_header (user, pass) =
  let base64 = Base64.encode_string (user ^ ":" ^ pass) in
  " -H \"Authorization: Basic " ^ base64 ^ "\" "

let passphrase = function
  | "Administrator" -> ("admin", "Administrator")
  | "Operator" -> ("operator", "OperatorOperator")
  | "Metrics" -> ("metrics", "MetricsMetrics")
  | "Backup" -> ("backup", "BackupBackup")
  | s ->
    Printf.printf "passphrase for unsupported role %s requested\n" s;
    assert false

let prepare_setup _meth _path _cmd (state, role, _req) =
  (* 1. prepare server state *)
  let provision = "NETHSM_URL=\"https://localhost:8443/api\" ../../provision_test.sh"
  in
  let lock =
    let header = auth_header (passphrase "Administrator") in
    cmd "/lock" "POST" ^ header
  in
  let prepare_state = match state with
  | "Unprovisioned" -> ""
  | "Locked" -> provision ^ "\n" ^ lock
  | "Operational" -> provision
  | s ->
    Printf.printf "Error: Unknown prerequisite state in OpenAPI spec: %s\n" s;
    assert false
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
  Ezjsonm.get_strings @@ Ezjsonm.find req ["x-annotation-state"]

let req_roles req =
  Ezjsonm.get_strings @@ Ezjsonm.find req ["x-annotation-role"]

let subst_prefix = "x-test-value-"

let subst_prefix_len = String.length subst_prefix

let req_substs req =
  Ezjsonm.get_dict req
  |> List.filter_map (fun (k, v) -> 
    if Astring.String.is_prefix ~affix:subst_prefix k then
      let match' = 
        String.sub k subst_prefix_len (String.length k - subst_prefix_len) 
      in
      match v with
      | `String s -> Some (match',  s)
      |_ -> None
    else None)

let make_post_data req =
  match Ezjsonm.get_dict @@ Ezjsonm.find req ["requestBody"; "content"] with
  | exception Not_found -> [""]
  | mediatypes ->
    let f (mediatype, json) =
      let header = "-H \"Content-Type: " ^ mediatype ^ "\" " in
      let example = example_of_type json in
      header ^ "--data " ^ escape @@ Ezjsonm.value_to_string example
    in
    let mediatypes = List.rev mediatypes in
    List.map f mediatypes

(* Extracted metadata a specific endpoint *)
type req_data = {
  states: string list; (* HSM accepted states *)
  role: string option; (* role to use *)
  auth_header: string; (* command to add authentication headers for that role *)
  substs: (string * string) list; (* substitutions to use *)
}

type test = {
  test_res: [`Pos | `Neg];
  state: string;
  role: string option;
  auth_header: string;
  substs: (string * string) list;
}

let make_req_data req meth =
  let substs = req_substs req in
  let roles = req_roles req in
  let role, auth_header = match roles with
  | ["Public"] -> None, ""
  | "Administrator" :: _ -> Some "Administrator", auth_header (passphrase "Administrator")
  | "Operator" :: _ -> Some "Operator", auth_header (passphrase "Operator")
  | [ "Metrics" ] -> Some "Metrics", auth_header (passphrase "Metrics")
  | [ "Backup" ] -> Some "Backup", auth_header (passphrase "Backup")
  | r ->
    Printf.printf "can't handle roles (make_req_data): %s\n"
      (String.concat "; " r);
    assert false
  in
  let states = req_states req in
  let states_and_data_for_mediatype = match meth with
  | "get" -> [{states; role; auth_header; substs}]
  | "post"
  | "put" -> List.map (fun d -> {states; role; auth_header = auth_header ^ d; substs}) (make_post_data req)
  | m -> Printf.printf "Error: Method %s not allowed\n" m; assert false
  in
  let unroll_states {states; role; auth_header; substs} =
    let other_states = List.filter (fun x -> not @@ List.mem x states) all_states in
    List.append
      (List.map (fun s -> {test_res = `Neg; state = s; role; auth_header; substs}) other_states)
      (List.map (fun s -> {test_res = `Pos; state = s; role; auth_header; substs}) states)
  in
  List.concat_map unroll_states states_and_data_for_mediatype

let make_resp_data raml_meth =
  let response_codes = Ezjsonm.get_dict @@ Ezjsonm.find raml_meth ["responses"] in
  let get_example (code, meta) = match code with
  | "200" ->
    begin
      match Ezjsonm.get_dict @@ Ezjsonm.find meta ["content"] with
      | exception Not_found -> [("200", None)]
      | mediatypes ->
        List.map (fun (typ, yml) ->
          let example = example_of_type yml in
          ("200", Some (typ, example))) mediatypes
    end
  | somecode  -> [(somecode, None)];
  in
  let codes_and_examples = List.concat_map get_example response_codes in
  codes_and_examples

let has_match cmd match' =
  let regex = Str.regexp_string ("{" ^ match' ^ "}") in
  Str.string_match regex cmd 0 

let match_replace_by cmd (match', replace) =
  let regex = Str.regexp_string ("{" ^ match' ^ "}") in
  Str.global_replace regex replace cmd

let check_cmd_is_ready cmd =
  let regex = Str.regexp (".*{\\(.*\\)}.*") in
  let match' = Str.string_match regex cmd 0 in
  if match' then
    failwith 
      ("Request path has an unsubstituted field: {"^ (Str.matched_group 1 cmd)^"}")

let tests_for_states meth path cmd (response_code, response_body) 
                            {test_res; state; role; auth_header = req; substs} =
  let (outdir, test_file) = path_to_filename state meth path in
  ignore (Sys.command("mkdir -p " ^ outdir));

  let cmd' = List.fold_left match_replace_by cmd substs in
  check_cmd_is_ready cmd' |> ignore;

  (* for negative test cases (state tests), add an error code prefix *)
  let resp_code = if test_res = `Neg then "412_" else "" in
  let test_cmd = Printf.sprintf "%s %s  -D %sheaders.out -o body.out \n\n" cmd' req resp_code in

  if test_res = `Pos then
  begin
    (* tests for wrong IDs (in {KeyID}, {UserID}, {Tag}) *)
    List.iter (fun (match', _) -> 
      if has_match cmd match' then
        begin
          let wrong_key = match_replace_by cmd (match', "bogus") in
          let wrong_key_cmd = Printf.sprintf "%s %s  -D 404_wrong_%s_headers.out -o /dev/null \n\n" wrong_key req match' in
          write_cmd (outdir ^ "/404_wrong_" ^ match' ^ "_cmd.sh") wrong_key_cmd
        end 
      ) substs;

    (* if request contains --data json, prepare a wrong example *)
    let args = Str.split (Str.regexp "--data") req in
    if List.length args == 2 then
      begin
        (* prepare wrong json *)
        let headers = List.hd args in
        let wrong_json = "{}}}" in
        let wrong_req = Printf.sprintf " %s--data %s " headers (escape wrong_json) in
        let wrong_json_cmd = Printf.sprintf "%s %s  -D 400_wrong_json_headers.out -o /dev/null \n\n" cmd' wrong_req in
        write_cmd (outdir ^ "/400_wrong_json_cmd.sh") wrong_json_cmd;
      end;

    (* prepare wrong auth header if endpoint requires authentication *)
    begin match role with
      | None -> ()
      | Some r ->
        let current_auth = auth_header (passphrase r) in
        let someone_else = match r with
          | "Administrator" -> auth_header (passphrase "Backup")
          | "Operator" -> auth_header (passphrase "Metrics")
          | "Metrics" -> auth_header (passphrase "Backup")
          | "Backup" -> auth_header (passphrase "Metrics")
          | r ->
            Printf.printf "unknown role requested (invalid auth header) %s\n" r;
            assert false
        in
        let wrong_auth = Str.global_replace (Str.regexp_string current_auth) someone_else req in
        if req <> wrong_auth then
          begin
            let wrong_auth_cmd = Printf.sprintf "%s %s  -D 403_wrong_auth_headers.out -o /dev/null \n\n" cmd' wrong_auth in
            write_cmd (outdir ^ "/403_wrong_auth_cmd.sh") wrong_auth_cmd;
          end;
        let no_auth = Str.global_replace (Str.regexp_string current_auth) "" req in
        if req <> no_auth then
          begin
            let no_auth_cmd = Printf.sprintf "%s %s  -D 401_no_auth_headers.out -o /dev/null \n\n" cmd' no_auth in
            write_cmd (outdir ^ "/401_no_auth_cmd.sh") no_auth_cmd;
          end;
    end;

    let other_method = "PATCH" in
    let wrong_meth = Str.global_replace (Str.regexp_string {|GET|}) other_method cmd' in
    let wrong_meth' = Str.global_replace (Str.regexp_string {|PUT|}) other_method wrong_meth in
    let wrong_meth'' = Str.global_replace (Str.regexp_string {|POST|}) other_method wrong_meth' in
    if cmd' <> wrong_meth'' then
      begin
        let wrong_meth_cmd = Printf.sprintf "%s %s  -D 501_wrong_meth_headers.out -o /dev/null \n\n" wrong_meth'' req in
        write_cmd (outdir ^ "/501_wrong_meth_cmd.sh") wrong_meth_cmd;
      end;
    end; (* end if test_res = `Pos *)

  write_cmd (outdir ^ "/" ^ resp_code ^ test_file) test_cmd;

  (* prepare required state and role *)
  let setup_file = outdir ^ "/setup.sh" in
  let setup_cmd = prepare_setup meth path cmd (state, role, req) in
  write_cmd setup_file setup_cmd;

  let shutdown_file = outdir ^ "/shutdown.sh" in
  let shutdown_cmd =
    if path = "/system/shutdown" then "exit 1" else
    {|NETHSM_URL="http://localhost:8080/api" ../../shutdown_from_any_state.sh|}
  in
  write_cmd shutdown_file shutdown_cmd;

  if test_res = `Pos then
  begin
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
      ignore (Sys.command("touch " ^ outdir ^ "/body.skip"))
  end

let print_method path (meth, req) =
  if 
    List.mem meth allowed_methods (* skips descriptions *)
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

let endpoints api =
  let endpoints = Ezjsonm.(find api [ "paths" ]  |> get_dict)in
  List.map (fun (path, m) -> (path, Ezjsonm.get_dict m)) endpoints

let () =
  let paths = endpoints api in
  (*let paths = [List.nth paths 1] in*)
  List.iter print_methods paths;
