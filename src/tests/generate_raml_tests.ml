(*
  To call:
    dune exec ./generate_raml_tests.exe
*)

(*
  Data structure:

type raml = { header ..;
  types ..;
  endpoints ..}

*)

let host = "localhost"
let port = "8080"
let raml = "../../docs/nitrohsm-api.raml"
let allowed_methods = ["get" ; "put" ; "post"]
let allowed_request_types = [ "application/json" ; "application/x-pem-file" ; "application/octet-stream" ]

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

let make_req_data req = function
  | "get" -> [""]
  | "post" 
  | "put" -> 
    begin
      let mediatypes = Ezjsonm.get_dict @@ Ezjsonm.find req ["body"] in
      let f (mediatype, req') =
        if not @@ List.mem mediatype allowed_request_types
        then Printf.printf "Request type %s found but not supported, raml malformed?" mediatype;
        "--data " ^ escape @@ Ezjsonm.(value_to_string @@ find req' ["example"])
      in
      List.map f mediatypes
    end
  | m -> Printf.printf "method %s not allowed" m; [""]

let rec print_path (path, meta) =
  let (endpoints, _metadata) = get_endpoints meta in
  if endpoints <> [] 
  then List.iter (fun (subpath, m) -> print_path (path ^ subpath, m)) endpoints
  else begin 
    (*
    Printf.printf "Path is %s\n" path;
    Printf.printf "As YAML:\n%s\n=======\n" (Yaml.to_string_exn meta);
    *)
    let methods = Ezjsonm.get_dict meta in
    let p (meth, req) =
      if List.mem meth allowed_methods (* skips descriptions *)
      then begin 
        let cmd = Printf.sprintf "curl http://%s:%s%s -X %s" host port path (String.uppercase_ascii meth) in
        List.iter (Printf.printf "%s %s \n\n" cmd) (make_req_data req meth);
      end
    in
    List.iter p methods
  end

let example = CCIO.with_in raml CCIO.read_all
  |> Yaml.of_string
  |> Stdlib.Result.get_ok

(*let () = Sexplib.Sexp.pp_hum Format.std_formatter @@ Yaml.sexp_of_value example*)
let (endpoints, metadata) = get_endpoints example 

let types = List.assoc "types" metadata

(*
let () = List.iter print_path [List.nth endpoints 10]
*)

(* all paths, start from empty root *)
let () = print_path ("", example)
