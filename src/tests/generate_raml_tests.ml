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
let port = "2000"
let raml = "../../docs/nitrohsm-api.raml"
let allowed_methods = ["get" ; "put" ; "post"]
let allowed_request_types = [ "application/json" ; "application/x-pem-file" ]

let get_endpoints meta = 
  Ezjsonm.get_dict meta |> List.partition (fun (key, _v) -> CCString.prefix ~pre:"/" key)

let get_meth meth meta = (* e.g. met is "get", "put", "post" *)
  Ezjsonm.get_dict meta |> List.partition (fun (key, _v) -> key = meth)

(* TODO for each mediatype, set a header, get the example request *)
let make_req_data req = function
  | "get" -> ""
  | "post" 
  | "put" -> 
    begin
      let body = Ezjsonm.find req ["body"] in
      let mediatypes = Ezjsonm.get_dict @@ Ezjsonm.find req ["body"] in
      let f (mediatype, _req) =
        if not @@ List.mem mediatype allowed_request_types
        then Printf.printf "Request type %s found but not supported, raml malformed?" mediatype
      in
      let _s = List.iter f mediatypes in
      Ezjsonm.(value_to_string body)
    end
  | m -> Printf.printf "method %s not allowed" m; ""

let rec print_path (path, meta) =
  let (endpoints, _metadata) = get_endpoints meta in
  if endpoints <> [] 
  then List.iter (fun (subpath, m) -> print_path (path ^ subpath, m)) endpoints
  else begin 
    Printf.printf "Path is %s\n" path;
    Printf.printf "As YAML:\n%s\n=======\n" (Yaml.to_string_exn meta);
    let methods = Ezjsonm.get_dict meta in
    let p (meth, req) =
      if List.mem meth allowed_methods (* skips descriptions *)
      then begin 
        let cmd = Printf.sprintf "curl http://%s:%s%s -X %s" host port path (String.uppercase_ascii meth) in
        Printf.printf "%s %s \n\n" cmd (make_req_data req meth);
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


let () = List.iter print_path [List.nth endpoints 10]


(* all paths, start from empty root *)
(*
let () = print_path ("", example)
*)
