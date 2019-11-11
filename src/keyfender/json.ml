(* request data *)

type subject_req = { 
    countryName : string ;
    stateOrProvinceName : string ;
    localityName : string ;
    organizationName : string ;
    organizationalUnitName : string ;
    commonName : string ;
    emailAddress : string ;
} [@@deriving yojson]

(* TODO *)
let nonempty_new ~name s =
  if String.length s == 0
  then Error (Printf.sprintf "JSON field %s is empty." name)
  else Ok ()
 
let decode parse data =
  let open Rresult.R.Infix in
  (try Ok (Yojson.Safe.from_string data)
   with Yojson.Json_error msg -> Error (Printf.sprintf "Invalid JSON: %s." msg)) >>= fun json ->
  Rresult.R.reword_error (fun m -> Printf.sprintf "Invalid data for JSON schema: %s." m) 
    @@ parse json

(* TODO remove these *)
let nonempty s =
  if String.length s == 0
  then Error `Bad_request
  else Ok ()
 
let try_parse content =
  try
    Ok (Yojson.Safe.from_string content)
  with _ -> Error `Bad_request

let parse json_parser json =
  Rresult.R.reword_error (fun _ -> `Bad_request) @@ json_parser json
