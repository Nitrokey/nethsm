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
