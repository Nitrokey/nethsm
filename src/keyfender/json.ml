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

let nonempty ~name s =
  if String.length s == 0
  then Error (Printf.sprintf "JSON field %s is empty." name)
  else Ok ()

let decode parse data =
  let open Rresult.R.Infix in
  (try Ok (Yojson.Safe.from_string data)
   with Yojson.Json_error msg -> Error (Printf.sprintf "Invalid JSON: %s." msg)) >>= fun json ->
  Rresult.R.reword_error (fun m -> Printf.sprintf "Invalid data for JSON schema: %s." m)
    @@ parse json

let decode_time s =
  let open Rresult.R.Infix in
  (* since ~sub:true is _not_ passed to of_rfc3339,
     no trailing bytes (third return value will be String.length b.time) *)
  Rresult.R.reword_error (function `RFC3339 ((start, stop), e) ->
    Fmt.strf "Failed to decode timestamp: %a at position %d to %d." Ptime.pp_rfc3339_error e start stop)
    (Ptime.of_rfc3339 s) >>= fun (time, off, _) ->
  (* according to spec, we accept only UTC timestamps! *)
  (match off with None | Some 0 -> Ok () | _ -> Error "Error while parsing timestamp. Offset must be 0.") >>| fun () ->
  time

 (* TODO json object or string? *)
type passphrase_req = { passphrase : string } [@@deriving yojson]

let decode_passphrase json =
  let open Rresult.R.Infix in
  decode passphrase_req_of_yojson json >>= fun passphrase ->
  nonempty ~name:"passphrase" passphrase.passphrase >>| fun () ->
  passphrase.passphrase
