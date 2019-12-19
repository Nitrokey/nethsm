open Rresult.R.Infix

let nonempty ~name s =
  if String.length s == 0
  then Error (Printf.sprintf "JSON field %s is empty." name)
  else Ok ()

let to_ocaml parse json =
  Rresult.R.reword_error
    (fun m -> Printf.sprintf "Invalid data for JSON schema: %s." m)
    @@ parse json

let decode parse data =
  (try Ok (Yojson.Safe.from_string data)
   with Yojson.Json_error msg -> Error (Printf.sprintf "Invalid JSON: %s." msg)) >>= fun json ->
  to_ocaml parse json

type subject_req = {
    commonName : string ;
    countryName : string ;
    localityName : string ;
    stateOrProvinceName : string ;
    organizationName : string ;
    organizationalUnitName : string ;
    emailAddress : string ;
} [@@deriving yojson]

let decode_subject json =
  decode subject_req_of_yojson json >>= fun subject ->
  nonempty ~name:"commonName" subject.commonName >>| fun () ->
  subject

let to_distinguished_name subject =
  let open X509.Distinguished_name in
  let res = Relative_distinguished_name.empty in
  let add = Relative_distinguished_name.add in
  let res = if subject.commonName <> ""
  then add (CN subject.commonName) res
  else res in
  let res = if subject.countryName <> ""
  then add (C subject.countryName) res
  else res in
  let res = if subject.localityName <> ""
  then add (L subject.localityName) res
  else res in
  let res = if subject.stateOrProvinceName <> ""
  then add (ST subject.stateOrProvinceName) res
  else res in
  let res = if subject.organizationName <> ""
  then add (O subject.organizationName) res
  else res in
  let res = if subject.organizationalUnitName <> ""
  then add (OU subject.organizationalUnitName) res
  else res in
  let res = if subject.emailAddress <> ""
  then add (Mail subject.emailAddress) res
  else res in
  [ res ]

let decode_time s =
  (* since ~sub:true is _not_ passed to of_rfc3339,
     no trailing bytes (third return value will be String.length b.time) *)
  Rresult.R.reword_error (function `RFC3339 ((start, stop), e) ->
    Fmt.strf "Failed to decode timestamp: %a at position %d to %d." Ptime.pp_rfc3339_error e start stop)
    (Ptime.of_rfc3339 s) >>= fun (time, off, _) ->
  (* according to spec, we accept only UTC timestamps! *)
  (match off with None | Some 0 -> Ok () | _ -> Error "Error while parsing timestamp. Offset must be 0.") >>| fun () ->
  time

type passphrase_req = { passphrase : string } [@@deriving yojson]

let decode_passphrase json =
  to_ocaml passphrase_req_of_yojson json >>= fun passphrase ->
  nonempty ~name:"passphrase" passphrase.passphrase >>| fun () ->
  passphrase.passphrase

type provision_req = { unlockPassphrase : string ; adminPassphrase : string ; time : string }[@@deriving yojson]

let decode_provision_req json =
  to_ocaml provision_req_of_yojson json >>= fun b ->
  nonempty ~name:"unlockPassphrase" b.unlockPassphrase >>= fun () ->
  nonempty ~name:"adminPassphrase" b.adminPassphrase >>= fun () ->
  decode_time b.time >>| fun time ->
  (b.unlockPassphrase, b.adminPassphrase, time)

type ip = Ipaddr.V4.t
let ip_to_yojson ip = `String (Ipaddr.V4.to_string ip)
let ip_of_yojson = function
  | `String ip_str ->
    Rresult.R.reword_error (function `Msg msg -> msg)
      (Ipaddr.V4.of_string ip_str)
  | _ -> Error "expected string for IP"

type network = {
  ipAddress : ip ;
  netmask : ip ;
  gateway : ip ;
}[@@deriving yojson]

let decode_network json =
  decode network_of_yojson json

let is_unattended_boot_to_yojson r =
  `Assoc [ ("status", `String (if r then "on" else "off")) ]

let is_unattended_boot_of_yojson content =
  let parse = function
  | `Assoc [ ("status", `String r) ] ->
    if r = "on"
    then Ok true
    else if r = "off"
    then Ok false
    else Error "Invalid status data, expected 'on' or 'off'."
  | _ -> Error "Invalid status data, expected a dictionary with one entry 'status'."
  in
  decode parse content

type time_req = { time : string } [@@deriving yojson]

type log_level = Logs.level
let log_level_to_string l = Logs.level_to_string (Some l)
let log_level_of_string str = match Logs.level_of_string str with
  | Ok Some lvl -> Ok lvl
  | Ok None -> Error "parse error for log level"
  | Error (`Msg msg) -> Error msg

let log_level_to_yojson l = `String (log_level_to_string l)

let log_level_of_yojson = function
  | `String l -> log_level_of_string l
  | _ -> Error "expected string as log level"

type log =
  { ipAddress : ip ; port : int ; logLevel : log_level } [@@deriving yojson]

type random_req = { length : int }[@@deriving yojson]

type rsa_key = { primeP : string ; primeQ : string ; publicExponent : string } [@@deriving yojson]

type purpose = Sign | Encrypt [@@deriving yojson]

let purpose_of_yojson = function
  | `String _ as s -> purpose_of_yojson (`List [s])
  | _ -> Error "Expected JSON string for purpose"

let purpose_to_yojson purpose =
  match purpose_to_yojson purpose with
  | `List [l] -> l
  | _ -> assert false

type publicKey = {
  purpose : purpose ;
  algorithm : string ;
  modulus : string ;
  publicExponent : string ;
  operations : int
} [@@deriving yojson]

type private_key_req = {
  purpose: purpose ;
  algorithm: string ;
  key : rsa_key
}[@@deriving yojson]

type decrypt_mode =
  | Raw
  | PKCS1
  | OAEP_MD5
  | OAEP_SHA1
  | OAEP_SHA224
  | OAEP_SHA256
  | OAEP_SHA384
  | OAEP_SHA512
[@@deriving yojson]

let decrypt_mode_of_yojson = function
  | `String _ as s -> decrypt_mode_of_yojson (`List [s])
  | _ -> Error "Expected JSON string for decrypt mode"

type decrypt_req = { mode : decrypt_mode ; encrypted : string }[@@deriving yojson]

type sign_mode =
  | PKCS1
  | PSS_MD5
  | PSS_SHA1
  | PSS_SHA224
  | PSS_SHA256
  | PSS_SHA384
  | PSS_SHA512
[@@deriving yojson]

let sign_mode_of_yojson = function
  | `String _ as s -> sign_mode_of_yojson (`List [s])
  | _ -> Error "Expected JSON string for sign mode"

type sign_req = { mode : sign_mode ; message : string }[@@deriving yojson]

type generate_key_req = { purpose: purpose ; algorithm : string ; length : int ; id : (string [@default ""]) } [@@deriving yojson]

let is_alphanum s = Astring.String.for_all (function 'a'..'z'|'A'..'Z'|'0'..'9' -> true | _ -> false) s

(* TODO Json.decode_generate_key_req, nonempty id, alphanum id, length 1 - 128 *)
let valid_id id =
  (if String.length id <= 128
    then Ok ()
    else Error "ID cannot be longer than 128 characters.") >>= fun () ->
   if is_alphanum id then Ok () else Error "ID may only contain alphanumeric characters."


let decode_generate_key_req s =
  decode generate_key_req_of_yojson s >>= fun r ->
  valid_id r.id >>| fun () ->
  r

type role = [ `Administrator | `Operator | `Metrics | `Backup ] [@@deriving yojson]

let role_to_yojson role =
  match role_to_yojson role with
   `List [l] -> l | _ -> assert false

let role_of_yojson = function
  | `String _ as l -> role_of_yojson (`List [ l ] )
  | _ -> Error "expected string as role"

type user_req = {
  realName : string ;
  role : role ;
  passphrase : string ;
}[@@deriving yojson]

let decode_user_req content =
  decode user_req_of_yojson content >>= fun user ->
  nonempty ~name:"passphrase" user.passphrase >>| fun () ->
  user

type user_res = {
  realName : string ;
  role : role ;
}[@@deriving yojson]

type info = {
  vendor : string ;
  product : string ;
  version : string ;
}[@@deriving yojson]

type state = [
  | `Unprovisioned
  | `Operational
  | `Locked
  | `Busy
][@@deriving yojson]

let state_to_yojson state =
  `Assoc [ "state", match state_to_yojson state with `List [l] -> l | _ -> assert false ]

type version = int * int

let version_to_string (major, minor) = Printf.sprintf "%u.%u" major minor
let version_to_yojson v = `String (version_to_string v)
let version_of_yojson _ = Error "Cannot convert version"

type system_info = {
  firmwareVersion : string ;
  softwareVersion : version ;
  hardwareVersion : string ;
}[@@deriving yojson]

