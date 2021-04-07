open Rresult.R.Infix

let guard p err = if p then Ok () else Error err

type err = { message : string }[@@deriving yojson]

let error message =
  Yojson.Safe.to_string (err_to_yojson { message })

let nonempty ~name s =
  guard (String.length s > 0)
    (Printf.sprintf "JSON field %s is empty." name)

let valid_passphrase ~name s =
  guard (10 <= String.length s && String.length s <= 200)
    (Printf.sprintf "passphrase %s is not >= 10 and <= 200 characters" name)

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
  valid_passphrase ~name:"passphrase" passphrase.passphrase >>| fun () ->
  passphrase.passphrase

type provision_req = { unlockPassphrase : string ; adminPassphrase : string ; systemTime : string }[@@deriving yojson]

let decode_provision_req json =
  to_ocaml provision_req_of_yojson json >>= fun b ->
  valid_passphrase ~name:"unlockPassphrase" b.unlockPassphrase >>= fun () ->
  valid_passphrase ~name:"adminPassphrase" b.adminPassphrase >>= fun () ->
  decode_time b.systemTime >>| fun time ->
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

let random_req_of_yojson x =
  random_req_of_yojson x >>= fun rr ->
  if rr.length < 1 || rr.length > 1024 then
    Error "length must be between 1 and 1024"
  else
    Ok rr

type key = {
  primeP : (string [@default ""]) ;
  primeQ : (string [@default ""]) ;
  publicExponent : (string [@default ""]) ;
  data : (string [@default ""]) ;
} [@@deriving yojson]

type mechanism =
  | RSA_Decryption_RAW
  | RSA_Decryption_PKCS1
  | RSA_Decryption_OAEP_MD5
  | RSA_Decryption_OAEP_SHA1
  | RSA_Decryption_OAEP_SHA224
  | RSA_Decryption_OAEP_SHA256
  | RSA_Decryption_OAEP_SHA384
  | RSA_Decryption_OAEP_SHA512
  | RSA_Signature_PKCS1
  | RSA_Signature_PSS_MD5
  | RSA_Signature_PSS_SHA1
  | RSA_Signature_PSS_SHA224
  | RSA_Signature_PSS_SHA256
  | RSA_Signature_PSS_SHA384
  | RSA_Signature_PSS_SHA512
  | ED25519_Signature
  | ECDSA_P224_Signature
  | ECDSA_P256_Signature
  | ECDSA_P384_Signature
  | ECDSA_P521_Signature
[@@deriving yojson, ord]

let mechanism_of_yojson = function
  | `String _ as s -> mechanism_of_yojson (`List [s])
  | _ -> Error "Expected JSON string for mechanism"

let head = function
  | `List [l] -> l
  | _ -> assert false (* deriving yojson for polymorphic variants without
                         arguments always returns a singleton *)

let mechanism_to_yojson mechanism = head @@ mechanism_to_yojson mechanism

module MS = struct
  include Set.Make(struct
      type t = mechanism
      let compare (a : mechanism) (b : mechanism) = compare a b
    end)

  let to_yojson ms = `List (List.map mechanism_to_yojson (elements ms))

  let of_yojson = function
    | `List ms ->
      List.fold_left (fun acc m ->
          acc >>= fun acc ->
          mechanism_of_yojson m >>| fun m ->
          m :: acc)
        (Ok []) ms >>| fun ms ->
      of_list ms
    | _ -> Error "Expected JSON list for mechanisms"
end

let mechanisms_of_string m =
  List.fold_left (fun acc r ->
      acc >>= fun acc ->
      mechanism_of_yojson (`String r) >>| fun m ->
      m :: acc)
    (Ok []) (Astring.String.cuts ~sep:"," m) >>| fun ms ->
  MS.of_list ms

type algorithm =
  | RSA
  | ED25519
  | ECDSA_P224
  | ECDSA_P256
  | ECDSA_P384
  | ECDSA_P521
[@@deriving yojson]

let algorithm_of_yojson = function
  | `String _ as s -> algorithm_of_yojson (`List [s])
  | _ -> Error "Expected JSON string for algorithm"

let algorithm_to_yojson alg = head @@ algorithm_to_yojson alg

let algorithm_matches_mechanism alg m =
  match alg with
  | RSA ->
    List.mem m [ RSA_Decryption_RAW ; RSA_Decryption_PKCS1 ;
                 RSA_Decryption_OAEP_MD5 ; RSA_Decryption_OAEP_SHA1 ;
                 RSA_Decryption_OAEP_SHA224 ; RSA_Decryption_OAEP_SHA256 ;
                 RSA_Decryption_OAEP_SHA384 ; RSA_Decryption_OAEP_SHA512 ;
                 RSA_Signature_PKCS1 ; RSA_Signature_PSS_MD5 ;
                 RSA_Signature_PSS_SHA1 ; RSA_Signature_PSS_SHA224 ;
                 RSA_Signature_PSS_SHA256 ; RSA_Signature_PSS_SHA384 ;
                 RSA_Signature_PSS_SHA512 ]
  | ED25519 -> m = ED25519_Signature
  | ECDSA_P224 -> m = ECDSA_P224_Signature
  | ECDSA_P256 -> m = ECDSA_P256_Signature
  | ECDSA_P384 -> m = ECDSA_P384_Signature
  | ECDSA_P521 -> m = ECDSA_P521_Signature

type rsaPublicKey = {
  mechanisms : MS.t;
  algorithm : algorithm ;
  modulus : string ;
  publicExponent : string ;
  operations : int
} [@@deriving yojson]

type ecPublicKey = {
  mechanisms : MS.t ;
  algorithm : algorithm ;
  data : string ;
  operations : int
} [@@deriving yojson]

type private_key_req = {
  mechanisms : MS.t ;
  algorithm: algorithm ;
  key : key
}[@@deriving yojson]

type decrypt_mode =
  | RAW
  | PKCS1
  | OAEP_MD5
  | OAEP_SHA1
  | OAEP_SHA224
  | OAEP_SHA256
  | OAEP_SHA384
  | OAEP_SHA512
[@@deriving yojson]

let mechanism_of_decrypt_mode = function
  | RAW -> RSA_Decryption_RAW
  | PKCS1 -> RSA_Decryption_PKCS1
  | OAEP_MD5 -> RSA_Decryption_OAEP_MD5
  | OAEP_SHA1 -> RSA_Decryption_OAEP_SHA1
  | OAEP_SHA224 -> RSA_Decryption_OAEP_SHA224
  | OAEP_SHA256 -> RSA_Decryption_OAEP_SHA256
  | OAEP_SHA384 -> RSA_Decryption_OAEP_SHA384
  | OAEP_SHA512 -> RSA_Decryption_OAEP_SHA512

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
  | ED25519
  | ECDSA_P224
  | ECDSA_P256
  | ECDSA_P384
  | ECDSA_P521
[@@deriving yojson]

let mechanism_of_sign_mode = function
  | PKCS1 -> RSA_Signature_PKCS1
  | PSS_MD5 -> RSA_Signature_PSS_MD5
  | PSS_SHA1 -> RSA_Signature_PSS_SHA1
  | PSS_SHA224 -> RSA_Signature_PSS_SHA224
  | PSS_SHA256 -> RSA_Signature_PSS_SHA256
  | PSS_SHA384 -> RSA_Signature_PSS_SHA384
  | PSS_SHA512 -> RSA_Signature_PSS_SHA512
  | ED25519 -> ED25519_Signature
  | ECDSA_P224 -> ECDSA_P224_Signature
  | ECDSA_P256 -> ECDSA_P256_Signature
  | ECDSA_P384 -> ECDSA_P384_Signature
  | ECDSA_P521 -> ECDSA_P521_Signature

let sign_mode_of_yojson = function
  | `String _ as s -> sign_mode_of_yojson (`List [s])
  | _ -> Error "Expected JSON string for sign mode"

type sign_req = { mode : sign_mode ; message : string }[@@deriving yojson]

type generate_key_req = {
  mechanisms : MS.t ;
  algorithm : algorithm ;
  length : (int [@default 0]) ;
  id : (string [@default ""])
} [@@deriving yojson]

let is_alphanum s = Astring.String.for_all (function 'a'..'z'|'A'..'Z'|'0'..'9' -> true | _ -> false) s

let valid_id id =
  guard (String.length id >= 1)
    "ID cannot be shorter than 1 character." >>= fun () ->
  guard (String.length id <= 128)
    "ID cannot be longer than 128 characters." >>= fun () ->
  guard (is_alphanum id) "ID may only contain alphanumeric characters."

let decode_generate_key_req s =
  decode generate_key_req_of_yojson s >>= fun r ->
  (match r.algorithm with
   | RSA ->
     guard (1024 <= r.length && r.length <= 8192)
       "RSA key length must be between 1024 and 8192."
   | _ -> Ok ()) >>= fun () ->
  guard (MS.for_all (algorithm_matches_mechanism r.algorithm) r.mechanisms)
    "Mechanism does not match key algorithm" >>= fun () ->
  guard (MS.cardinal r.mechanisms > 0) "Empty set of mechanisms" >>= fun () ->
  let empty_or_valid id =
    if String.length id = 0 then Ok () else valid_id id
  in
  empty_or_valid r.id >>| fun () ->
  r

type role = [ `Administrator | `Operator | `Metrics | `Backup ] [@@deriving yojson]

let role_to_yojson role = head @@ role_to_yojson role

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
  valid_passphrase ~name:"passphrase" user.passphrase >>| fun () ->
  user

type user_res = {
  realName : string ;
  role : role ;
}[@@deriving yojson]

type info = {
  vendor : string ;
  product : string ;
}[@@deriving yojson]

type state = [
  | `Unprovisioned
  | `Operational
  | `Locked
][@@deriving yojson]

let state_to_yojson state =
  `Assoc [ "state", head @@ state_to_yojson state ]

type version = int * int

let version_to_string (major, minor) = Printf.sprintf "%u.%u" major minor
let version_to_yojson v = `String (version_to_string v)
let version_of_yojson _ = Error "Cannot convert version"

type system_info = {
  firmwareVersion : string ;
  softwareVersion : version ;
  hardwareVersion : string ;
  buildTag : string ;
}[@@deriving yojson]
