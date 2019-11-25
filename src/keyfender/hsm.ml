module type S = sig

  val now : unit -> Ptime.t

  type status_code =
    | Internal_server_error
    | Bad_request
    | Precondition_failed
    | Conflict

  (* string is the body, which may contain error message *)
  type error = status_code * string

  val error_to_code : status_code -> int

  type info = {
    vendor : string ;
    product : string ;
    version : string ;
  }

  val info_to_yojson : info -> Yojson.Safe.t

  type state = [
    | `Unprovisioned
    | `Operational
    | `Locked
    | `Busy
  ]

  val pp_state : state Fmt.t

  val state_to_yojson : state -> Yojson.Safe.t

  type version = int * int

  type system_info = {
    firmwareVersion : string ;
    softwareVersion : version ;
    hardwareVersion : string ;
  }

  val system_info_to_yojson : system_info -> Yojson.Safe.t

  type t

  val info : t -> info

  val state : t -> state

  val lock : t -> unit

  val certificate_chain : t ->
    (X509.Certificate.t * X509.Certificate.t list * X509.Private_key.t) Lwt.t

  val network_configuration : t ->
    (Ipaddr.V4.t * Ipaddr.V4.Prefix.t * Ipaddr.V4.t option) Lwt.t

  val provision : t -> unlock:string -> admin:string -> Ptime.t ->
    (unit, error) result Lwt.t

  val unlock_with_passphrase : t -> passphrase:string ->
    (unit, error) result Lwt.t

  val random : int -> string

  val generate_id : unit -> string

  module Pclock : Mirage_clock.PCLOCK

  module Config : sig
    val set_unlock_passphrase : t -> passphrase:string ->
      (unit, error) result Lwt.t

    val unattended_boot : t -> (bool, error) result Lwt.t

    val set_unattended_boot : t -> bool ->
      (unit, error) result Lwt.t

    val tls_public_pem : t -> string Lwt.t

    val tls_cert_pem : t -> string Lwt.t

    val set_tls_cert_pem : t -> string ->
      (unit, error) result Lwt.t

    val tls_csr_pem : t -> Json.subject_req -> string Lwt.t

    type network = {
      ipAddress : Ipaddr.V4.t ;
      netmask : Ipaddr.V4.t ;
      gateway : Ipaddr.V4.t ;
    }

    val network_to_yojson : network -> Yojson.Safe.t

    val network_of_yojson : Yojson.Safe.t -> (network, string) result

    val network : t -> network Lwt.t

    val set_network : t -> network ->
      (unit, error) result Lwt.t

    type log = { ipAddress : Ipaddr.V4.t ; port : int ; logLevel : Logs.level }

    val log_to_yojson : log -> Yojson.Safe.t

    val log_of_yojson : Yojson.Safe.t -> (log, string) result

    val log : t -> log Lwt.t

    val set_log : t -> log -> (unit, error) result Lwt.t

    val backup_passphrase : t -> passphrase:string ->
      (unit, error) result Lwt.t

    val time : t -> Ptime.t Lwt.t

    val set_time : t -> Ptime.t -> (unit, error) result Lwt.t
  end

  module System : sig
    val system_info : t -> system_info

    val reboot : t -> unit

    val shutdown : t -> unit

    val reset : t -> (unit, error) result Lwt.t

    val update : t -> string Lwt_stream.t -> (string, error) result Lwt.t

    val commit_update : t -> (unit, error) result

    val cancel_update : t -> (unit, error) result

    val backup : t -> (string option -> unit) ->
      (unit, error) result Lwt.t

    val restore : t -> Uri.t -> string Lwt_stream.t ->
      (unit, error) result Lwt.t
  end

  module User : sig
    type role = [ `Administrator | `Operator | `Metrics | `Backup ]

    val role_of_yojson : Yojson.Safe.t -> (role, string) result
    val role_to_yojson : role -> Yojson.Safe.t

    val is_authenticated : t -> username:string -> passphrase:string ->
      bool Lwt.t

    val is_authorized : t -> string -> role -> bool Lwt.t

    val list : t -> (string list, error) result Lwt.t

    val exists : t -> id:string -> (bool, error) result Lwt.t

    val get : t -> id:string -> (string * role, error) result Lwt.t

    val add : id:string -> t -> role:role -> passphrase:string ->
      name:string -> (unit, error) result Lwt.t

    val remove : t -> id:string -> (unit, error) result Lwt.t

    val set_passphrase : t -> id:string -> passphrase:string ->
      (unit, error) result Lwt.t
  end

  module Keys : sig
    type purpose = Sign | Encrypt

    val purpose_of_yojson : Yojson.Safe.t -> (purpose, string) result

    val purpose_to_yojson : purpose -> Yojson.Safe.t

    val exists : t -> id:string -> (bool, error) result Lwt.t

    val list : t -> (string list, error) result Lwt.t

    val add_json : id:string -> t -> purpose -> p:string -> q:string -> e:string ->
      (unit, error) result Lwt.t

    val add_pem : id:string -> t -> purpose -> string ->
      (unit, error) result Lwt.t

    val generate : id:string -> t -> purpose -> length:int ->
      (unit, error) result Lwt.t

    val remove : t -> id:string -> (unit, error) result Lwt.t

    type publicKey = { purpose : purpose ; algorithm : string ; modulus : string ; publicExponent : string ; operations : int }

    val publicKey_to_yojson : publicKey -> Yojson.Safe.t

    val get_json : t -> id:string -> (publicKey, error) result Lwt.t

    val get_pem : t -> id:string -> (string, error) result Lwt.t

    val csr_pem : t -> id:string -> Json.subject_req -> (string, error) result Lwt.t

    val get_cert : t -> id:string -> ((string * string) option, error) result Lwt.t

    val set_cert : t -> id:string -> content_type:string -> string -> (unit, error) result Lwt.t

    val remove_cert : t -> id:string -> (unit, error) result Lwt.t

    type decrypt_mode = Raw | PKCS1 | OAEP_MD5 | OAEP_SHA1 | OAEP_SHA224 | OAEP_SHA256 | OAEP_SHA384 | OAEP_SHA512

    val decrypt_mode_of_yojson : Yojson.Safe.t -> (decrypt_mode, string) result

    val decrypt_mode_to_yojson : decrypt_mode -> Yojson.Safe.t

    val decrypt : t -> id:string -> decrypt_mode -> string -> (string, error) result Lwt.t

    type sign_mode = PKCS1 | PSS_MD5 | PSS_SHA1 | PSS_SHA224 | PSS_SHA256 | PSS_SHA384 | PSS_SHA512

    val sign_mode_of_yojson : Yojson.Safe.t -> (sign_mode, string) result

    val sign_mode_to_yojson : sign_mode -> Yojson.Safe.t

    val sign : t -> id:string -> sign_mode -> string -> (string, error) result Lwt.t
  end
end

let lwt_error_to_msg ~pp_error thing =
  let open Lwt.Infix in
  thing >|= fun x ->
  Rresult.R.error_to_msg ~pp_error x

let hsm_src = Logs.Src.create "hsm" ~doc:"HSM log"
module Log = (val Logs.src_log hsm_src : Logs.LOG)

module Make (Rng : Mirage_random.S) (KV : Mirage_kv.RW) (Pclock : Mirage_clock.PCLOCK) = struct
  (* fatal is called on error conditions we do not expect (hardware failure,
     KV inconsistency).

     TODO this is temporary and may instead result in a HSM that:
     (a) reports a more detailed error (if available) -- already done at call site using Logs
     (b) can be reset to factory defaults (and then be provisioned)
     (c) can be backed up? or sent in for recovery / hardware replacement
  *)
  let fatal prefix ~pp_error e =
    Log.err (fun m -> m "fatal in %s %a" prefix pp_error e);
    invalid_arg "fatal!"

  let lwt_error_fatal prefix ~pp_error thing =
    let open Lwt.Infix in
    thing >|= function
    | Ok a -> Ok a
    | Error e -> fatal prefix ~pp_error e

  type status_code =
    | Internal_server_error
    | Bad_request
    | Precondition_failed
    | Conflict

  (* string is the body, which may contain error message *)
  type error = status_code * string

  let error_to_code code =
    let status = match code with
    | Internal_server_error -> `Internal_server_error
    | Bad_request -> `Bad_request
    | Precondition_failed -> `Precondition_failed
    | Conflict -> `Conflict
    in
    Cohttp.Code.code_of_status status

  let internal_server_error context pp_err f =
    let open Lwt.Infix in
    f >|= function
    | Ok x -> Ok x
    | Error e ->
      Log.err (fun m -> m "Error: %a while writing to key-value store: %s." pp_err e context);
      Error (Internal_server_error, "Could not write to disk. Check hardware.")

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

  let pp_state ppf s =
    Fmt.string ppf (match s with
        | `Unprovisioned -> "unprovisioned"
        | `Operational -> "operational"
        | `Locked -> "locked"
        | `Busy -> "busy")

  let state_to_yojson state =
    `Assoc [ "state", match state_to_yojson state with `List [l] -> l | _ -> assert false ]

  type version = int * int

  let version_to_string (major, minor) = Printf.sprintf "%u.%u" major minor
  let version_of_string s = match Astring.String.cut ~sep:"." s with
    | None -> Error (Bad_request, "Failed to parse version: no separator (.). A valid version would be '4.2'.")
    | Some (major, minor) ->
      try
        let ma = int_of_string major
        and mi = int_of_string minor
        in
        Ok (ma, mi)
      with Failure _ -> Error (Bad_request, "Failed to parse version: Not a number. A valid version would be '4.2'.")

  let version_to_yojson v = `String (version_to_string v)
  let version_of_yojson _ = Error "Cannot convert version"
  let version_is_upgrade ~current ~update = fst current <= fst update

  type system_info = {
    firmwareVersion : string ;
    softwareVersion : version ;
    hardwareVersion : string ;
  }[@@deriving yojson]

  module Config_store = Config_store.Make(KV)
  module Domain_key_store = Domain_key_store.Make(Rng)(KV)
  module Encrypted_store = Encrypted_store.Make(Rng)(KV)

  type keys = {
    domain_key : Cstruct.t ; (* needed when unlock passphrase changes and likely for unattended boot *)
    auth_store : Encrypted_store.t ;
    key_store : Encrypted_store.t ;
  }

  type internal_state =
    | Unprovisioned
    | Operational of keys
    | Locked
    | Busy

  let to_external_state = function
    | Unprovisioned -> `Unprovisioned
    | Operational _ -> `Operational
    | Locked -> `Locked
    | Busy -> `Busy

  type t = {
    mutable state : internal_state ;
    mutable has_changes : string option ;
    kv : KV.t ;
    info : info ;
    system_info : system_info ;
  }

  let state t = to_external_state t.state

  let lock t = t.state <- Locked

  let time_offset = ref Ptime.Span.zero

  let now () =
    let hw_clock = Ptime.v (Pclock.now_d_ps ()) in
    match Ptime.add_span hw_clock !time_offset with
    | None -> Ptime.epoch
    | Some ts -> ts

  let set_time_offset ?hw_clock t timestamp =
    let hw_clock = match hw_clock with 
    | Some ts -> ts
    | None -> Ptime.v (Pclock.now_d_ps ()) 
    in
    let span = Ptime.diff timestamp hw_clock in
    time_offset := span;
    internal_server_error "Write time offset" KV.pp_write_error
      (Config_store.set t.kv Time_offset span)

  let prepare_keys t slot credentials =
    let open Lwt_result.Infix in
    let get_salt_key = function
      | Domain_key_store.Passphrase -> Config_store.Unlock_salt
      | Domain_key_store.Device_id -> Config_store.Device_id_salt
    in
    internal_server_error "Prepare keys" Config_store.pp_error
      (Config_store.get t.kv (get_salt_key slot)) >>= fun salt ->
    let unlock_key = Crypto.key_of_passphrase ~salt credentials in
    Lwt_result.map_err (function `Msg m -> Bad_request, m)
      (Domain_key_store.get t.kv slot ~unlock_key) >|= fun domain_key ->
    let auth_store_key, key_store_key =
      Cstruct.split domain_key Crypto.key_len
    in
    (domain_key, auth_store_key, key_store_key)

  let unlock_store kv slot key =
    let open Lwt_result.Infix in
    let slot_str = Encrypted_store.slot_to_string slot in
    internal_server_error
      ("connecting to " ^ slot_str ^ " store")
      Encrypted_store.pp_connect_error
      (Encrypted_store.unlock Version.current slot ~key kv)
    >>= function
        | `Version_greater (stored, _t) ->
          (* upgrade code for authentication store *)
          Lwt.return @@ Error (Internal_server_error, Fmt.strf "%s store too old (%a), no migration code" slot_str Version.pp stored)
        | `Kv store -> Lwt.return @@ Ok store

  (* credential is passphrase or device id, depending on boot mode *)
  let unlock t slot credentials =
    let open Lwt_result.Infix in
    (* state is already checked in Handler_unlock.service_available *)
    assert (state t = `Locked) ;
    prepare_keys t slot credentials >>= fun (domain_key, as_key, ks_key) ->
    unlock_store t.kv Authentication as_key >>= fun auth_store ->
    unlock_store t.kv Key ks_key >|= fun key_store ->
    let keys = { domain_key ; auth_store ; key_store } in
    t.state <- Operational keys

  let unlock_with_device_id t ~device_id = unlock t Device_id device_id

  let unlock_with_passphrase t ~passphrase = unlock t Passphrase passphrase

  let boot_config_store t =
    let open Lwt_result.Infix in
    lwt_error_fatal "get time offset" ~pp_error:Config_store.pp_error
      (Config_store.get_opt t.kv Time_offset >|= function
        | None -> ()
        | Some span -> time_offset := span) >>= fun () ->
    lwt_error_fatal "get unlock-salt" ~pp_error:Config_store.pp_error
      (Config_store.get_opt t.kv Unlock_salt) >>= function
        | None -> Lwt.return (Ok t)
        | Some _ ->
          t.state <- Locked;
          lwt_error_fatal "get unattended boot" ~pp_error:Config_store.pp_error
            (Config_store.get_opt t.kv Unattended_boot) >>= function
          | Some true ->
            begin
              let open Lwt.Infix in
              let device_id = "my device id, psst" in
              (unlock_with_device_id t ~device_id >|= function
                | Ok () -> ()
                | Error (_, msg) ->
                  Log.err (fun m -> m "unattended boot failed with %s" msg)) >|= fun () ->
              Ok t
            end
          | None | Some false -> Lwt.return (Ok t)

  let boot kv =
    let t =
      {
        state = Unprovisioned ;
        has_changes = None ;
        kv ;
        info = { vendor = "Nitrokey UG" ; product = "NitroHSM" ; version = "v1" } ;
        system_info = { firmwareVersion = "1" ; softwareVersion = (1, 7) ; hardwareVersion = "2.2.2" } ;
      }
    in
    let open Lwt.Infix in
    begin
      let open Lwt_result.Infix in
      lwt_error_to_msg ~pp_error:Config_store.pp_error
        (Config_store.get_opt t.kv Version) >>= function
      | None ->
        (* uninitialized / unprovisioned device, write version *)
        lwt_error_to_msg ~pp_error:KV.pp_write_error
          (Config_store.set t.kv Version Version.current >|= fun () -> t)
      | Some version ->
        match Version.(compare current version) with
        | `Equal -> boot_config_store t
        | `Smaller ->
          let msg =
            "store has higher version than software, please update software version"
          in
        Lwt.return (Error (`Msg msg))
        | `Greater ->
          (* here's the place to embed migration code, at least for the
              configuration store *)
          let msg =
            "store has smaller version than software, data will be migrated!"
          in
          Lwt.return (Error (`Msg msg))
    end >|= function
    | Ok t -> t
    | Error `Msg msg ->
      Log.err (fun m -> m "error booting %s" msg);
      invalid_arg "broken NitroHSM"

  let info t = t.info

  let generate_csr ?(dn = [ X509.Distinguished_name.(Relative_distinguished_name.singleton (CN "keyfender")) ]) priv =
    X509.Signing_request.create dn priv, dn

  let generate_cert t priv =
    let open Lwt_result.Infix in
    (* this is before provisioning, our posix time may be not accurate *)
    let valid_from = Ptime.epoch
    and valid_until = Ptime.max
    in
    let csr, dn = generate_csr priv in
    let cert =
      X509.Signing_request.sign csr ~valid_from ~valid_until priv dn
    in
    lwt_error_fatal "write certificate to configuration store"
      ~pp_error:KV.pp_write_error
      (Config_store.set t.kv Certificate (cert, []) >|= fun () -> cert)

  let certificate_chain t =
    Lwt_result.get_exn
      (let open Lwt_result.Infix in
       lwt_error_fatal "get private key from configuration store"
         ~pp_error:Config_store.pp_error
         (Config_store.get_opt t.kv Private_key) >>= function
       | Some priv ->
         lwt_error_fatal "get certificate from configuration store"
           ~pp_error:Config_store.pp_error
           (Config_store.get t.kv Certificate >|= fun (cert, chain) ->
            cert, chain, priv)
       | None  ->
         (* no key -> generate, generate certificate *)
         let priv = `RSA (Nocrypto.Rsa.generate Crypto.initial_key_rsa_bits) in
         generate_cert t priv >>= fun cert ->
         lwt_error_fatal "set private key to configuration store"
           ~pp_error:KV.pp_write_error
           (Config_store.set t.kv Private_key priv >|= fun () ->
            (cert, [], priv)))

  let default_network_configuration =
    let ip = Ipaddr.V4.of_string_exn "192.168.1.1" in
    ip, Ipaddr.V4.Prefix.make 24 ip, None

  let network_configuration t =
    let open Lwt.Infix in
    Config_store.(get t.kv Ip_config) >|= function
    | Ok cfg -> cfg
    | Error e ->
      Log.warn (fun m -> m "error %a while retrieving IP, using default"
                   Config_store.pp_error e);
      default_network_configuration

  let random n = Cstruct.to_string @@ Nocrypto.Base64.encode @@ Rng.generate n

  let generate_id () =
    let `Hex id = Hex.of_cstruct (Rng.generate 10) in
    id

  module Pclock = struct
    let now_d_ps () = Ptime.(Span.to_d_ps @@ to_span @@ now ())
    let current_tz_offset_s () = None
    let period_d_ps () = None
  end

  module User = struct
    let user_src = Logs.Src.create "hsm.user" ~doc:"HSM user log"
    module Access = (val Logs.src_log user_src : Logs.LOG)

    type role = [ `Administrator | `Operator | `Metrics | `Backup ] [@@deriving yojson]

    let role_to_yojson role =
      match role_to_yojson role with
       `List [l] -> l | _ -> assert false

    let role_of_yojson = function
      | `String _ as l -> role_of_yojson (`List [ l ] )
      | _ -> Error "expected string as role"

    let pp_role ppf r =
      Fmt.string ppf @@ match r with
      | `Administrator -> "R-Administrator"
      | `Operator -> "R-Operator"
      | `Metrics -> "R-Metrics"
      | `Backup -> "R-Backup"

    type user = {
      name : string ;
      salt : string ;
      digest : string ;
      role : role
    }[@@deriving yojson]

    let read_decode store id =
      let open Lwt.Infix in
      Encrypted_store.get store (Mirage_kv.Key.v id) >|= function
      | Error e -> Error (`Encrypted_store e)
      | Ok data ->
        Rresult.R.reword_error
          (fun err -> `Json_decode err)
          (Json.decode user_of_yojson data)

    let pp_find_error ppf = function
      | `Encrypted_store kv -> Encrypted_store.pp_error ppf kv
      | `Json_decode msg -> Fmt.pf ppf "json decode failure %s" msg

    let write store id user =
      let user_str = Yojson.Safe.to_string (user_to_yojson user) in
      internal_server_error "Write user" Encrypted_store.pp_write_error
        (Encrypted_store.set store (Mirage_kv.Key.v id) user_str)

    (* functions below are exported, and take a Hsm.t directly, this the
       wrapper to unpack the auth_store handle. *)
    let in_store t =
      match t.state with
      | Operational keys -> keys.auth_store
      | _ -> assert false (* checked by webmachine Handler_user.service_available *)

    let get_user t id =
      let keys = in_store t in
      read_decode keys id

    let is_authenticated t ~username ~passphrase =
      let open Lwt.Infix in
      get_user t username >|= function
      | Error e ->
        Access.warn (fun m -> m "%s unauthenticated: %a" username pp_find_error e);
        false
      | Ok user ->
        let pass = Crypto.key_of_passphrase ~salt:(Cstruct.of_string user.salt) passphrase in
        Cstruct.equal pass (Cstruct.of_string user.digest)

    let is_authorized t username role =
      let open Lwt.Infix in
      get_user t username >|= function
      | Error e ->
        Access.warn (fun m -> m "%s unauthorized for %a: %a" username
                        pp_role role pp_find_error e);
        false
      | Ok user -> user.role = role

    let exists t ~id =
      let open Lwt_result.Infix in
      let store = in_store t in
      internal_server_error "Exists user" Encrypted_store.pp_error
       (Encrypted_store.exists store (Mirage_kv.Key.v id) >|= function
        | None -> false
        | Some _ -> true)

    let get t ~id =
      let open Lwt_result.Infix in
      let store = in_store t in
      internal_server_error "Read user" pp_find_error
        (read_decode store id >|= fun user ->
         user.name, user.role)

    (* TODO: validate username/id *)
    let add ~id t ~role ~passphrase ~name =
      let open Lwt_result.Infix in
      let store = in_store t in
      Lwt.bind (read_decode store id)
        (function
          | Error `Encrypted_store `Kv (`Not_found _) ->
            let user =
              let salt = Rng.generate Crypto.salt_len in
              let digest = Crypto.key_of_passphrase ~salt passphrase in
              { name ; salt = Cstruct.to_string salt ;
                digest = Cstruct.to_string digest ; role }
            in
            write store id user >|= fun () ->
            Access.info (fun m -> m "added %s (%s)" name id)
          | Ok _ -> Lwt.return (Error (Conflict, "user already exists"))
          | Error _ as e ->
            internal_server_error "Adding user" pp_find_error
              (Lwt.return e))

    let list t =
      let open Lwt_result.Infix in
      let store = in_store t in
      internal_server_error "List users" Encrypted_store.pp_error
        (Encrypted_store.list store Mirage_kv.Key.empty) >|= fun xs ->
      List.map fst (List.filter (fun (_, typ) -> typ = `Value) xs)

    let remove t ~id =
      let open Lwt_result.Infix in
      let store = in_store t in
      internal_server_error "Remove user" Encrypted_store.pp_write_error
        (Encrypted_store.remove store (Mirage_kv.Key.v id) >|= fun () ->
         Access.info (fun m -> m "removed (%s)" id))

    let set_passphrase t ~id ~passphrase =
      let open Lwt_result.Infix in
      let store = in_store t in
      internal_server_error "Read user" pp_find_error
        (read_decode store id) >>= fun user ->
      let salt' = Rng.generate Crypto.salt_len in
      let digest' = Crypto.key_of_passphrase ~salt:salt' passphrase in
      let user' =
        { user with salt = Cstruct.to_string salt' ;
                    digest = Cstruct.to_string digest' }
      in
      write store id user' >|= fun () ->
      Access.info (fun m -> m "changed %s (%s) passphrase" id user.name)
  end

  module Keys = struct
    let keys_src = Logs.Src.create "hsm.key" ~doc:"HSM key log"
    module Access = (val Logs.src_log keys_src : Logs.LOG)

    type purpose = Sign | Encrypt [@@deriving yojson]

    let purpose_of_yojson = function
      | `String _ as s -> purpose_of_yojson (`List [s])
      | _ -> Error "Expected JSON string for purpose"

    let purpose_to_yojson purpose =
      match purpose_to_yojson purpose with
      | `List [l] -> l
      | _ -> assert false

    (* functions below are exported, and take a Hsm.t directly, this the
       wrapper to unpack the auth_store handle. *)
    let key_store t =
      match t.state with
      | Operational keys -> keys.key_store
      | _ -> assert false (* checked by webmachine Handler_keys.service_available *)

    let list t =
      let open Lwt_result.Infix in
      let store = key_store t in
      internal_server_error "List keys" Encrypted_store.pp_error
        (Encrypted_store.list store Mirage_kv.Key.empty) >|= fun xs ->
      List.map fst (List.filter (fun (_, typ) -> typ = `Value) xs)

    (* how a key is persisted in the kv store. note that while nocrypto
       provides s-expression conversions, these have been removed from the
       trunk version -- it is also not safe to embed s-expressions into json.
       to avoid these issues, we use PKCS8 encoding as PEM (embedding DER in
       json is not safe as well)!
    *)
    type priv = Nocrypto.Rsa.priv
    let priv_to_yojson p =
      `String (Cstruct.to_string (X509.Private_key.encode_pem (`RSA p)))
    let priv_of_yojson = function
      | `String data ->
        begin match X509.Private_key.decode_pem (Cstruct.of_string data) with
          | Ok `RSA priv -> Ok priv
          | Error `Msg m -> Error m
        end
      | _ -> Error "Expected json string as private key"

    let exists t ~id =
      let open Lwt_result.Infix in
      let store = key_store t in
      internal_server_error "Exists key" Encrypted_store.pp_error
       (Encrypted_store.exists store (Mirage_kv.Key.v id) >|= function
        | None -> false
        | Some _ -> true)

    type key = {
      purpose : purpose ;
      priv : priv ;
      cert : (string * string) option ;
    } [@@deriving yojson]

    let encode_and_write t id key =
      let store = key_store t
      and value = key_to_yojson key
      and kv_key = Mirage_kv.Key.v id
      in
      internal_server_error "Write key" Encrypted_store.pp_write_error
        (Encrypted_store.set store kv_key (Yojson.Safe.to_string value))

    let add ~id t purpose priv =
      let open Lwt_result.Infix in
      let store = key_store t in
      let key = Mirage_kv.Key.v id in
      internal_server_error "Exist key" Encrypted_store.pp_error
        (Encrypted_store.exists store key) >>= function
      | Some _ ->
        Lwt.return (Error (Bad_request, "Key with id " ^ id ^ " already exists"))
      | None ->
        encode_and_write t id { purpose ; priv ; cert = None }

    let add_json ~id t purpose ~p ~q ~e =
      let open Nocrypto in
      let to_z ctx data =
        match Base64.decode (Cstruct.of_string data) with
        | Some num -> Ok (Numeric.Z.of_cstruct_be num)
        | None -> Error ("Invalid base64 encoded value in '" ^ ctx ^ "': " ^ data)
      in
      match
        let open Rresult.R.Infix in
        to_z "p" p >>= fun p ->
        to_z "q" q >>= fun q ->
        to_z "e" e >>| fun e ->
        Rsa.priv_of_primes ~e ~p ~q
      with
      | Error e -> Lwt.return (Error (Bad_request, e))
      | Ok priv -> add ~id t purpose priv

    let add_pem ~id t purpose data =
      match X509.Private_key.decode_pem (Cstruct.of_string data) with
      | Error `Msg m -> Lwt.return (Error (Bad_request, m))
      | Ok `RSA priv -> add ~id t purpose priv

    let generate ~id t purpose ~length =
      if 1024 <= length && length <= 8192 then 
        let priv = Nocrypto.Rsa.generate length in
        add ~id t purpose priv
      else Lwt.return @@ Error (Bad_request, "Length must be between 1024 and 8192.")

    let remove t ~id =
      let open Lwt_result.Infix in
      let store = key_store t in
      internal_server_error "Remove key" Encrypted_store.pp_write_error
        (Encrypted_store.remove store (Mirage_kv.Key.v id) >|= fun () ->
         Access.info (fun m -> m "removed (%s)" id))

    type publicKey = {
      purpose : purpose ;
      algorithm : string ;
      modulus : string ;
      publicExponent : string ;
      operations : int
    } [@@deriving yojson]

    let get_key t id =
      let open Lwt_result.Infix in
      let store = key_store t in
      let key = Mirage_kv.Key.v id in
      internal_server_error "Read key" Encrypted_store.pp_error
        (Encrypted_store.get store key) >>= fun key_raw ->
      Lwt.return (match Json.decode key_of_yojson key_raw with
          | Ok k -> Ok k
          | Error e -> Error (Internal_server_error, e))

    let get_json t ~id =
      let open Lwt_result.Infix in
      get_key t id >|= fun key ->
      let z_to_b64 n =
        Cstruct.to_string Nocrypto.(Base64.encode @@ Numeric.Z.to_cstruct_be n)
      in
      { purpose = key.purpose ;
        algorithm = "RSA" ;
        modulus = z_to_b64 key.priv.Nocrypto.Rsa.n ;
        publicExponent = z_to_b64 key.priv.Nocrypto.Rsa.e ;
        operations = 0 ;
      }

    let get_pem t ~id =
      let open Lwt_result.Infix in
      get_key t id >|= fun key ->
      Cstruct.to_string @@ X509.Private_key.encode_pem (`RSA key.priv)

    let csr_pem t ~id subject =
      let open Lwt_result.Infix in
      get_key t id >|= fun key ->
      let subject' = Json.to_distinguished_name subject in
      let csr = X509.Signing_request.create subject' (`RSA key.priv) in
      Cstruct.to_string @@ X509.Signing_request.encode_pem csr

    let get_cert t ~id =
      let open Lwt_result.Infix in
      get_key t id >|= fun key ->
      key.cert

    let set_cert t ~id ~content_type data =
      let open Lwt_result.Infix in
      get_key t id >>= fun key ->
      match key.cert with
      | Some _ -> Lwt.return (Error (Conflict, "Key already contains a certificate"))
      | None ->
        let key' = { key with cert = Some (content_type, data) } in
        encode_and_write t id key'

    let remove_cert t ~id =
      let open Lwt_result.Infix in
      get_key t id >>= fun key ->
      match key.cert with
      | None -> Lwt.return (Error (Conflict, "Key already contains a certificate"))
      | Some _ ->
        let key' = { key with cert = None } in
        encode_and_write t id key'

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

    module Oaep_md5 = Nocrypto.Rsa.OAEP(Nocrypto.Hash.MD5)
    module Oaep_sha1 = Nocrypto.Rsa.OAEP(Nocrypto.Hash.SHA1)
    module Oaep_sha224 = Nocrypto.Rsa.OAEP(Nocrypto.Hash.SHA224)
    module Oaep_sha256 = Nocrypto.Rsa.OAEP(Nocrypto.Hash.SHA256)
    module Oaep_sha384 = Nocrypto.Rsa.OAEP(Nocrypto.Hash.SHA384)
    module Oaep_sha512 = Nocrypto.Rsa.OAEP(Nocrypto.Hash.SHA512)

    let decrypt t ~id decrypt_mode data =
      let open Lwt_result.Infix in
      get_key t id >>= fun key_data ->
      let key = key_data.priv in
      Lwt.return @@
      let oneline = Astring.String.(concat ~sep:"" (cuts ~sep:"\n" data)) in
      match Nocrypto.Base64.decode (Cstruct.of_string oneline) with
      | None -> Error (Bad_request, "Couldn't decode data from base64.")
      | Some encrypted_data ->
        if key_data.purpose = Encrypt then
          let dec_cs_opt =
            match decrypt_mode with
            | Raw ->
              (try Some (Nocrypto.Rsa.decrypt ~key encrypted_data)
               with Nocrypto.Rsa.Insufficient_key -> None)
            | PKCS1 -> Nocrypto.Rsa.PKCS1.decrypt ~key encrypted_data
            | OAEP_MD5 -> Oaep_md5.decrypt ~key encrypted_data
            | OAEP_SHA1 -> Oaep_sha1.decrypt ~key encrypted_data
            | OAEP_SHA224 -> Oaep_sha224.decrypt ~key encrypted_data
            | OAEP_SHA256 -> Oaep_sha256.decrypt ~key encrypted_data
            | OAEP_SHA384 -> Oaep_sha384.decrypt ~key encrypted_data
            | OAEP_SHA512 -> Oaep_sha512.decrypt ~key encrypted_data
          in
          match dec_cs_opt with
          | None -> Error (Bad_request, "Decryption failure.")
          | Some cs -> Ok (Nocrypto.Base64.encode cs |> Cstruct.to_string)
        else
          Error (Bad_request, "Key purpose is not encrypt.")

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

    module Pss_md5 = Nocrypto.Rsa.PSS(Nocrypto.Hash.MD5)
    module Pss_sha1 = Nocrypto.Rsa.PSS(Nocrypto.Hash.SHA1)
    module Pss_sha224 = Nocrypto.Rsa.PSS(Nocrypto.Hash.SHA224)
    module Pss_sha256 = Nocrypto.Rsa.PSS(Nocrypto.Hash.SHA256)
    module Pss_sha384 = Nocrypto.Rsa.PSS(Nocrypto.Hash.SHA384)
    module Pss_sha512 = Nocrypto.Rsa.PSS(Nocrypto.Hash.SHA512)

    let sign t ~id sign_mode data =
      let open Lwt_result.Infix in
      get_key t id >>= fun key_data ->
      let key = key_data.priv in
      Lwt.return @@
      let oneline = Astring.String.(concat ~sep:"" (cuts ~sep:"\n" data)) in
      match Nocrypto.Base64.decode (Cstruct.of_string oneline) with
      | None -> Error (Bad_request, "Couldn't decode data from base64.")
      | Some to_sign ->
        if key_data.purpose = Sign then
          try
            let signature =
              match sign_mode with
              | PKCS1 -> Nocrypto.Rsa.PKCS1.sig_encode ~key to_sign
              | PSS_MD5 -> Pss_md5.sign ~key to_sign
              | PSS_SHA1 -> Pss_sha1.sign ~key to_sign
              | PSS_SHA224 -> Pss_sha224.sign ~key to_sign
              | PSS_SHA256 -> Pss_sha256.sign ~key to_sign
              | PSS_SHA384 -> Pss_sha384.sign ~key to_sign
              | PSS_SHA512 -> Pss_sha512.sign ~key to_sign
            in
            Ok (Nocrypto.Base64.encode signature |> Cstruct.to_string)
          with Nocrypto.Rsa.Insufficient_key -> Error (Bad_request, "Signing failure.")
        else
          Error (Bad_request, "Key purpose is not sign.")

  end

  let provision_mutex = Lwt_mutex.create ()

  let provision t ~unlock ~admin time =
    Lwt_mutex.with_lock provision_mutex (fun () ->
        let open Lwt_result.Infix in
        (* state already checked in Handler_provision.service_available *)
        assert (state t = `Unprovisioned);
        let unlock_salt = Rng.generate Crypto.salt_len in
        let unlock_key = Crypto.key_of_passphrase ~salt:unlock_salt unlock in
        let domain_key = Rng.generate (Crypto.key_len * 2) in
        let auth_store_key, key_store_key =
          Cstruct.split domain_key Crypto.key_len
        in
        internal_server_error
          "Initializing authentication store" Encrypted_store.pp_write_error
          (Encrypted_store.initialize Version.current Authentication ~key:auth_store_key t.kv)
        >>= fun auth_store ->
        internal_server_error
          "Initializing key store" Encrypted_store.pp_write_error
          (Encrypted_store.initialize Version.current Key ~key:key_store_key t.kv)
        >>= fun key_store ->
        let keys = { domain_key ; auth_store ; key_store } in
        t.state <- Operational keys;
        (* to avoid dangerous persistent states, do the exact sequence:
           (1) write admin user
           (2) write domain key
           (3) write unlock-salt

           reading back on system start first reads unlock-salt, if this fails,
           the HSM is in unprovisioned state *)
        User.add ~id:"admin" t ~role:`Administrator ~passphrase:admin ~name:"admin" >>= fun _id ->
        internal_server_error "set domain key" KV.pp_write_error
          (Domain_key_store.set t.kv Passphrase ~unlock_key domain_key) >>= fun () ->
        internal_server_error "set unlock-salt" KV.pp_write_error
          (Config_store.set t.kv Unlock_salt unlock_salt) >>= fun () ->
        set_time_offset t time
      )

  module Config = struct

    let salted passphrase =
      let salt = Rng.generate Crypto.salt_len in
      let key = Crypto.key_of_passphrase ~salt passphrase in
      salt, key

    let set_unlock_passphrase t ~passphrase =
      match t.state with
      | Operational keys ->
        let open Lwt_result.Infix in
        let unlock_salt, unlock_key = salted passphrase in
        (* TODO the two writes below should be a transaction *)
        internal_server_error "Write unlock salt" KV.pp_write_error
          (Config_store.set t.kv Unlock_salt unlock_salt) >>= fun () ->
        internal_server_error "Write passphrase" KV.pp_write_error
          (Domain_key_store.set t.kv Passphrase ~unlock_key keys.domain_key)
      | _ -> assert false (* Handler_config.service_available checked that we are operational *)

    let unattended_boot t =
      let open Lwt_result.Infix in
      internal_server_error "Read unattended boot" Config_store.pp_error
        (Config_store.get_opt t.kv Unattended_boot >|=
         function None -> false | Some v -> v)

    let set_unattended_boot t status =
      let open Lwt_result.Infix in
      (* (a) change setting in configuration store *)
      (* (b) add or remove salt in configuration store *)
      (* (c) add or remove to domain_key store *)
      match t.state with
      | Operational keys ->
        internal_server_error "Write unattended boot" KV.pp_write_error
          (Config_store.set t.kv Unattended_boot status) >>= fun () ->
        if status then begin
          let salt, unlock_key = salted "my device id, psst" in
          internal_server_error "Write device ID salt" KV.pp_write_error
            (Config_store.set t.kv Device_id_salt salt) >>= fun () ->
          internal_server_error "Write device ID" KV.pp_write_error
            (Domain_key_store.set t.kv Device_id ~unlock_key keys.domain_key)
        end else begin
          internal_server_error "Remove device ID salt" KV.pp_write_error
            (Config_store.remove t.kv Device_id_salt) >>= fun () ->
          internal_server_error "Remove device ID" KV.pp_write_error
            (Domain_key_store.remove t.kv Device_id)
        end
      | _ -> assert false (* Handler_config.service_available checked that we are operational *)

    let tls_public_pem t =
      let open Lwt.Infix in
      certificate_chain t >|= fun (certificate, _, _) ->
      let public = X509.Certificate.public_key certificate in
      Cstruct.to_string (X509.Public_key.encode_pem public)

    let tls_cert_pem t =
      let open Lwt.Infix in
      certificate_chain t >|= fun (cert, chain, _) ->
      Cstruct.to_string (X509.Certificate.encode_pem_multiple (cert :: chain))

    let set_tls_cert_pem t cert_data =
      (* validate the incoming chain (we'll use it for the TLS server):
         - there's one server certificate at either end (matching our private key)
         - the chain itself is properly signed (i.e. a full chain missing the TA)
         --> take the last element as TA (unchecked), and verify the chain!
         - TODO use current system time for verification
      *)
      match X509.Certificate.decode_pem_multiple (Cstruct.of_string cert_data) with
      | Error `Msg m -> Lwt.return @@ Error (Bad_request, m)
      | Ok [] -> Lwt.return @@ Error (Bad_request, "empty certificate chain")
      | Ok (cert :: chain) ->
        let open Lwt.Infix in
        certificate_chain t >>= fun (_, _, `RSA priv) ->
        if `RSA (Nocrypto.Rsa.pub_of_priv priv) = X509.Certificate.public_key cert then
          let valid = match List.rev chain with
            | [] -> Ok cert
            | ta :: chain' ->
              let our_chain = cert :: List.rev chain' in
              Rresult.R.error_to_msg ~pp_error:X509.Validation.pp_chain_error
                (X509.Validation.verify_chain ~anchors:[ta] our_chain)
          in
          match valid with
          | Error `Msg m -> Lwt.return @@ Error (Bad_request, m)
          | Ok _ ->
            internal_server_error "Write certificate" KV.pp_write_error
              (Config_store.set t.kv Certificate (cert, chain))
        else
          Lwt.return @@ Error (Bad_request, "public key in certificate does not match private key")

    let tls_csr_pem t subject =
      let open Lwt.Infix in
      certificate_chain t >|= fun (_, _, priv) ->
      let dn = Json.to_distinguished_name subject in 
      let csr, _ = generate_csr ~dn priv in
      Cstruct.to_string (X509.Signing_request.encode_pem csr)

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

    let network t =
      let open Lwt.Infix in
      network_configuration t >|= fun (ipAddress, prefix, route) ->
      let netmask = Ipaddr.V4.Prefix.netmask prefix
      and gateway = match route with None -> Ipaddr.V4.any | Some ip -> ip
      in
      { ipAddress ; netmask ; gateway }

    let set_network t network =
      let open Lwt_result.Infix in
      Lwt.return (
        try
          Ok (Ipaddr.V4.Prefix.of_netmask network.netmask network.ipAddress)
        with
          Ipaddr.Parse_error (err, packet) ->
          Error (Bad_request, Fmt.strf "error %s parsing netmask %s" err packet)) >>= fun prefix ->
      let route =
        if Ipaddr.V4.compare network.gateway Ipaddr.V4.any = 0 then
          None
        else
          Some network.gateway
      in
      (* TODO if successful, reboot (or set the IP address) after responding *)
      internal_server_error "Write network configuration" KV.pp_write_error
        Config_store.(set t.kv Ip_config (network.ipAddress, prefix, route))

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

    let default_log = { ipAddress = Ipaddr.V4.any ; port = 514 ; logLevel = Info }

    let log t =
      let open Lwt.Infix in
      Config_store.get_opt t.kv Log_config >|= function
      | Ok None -> default_log
      | Ok Some (ipAddress, port, logLevel) -> { ipAddress ; port ; logLevel }
      | Error e ->
        Log.warn (fun m -> m "error %a while getting log configuration"
                     Config_store.pp_error e);
        default_log

    let set_log t log =
      internal_server_error "Write log config" KV.pp_write_error
        (Config_store.set t.kv Log_config (log.ipAddress, log.port, log.logLevel))

    let backup_passphrase t ~passphrase =
      match t.state with
      | Operational _keys ->
        let open Lwt_result.Infix in
        let backup_salt, backup_key = salted passphrase in
        (* TODO the two writes below should be a transaction *)
        internal_server_error "Write backup salt" KV.pp_write_error
          (Config_store.set t.kv Backup_salt backup_salt) >>= fun () ->
        internal_server_error "Write backup key" KV.pp_write_error
          (Config_store.set t.kv Backup_key backup_key)
      | _ -> assert false (* Handler_config.service_available checked that we are operational *)

    let time _t = Lwt.return (now ())

    let set_time = set_time_offset ?hw_clock:None
  end

  module System = struct
    let system_info t = t.system_info

    (* TODO call hardware *)
    let reboot t =
      t.state <- Busy

    (* TODO call hardware *)
    let shutdown t =
      t.state <- Busy

    let reset t =
      t.state <- Unprovisioned;
      internal_server_error "Reset" KV.pp_write_error
        (KV.remove t.kv Mirage_kv.Key.empty)
      (* TODO reboot the hardware *)

    let put_back stream chunk = Lwt_stream.append (Lwt_stream.of_list [ chunk ]) stream

    let read_n stream n =
      let rec read prefix =
        let open Lwt.Infix in
        Lwt_stream.get stream >>= function
        | None -> Lwt.return @@ Error (Bad_request, "Malformed update")
        | Some data ->
          let str = prefix ^ data in
          if String.length str >= n
          then
            let data, rest = Astring.String.span ~min:n ~max:n str in
            Lwt.return @@ Ok (data, put_back stream rest)
          else read str
      in
      read ""

    let get_length stream =
      let open Lwt_result.Infix in
      read_n stream 2 >|= fun (data, stream') ->
      let length = Cstruct.BE.get_uint16 (Cstruct.of_string data) 0 in
      (length, stream')

    let get_data (l, s) = read_n s l

    let get_field s =
      let open Lwt_result.Infix in
      get_length s >>=
      get_data

    (* TODO encode like backup *)
    let update t s =
      let empty = Cstruct.empty in
      let update t _data = t in
      let get t = t in
      let open Lwt_result.Infix in
      (* stream contains:
         - signature (hash of the rest)
         - changelog
         - version number
         - software image,
         first three are prefixed by 4 byte length *)
      get_field s >>= fun (_signature, s') ->
      let hash = empty in
      get_field s' >>= fun (changes, s'') ->
      let hash' = update hash changes in
      get_field s'' >>= fun (version, s''') ->
      Lwt.return (version_of_string version) >>= fun version' ->
      let hash'' = update hash' version in
      Lwt_stream.fold_s (fun chunk acc ->
        match acc with
        | Error e -> Lwt.return (Error e)
        | Ok hash ->
          (*TODO stream to s_update*)
          let hash' = update hash chunk in
          Lwt.return @@ Ok hash')
        s''' (Ok hash'') >>= fun hash ->
      let _final = get hash in
      let gc_stat = Gc.stat () in
      Logs.app (fun m -> m "%u top heap words" gc_stat.top_heap_words);
      (* TODO verify signature *)
      let current = t.system_info.softwareVersion in
      if version_is_upgrade ~current ~update:version' then
      begin
        (* store changelog *)
        t.has_changes <- Some changes;
        Lwt.return (Ok changes)
      end
      else
        Lwt.return (Error (Conflict, "Software version downgrade not allowed."))

    let commit_update t =
      match t.has_changes with
      | None -> Error (Precondition_failed, "No update available. Please upload a system image to /system/update.")
      | Some _changes -> Ok () (* TODO call hardware *)

    let cancel_update t =
      match t.has_changes with
      | None -> Error (Precondition_failed, "No update available. Please upload a system image to /system/update.")
      | Some _changes -> t.has_changes <- None; Ok ()

    let prefix_len s = string_of_int (String.length s) ^ ":" ^ s

    let rec backup_directory kv push backup_key path =
      let open Lwt.Infix in
      KV.list kv path >>= function
      | Error e ->
        Log.err (fun m -> m "Error %a while listing path %a during backup."
                    KV.pp_error e Mirage_kv.Key.pp path);
        Lwt.return_unit
      | Ok entries ->
        (* for each key, retrieve value and call push *)
        Lwt_list.iter_s (fun (subpath, kind) ->
            let key = Mirage_kv.Key.(path / subpath) in
            match kind with
            | `Value ->
              begin
                KV.get kv key >|= function
                | Ok data ->
                  let key_str = Mirage_kv.Key.to_string key in
                  (* TODO is it ok to encrypt each entry individually? *)
                  (* encrypt the stream instead *)
                  let data = prefix_len key_str ^ prefix_len data in
                  let adata = Cstruct.of_string "backup" in (* TODO use backup2 *)
                  let encrypted_data = Crypto.encrypt Rng.generate ~key:backup_key ~adata (Cstruct.of_string data) in
                  push (Some (prefix_len (Cstruct.to_string encrypted_data)))
                | Error e ->
                  Log.err (fun m -> m "Error %a while retrieving value %a during backup."
                              KV.pp_error e Mirage_kv.Key.pp key)
              end
            | `Dictionary -> backup_directory kv push backup_key key)
          entries

    let backup t push =
      let open Lwt.Infix in
      Config_store.get_opt t.kv Backup_key >>= function
      | Error e ->
        Log.err (fun m -> m "Error %a while reading backup key." Config_store.pp_error e);
        Lwt.return (Error (Internal_server_error, "Corrupted disk. Check hardware."))
      | Ok None -> Lwt.return (Error (Precondition_failed, "Please configure backup key before doing a backup."))
      | Ok Some backup_key ->
        (* iteratae over keys in KV store *)
        let backup_key' = Crypto.GCM.of_secret backup_key in
        Config_store.get t.kv Backup_salt >>= function
        | Error e ->
          Log.err (fun m -> m "error %a while reading backup salt" Config_store.pp_error e);
          Lwt.return (Error (Internal_server_error, "Corrupted disk. Check hardware."))
        | Ok backup_salt ->
          push (Some (prefix_len (Cstruct.to_string backup_salt)));
          backup_directory t.kv push backup_key' Mirage_kv.Key.empty >|= fun () ->
          push None;
          Ok ()

    exception Decoding_error

    let decode_value char_stream =
      let open Lwt.Infix in
      (* the char stream contains an integer (length of value), followed by ":",
         followed by value *)
      let to_str xs = List.to_seq xs |> String.of_seq in
      (* TODO size-bound the get_while *)
      Lwt.catch (fun () ->
          (Lwt_stream.get_while
             (function ':' -> false | '0'..'9' -> true | _ -> raise Decoding_error)
             char_stream >|= to_str >|= int_of_string) >>= fun n ->
          Lwt_stream.junk char_stream >>= fun () ->
          Lwt_stream.nget n char_stream >|= to_str >|= fun data ->
          Ok data)
        (function
          | Failure _ | Decoding_error ->
            Lwt.return (Error (Bad_request, "Malformed length field in backup data. Backup not readable, try another one."))
          | e -> raise e)

    let split_kv data =
      (* len:key len:value *)
      let msg = "Missing length field in backup data. Backup not readable, try another one." in
      match Astring.String.cut ~sep:":" data with
      | None -> Error (Bad_request, msg)
      | Some (len_str, rest) ->
        let len = int_of_string len_str in
        let key = String.sub rest 0 len in
        match Astring.String.cut ~sep:":" (String.sub rest len (String.length rest - len)) with
        | None -> Error (Bad_request, msg)
        | Some (len, data) ->
          if String.length data = int_of_string len then
            Ok (key, data)
          else
            Error (Bad_request, "Unexpected length in backup data. Backup not readable, try another one.")

    let read_and_decrypt char_stream key =
      let open Lwt.Infix in
      decode_value char_stream >|= function
      | Error e -> Error e
      | Ok encrypted_data ->
        let adata = Cstruct.of_string "backup" in
        match Crypto.decrypt ~key ~adata (Cstruct.of_string encrypted_data) with
        | Ok kv -> split_kv (Cstruct.to_string kv)
        | Error `Insufficient_data -> Error (Bad_request, "Could not decrypt backup. Backup incomplete, try another one.")
        | Error `Not_authenticated -> Error (Bad_request, "Could not decrypt backup, authentication failed. Is the passphrase correct?")

    let get_query_parameters uri =
      match Uri.get_query_param uri "systemTime" with
      | None -> Error (Bad_request, "Request is missing system time.")
      | Some timestamp -> match Json.decode_time timestamp with
        | Error e -> Error (Bad_request, "Request parse error: " ^ e ^ ".")
        | Ok timestamp -> 
          match Uri.get_query_param uri "backupPassphrase" with
          | None -> Error (Bad_request, "Request is missing backup passphrase.")
          | Some backup_passphrase -> Ok (timestamp, backup_passphrase)

    let restore t uri stream =
      let open Lwt.Infix in
      let (>>==) = Lwt_result.bind in
      let hw_clock = Ptime.v (Pclock.now_d_ps ()) in
      Lwt.return @@ get_query_parameters uri >>== fun (timestamp, backup_passphrase) ->
      let char_stream = Lwt_stream.(concat (map of_string stream)) in
      decode_value char_stream >>== fun backup_salt ->
      let backup_key =
        Crypto.key_of_passphrase ~salt:(Cstruct.of_string backup_salt) backup_passphrase
      in
      let key = Crypto.GCM.of_secret backup_key in
      let rec next () =
        Lwt_stream.is_empty char_stream >>= function
        | true -> t.state <- Locked ; Lwt.return (Ok ())
        | false ->
          read_and_decrypt char_stream key >>== fun (k, v) ->
          internal_server_error "restoring backup (writing to KV)" KV.pp_write_error
            (KV.set t.kv (Mirage_kv.Key.v k) v) >>== fun () ->
          next () 
      in
      let open Lwt_result.Infix in
      next () >>= fun () ->
      set_time_offset ~hw_clock t timestamp
  end
end
