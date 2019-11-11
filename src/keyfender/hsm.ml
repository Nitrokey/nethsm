module type S = sig

  type status_code =  
               | Internal_server_error 
               | Bad_request
               | Precondition_failed
  
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
    (unit, [> `Msg of string ]) result Lwt.t

  val unlock_with_passphrase : t -> passphrase:string ->
    (unit, [> `Msg of string ]) result Lwt.t

  val random : int -> string

  module Config : sig
    val set_unlock_passphrase : t -> passphrase:string ->
      (unit, [> `Msg of string ]) result Lwt.t

    val unattended_boot : t -> (bool, [> `Msg of string ]) result Lwt.t

    val set_unattended_boot : t -> bool ->
      (unit, [> `Msg of string ]) result Lwt.t

    val tls_public_pem : t -> string Lwt.t

    val tls_cert_pem : t -> string Lwt.t

    val set_tls_cert_pem : t -> string ->
      (unit, [> `Msg of string ]) result Lwt.t

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
      (unit, [> `Msg of string ]) result Lwt.t

    type log = { ipAddress : Ipaddr.V4.t ; port : int ; logLevel : Logs.level }

    val log_to_yojson : log -> Yojson.Safe.t

    val log_of_yojson : Yojson.Safe.t -> (log, string) result

    val log : t -> log Lwt.t

    val set_log : t -> log -> (unit, [> `Msg of string ]) result Lwt.t

    val backup_passphrase : t -> passphrase:string ->
      (unit, [> `Msg of string ]) result Lwt.t

    val time : t -> Ptime.t Lwt.t

    val set_time : t -> Ptime.t -> (unit, [> `Msg of string ]) result Lwt.t
  end

  module System : sig
    val system_info : t -> system_info

    val reboot : t -> unit

    val shutdown : t -> unit

    val reset : t -> (unit, [> `Msg of string ]) result Lwt.t 

    val update : t -> string Lwt_stream.t -> (string, [> `Msg of string ]) result Lwt.t

    val commit_update : t -> (unit, [> `Msg of string ]) result Lwt.t

    val cancel_update : t -> unit

    val backup : t -> (string option -> unit) ->
      (unit, error) result Lwt.t

    val restore : t -> Uri.t -> string Lwt_stream.t ->
      (unit, error) result Lwt.t
  end

  module User : sig
    type role = [ `Administrator | `Operator | `Metrics | `Backup ]

    val is_authenticated : t -> username:string -> passphrase:string ->
      bool Lwt.t

    val is_authorized : t -> string -> role -> bool Lwt.t

    val list : t -> (string list, [> `Msg of string ]) result Lwt.t

    val add : ?id:string -> t -> role:role -> passphrase:string ->
      name:string -> (unit, [> `Msg of string ]) result Lwt.t

    val remove : t -> string -> (unit, [> `Msg of string ]) result Lwt.t

    val set_passphrase : t -> id:string -> passphrase:string ->
      (unit, [> `Msg of string ]) result Lwt.t
  end
end

let lwt_error_to_msg ~pp_error thing =
  let open Lwt.Infix in
  thing >|= fun x ->
  Rresult.R.error_to_msg ~pp_error x

let hsm_src = Logs.Src.create "hsm" ~doc:"HSM log"
module Log = (val Logs.src_log hsm_src : Logs.LOG)

module Make (Rng : Mirage_random.C) (KV : Mirage_kv_lwt.RW) (Pclock : Mirage_clock.PCLOCK) = struct
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
  
  (* string is the body, which may contain error message *)
  type error = status_code * string

  let error_to_code code =
    let status = match code with
    | Internal_server_error -> `Internal_server_error
    | Bad_request -> `Bad_request
    | Precondition_failed -> `Precondition_failed in
    Cohttp.Code.code_of_status status

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
    `Assoc [ ("state", match state_to_yojson state with
        `List [l] -> l | _ -> assert false) ]

  type version = int * int 

  let version_to_string (major, minor) = Printf.sprintf "%u.%u" major minor
  let version_of_string s = match Astring.String.cut ~sep:"." s with
    | None -> Error (`Msg "Failed to parse version: no separator (.)")
    | Some (major, minor) -> 
      try 
        let ma = int_of_string major
        and mi = int_of_string minor
        in
        Ok (ma, mi) 
      with Failure _ -> Error (`Msg "Failed to parse version")                  

  let version_to_yojson v = `String (version_to_string v)
  let version_of_yojson _ = Error "Cannot convert version"
  let version_is_upgrade ~current ~update = fst current <= fst update

  type system_info = {
    firmwareVersion : string ;
    softwareVersion : version ;
    hardwareVersion : string ;
  }[@@deriving yojson]

  module Kv_config = Kv_config.Make(KV)
  module Kv_domain = Kv_domain_key.Make(Rng)(KV)
  module Kv_crypto = Kv_crypto.Make(Rng)(KV)

  type keys = {
    domain_key : Cstruct.t ; (* needed when unlock passphrase changes and likely for unattended boot *)
    auth_store : Kv_crypto.t ;
    key_store : Kv_crypto.t ;
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

  let expect_state t desired_state =
    let st = state t in
    let r =
      if st = desired_state then
        Ok ()
      else
        Rresult.R.error_msgf "expected HSM in %a, but it is %a"
          pp_state desired_state pp_state st
    in
    Lwt.return r

  let prepare_keys t slot credentials =
    let open Lwt_result.Infix in
    let get_salt_key = function
      | Kv_domain.Passphrase -> Kv_config.Unlock_salt
      | Kv_domain.Device_id -> Kv_config.Device_id_salt
    in
    lwt_error_to_msg ~pp_error:Kv_config.pp_error
      (Kv_config.get t.kv (get_salt_key slot)) >>= fun salt ->
    let unlock_key = Crypto.key_of_passphrase ~salt credentials in
    Kv_domain.get t.kv slot ~unlock_key >|= fun domain_key ->
    let auth_store_key, key_store_key =
      Cstruct.split domain_key Crypto.key_len
    in
    (domain_key, auth_store_key, key_store_key)

  let unlock_store kv slot key =
    let open Lwt_result.Infix in
    let slot_str = Kv_crypto.slot_to_string slot in
    lwt_error_fatal
      ("connecting to " ^ slot_str ^ " store")
      ~pp_error:Kv_crypto.pp_connect_error
      (Kv_crypto.unlock Version.current slot ~key kv)
    >>= (function
        | `Version_greater (stored, _t) ->
          (* upgrade code for authentication store *)
          fatal (slot_str ^ " store too old, no migration code")
            ~pp_error:Version.pp stored
        | `Kv store -> Lwt.return (Ok store))

  (* credential is passphrase or device id, depending on boot mode *)
  let unlock t slot credentials =
    let open Lwt_result.Infix in
    expect_state t `Locked >>= fun () ->
    prepare_keys t slot credentials >>= fun (domain_key, as_key, ks_key) ->
    unlock_store t.kv Authentication as_key >>= fun auth_store ->
    unlock_store t.kv Key ks_key >|= fun key_store ->
    let keys = { domain_key ; auth_store ; key_store } in
    t.state <- Operational keys

  let unlock_with_device_id t ~device_id = unlock t Device_id device_id

  let unlock_with_passphrase t ~passphrase = unlock t Passphrase passphrase

  let boot_config_store t =
    let open Lwt_result.Infix in
    lwt_error_fatal "get unlock-salt" ~pp_error:Kv_config.pp_error
      (Kv_config.get_opt t.kv Unlock_salt) >>= function
        | None -> Lwt.return (Ok t)
        | Some _ ->
          t.state <- Locked;
          lwt_error_fatal "get unattended boot" ~pp_error:Kv_config.pp_error
            (Kv_config.get_opt t.kv Unattended_boot) >>= function
          | Some true ->
            begin
              let open Lwt.Infix in
              let device_id = "my device id, psst" in
              (unlock_with_device_id t ~device_id >|= function
                | Ok () -> ()
                | Error `Msg msg ->
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
      lwt_error_to_msg ~pp_error:Kv_config.pp_error
        (Kv_config.get_opt t.kv Version) >>= function
      | None ->
        (* uninitialized / unprovisioned device, write version *)
        lwt_error_to_msg ~pp_error:KV.pp_write_error
          (Kv_config.set t.kv Version Version.current >|= fun () -> t)
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

  let generate_csr ?(dn = X509.Distinguished_name.singleton CN "keyfender") priv =
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
      (Kv_config.set t.kv Certificate (cert, []) >|= fun () -> cert)

  let certificate_chain t =
    Lwt_result.get_exn
      (let open Lwt_result.Infix in
       lwt_error_fatal "get private key from configuration store"
         ~pp_error:Kv_config.pp_error
         (Kv_config.get_opt t.kv Private_key) >>= function
       | Some priv ->
         lwt_error_fatal "get certificate from configuration store"
           ~pp_error:Kv_config.pp_error
           (Kv_config.get t.kv Certificate >|= fun (cert, chain) ->
            cert, chain, priv)
       | None  ->
         (* no key -> generate, generate certificate *)
         let priv = `RSA (Nocrypto.Rsa.generate Crypto.initial_key_rsa_bits) in
         generate_cert t priv >>= fun cert ->
         lwt_error_fatal "set private key to configuration store"
           ~pp_error:KV.pp_write_error
           (Kv_config.set t.kv Private_key priv >|= fun () ->
            (cert, [], priv)))

  let default_network_configuration =
    let ip = Ipaddr.V4.of_string_exn "192.168.1.1" in
    ip, Ipaddr.V4.Prefix.make 24 ip, None

  let network_configuration t =
    let open Lwt.Infix in
    Kv_config.(get t.kv Ip_config) >|= function
    | Ok cfg -> cfg
    | Error e ->
      Log.warn (fun m -> m "error %a while retrieving IP, using default"
                   Kv_config.pp_error e);
      default_network_configuration

  let random n = Cstruct.to_string @@ Nocrypto.Base64.encode @@ Rng.generate n

  module User = struct
    let user_src = Logs.Src.create "hsm.user" ~doc:"HSM user log"
    module Access = (val Logs.src_log user_src : Logs.LOG)

    type role = [ `Administrator | `Operator | `Metrics | `Backup ] [@@deriving yojson]

    type user = { name : string ; salt : string ; digest : string ; role : role } [@@deriving yojson]

    let pp_role ppf r =
      Fmt.string ppf @@ match r with
      | `Administrator -> "R-Administrator"
      | `Operator -> "R-Operator"
      | `Metrics -> "R-Metrics"
      | `Backup -> "R-Backup"

    let decode data =
      let open Rresult.R.Infix in
      (try Ok (Yojson.Safe.from_string data)
       with Yojson.Json_error msg -> Error (`Json_parse msg)) >>= fun json ->
      (match user_of_yojson json with
       | Ok user -> Ok user
       | Error msg -> Error (`Json_decode msg))

    let read_decode store id =
      let open Lwt.Infix in
      Kv_crypto.get store (Mirage_kv.Key.v id) >|= function
      | Error e -> Error (`Kv_crypto e)
      | Ok data -> decode data

    let pp_find_error ppf = function
      | `Kv_crypto kv -> Kv_crypto.pp_error ppf kv
      | `Json_decode msg -> Fmt.pf ppf "json decode failure %s" msg
      | `Json_parse msg -> Fmt.pf ppf "json parse error %s" msg

    let write store id user =
      let user_str = Yojson.Safe.to_string (user_to_yojson user) in
      lwt_error_to_msg ~pp_error:Kv_crypto.pp_write_error
        (Kv_crypto.set store (Mirage_kv.Key.v id) user_str)

    (* functions below are exported, and take a Hsm.t directly, this the
       wrapper to unpack the auth_store handle. *)
    let in_store t =
      match t.state with
      | Operational keys -> Ok keys.auth_store
      | _ -> Rresult.R.error_msgf "expected operation HSM, found %a"
               pp_state (state t)

    let get_user t id =
      let open Lwt_result.Infix in
      Lwt.return (in_store t) >>= fun keys ->
      lwt_error_to_msg ~pp_error:pp_find_error (read_decode keys id)

    let is_authenticated t ~username ~passphrase =
      let open Lwt.Infix in
      get_user t username >|= function
      | Error `Msg e ->
        Access.warn (fun m -> m "%s unauthenticated: %s" username e);
        false
      | Ok user ->
        let pass = Crypto.key_of_passphrase ~salt:(Cstruct.of_string user.salt) passphrase in
        Cstruct.equal pass (Cstruct.of_string user.digest)

    let is_authorized t username role =
      let open Lwt.Infix in
      get_user t username >|= function
      | Error `Msg e ->
        Access.warn (fun m -> m "%s unauthorized for %a: %s" username pp_role role e);
        false
      | Ok user -> user.role = role

    (* TODO: validate username/id *)
    let add ?id t ~role ~passphrase ~name =
      let id = match id with
        | Some id -> id
        | None ->
          let `Hex id = Hex.of_cstruct (Rng.generate 10) in
          id
      in
      let open Lwt_result.Infix in
      Lwt.return (in_store t) >>= fun store ->
      Lwt.bind (read_decode store id)
        (function
          | Error `Kv_crypto `Kv (`Not_found _) ->
            let user =
              let salt = Rng.generate Crypto.salt_len in
              let digest = Crypto.key_of_passphrase ~salt passphrase in
              { name ; salt = Cstruct.to_string salt ;
                digest = Cstruct.to_string digest ; role }
            in
            write store id user >|= fun () ->
            Access.info (fun m -> m "added %s (%s)" name id)
          | Ok _ -> Lwt.return (Error (`Msg "user already exists"))
          | Error _ as e ->
            Lwt.return (Rresult.R.error_to_msg ~pp_error:pp_find_error e))

    let list t =
      let open Lwt_result.Infix in
      Lwt.return (in_store t) >>= fun store ->
      lwt_error_to_msg ~pp_error:Kv_crypto.pp_error
        (Kv_crypto.list store Mirage_kv.Key.empty) >|= fun xs ->
      List.map fst (List.filter (fun (_, typ) -> typ = `Value) xs)

    let remove t id =
      let open Lwt_result.Infix in
      Lwt.return (in_store t) >>= fun store ->
      lwt_error_to_msg ~pp_error:Kv_crypto.pp_write_error
        (Kv_crypto.remove store (Mirage_kv.Key.v id) >|= fun () ->
         Access.info (fun m -> m "removed (%s)" id))

    let set_passphrase t ~id ~passphrase =
      let open Lwt_result.Infix in
      Lwt.return (in_store t) >>= fun store ->
      lwt_error_to_msg ~pp_error:pp_find_error
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

  let provision_mutex = Lwt_mutex.create ()

  let provision t ~unlock ~admin _time =
    Lwt_mutex.with_lock provision_mutex (fun () ->
        let open Lwt_result.Infix in
        expect_state t `Unprovisioned >>= fun () ->
        let unlock_salt = Rng.generate Crypto.salt_len in
        let unlock_key = Crypto.key_of_passphrase ~salt:unlock_salt unlock in
        let domain_key = Rng.generate (Crypto.key_len * 2) in
        let auth_store_key, key_store_key =
          Cstruct.split domain_key Crypto.key_len
        in
        lwt_error_fatal
          "initializing authentication store" ~pp_error:Kv_crypto.pp_write_error
          (Kv_crypto.initialize Version.current Authentication ~key:auth_store_key t.kv)
        >>= fun auth_store ->
        lwt_error_fatal
          "initializing key store" ~pp_error:Kv_crypto.pp_write_error
          (Kv_crypto.initialize Version.current Key ~key:key_store_key t.kv)
        >>= fun key_store ->
        let keys = { domain_key ; auth_store ; key_store } in
        t.state <- Operational keys;
        (* to avoid dangerous persistent states, do the exact sequence:
           (1) write admin user
           (2) write domain key
           (3) write unlock-salt

           reading back on system start first reads unlock-salt, if this fails,
           the HSM is in unprovisioned state *)
        lwt_error_fatal "set admin user" ~pp_error:Rresult.R.pp_msg
          (User.add ~id:"admin" t ~role:`Administrator ~passphrase:admin ~name:"admin") >>= fun () ->
        lwt_error_fatal "set domain key" ~pp_error:KV.pp_write_error
          (Kv_domain.set t.kv Passphrase ~unlock_key domain_key) >>= fun () ->
        lwt_error_fatal "set unlock-salt" ~pp_error:KV.pp_write_error
          (Kv_config.set t.kv Unlock_salt unlock_salt)
          (* TODO compute "time - our_current_idea_of_now", store offset in
                  configuration store *)
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
        lwt_error_to_msg ~pp_error:KV.pp_write_error
          (Kv_config.set t.kv Unlock_salt unlock_salt) >>= fun () ->
        lwt_error_to_msg ~pp_error:KV.pp_write_error
          (Kv_domain.set t.kv Passphrase ~unlock_key keys.domain_key)
      | _ ->
        Lwt.return
          (Rresult.R.error_msgf "expected operation HSM, found %a"
             pp_state (state t))

    let unattended_boot t =
      let open Lwt_result.Infix in
      lwt_error_to_msg ~pp_error:Kv_config.pp_error
        (Kv_config.get_opt t.kv Unattended_boot >|=
         function None -> false | Some v -> v)

    let set_unattended_boot t status =
      let open Lwt_result.Infix in
      (* (a) change setting in configuration store *)
      (* (b) add or remove salt in configuration store *)
      (* (c) add or remove to domain_key store *)
      match t.state with
      | Operational keys ->
        lwt_error_to_msg ~pp_error:KV.pp_write_error
          (Kv_config.set t.kv Unattended_boot status) >>= fun () ->
        if status then begin
          let salt, unlock_key = salted "my device id, psst" in
          lwt_error_to_msg ~pp_error:KV.pp_write_error
            (Kv_config.set t.kv Device_id_salt salt) >>= fun () ->
          lwt_error_to_msg ~pp_error:KV.pp_write_error
            (Kv_domain.set t.kv Device_id ~unlock_key keys.domain_key)
        end else begin
          lwt_error_to_msg ~pp_error:KV.pp_write_error
            (Kv_config.remove t.kv Device_id_salt) >>= fun () ->
          lwt_error_to_msg ~pp_error:KV.pp_write_error
            (Kv_domain.remove t.kv Device_id)
        end
      | _ ->
        Lwt.return
          (Rresult.R.error_msgf "expected operation HSM, found %a"
             pp_state (state t))

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
      | Error e -> Lwt.return (Error e)
      | Ok [] -> Lwt.return (Error (`Msg "empty certificate chain"))
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
          | Error e -> Lwt.return (Error e)
          | Ok _ ->
            lwt_error_to_msg ~pp_error:KV.pp_write_error
              (Kv_config.set t.kv Certificate (cert, chain))
        else
          Lwt.return (Error (`Msg "public key in certificate does not match private key"))

    let tls_csr_pem t subject =
      let open Lwt.Infix in
      certificate_chain t >|= fun (_, _, priv) ->
      (* TODO add entire subject here *)
      let dn = X509.Distinguished_name.singleton CN subject.Json.commonName in
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
          Rresult.R.error_msgf "error %s parsing netmask %s" err packet) >>= fun prefix ->
      let route =
        if Ipaddr.V4.compare network.gateway Ipaddr.V4.any = 0 then
          None
        else
          Some network.gateway
      in
      (* TODO if successful, reboot (or set the IP address) after responding *)
      lwt_error_to_msg ~pp_error:KV.pp_write_error
        Kv_config.(set t.kv Ip_config (network.ipAddress, prefix, route))

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
      Kv_config.get_opt t.kv Log_config >|= function
      | Ok None -> default_log
      | Ok Some (ipAddress, port, logLevel) -> { ipAddress ; port ; logLevel }
      | Error e ->
        Log.warn (fun m -> m "error %a while getting log configuration"
                     Kv_config.pp_error e);
        default_log

    let set_log t log =
      lwt_error_to_msg ~pp_error:KV.pp_write_error
        (Kv_config.set t.kv Log_config (log.ipAddress, log.port, log.logLevel))

    let backup_passphrase t ~passphrase =
      match t.state with
      | Operational _keys ->
        let open Lwt_result.Infix in
        let backup_salt, backup_key = salted passphrase in
        (* TODO the two writes below should be a transaction *)
        lwt_error_to_msg ~pp_error:KV.pp_write_error
          (Kv_config.set t.kv Backup_salt backup_salt) >>= fun () ->
        lwt_error_to_msg ~pp_error:KV.pp_write_error
          (Kv_config.set t.kv Backup_key backup_key)
      | _ ->
        Lwt.return
          (Rresult.R.error_msgf "expected operation HSM, found %a"
             pp_state (state t))

    let time t =
      let open Lwt.Infix in
      Kv_config.get_opt t.kv Time_offset >|= fun offset ->
      let span = match offset with
        | Ok None -> Ptime.Span.zero
        | Ok Some span -> span
        | Error e ->
          Log.warn (fun m -> m "error %a getting time offset" Kv_config.pp_error e);
          Ptime.Span.zero
      in
      let now = Ptime.v (Pclock.now_d_ps ()) in
      match Ptime.add_span now span with
      | None -> Ptime.epoch
      | Some ts -> ts

    let set_time t timestamp =
      let now = Ptime.v (Pclock.now_d_ps ()) in
      let span = Ptime.diff timestamp now in
      lwt_error_to_msg ~pp_error:KV.pp_write_error
        (Kv_config.set t.kv Time_offset span)
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
      lwt_error_to_msg ~pp_error:KV.pp_write_error
        (KV.remove t.kv Mirage_kv.Key.empty)
      (* TODO reboot the hardware *)

    let put_back stream chunk = Lwt_stream.append (Lwt_stream.of_list [ chunk ]) stream

    let read_n stream n =
      let rec read prefix =
        let open Lwt.Infix in
        Lwt_stream.get stream >>= function
        | None -> Lwt.return @@ Error (`Msg "Malformed update")
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
      (* TODO verify signature *)
      let current = t.system_info.softwareVersion in
      if version_is_upgrade ~current ~update:version' then
      begin
        (* store changelog *)
        t.has_changes <- Some changes;
        Lwt.return (Ok changes)
      end
      else
        Lwt.return (Error (`Msg "Software version downgrade not allowed."))

    let commit_update t =
      match t.has_changes with
      | None -> Lwt.return @@ Error (`Msg "No update available")
      | Some _changes ->
      (* TODO commit update, do we cover all error variants? *)
      Lwt.return @@ Ok ()

    let cancel_update t =
      t.has_changes <- None

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
      Kv_config.get_opt t.kv Backup_key >>= function
      | Error e ->
        Log.err (fun m -> m "Error %a while reading backup key." Kv_config.pp_error e);
        Lwt.return (Error (Internal_server_error, "Corrupted disk. Check hardware."))
      | Ok None -> Lwt.return (Error (Precondition_failed, "Please configure backup key before doing a backup."))
      | Ok Some backup_key ->
        (* iteratae over keys in KV store *)
        let backup_key' = Crypto.GCM.of_secret backup_key in
        Kv_config.get t.kv Backup_salt >>= function
        | Error e ->
          Log.err (fun m -> m "error %a while reading backup salt" Kv_config.pp_error e);
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

    let restore t uri stream =
      let open Lwt.Infix in
      let char_stream = Lwt_stream.(concat (map of_string stream)) in
      match Uri.get_query_param uri "backupPassphrase" with
      | None -> Lwt.return (Error (Bad_request, "Request is missing backup passphrase."))
      | Some backup_passphrase ->
        decode_value char_stream >>= function
        | Error e -> Lwt.return (Error e)
        | Ok backup_salt ->
          let backup_key =
            Crypto.key_of_passphrase ~salt:(Cstruct.of_string backup_salt) backup_passphrase
          in
          let key = Crypto.GCM.of_secret backup_key in
          let rec next () =
            Lwt_stream.is_empty char_stream >>= function
            | true -> t.state <- Locked ; Lwt.return (Ok ())
            | false ->
              read_and_decrypt char_stream key >>= function
              | Error e -> Lwt.return (Error e)
              | Ok (k, v) ->
                KV.set t.kv (Mirage_kv.Key.v k) v >>= function
                | Ok () -> next ()
                | Error e ->
                  Log.err (fun m -> m "error %a restoring backup (writing to KV)"
                              KV.pp_write_error e);
                  Lwt.return (Error (Internal_server_error, "Could not restore backup, disk failure? Check the hardware."))
          in
          next ()
  end
end
