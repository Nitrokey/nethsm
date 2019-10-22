module type S = sig

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
  ]

  val state_to_yojson : state -> Yojson.Safe.t

  type system_info = {
    firmwareVersion : string ;
    softwareVersion : string ;
    hardwareVersion : string ;
  }

  val system_info_to_yojson : system_info -> Yojson.Safe.t

  type t

  val info : t -> info

  val state : t -> state

  val certificate_chain : t ->
    (X509.Certificate.t * X509.Certificate.t list * X509.Private_key.t) Lwt.t

  val network_configuration : t ->
    (Ipaddr.V4.t * Ipaddr.V4.Prefix.t * Ipaddr.V4.t option) Lwt.t

  val provision : t -> unlock:string -> admin:string -> Ptime.t ->
    (unit, [> `Msg of string ]) result Lwt.t

  val unlock : t -> passphrase:string ->
    (unit, [> `Msg of string ]) result Lwt.t

  module Config : sig
    val change_unlock_passphrase : t -> passphrase:string ->
      (unit, [> `Msg of string ]) result Lwt.t

    val unattended_boot : unit -> unit

    val tls_public_pem : t -> string Lwt.t

    val tls_cert_pem : t -> string Lwt.t

    val change_tls_cert_pem : t -> string ->
      (unit, [> `Msg of string ]) result Lwt.t

    val tls_csr_pem : t -> string Lwt.t

    type network = {
      ipAddress : Ipaddr.V4.t ;
      netmask : Ipaddr.V4.t ;
      gateway : Ipaddr.V4.t ;
    }

    val network_to_yojson : network -> Yojson.Safe.t

    val network_of_yojson : Yojson.Safe.t -> (network, string) result

    val network : t -> network Lwt.t

    val change_network : t -> network ->
      (unit, [> `Msg of string ]) result Lwt.t

    val logging : unit -> unit

    val backup_passphrase : unit -> unit

    val time : unit -> unit
  end

  module System : sig
    val system_info : t -> system_info

    val reboot : unit -> unit

    val shutdown : unit -> unit

    val reset : t -> unit

    val update : unit -> unit

    val backup : unit -> unit

    val restore : unit -> unit
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

    val change_passphrase : t -> id:string -> passphrase:string ->
      (unit, [> `Msg of string ]) result Lwt.t
  end
end

let lwt_error_to_msg ~pp_error thing =
  let open Lwt.Infix in
  thing >|= fun x ->
  Rresult.R.error_to_msg ~pp_error x

let hsm_src = Logs.Src.create "hsm" ~doc:"HSM log"
module Log = (val Logs.src_log hsm_src : Logs.LOG)

module Make (Rng : Mirage_random.C) (KV : Mirage_kv_lwt.RW) = struct
  (* fatal is called on error conditions we do not expect (hardware failure,
     KV inconsistency).

     TODO this is temporary and may instead result in a HSM that:
     (a) reports a more detailed error (if available) -- already done at call site using Logs
     (b) can be reset to factory defaults (and then be provisioned)
     (c) can be backed up? or sent in for recovery / hardware replacement
  *)
  let fatal prefix ~pp_error e =
    Log.err (fun m -> m "fatal in %s %a" prefix pp_error e);
    assert false

  let lwt_error_fatal prefix ~pp_error thing =
    let open Lwt.Infix in
    thing >|= function
    | Ok a -> Ok a
    | Error e -> fatal prefix ~pp_error e

  type info = {
    vendor : string ;
    product : string ;
    version : string ;
  }[@@deriving yojson]

  type state = [
    | `Unprovisioned
    | `Operational
    | `Locked
  ][@@deriving yojson]

  let pp_state ppf s =
    Fmt.string ppf (match s with
        | `Unprovisioned -> "unprovisioned"
        | `Operational -> "operational"
        | `Locked -> "locked")


  let state_to_yojson state =
    `Assoc [ ("state", match state_to_yojson state with
        `List [l] -> l | _ -> assert false) ]

  type system_info = {
    firmwareVersion : string ;
    softwareVersion : string ;
    hardwareVersion : string ;
  }[@@deriving yojson]

  module Kv_config = Kv_config.Make(KV)
  module Kv_domain = Kv_domain_key.Make(Rng)(KV)
  module Kv_crypto = Kv_crypto.Make(Rng)(KV)

  type keys = {
    domain_key : Cstruct.t ; (* needed when unloc kpassphrase changes and likely for unattended boot *)
    auth_store : Kv_crypto.t ;
    key_store : Kv_crypto.t ;
  }

  type internal_state =
    | Unprovisioned
    | Locked
    | Operational of keys

  let to_external_state = function
    | Unprovisioned -> `Unprovisioned
    | Locked -> `Locked
    | Operational _ -> `Operational

  type t = {
    mutable state : internal_state ;
    kv : KV.t ;
    info : info ;
    system_info : system_info ;
  }

  let state t = to_external_state t.state

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

  let make kv =
    let t =
      {
        state = Unprovisioned ;
        kv ;
        info = { vendor = "Nitrokey UG" ; product = "NitroHSM" ; version = "v1" } ;
        system_info = { firmwareVersion = "1" ; softwareVersion = "0.7rc3" ; hardwareVersion = "2.2.2" } ;
      }
    in
    let open Lwt_result.Infix in
    Lwt_result.get_exn
      (lwt_error_fatal "get version from configuration store"
         ~pp_error:Kv_config.pp_error
         (Kv_config.get_opt t.kv Version >>= function
           | None ->
             (* uninitialized / unprovisioned device, write version *)
             lwt_error_fatal "set version to configuration store"
               ~pp_error:KV.pp_write_error
               (Kv_config.set t.kv Version Version.current >|= fun () -> t)
           | Some version ->
             match Version.(compare current version) with
             | `Equal ->
               (* if unlock-salt is present, go to locked *)
               lwt_error_fatal "get unlock-salt" ~pp_error:Kv_config.pp_error
                 (Kv_config.get_opt t.kv Unlock_salt >|= function
                   | Some _ -> t.state <- Locked; t
                   | None -> t)
             | `Smaller ->
               fatal "configuration version smaller" ~pp_error:Fmt.string "exiting"
             | `Greater ->
               (* here's the place to embed migration code, at least for the
                  configuration store *)
               fatal "configuration version greater"
                 ~pp_error:Fmt.string "no migration code available"))

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

    let change_passphrase t ~id ~passphrase =
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
          (Kv_crypto.initialize Version.current `Authentication ~key:auth_store_key t.kv)
        >>= fun auth_store ->
        lwt_error_fatal
          "initializing key store" ~pp_error:Kv_crypto.pp_write_error
          (Kv_crypto.initialize Version.current `Key ~key:key_store_key t.kv)
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
          (Kv_domain.set t.kv `Passphrase ~unlock_key domain_key) >>= fun () ->
        lwt_error_fatal "set unlock-salt" ~pp_error:KV.pp_write_error
          (Kv_config.set t.kv Unlock_salt unlock_salt)
          (* TODO compute "time - our_current_idea_of_now", store offset in
                  configuration store *)
      )

  let unlock t ~passphrase =
    let open Lwt_result.Infix in
    expect_state t `Locked >>= fun () ->
    lwt_error_fatal "get unlock-salt" ~pp_error:Kv_config.pp_error
      (Kv_config.get t.kv Unlock_salt) >>= fun salt ->
    let unlock_key = Crypto.key_of_passphrase ~salt passphrase in
    lwt_error_fatal "get domain key" ~pp_error:Rresult.R.pp_msg
      (Kv_domain.get t.kv `Passphrase ~unlock_key) >>= fun domain_key ->
    let auth_store_key, key_store_key =
      Cstruct.split domain_key Crypto.key_len
    in
    lwt_error_fatal
      "connecting to authentication store" ~pp_error:Kv_crypto.pp_connect_error
      (Kv_crypto.connect Version.current `Authentication ~key:auth_store_key t.kv)
    >>= (function
        | `Version_greater (stored, _t) ->
          (* upgrade code for authentication store *)
          fatal "authentication store too old, no migration code"
            ~pp_error:Version.pp stored
        | `Kv auth_store -> Lwt.return (Ok auth_store)) >>= fun auth_store ->
    lwt_error_fatal
      "connecting to key store" ~pp_error:Kv_crypto.pp_connect_error
      (Kv_crypto.connect Version.current `Key ~key:key_store_key t.kv)
    >>= (function
        | `Version_greater (stored, _t) ->
          (* upgrade code for key store *)
          fatal "key store too old, no migration code"
            ~pp_error:Version.pp stored
        | `Kv key_store -> Lwt.return (Ok key_store)) >|= fun key_store ->
    let keys = { domain_key ; auth_store ; key_store } in
    t.state <- Operational keys

  module Config = struct
    let change_unlock_passphrase t ~passphrase =
      match t.state with
      | Operational keys ->
        let open Lwt_result.Infix in
        let unlock_salt = Rng.generate Crypto.salt_len in
        let unlock_key = Crypto.key_of_passphrase ~salt:unlock_salt passphrase in
        (* TODO the two writes below should be a transaction *)
        lwt_error_to_msg ~pp_error:KV.pp_write_error
          (Kv_config.set t.kv Unlock_salt unlock_salt) >>= fun () ->
        lwt_error_to_msg ~pp_error:KV.pp_write_error
          (Kv_domain.set t.kv `Passphrase ~unlock_key keys.domain_key)
      | _ ->
        Lwt.return
          (Rresult.R.error_msgf "expected operation HSM, found %a"
             pp_state (state t))

    let unattended_boot () = ()

    let tls_public_pem t =
      let open Lwt.Infix in
      certificate_chain t >|= fun (certificate, _, _) ->
      let public = X509.Certificate.public_key certificate in
      Cstruct.to_string (X509.Public_key.encode_pem public)

    let tls_cert_pem t =
      let open Lwt.Infix in
      certificate_chain t >|= fun (cert, chain, _) ->
      Cstruct.to_string (X509.Certificate.encode_pem_multiple (cert :: chain))

    let change_tls_cert_pem t cert_data =
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

    let tls_csr_pem t =
      let open Lwt.Infix in
      certificate_chain t >|= fun (_, _, priv) ->
      let csr, _ = generate_csr priv in
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

    let change_network t network =
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
      lwt_error_to_msg ~pp_error:KV.pp_write_error
        Kv_config.(set t.kv Ip_config (network.ipAddress, prefix, route))

    let logging () = ()

    let backup_passphrase () = ()

    let time () = ()
  end

  module System = struct
    let system_info t = t.system_info

    let reboot () = ()

    let shutdown () = ()

    let reset _t = ()

    let update () = ()

    let backup () = ()

    let restore () = ()
  end
end
