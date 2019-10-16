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

  val provision : t -> unlock:string -> admin:string -> Ptime.t ->
    (unit, [> `Msg of string ]) result Lwt.t

  val unlock : t -> passphrase:string ->
    (unit, [> `Msg of string ]) result Lwt.t

  (* /config *)

  val change_unlock_passphrase : t -> passphrase:string ->
    (unit, [> `Msg of string ]) result Lwt.t

  val unattended_boot : unit -> unit

  val tls_public_pem : t -> string Lwt.t

  val tls_cert_pem : t -> string Lwt.t

  val change_tls_cert_pem : t -> string ->
    (unit, [> `Msg of string ]) result Lwt.t

  val tls_csr_pem : t -> string Lwt.t

  val network : unit -> unit

  val logging : unit -> unit

  val backup_passphrase : unit -> unit

  val time : unit -> unit

  (* /system *)

  val system_info : t -> system_info

  val reboot : unit -> unit

  val shutdown : unit -> unit

  val reset : t -> unit

  val update : unit -> unit

  val backup : unit -> unit

  val restore : unit -> unit

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

open Lwt.Infix

let hsm_src = Logs.Src.create "hsm" ~doc:"HSM log"
module Log = (val Logs.src_log hsm_src : Logs.LOG)

module Make (Rng : Mirage_random.C) (KV : Mirage_kv_lwt.RW) = struct
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

  (* TODO instead of mutable and option, push kvs + dk into state polyvar!? *)
  type t = {
    mutable state : state ;
    kv : KV.t ;
    mutable domain_key : Cstruct.t ; (* needed when unlockpassphrase changes / unattended boot *)
    mutable auth_store : Kv_crypto.t option ;
    mutable key_store : Kv_crypto.t option ;
    info : info ;
    system_info : system_info ;
  }

  let expect_state t state =
    let r =
      if t.state = state then
        Ok ()
      else
        Rresult.R.error_msgf "expected HSM in %a, but it is %a"
          pp_state state pp_state t.state
    in
    Lwt.return r

  (* fatal is called on error conditions we do not expect (hardware failure,
     KV inconsistency).

     TODO this is temporary and may instead result in a HSM that:
     (a) reports a more detailed error (if available) -- already done at call site using Logs
     (b) can be reset to factory defaults (and then be provisioned)
     (c) can be backed up? or sent in for recovery / hardware replacement
  *)
  let fatal () = assert false

  let make kv =
    let t =
      {
        state = `Unprovisioned ;
        kv ;
        domain_key = Cstruct.empty ;
        auth_store = None ; key_store = None ;
        info = { vendor = "Nitrokey UG" ; product = "NitroHSM" ; version = "v1" } ;
        system_info = { firmwareVersion = "1" ; softwareVersion = "0.7rc3" ; hardwareVersion = "2.2.2" } ;
      }
    in
    Kv_config.get t.kv Version >>= function
    | Error `Kv `Not_found _ ->
      (* uninitialised / unprovisioned device, write version *)
      begin Kv_config.set t.kv Version Version.current >|= function
        | Ok () -> t
        | Error e ->
          Log.err (fun m -> m "error %a writing version to store"
                      KV.pp_write_error e);
          fatal ()
      end
    | Error e ->
      Log.err (fun m -> m "unexpected %a reading version" Kv_config.pp_error e);
      fatal ()
    | Ok version -> match Version.(compare current version) with
      | `Smaller -> fatal ()
      | `Greater ->
        (* here's the place to embed migration code, at least for the
             configuration store *)
        fatal ()
      | `Equal ->
        begin
          (* if unlock-salt is present, go to locked *)
          Kv_config.get t.kv Unlock_salt >|= function
          | Ok _ -> t.state <- `Locked; t
          | Error `Kv `Not_found _ -> t
          | Error e ->
            Log.err (fun m -> m "unexpected %a reading unlock-salt"
                        Kv_config.pp_error e);
            fatal ()
        end

  let info t = t.info

  let state t = t.state

  let generate_csr ?(dn = X509.Distinguished_name.singleton CN "keyfender") priv =
    X509.Signing_request.create dn priv, dn

  let generate_cert t priv =
    (* this is before provisioning, our posix time may be not accurate *)
    let valid_from = Ptime.epoch
    and valid_until = Ptime.max
    in
    let csr, dn = generate_csr priv in
    let cert =
      X509.Signing_request.sign csr ~valid_from ~valid_until priv dn
    in
    Kv_config.set t.kv Certificate (cert, []) >|= function
    | Error e ->
      Log.err (fun m -> m "couldn't write certificate %a" KV.pp_write_error e);
      fatal ()
    | Ok () -> cert

  let certificate_chain t =
    Kv_config.get t.kv Private_key >>= function
    | Ok priv ->
      begin
        Kv_config.get t.kv Certificate >>= function
        | Ok (certs, chain) -> Lwt.return (certs, chain, priv)
        | Error `Kv `Not_found _ ->
          (* cannot happen: certificate is written first, private key afterwards *)
          Log.err (fun m -> m "unexpected not found reading TLS certificate");
          fatal ()
        | Error e ->
          Log.err (fun m -> m "unexpected %a reading TLS certificate"
                      Kv_config.pp_error e);
          fatal ()
      end
    | Error `Kv `Not_found _ ->
      begin
        (* no key -> generate, generate certificate *)
        let priv = `RSA (Nocrypto.Rsa.generate Crypto.initial_key_rsa_bits) in
        generate_cert t priv >>= fun cert ->
        Kv_config.set t.kv Private_key priv >>= function
        | Error e ->
          Log.err (fun m -> m "error writing private key %a"
                      KV.pp_write_error e);
          fatal ()
        | Ok () -> Lwt.return (cert, [], priv)
      end
    | Error e ->
      Log.err (fun m -> m "unexpected %a reading TLS private key"
                  Kv_config.pp_error e);
      fatal ()

  module User = struct
    type role = [ `Administrator | `Operator | `Metrics | `Backup ] [@@deriving yojson]
    type user = { name : string ; salt : string ; digest : string ; role : role } [@@deriving yojson]

    let decode data =
      let open Rresult.R.Infix in
      (try Ok (Yojson.Safe.from_string data) with _ -> Error `Json_decode) >>= fun json ->
      (match user_of_yojson json with Ok user -> Ok user | Error _ -> Error `Json_decode)

    let find t id =
      match t.auth_store with
      | None -> Lwt.return (Error `Not_unlocked)
      | Some auth ->
        Kv_crypto.get auth (Mirage_kv.Key.v id) >|= function
        | Error _ -> Error `Not_found (* TODO other errors? *)
        | Ok data -> decode data

    let is_authenticated t ~username ~passphrase =
      find t username >|= function
      | Error _ -> false (* TODO write log *)
      | Ok user ->
        let pass = Crypto.key_of_passphrase ~salt:(Cstruct.of_string user.salt) passphrase in
        Cstruct.equal pass (Cstruct.of_string user.digest)

    let is_authorized t username role =
      find t username >|= function
      | Error _ -> false
      | Ok user -> user.role = role

    let write t id user =
      match t.auth_store with
      | None -> Lwt.return (Error (`Msg "not unlocked"))
      | Some auth_store ->
        let user_str = Yojson.Safe.to_string (user_to_yojson user) in
        Kv_crypto.set auth_store (Mirage_kv.Key.v id) user_str >|=
        Rresult.R.reword_error
          (fun e -> `Msg (Fmt.to_to_string Kv_crypto.pp_write_error e))

    (* TODO: validate username/id *)
    let add ?id t ~role ~passphrase ~name =
      let id = match id with
        | Some id -> id
        | None ->
          let `Hex id = Hex.of_cstruct (Rng.generate 10) in
          id
      in
      let user =
        let salt = Rng.generate Crypto.salt_len in
        let digest = Crypto.key_of_passphrase ~salt passphrase in
        { name ; salt = Cstruct.to_string salt ;
          digest = Cstruct.to_string digest ; role }
      in
      find t id >>= function
      | Error `Not_found -> write t id user
      | Ok _ -> Lwt.return (Error (`Msg "user already exists"))
      | Error `Not_unlocked -> Lwt.return (Error (`Msg "HSM not unlocked"))
      | Error `Json_decode -> Lwt.return (Error (`Msg "json decoding failure"))

    let list t =
      match t.auth_store with
      | None -> Lwt.return (Error (`Msg "no auth store"))
      | Some auth_store ->
        Kv_crypto.list auth_store Mirage_kv.Key.empty >|= function
        | Error e -> Error (`Msg (Fmt.to_to_string Kv_crypto.pp_error e))
        | Ok xs ->
          let ids = List.map fst (List.filter (fun (_, typ) -> typ = `Value) xs) in
          Ok ids

    let remove t name =
      match t.auth_store with
      | None -> Lwt.return (Error (`Msg "no auth store"))
      | Some auth_store ->
        Kv_crypto.remove auth_store (Mirage_kv.Key.v name) >|= function
        | Ok () -> Ok ()
        | Error e -> Error (`Msg (Fmt.to_to_string Kv_crypto.pp_write_error e))

    let change_passphrase t ~id ~passphrase =
      find t id >>= function
      | Error _ -> Lwt.return (Error (`Msg "couldn't find user"))
      | Ok user ->
        let salt' = Rng.generate Crypto.salt_len in
        let digest' = Crypto.key_of_passphrase ~salt:salt' passphrase in
        let user' =
          { user with salt = Cstruct.to_string salt' ;
                      digest = Cstruct.to_string digest' }
        in
        write t id user'
  end

  let transition_to_operational ~init t domain_key =
    t.domain_key <- domain_key;
    let auth_store_key, key_store_key =
      Cstruct.split domain_key Crypto.key_len
    in
    (* TODO this may fail unexpectedly: auth_store set to Some h, but neither
            key_store nor state being updated ~> inconsistency *)
    (Kv_crypto.connect ~init Version.current `Authentication ~key:auth_store_key t.kv >|= function
      | Error `Msg e ->
        Log.err (fun m -> m "error %s connection auth store" e); fatal ()
      | Error `Different_version (_t, stored) ->
        (* here should the code for data upgrades be! *)
        Log.err (fun m -> m "different version: current %s, stored %s"
                    Version.(to_string current) (Version.to_string stored));
        fatal ()
      | Ok kv_auth -> t.auth_store <- Some kv_auth) >>= fun () ->
    (Kv_crypto.connect ~init Version.current `Key ~key:key_store_key t.kv >|= function
      | Error `Msg e ->
        Log.err (fun m -> m "error %s connection key store" e); fatal ()
      | Error `Different_version (_t, stored) ->
        (* here should the code for data upgrades be! *)
        Log.err (fun m -> m "different version: current %s, stored %s"
                    Version.(to_string current) (Version.to_string stored));
        fatal ()
      | Ok kv_key -> t.key_store <- Some kv_key) >|= fun () ->
    t.state <- `Operational

  let provision_mutex = Lwt_mutex.create ()

  let provision t ~unlock ~admin _time =
    Lwt_mutex.with_lock provision_mutex (fun () ->
        let open Lwt_result.Infix in
        expect_state t `Unprovisioned >>= fun () ->
        let open Lwt.Infix in
        let unlock_salt = Rng.generate Crypto.salt_len in
        let unlock_key = Crypto.key_of_passphrase ~salt:unlock_salt unlock in
        let domain_key = Rng.generate (Crypto.key_len * 2) in
        transition_to_operational ~init:true t domain_key >>= fun () ->
        (* to avoid dangerous persistent states, do the exact sequence:
           (1) write admin user
           (2) write domain key
           (3) write unlock-salt

           reading back on system start first reads unlock-salt, if this fails,
           the HSM is in unprovisioned state *)
        User.add ~id:"admin" t ~role:`Administrator ~passphrase:admin ~name:"admin" >>= function
        | Error `Msg msg ->
          Log.err (fun m -> m "error writing admin user %s" msg);
          fatal ()
        | Ok () ->
          Kv_domain.set t.kv `Passphrase ~unlock_key domain_key >>= function
          | Error e ->
            Log.err (fun m -> m "error writing domain_key %a"
                        KV.pp_write_error e);
            fatal ()
          | Ok () ->
            Kv_config.set t.kv Unlock_salt unlock_salt >|= function
            | Error e ->
              Log.err (fun m -> m "error writing unlock-salt %a"
                          KV.pp_write_error e);
              fatal ()
            | Ok () -> Ok ()
            (* TODO compute "time - our_current_idea_of_now", store offset in
                    configuration store *)
      )

  let unlock t ~passphrase =
    let open Lwt_result.Infix in
    expect_state t `Locked >>= fun () ->
    let open Lwt.Infix in
    Kv_config.get t.kv Unlock_salt >>= function
    | Error e ->
      Log.err (fun m -> m "couldn't read salt %a" Kv_config.pp_error e);
      fatal ()
    | Ok salt ->
      let unlock_key = Crypto.key_of_passphrase ~salt passphrase in
      Kv_domain.get t.kv `Passphrase ~unlock_key >>= function
      | Error `Msg e ->
        (* cannot happen: domain key is written before unlock-salt *)
        Log.err (fun m -> m "couldn't read domain key %s" e);
        fatal ()
      | Ok domain_key ->
        transition_to_operational ~init:false t domain_key >|= fun () ->
        Ok ()

  (* /config *)

  let change_unlock_passphrase t ~passphrase =
    let open Lwt_result.Infix in
    expect_state t `Operational >>= fun () ->
    let open Lwt.Infix in
    let unlock_salt = Rng.generate Crypto.salt_len in
    let unlock_key = Crypto.key_of_passphrase ~salt:unlock_salt passphrase in
    (* TODO (a) write error handling (b) the two writes below should be a transaction *)
    Kv_config.set t.kv Unlock_salt unlock_salt >>= fun _ ->
    Kv_domain.set t.kv `Passphrase ~unlock_key t.domain_key >|= fun _ ->
    Ok ()

  let unattended_boot () = ()

  let tls_public_pem t =
    certificate_chain t >|= fun (certificate, _, _) ->
    let public = X509.Certificate.public_key certificate in
    Cstruct.to_string (X509.Public_key.encode_pem public)

  let tls_cert_pem t =
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
          Kv_config.set t.kv Certificate (cert, chain) >|=
          Rresult.R.error_to_msg ~pp_error:KV.pp_write_error
      else
        Lwt.return (Error (`Msg "public key in certificate does not match private key"))

  let tls_csr_pem t =
    certificate_chain t >|= fun (_, _, priv) ->
    let csr, _ = generate_csr priv in
    Cstruct.to_string (X509.Signing_request.encode_pem csr)

  let network () = ()

  let logging () = ()

  let backup_passphrase () = ()

  let time () = ()

  (* /system *)

  let system_info t = t.system_info

  let reboot () = ()

  let shutdown () = ()

  let reset _t = ()

  let update () = ()

  let backup () = ()

  let restore () = ()
end
