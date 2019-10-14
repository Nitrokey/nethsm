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

  val system_info : t -> system_info

  val state : t -> state

  val certificate : t -> Tls.Config.own_cert Lwt.t

  val provision : t -> unlock:string -> admin:string -> Ptime.t ->
    (unit, [> `Msg of string ]) result Lwt.t

  val unlock : t -> passphrase:string ->
    (unit, [> `Msg of string ]) result Lwt.t

  val change_unlock_passphrase : t -> passphrase:string ->
    (unit, [> `Msg of string ]) result Lwt.t

  val reboot : unit -> unit

  val shutdown : unit -> unit

  val reset : t -> unit

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

  type t = {
    mutable state : state ;
    kv : KV.t ;
    mutable domain_key : Cstruct.t ; (* needed when unlockpassphrase changes / unattended boot *)
    mutable auth_store : Kv_crypto.t option ;
    mutable key_store : Kv_crypto.t option ;
    info : info ;
    system_info : system_info ;
  }

  type version = V0

  let compare_version a b = match a, b with
    | V0, V0 -> `Equal

  let version_to_string = function V0 -> "0"

  let version_of_string = function
    | "0" -> Ok V0
    | s -> Error (`Msg ("unknown version " ^ s))

  let my_version = V0

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
    Kv_config.get t.kv `Version >>= function
    | Error `Not_found _ ->
      (* uninitialised / unprovisioned device, write version *)
      begin Kv_config.set t.kv `Version (version_to_string my_version) >|= function
        | Ok () -> t
        | Error e ->
          Log.err (fun m -> m "error %a while writing version to store"
                      KV.pp_write_error e);
          fatal ()
      end
    | Error e ->
      Log.err (fun m -> m "unexpected %a while reading version"
                  KV.pp_error e);
      fatal ()
    | Ok data -> match version_of_string data with
      | Error `Msg e ->
        Log.err (fun m -> m "couldn't parse version %s" e);
        (* happens with a new kv-store and old software, which we disallow *)
        fatal ()
      | Ok version ->
        match compare_version my_version version with
        | `Smaller -> fatal ()
        | `Greater ->
          (* here's the place to embed migration code, at least for the
             configuration store *)
          fatal ()
        | `Equal ->
          begin
            (* if unlock-salt is present, go to locked *)
            Kv_config.get t.kv `Unlock_salt >|= function
            | Ok _ -> t.state <- `Locked; t
            | Error (`Not_found _) -> t
            | Error e ->
              Log.err (fun m -> m "unexpected %a while reading unlock-salt"
                          KV.pp_error e);
              fatal ()
          end

  let info t = t.info

  let system_info t = t.system_info

  let state t = t.state

  let generate_cert t priv =
    (* this is before provisioning, our posix time may be not accurate *)
    let valid_from = Ptime.epoch
    and valid_until = Ptime.max
    in
    let dn = X509.Distinguished_name.singleton CN "keyfender" in
    let csr = X509.Signing_request.create dn priv in
    let cert =
      X509.Signing_request.sign csr ~valid_from ~valid_until priv dn
    in
    let pem_cert = Cstruct.to_string (X509.Certificate.encode_pem cert) in
    Kv_config.set t.kv `Certificate pem_cert >|= function
    | Error e ->
      Log.err (fun m -> m "couldn't write certificate %a" KV.pp_write_error e);
      fatal ()
    | Ok () -> cert

  let certificate t =
    Kv_config.get t.kv `Private_key >>= function
    | Ok priv_pem ->
      begin
        let raw_priv =
          (* TODO once x509 0.8.1 is released, use DER instead of PEM *)
          match X509.Private_key.decode_pem (Cstruct.of_string priv_pem) with
          | Ok `RSA priv -> priv
          | Error `Msg msg ->
            Log.err (fun m -> m "%s while decoding TLS private key" msg);
            fatal ()
        in
        Kv_config.get t.kv `Certificate >>= function
        | Ok cert_pem ->
          let certs =
            match X509.Certificate.decode_pem_multiple (Cstruct.of_string cert_pem) with
            | Ok certs -> certs
            | Error (`Msg msg) ->
              Log.err (fun m -> m "%s while decoding certificates" msg);
              fatal ()
          in
          Lwt.return (`Single (certs, raw_priv))
        | Error (`Not_found _) ->
          (* this cannot happen: certificate is written first, private key afterwards *)
          Log.err (fun m -> m "unexpected not found reading TLS certificate");
          fatal ()
        | Error e ->
          Log.err (fun m -> m "unexpected %a while reading TLS certificate"
                      KV.pp_error e);
          fatal ()
      end
    | Error (`Not_found _) ->
      begin
        (* no key -> generate, generate certificate *)
        let priv, raw_priv =
          let p = Nocrypto.Rsa.generate Crypto.initial_key_rsa_bits in
          `RSA p, p
        in
        let priv_pem = Cstruct.to_string (X509.Private_key.encode_pem priv) in
        generate_cert t priv >>= fun cert ->
        Kv_config.set t.kv `Private_key priv_pem >>= function
        | Error e ->
          Log.err (fun m -> m "error writing private key %a"
                      KV.pp_write_error e);
          fatal ()
        | Ok () -> Lwt.return (`Single ([ cert ], raw_priv))
      end
    | Error e ->
      Log.err (fun m -> m "unexpected %a while reading TLS private key"
                  KV.pp_error e);
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
    let auth_store_key, key_store_key = Cstruct.split domain_key Crypto.key_len in
    (Kv_crypto.connect ~init `Authentication ~key:auth_store_key t.kv >|= function
      | Error `Msg e -> Log.err (fun m -> m "error %s connection auth store" e); fatal ()
      | Ok kv_auth -> t.auth_store <- Some kv_auth) >>= fun () ->
    (Kv_crypto.connect ~init `Key ~key:key_store_key t.kv >|= function
      | Error `Msg e -> Log.err (fun m -> m "error %s connection key store" e); fatal ()
      | Ok kv_key -> t.key_store <- Some kv_key) >|= fun () ->
    t.state <- `Operational

  let provision_mutex = Lwt_mutex.create ()

  let provision t ~unlock ~admin _time =
    Lwt_mutex.with_lock provision_mutex (fun () ->
        if t.state <> `Unprovisioned then begin
          Log.err (fun m -> m "HSM is already provisioned");
          Lwt.return (Error (`Msg "HSM already provisioned"))
        end else begin
          let unlock_salt = Rng.generate Crypto.salt_len in
          let unlock_key = Crypto.key_of_passphrase ~salt:unlock_salt unlock in
          let domain_key = Rng.generate (Crypto.key_len * 2) in
          transition_to_operational ~init:true t domain_key >>= fun () ->
          (* to avoid dangerous persistent states, do the exact sequence:
             (1) write admin user
             (2) write domain key
             (3) write unlock-salt

             reading back on system start first reads unlock-salt, if this
             fails, the HSM is in unprovisioned state
             TODO: use explicit unprovisioned vs provisioned information by
                   writing an empty file (config/provisioned) *)
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
              Kv_config.set t.kv `Unlock_salt (Cstruct.to_string unlock_salt) >|= function
              | Error e ->
                Log.err (fun m -> m "error writing unlock-salt %a"
                            KV.pp_write_error e);
                fatal ()
              | Ok () -> Ok ()
              (* TODO compute "time - our_current_idea_of_now", store offset
                 in configuration store *)
        end)

  let unlock t ~passphrase =
    match t.state with
    | `Unprovisioned | `Operational ->
      Log.err (fun m -> m "expected locked NitroHSM, found %a" pp_state t.state);
      Lwt.return (Error (`Msg "NitroHSM is not locked"))
    | `Locked ->
      Kv_config.get t.kv `Unlock_salt >>= function
      | Error e ->
        Log.err (fun m -> m "couldn't read salt %a" KV.pp_error e);
        fatal ()
      | Ok salt ->
        let unlock_key = Crypto.key_of_passphrase ~salt:(Cstruct.of_string salt) passphrase in
        Kv_domain.get t.kv `Passphrase ~unlock_key >>= function
        | Error `Msg e ->
          (* cannot happen: domain key is written before unlock-salt *)
          Log.err (fun m -> m "couldn't read domain key %s" e);
          fatal ()
        | Ok domain_key ->
          transition_to_operational ~init:false t domain_key >|= fun () ->
          Ok ()

  let change_unlock_passphrase t ~passphrase =
    match t.state with
    | `Unprovisioned | `Locked ->
      Log.warn (fun m -> m "expected operational NitroHSM, found %a" pp_state t.state);
      Lwt.return (Error (`Msg "NitroHSM is not operational"))
    | `Operational ->
      let unlock_salt = Rng.generate Crypto.salt_len in
      let unlock_key = Crypto.key_of_passphrase ~salt:unlock_salt passphrase in
      (* TODO (a) write error handling (b) the two writes below should be a transaction *)
      Kv_config.set t.kv `Unlock_salt (Cstruct.to_string unlock_salt) >>= fun _ ->
      Kv_domain.set t.kv `Passphrase ~unlock_key t.domain_key >|= fun _ ->
      Ok ()

  let reboot () = ()

  let shutdown () = ()

  let reset _t = ()
end
