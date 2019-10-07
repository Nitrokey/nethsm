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
    (* if unlock-salt is present, go to locked *)
    Kv_config.get t.kv `Unlock_salt >|= function
    | Ok _ -> t.state <- `Locked; t
    | Error (`Not_found _) -> t
    | Error e ->
      Log.err (fun m -> m "unexpected %a while reading unlock-salt"
                  KV.pp_error e);
      assert false

  let info t = t.info

  let system_info t = t.system_info

  let state t = t.state

  let generate_cert t priv =
    let valid_from = Ptime.epoch
    and valid_until = Ptime.max
    in
    let dn = X509.Distinguished_name.singleton CN "keyfender" in
    let csr = X509.Signing_request.create dn priv in
    let cert =
      X509.Signing_request.sign csr ~valid_from ~valid_until priv dn
    in
    (* TODO write error handling! *)
    let pem_cert = Cstruct.to_string (X509.Certificate.encode_pem cert) in
    Kv_config.set t.kv `Certificate pem_cert >|= fun _ ->
    cert

  let certificate t =
    (* TODO private key generation and certificate issuing should be a transaction! *)
    Kv_config.get t.kv `Private_key >>= function
    | Ok priv_pem ->
      begin
        (* TODO handle decode and read errors below *)
        let priv, raw_priv =
          match X509.Private_key.decode_pem (Cstruct.of_string priv_pem) with
          | Ok (`RSA priv) -> `RSA priv, priv
          | Error (`Msg msg) ->
            Log.err (fun m -> m "%s while decoding TLS private key" msg);
            assert false
        in
        Kv_config.get t.kv `Certificate >>= function
        | Ok cert_pem ->
          let certs =
            match X509.Certificate.decode_pem_multiple (Cstruct.of_string cert_pem) with
            | Ok certs -> certs
            | Error (`Msg msg) ->
              Log.err (fun m -> m "%s while decoding certificates" msg);
              assert false
          in
          Lwt.return (`Single (certs, raw_priv))
        | Error (`Not_found _) ->
          (* private key present, certificate absent *)
          generate_cert t priv >>= fun cert ->
          Lwt.return (`Single ([ cert ], raw_priv))
        | Error e ->
          Log.err (fun m -> m "unexpected %a while reading TLS certificate"
                      KV.pp_error e);
          assert false
      end
    | Error (`Not_found _) ->
      (* no key -> generate, generate certificate *)
      let priv, raw_priv = let p = Nocrypto.Rsa.generate 4096 in `RSA p, p in
      (* TODO handle write error *)
      let priv_pem = Cstruct.to_string (X509.Private_key.encode_pem priv) in
      Kv_config.set t.kv `Private_key priv_pem >>= fun _ ->
      generate_cert t priv >>= fun cert ->
      Lwt.return (`Single ([ cert ], raw_priv))
    | Error e ->
      Log.err (fun m -> m "unexpected %a while reading TLS private key"
                  KV.pp_error e);
      assert false

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
        let salt = Rng.generate 16 in
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
        let salt' = Rng.generate 16 in
        let digest' = Crypto.key_of_passphrase ~salt:salt' passphrase in
        let user' =
          { user with salt = Cstruct.to_string salt' ;
                      digest = Cstruct.to_string digest' }
        in
        write t id user'
  end

  let transition_to_operational t domain_key =
    t.domain_key <- domain_key;
    let auth_store_key, key_store_key = Cstruct.split domain_key Crypto.key_len in
    t.auth_store <- Some (Kv_crypto.connect `Authentication ~key:auth_store_key t.kv);
    t.key_store <- Some (Kv_crypto.connect `Key ~key:key_store_key t.kv);
    t.state <- `Operational

  let provision_mutex = Lwt_mutex.create ()

  let provision t ~unlock ~admin _time =
    (* TODO writes to KV (config + domain) should be a transaction! *)
    Lwt_mutex.with_lock provision_mutex (fun () ->
        if t.state <> `Unprovisioned then begin
          Log.err (fun m -> m "HSM is already provisioned");
          Lwt.return (Error (`Msg "HSM already provisioned"))
        end else begin
          let unlock_salt = Rng.generate 16 in
          let unlock_key = Crypto.key_of_passphrase ~salt:unlock_salt unlock in
          let domain_key = Rng.generate (Crypto.key_len * 2) in
          transition_to_operational t domain_key;
          Kv_config.set t.kv `Unlock_salt (Cstruct.to_string unlock_salt) >>= fun _ ->
          Kv_domain.set t.kv `Passphrase ~unlock_key domain_key >>= fun _ ->
          User.add ~id:"admin" t ~role:`Administrator ~passphrase:admin ~name:"admin" >|= fun _ ->
          Ok ()
          (* TODO compute "time - our_current_idea_of_now", store offset in configuration store *)
        end)

  let unlock t ~passphrase =
    (* TODO handle read errors in this function properly! *)
    match t.state with
    | `Unprovisioned ->
      Log.err (fun m -> m "HSM is not provisioned");
      Lwt.return (Error (`Msg "HSM is not provisioned"))
    | `Operational ->
      Log.err (fun m -> m "HSM is already unlocked");
      Lwt.return (Error (`Msg "HSM already unlocked"))
    | `Locked ->
      Kv_config.get t.kv `Unlock_salt >>= function
      | Error e ->
        Log.err (fun m -> m "couldn't read salt %a" KV.pp_error e);
        Lwt.return (Error (`Msg "couldn't read salt"))
      | Ok salt ->
        let unlock_key = Crypto.key_of_passphrase ~salt:(Cstruct.of_string salt) passphrase in
        Kv_domain.get t.kv `Passphrase ~unlock_key >|= function
        | Error (`Msg e) ->
          Log.err (fun m -> m "couldn't read domain key %s" e);
          Error (`Msg "couldn't read domain key")
        | Ok domain_key ->
          transition_to_operational t domain_key;
          Ok ()

  let change_unlock_passphrase t ~passphrase =
    match t.state with
    | `Unprovisioned | `Locked ->
      Log.warn (fun m -> m "attempted to change unlock passphrase while not unlocked");
      Lwt.return (Error (`Msg "NitroHSM needs to be unlocked to change unlock passphrase"))
    | `Operational ->
      let unlock_salt = Rng.generate 16 in
      let unlock_key = Crypto.key_of_passphrase ~salt:unlock_salt passphrase in
      (* TODO (a) write error handling (b) the two writes below should be a transaction *)
      Kv_config.set t.kv `Unlock_salt (Cstruct.to_string unlock_salt) >>= fun _ ->
      Kv_domain.set t.kv `Passphrase ~unlock_key t.domain_key >|= fun _ ->
      Ok ()

  let reboot () = ()

  let shutdown () = ()

  let reset _t = ()
end
