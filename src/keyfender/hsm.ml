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

  type role = Administrator | Operator | Metrics | Backup

  type t

  val info : t -> info

  val system_info : t -> system_info

  val state : t -> state

  val certificate : t -> Tls.Config.own_cert Lwt.t

  val is_authenticated : t -> username:string -> passphrase:string -> bool Lwt.t

  val is_authorized : t -> string -> role -> bool Lwt.t

  val provision : t -> unlock:string -> admin:string -> Ptime.t ->
    (unit, [> `Msg of string ]) result Lwt.t

  val unlock : t -> passphrase:string ->
    (unit, [> `Msg of string ]) result Lwt.t

  val reboot : unit -> unit

  val shutdown : unit -> unit

  val reset : unit -> unit

  val list_users : t -> (string list, [> `Msg of string ]) result Lwt.t

  val add_user : t -> role:role -> passphrase:string -> name:string ->
    (unit, [> `Msg of string ]) result Lwt.t

  val remove_user : t -> string -> (unit, [> `Msg of string ]) result Lwt.t

  val change_user_passphrase : t -> name:string -> passphrase:string ->
    (unit, [> `Msg of string ]) result Lwt.t
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

  type role = Administrator | Operator | Metrics | Backup [@@deriving yojson]
  type user = { name : string ; salt : string ; digest : string ; role : role } [@@deriving yojson]

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

  module Key = Mirage_kv.Key

  let config_key = Key.v "config"

  let read_config t key =
    KV.get t.kv (Key.add config_key key)

  let write_config t key value =
    KV.set t.kv (Key.add config_key key) value

  let domain_key = Key.v "domain"

  let domain_key_name = function
    | `Passphrase -> "0"

  let read_domain_key t key =
    KV.get t.kv (Key.add domain_key (domain_key_name key))

  let write_domain_key t key value =
    KV.set t.kv (Key.add domain_key (domain_key_name key)) value

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
    read_config t "unlock-salt" >|= function
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
    (* TODO error handling! *)
    write_config t "public.pem" (Cstruct.to_string (X509.Certificate.encode_pem cert)) >|= fun _ ->
    cert

  let certificate t =
    read_config t "key.pem" >>= function
    | Ok priv_pem ->
      begin
        let priv, raw_priv =
          match X509.Private_key.decode_pem (Cstruct.of_string priv_pem) with
          | Ok (`RSA priv) -> `RSA priv, priv
          | Error (`Msg msg) ->
            Log.err (fun m -> m "%s while decoding TLS private key" msg);
            assert false
        in
        read_config t "public.pem" >>= function
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
      write_config t "key.pem" (Cstruct.to_string (X509.Private_key.encode_pem priv)) >>= fun _ ->
      generate_cert t priv >>= fun cert ->
      Lwt.return (`Single ([ cert ], raw_priv))
    | Error e ->
      Log.err (fun m -> m "unexpected %a while reading TLS private key"
                  KV.pp_error e);
      assert false

  let decode_user data =
    let open Rresult.R.Infix in
    (try Ok (Yojson.Safe.from_string data) with _ -> Error `Json_decode) >>= fun json ->
    (match user_of_yojson json with Ok user -> Ok user | Error _ -> Error `Json_decode)

  let find_user t username =
    match t.auth_store with
    | None -> Lwt.return (Error `Not_unlocked)
    | Some auth ->
      Kv_crypto.get auth (Key.v username) >|= function
      | Error _ -> Error `Not_found (* TODO other errors? *)
      | Ok data -> decode_user data

  let is_authenticated t ~username ~passphrase =
    find_user t username >|= function
    | Error _ -> false (* TODO write log *)
    | Ok user ->
      let pass = Crypto.key_of_passphrase ~salt:(Cstruct.of_string user.salt) passphrase in
      Cstruct.equal pass (Cstruct.of_string user.digest)

  let is_authorized t username role =
    find_user t username >|= function
    | Error _ -> false
    | Ok user -> user.role = role

  let write_user t user =
    match t.auth_store with
    | None -> Lwt.return (Error (`Msg "not unlocked"))
    | Some auth_store ->
      let user_str = Yojson.Safe.to_string (user_to_yojson user) in
      Kv_crypto.set auth_store (Key.v user.name) user_str >|=
      Rresult.R.reword_error
        (fun e -> `Msg (Fmt.to_to_string Kv_crypto.pp_write_error e))

  (* TODO: handle conflict (user already exists), validate usename/id, generate id *)
  let add_user t ~role ~passphrase ~name =
    let user =
      let salt = Rng.generate 16 in
      let digest = Crypto.key_of_passphrase ~salt passphrase in
      { name ; salt = Cstruct.to_string salt ;
        digest = Cstruct.to_string digest ; role }
    in
    write_user t user

  let list_users t =
    match t.auth_store with
    | None -> Lwt.return (Error (`Msg "no auth store"))
    | Some auth_store ->
      Kv_crypto.list auth_store Key.empty >|= function
      | Error e -> Error (`Msg (Fmt.to_to_string Kv_crypto.pp_error e))
      | Ok xs ->
        let ids = List.map fst (List.filter (fun (_, typ) -> typ = `Value) xs) in
        Ok ids

  let remove_user t name =
    match t.auth_store with
    | None -> Lwt.return (Error (`Msg "no auth store"))
    | Some auth_store ->
      Kv_crypto.remove auth_store (Key.v name) >|= function
      | Ok () -> Ok ()
      | Error e -> Error (`Msg (Fmt.to_to_string Kv_crypto.pp_write_error e))

  let change_user_passphrase t ~name ~passphrase =
    find_user t name >>= function
    | Error _ -> Lwt.return (Error (`Msg "couldn't find user"))
    | Ok user ->
      let salt' = Rng.generate 16 in
      let digest' = Crypto.key_of_passphrase ~salt:salt' passphrase in
      let user' =
        { user with salt = Cstruct.to_string salt' ;
                    digest = Cstruct.to_string digest' }
      in
      write_user t user'

  let set_domain_key t domain_key =
    t.domain_key <- domain_key;
    let auth_store_key, key_store_key = Cstruct.split domain_key Crypto.key_len in
    t.auth_store <- Some (Kv_crypto.connect ~prefix:"auth" ~key:auth_store_key t.kv);
    t.key_store <- Some (Kv_crypto.connect ~prefix:"key" ~key:key_store_key t.kv);
    t.state <- `Operational

  let provision_mutex = Lwt_mutex.create ()

  let provision t ~unlock ~admin _time =
    Lwt_mutex.with_lock provision_mutex (fun () ->
        if t.state <> `Unprovisioned then begin
          Log.err (fun m -> m "HSM is already provisioned");
          Lwt.return (Error (`Msg "HSM already provisioned"))
        end else begin
          let unlock_salt = Rng.generate 16 in
          let unlock_key = Crypto.key_of_passphrase ~salt:unlock_salt unlock in
          let domain_key = Rng.generate (Crypto.key_len * 2) in
          set_domain_key t domain_key;
          let enc_domain_key = Crypto.encrypt_domain_key Rng.generate ~unlock_key domain_key in
          (* TODO handle write errors *)
          write_config t "unlock-salt" (Cstruct.to_string unlock_salt) >>= fun _ ->
          write_domain_key t `Passphrase (Cstruct.to_string enc_domain_key) >>= fun _ ->
          add_user t ~role:Administrator ~passphrase:admin ~name:"admin" >|= fun _ ->
          Ok ()
          (* TODO:
             - compute "time - our_current_idea_of_now", store offset in configuration store *)
        end)

  let unlock t ~passphrase =
    match t.state with
    | `Unprovisioned ->
      Log.err (fun m -> m "HSM is not provisioned");
      Lwt.return (Error (`Msg "HSM is not provisioned"))
    | `Operational ->
      Log.err (fun m -> m "HSM is already unlocked");
      Lwt.return (Error (`Msg "HSM already unlocked"))
    | `Locked ->
      read_config t "unlock-salt" >>= function
      | Error e ->
        (* TODO handle this error properly!? *)
        Log.err (fun m -> m "couldn't read salt %a" KV.pp_error e);
        Lwt.return (Error (`Msg "couldn't read salt"))
      | Ok salt ->
        let unlock_key = Crypto.key_of_passphrase ~salt:(Cstruct.of_string salt) passphrase in
        read_domain_key t `Passphrase >|= function
        | Error e ->
          (* TODO handle this error properly!? *)
          Log.err (fun m -> m "couldn't read domain key %a" KV.pp_error e);
          Error (`Msg "couldn't read domain key")
        | Ok enc_domain_key ->
          match Crypto.decrypt_domain_key ~unlock_key (Cstruct.of_string enc_domain_key) with
          | Error (`Msg str) ->
            Log.err (fun m -> m "decryption of domain key failed %s" str);
            Error (`Msg str)
          | Ok domain_key ->
            set_domain_key t domain_key;
            Ok ()

  let reboot () = ()

  let shutdown () = ()

  let reset () = ()
end
