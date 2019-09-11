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

  type user = { name : string ; password : string ; role : role }

  type t

  val info : t -> info

  val system_info : t -> system_info

  val state : t -> state

  val certificate : t -> Tls.Config.own_cert Lwt.t

  val is_authenticated : t -> username:string -> password:string -> bool

  val is_authorized : t -> string -> role -> bool

  val provision : t -> unlock:string -> admin:string -> Ptime.t -> unit

  val reboot : unit -> unit

  val shutdown : unit -> unit

  val reset : unit -> unit
end

open Lwt.Infix

let hsm_src = Logs.Src.create "hsm" ~doc:"HSM log"
module Log = (val Logs.src_log hsm_src : Logs.LOG)

module Make (KV : Mirage_kv_lwt.RW) = struct
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

  type role = Administrator | Operator | Metrics | Backup
  type user = { name : string ; password : string ; role : role }
  type users = user list

  type t = {
    mutable state : state ;
    kv : KV.t ;
    info : info ;
    system_info : system_info ;
    users : users ;
  }

  module Key = Mirage_kv.Key

  let config_key = Key.v "config"

  let read_config t key =
    KV.get t.kv (Key.add config_key key)

  let write_config t key value =
    KV.set t.kv (Key.add config_key key) value

  let make kv =
    let t =
      {
        state = `Unprovisioned ;
        kv ;
        info = { vendor = "Nitrokey UG" ; product = "NitroHSM" ; version = "v1" } ;
        system_info = { firmwareVersion = "1" ; softwareVersion = "0.7rc3" ; hardwareVersion = "2.2.2" } ;
        (* TODO these are dummies *)
        users = [ { name = "admin" ; password = "test1" ; role = Administrator } ;
                  { name = "operator" ; password = "test2" ; role = Operator } ] ;
      }
    in
    (* if unlock-salt and unlock-iterations is present, go to locked *)
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

  let is_authenticated t ~username ~password =
    List.exists (fun u -> u.name = username && u.password = password) t.users

  let is_authorized t username role =
    List.exists (fun u -> u.name = username && u.role = role) t.users

  let provision t ~unlock:_ ~admin:_ _time = t.state <- `Operational

  let reboot () = ()

  let shutdown () = ()

  let reset () = ()
end
