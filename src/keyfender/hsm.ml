module type S = sig

  module Metrics : sig
    val http_status : Cohttp.Code.status_code -> unit
    val retrieve : unit -> (string * string) list
  end

  val now : unit -> Ptime.t

  type status_code =
    | Internal_server_error
    | Bad_request
    | Precondition_failed
    | Conflict
    | Too_many_requests

  (* string is the body, which may contain error message *)
  type error = status_code * string

  val error_to_code : status_code -> int

  val pp_state : Json.state Fmt.t

  type cb =
    | Log of Json.log
    | Network of Ipaddr.V4.Prefix.t * Ipaddr.V4.t option
    | Tls of Tls.Config.own_cert
    | Shutdown
    | Reboot
    | Reset

  val cb_to_string : cb -> string

  type t

  val equal : t -> t -> bool Lwt.t

  val info : t -> Json.info

  val state : t -> Json.state

  val lock : t -> unit

  val own_cert : t -> Tls.Config.own_cert

  val network_configuration : t ->
    (Ipaddr.V4.t * Ipaddr.V4.Prefix.t * Ipaddr.V4.t option) Lwt.t

  val provision : t -> unlock:string -> admin:string -> Ptime.t ->
    (unit, error) result Lwt.t

  val unlock_with_passphrase : t -> passphrase:string ->
    (unit, error) result Lwt.t

  val random : int -> string

  val generate_id : unit -> string

  module Config : sig
    val set_unlock_passphrase : t -> passphrase:string ->
      (unit, error) result Lwt.t

    val unattended_boot : t -> (bool, error) result Lwt.t

    val set_unattended_boot : t -> bool ->
      (unit, error) result Lwt.t

    val unattended_boot_digest : t -> string option Lwt.t

    val tls_public_pem : t -> string Lwt.t

    val tls_public_pem_digest : t -> string option Lwt.t

    val tls_cert_pem : t -> string Lwt.t

    val set_tls_cert_pem : t -> string ->
      (unit, error) result Lwt.t

    val tls_cert_digest : t -> string option Lwt.t

    val tls_csr_pem : t -> Json.subject_req -> string Lwt.t

    val network : t -> Json.network Lwt.t

    val set_network : t -> Json.network ->
      (unit, error) result Lwt.t

    val network_digest : t -> string option Lwt.t

    val log : t -> Json.log Lwt.t

    val set_log : t -> Json.log -> (unit, error) result Lwt.t

    val log_digest : t -> string option Lwt.t

    val set_backup_passphrase : t -> passphrase:string ->
      (unit, error) result Lwt.t

    val time : t -> Ptime.t Lwt.t

    val set_time : t -> Ptime.t -> (unit, error) result Lwt.t
  end

  module System : sig
    val system_info : t -> Json.system_info

    val reboot : t -> unit Lwt.t

    val shutdown : t -> unit Lwt.t

    val reset : t -> unit Lwt.t

    val update : t -> string Lwt_stream.t -> (string, error) result Lwt.t

    val commit_update : t -> (unit, error) result

    val cancel_update : t -> (unit, error) result

    val backup : t -> (string option -> unit) ->
      (unit, error) result Lwt.t

    val restore : t -> Uri.t -> string Lwt_stream.t ->
      (unit, error) result Lwt.t
  end

  module User : sig
    val is_authenticated : t -> username:string -> passphrase:string ->
      bool Lwt.t

    val is_authorized : t -> string -> Json.role -> bool Lwt.t

    val list : t -> (string list, error) result Lwt.t

    val exists : t -> id:string -> (bool, error) result Lwt.t

    val get : t -> id:string -> (string * Json.role, error) result Lwt.t

    val add : id:string -> t -> role:Json.role -> passphrase:string ->
      name:string -> (unit, error) result Lwt.t

    val remove : t -> id:string -> (unit, error) result Lwt.t

    val set_passphrase : t -> id:string -> passphrase:string ->
      (unit, error) result Lwt.t

    val list_digest : t -> string option Lwt.t

    val digest : t -> id:string -> string option Lwt.t
  end

  module Key : sig
    val exists : t -> id:string -> (bool, error) result Lwt.t

    val list : t -> (string list, error) result Lwt.t

    val add_json : id:string -> t -> Json.purpose -> string -> Json.key ->
      (unit, error) result Lwt.t

    val add_pem : id:string -> t -> Json.purpose -> string ->
      (unit, error) result Lwt.t

    val generate : id:string -> t -> string -> Json.purpose -> length:int ->
      (unit, error) result Lwt.t

    val remove : t -> id:string -> (unit, error) result Lwt.t

    val get_json : t -> id:string -> (Yojson.Safe.t, error) result Lwt.t

    val get_pem : t -> id:string -> (string, error) result Lwt.t

    val csr_pem : t -> id:string -> Json.subject_req -> (string, error) result Lwt.t

    val get_cert : t -> id:string -> ((string * string) option, error) result Lwt.t

    val set_cert : t -> id:string -> content_type:string -> string -> (unit, error) result Lwt.t

    val remove_cert : t -> id:string -> (unit, error) result Lwt.t

    val decrypt : t -> id:string -> Json.decrypt_mode -> string -> (string, error) result Lwt.t

    val sign : t -> id:string -> Json.sign_mode -> string -> (string, error) result Lwt.t

    val list_digest : t -> string option Lwt.t

    val digest : t -> id:string -> string option Lwt.t
  end
end

let to_hex str =
  let `Hex hex = Hex.of_string str in
  hex

let lwt_error_to_msg ~pp_error thing =
  let open Lwt.Infix in
  thing >|= fun x ->
  Rresult.R.error_to_msg ~pp_error x

let hsm_src = Logs.Src.create "hsm" ~doc:"HSM log"
module Log = (val Logs.src_log hsm_src : Logs.LOG)

module Make (Rng : Mirage_random.S) (KV : Mirage_kv.RW) (Time : Mirage_time.S) (Monotonic_clock : Mirage_clock.MCLOCK) (Clock : Hsm_clock.HSMCLOCK) = struct
  module Metrics = struct
    let db = Hashtbl.create 13

    let retrieve () =
      Hashtbl.fold (fun k v acc -> (k, v) :: acc) db []

    let sample_interval = Duration.of_sec 1

    let now () = Monotonic_clock.elapsed_ns ()

    let uptime_src =
      let open Metrics in
      let doc = "Uptime" in
      let data now =
        let seconds = Duration.to_sec now in
        Data.v [ int "uptime" seconds ]
      in
      Src.v ~doc ~tags:Metrics.Tags.[] ~data "uptime"

    let log_src =
      let open Metrics in
      let doc = "Log message types" in
      let data (warns, errs) =
        Data.v [ int "warn msgs" warns ; int "err msgs" errs ]
      in
      Src.v ~doc ~tags:Metrics.Tags.[] ~data "log msg type"

    let gc_src =
      let open Metrics in
      let doc = "Garbage collection" in
      let data (live, free) =
        Data.v [ int "live_words_bytes" live ; int "free_words_bytes" free ]
      in
      Src.v ~doc ~tags:Metrics.Tags.[] ~data "gc"

    let key_ops_src =
      let open Metrics in
      let doc = "Key operations" in
      let data (generate, sign, decrypt) =
        Data.v [ int "generate" generate ; int "sign" sign ; int "decrypt" decrypt ]
      in
      Src.v ~doc ~tags:Metrics.Tags.[] ~data "key operations"

    let ops = ref (0, 0, 0)

    let key_op op =
      let g, s, d = !ops in
      (match op with
      | `Generate -> ops := g + 1, s, d
      | `Sign -> ops := g, s + 1, d
      | `Decrypt -> ops := g, s, d + 1);
      Metrics.add key_ops_src (fun t -> t) (fun m -> m !ops)

    let http_status = Hashtbl.create 7

    let http_status_src =
      let open Metrics in
      let doc = "HTTP status" in
      let data () =
        let codes =
          Hashtbl.fold
            (fun k v acc -> uint ("http " ^ string_of_int k) v :: acc)
            http_status []
        in
        Data.v codes
      in
      Src.v ~doc ~tags:Metrics.Tags.[] ~data "http status"

    let http_status status =
      let code = Cohttp.Code.code_of_status status in
      let old_counter = match Hashtbl.find_opt http_status code with None -> 0 | Some x -> x in
      Hashtbl.replace http_status code (succ old_counter);
      Metrics.add http_status_src (fun t -> t) (fun m -> m ())

    let rec sample () =
      let open Lwt.Infix in
      Metrics.add uptime_src (fun t -> t) (fun m -> m (now ()));
      Metrics.add log_src (fun t -> t) (fun m -> m (Logs.warn_count (), Logs.err_count ()));
      let gc_stat = Gc.stat () in
      Metrics.add gc_src (fun t -> t) (fun m -> m (gc_stat.live_words * 8, gc_stat.free_words * 8));
      Time.sleep_ns sample_interval >>=
      sample

    let set_mem_reporter () =
      let report ~tags:_ ~data ~over _src k =
        let data_fields = Metrics.Data.fields data in
        (* let name = Metrics.Src.name src in *)
        let field f =
          Fmt.to_to_string Metrics.pp_key f, Fmt.to_to_string Metrics.pp_value f
        in
        let fields = List.map field in
        (* let timestamp =
          match Metrics.Data.timestamp data with
          | Some ts -> ts
          | None -> Int64.to_string (now ())
           in *)
        (* let d = name, fields tags, fields data_fields, timestamp in*)
        List.iter
          (fun (field_name, field_value) -> Hashtbl.replace db field_name field_value)
          (fields data_fields);
        over (); k ()
      in
      let at_exit () = () in
      Metrics.enable_all ();
      Metrics.set_reporter {Metrics.report; now; at_exit};
      Lwt.async sample
  end

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
    | Too_many_requests

  (* string is the body, which may contain error message *)
  type error = status_code * string

  let error_to_code code =
    let status = match code with
    | Internal_server_error -> `Internal_server_error
    | Bad_request -> `Bad_request
    | Precondition_failed -> `Precondition_failed
    | Conflict -> `Conflict
    | Too_many_requests -> `Too_many_requests
    in
    Cohttp.Code.code_of_status status

  let internal_server_error context pp_err f =
    let open Lwt.Infix in
    f >|= function
    | Ok x -> Ok x
    | Error e ->
      Log.err (fun m -> m "Error: %a while writing to key-value store: %s." pp_err e context);
      Error (Internal_server_error, "Could not write to disk. Check hardware.")

  let pp_state ppf s =
    Fmt.string ppf (match s with
        | `Unprovisioned -> "unprovisioned"
        | `Operational -> "operational"
        | `Locked -> "locked")

  type cb =
    | Log of Json.log
    | Network of Ipaddr.V4.Prefix.t * Ipaddr.V4.t option
    | Tls of Tls.Config.own_cert
    | Shutdown
    | Reboot
    | Reset

  let cb_to_string = function
    | Log l -> "LOG " ^ Yojson.Safe.to_string (Json.log_to_yojson l)
    | Network (prefix, gw) ->
      let gw = match gw with None -> "no" | Some ip -> Ipaddr.V4.to_string ip in
      "NETWORK " ^ Ipaddr.V4.Prefix.to_string prefix ^ ", gateway: " ^ gw
    | Tls _ -> "TLS_CERTIFICATE"
    | Shutdown -> "SHUTDOWN"
    | Reboot -> "REBOOT"
    | Reset -> "RESET"

  let version_of_string s = match Astring.String.cut ~sep:"." s with
    | None -> Error (Bad_request, "Failed to parse version: no separator (.). A valid version would be '4.2'.")
    | Some (major, minor) ->
      try
        let ma = int_of_string major
        and mi = int_of_string minor
        in
        Ok (ma, mi)
      with Failure _ -> Error (Bad_request, "Failed to parse version: Not a number. A valid version would be '4.2'.")

  let version_is_upgrade ~current ~update = fst current <= fst update

  module Config_store = Config_store.Make(KV)
  module Domain_key_store = Domain_key_store.Make(Rng)(KV)
  module Encrypted_store = Encrypted_store.Make(Rng)(KV)

  type keys = {
    domain_key : Cstruct.t ; (* needed when unlock passphrase changes and likely for unattended boot *)
    auth_store : Encrypted_store.t ;
    key_store : Encrypted_store.t ;
  }

  let equal_keys a b = Cstruct.equal a.domain_key b.domain_key

  type internal_state =
    | Unprovisioned
    | Operational of keys
    | Locked
      [@@deriving eq]

  let to_external_state = function
    | Unprovisioned -> `Unprovisioned
    | Operational _ -> `Operational
    | Locked -> `Locked

  type t = {
    mutable state : internal_state ;
    mutable has_changes : string option ;
    key : X509.Private_key.t ;
    mutable cert : X509.Certificate.t ;
    mutable chain : X509.Certificate.t list ;
    kv : KV.t ;
    info : Json.info ;
    system_info : Json.system_info ;
    mbox : cb Lwt_mvar.t ;
    device_id : string ;
  }

  let state t = to_external_state t.state

  let lock t = t.state <- Locked

  let kv_equal a b =
    let open Lwt_result.Infix in
    let rec traverse root =
      let for_all acc path =
        Lwt.return acc >>= fun acc' ->
        traverse path >|= fun v ->
        acc' && v
      in
      KV.exists a root >>= fun a_typ ->
      KV.exists b root >>= fun b_typ ->
      match a_typ, b_typ with
      | Some `Value, Some `Value ->
        KV.get a root >>= fun v ->
        KV.get b root >>= fun v' ->
        Lwt_result.return (String.equal v v')
      | Some `Dictionary, Some `Dictionary ->
        KV.list a root >>= fun l ->
        KV.list b root >>= fun l' ->
        if List.length l = List.length l' && List.for_all2 (=) l l'
        then
          Lwt_list.fold_left_s for_all (Ok true)
            (List.map (Mirage_kv.Key.add root) (fst (List.split l)))
        else
          Lwt_result.return false
      | _ -> Lwt_result.return false
    in
    let get_ok v =
      let open Lwt.Infix in
      v >|= function Ok v -> v | Error _ -> false
    in
    traverse Mirage_kv.Key.empty |> get_ok

  let equal a b =
    let open Lwt.Infix in
    kv_equal a.kv b.kv >|= fun equal_kv ->
    equal_internal_state a.state b.state
    && a.has_changes = b.has_changes
    && a.info = b.info
    && a.system_info = b.system_info
    && equal_kv

  let now () = Clock.now ()

  let write_lock = Lwt_mutex.create ()

  let set_time_offset kv timestamp =
    Clock.set timestamp;
    let span = Clock.get_offset () in
    internal_server_error "Write time offset" KV.pp_write_error
      (Config_store.set kv Time_offset span)

  let prepare_keys kv slot credentials =
    let open Lwt_result.Infix in
    let get_salt_key = function
      | Domain_key_store.Passphrase -> Config_store.Unlock_salt
      | Domain_key_store.Device_id -> Config_store.Device_id_salt
    in
    internal_server_error "Prepare keys" Config_store.pp_error
      (Config_store.get kv (get_salt_key slot)) >>= fun salt ->
    let unlock_key = Crypto.key_of_passphrase ~salt credentials in
    Lwt_result.map_err (function `Msg m -> Bad_request, m)
      (Domain_key_store.get kv slot ~unlock_key) >|= fun domain_key ->
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
  let unlock kv slot credentials =
    let open Lwt_result.Infix in
    (* state is already checked in Handler_unlock.service_available *)
    prepare_keys kv slot credentials >>= fun (domain_key, as_key, ks_key) ->
    unlock_store kv Authentication as_key >>= fun auth_store ->
    unlock_store kv Key ks_key >|= fun key_store ->
    let keys = { domain_key ; auth_store ; key_store } in
    Operational keys

  let unlock_with_device_id kv ~device_id = unlock kv Device_id device_id

  let unlock_with_passphrase t ~passphrase =
    let open Lwt_result.Infix in
    unlock t.kv Passphrase passphrase >|= fun state' ->
    t.state <- state'

  let generate_cert () =
    let priv = `RSA (Mirage_crypto_pk.Rsa.generate ~bits:Crypto.initial_key_rsa_bits ()) in
    (* this is before provisioning, our posix time may be not accurate *)
    let valid_from = Ptime.epoch
    and valid_until = Ptime.max
    in
    let dn = [ X509.Distinguished_name.(Relative_distinguished_name.singleton (CN "keyfender")) ] in
    let csr = X509.Signing_request.create dn priv in
    match X509.Signing_request.sign csr ~valid_from ~valid_until priv dn with
    | Error e ->
      fatal "signing certificate signing request"
        ~pp_error:X509.Validation.pp_signature_error e
    | Ok cert -> cert, priv

  let certificate_chain kv =
    let open Lwt_result.Infix in
    lwt_error_fatal "get private key from configuration store"
      ~pp_error:Config_store.pp_error
      (Config_store.get kv Private_key) >>= fun priv ->
    lwt_error_fatal "get certificate from configuration store"
      ~pp_error:Config_store.pp_error
      (Config_store.get kv Certificate) >|= fun (cert, chain) ->
    cert, chain, priv

  let boot_config_store kv device_id =
    let open Lwt_result.Infix in
    lwt_error_fatal "get time offset" ~pp_error:Config_store.pp_error
      (Config_store.get_opt kv Time_offset >|= function
        | None -> ()
        | Some span ->
          let `Raw now_raw = Clock.now_raw () in
          match Ptime.add_span now_raw span with
          | None ->
            Log.warn (fun m -> m "time offset from config store out of range")
          | Some ts -> Clock.set ts) >>= fun () ->
    lwt_error_fatal "get unlock-salt" ~pp_error:Config_store.pp_error
      (Config_store.get kv Unlock_salt) >>= fun _ ->
    lwt_error_fatal "get unattended boot" ~pp_error:Config_store.pp_error
      (Config_store.get_opt kv Unattended_boot) >>= function
    | Some true ->
      begin
        let open Lwt.Infix in
        unlock_with_device_id kv ~device_id >|= function
        | Ok s -> Ok s
        | Error (_, msg) ->
          Log.err (fun m -> m "unattended boot failed with %s" msg);
          Ok Locked
      end
    | None | Some false -> Lwt.return (Ok Locked)

  let boot ~device_id kv =
    Metrics.set_mem_reporter ();
    let info = { Json.vendor = "Nitrokey UG" ; product = "NitroHSM" ; version = "v1" }
    and system_info = { Json.firmwareVersion = "1" ; softwareVersion = (1, 7) ; hardwareVersion = "2.2.2" }
    and has_changes = None
    and mbox = Lwt_mvar.create_empty ()
    in
    let open Lwt.Infix in
    begin
      let open Lwt_result.Infix in
      lwt_error_to_msg ~pp_error:Config_store.pp_error
        (Config_store.get_opt kv Version) >>= function
      | None ->
        (* uninitialized / unprovisioned device *)
        let state = Unprovisioned
        and cert, key = generate_cert ()
        and chain = []
        in
        let t = { state ; has_changes ; key ; cert ; chain ; kv ; info ; system_info ; mbox ; device_id } in
        Lwt.return (Ok t)
      | Some version ->
        match Version.(compare current version) with
        | `Equal ->
          boot_config_store kv device_id >>= fun state ->
          certificate_chain kv >|= fun (cert, chain, key) ->
          { state ; has_changes ; key ; cert ; chain ; kv ; info ; system_info ; mbox ; device_id }
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
    | Ok t -> t, t.mbox
    | Error `Msg msg ->
      Log.err (fun m -> m "error booting %s" msg);
      invalid_arg "broken NitroHSM"

  let info t = t.info

  let own_cert t =
    match t.key with
    | `RSA pk -> `Single (t.cert :: t.chain, pk)
    | _ -> `None (* cannot happen *)

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

  let random n = Base64.encode_string @@ Cstruct.to_string @@ Mirage_crypto_rng.generate n

  let generate_id () =
    let `Hex id = Hex.of_cstruct (Mirage_crypto_rng.generate 10) in
    id

  module User = struct
    let user_src = Logs.Src.create "hsm.user" ~doc:"HSM user log"
    module Access = (val Logs.src_log user_src : Logs.LOG)

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
      role : Json.role
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
      Lwt_mutex.with_lock write_lock (fun () ->
          internal_server_error "Write user" Encrypted_store.pp_write_error
            (Encrypted_store.set store (Mirage_kv.Key.v id) user_str))

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

    let prepare_user ~name ~passphrase ~role =
      let salt = Rng.generate Crypto.salt_len in
      let digest = Crypto.key_of_passphrase ~salt passphrase in
      { name ; salt = Cstruct.to_string salt ; digest = Cstruct.to_string digest ; role }

    (* TODO: validate username/id *)
    let add ~id t ~role ~passphrase ~name =
      let open Lwt_result.Infix in
      let store = in_store t in
      Lwt.bind (read_decode store id)
        (function
          | Error `Encrypted_store `Kv (`Not_found _) ->
            let user = prepare_user ~name ~passphrase ~role in
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
      Lwt_mutex.with_lock write_lock (fun () ->
          internal_server_error "Remove user" Encrypted_store.pp_write_error
            (Encrypted_store.remove store (Mirage_kv.Key.v id) >|= fun () ->
             Access.info (fun m -> m "removed (%s)" id)))


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

    let list_digest t =
      let open Lwt.Infix in
      let store = in_store t in
      Encrypted_store.digest store Mirage_kv.Key.empty >|= function
      | Ok digest -> Some (to_hex digest)
      | Error _ -> None

    let digest t ~id =
      let open Lwt.Infix in
      let store = in_store t in
      Encrypted_store.digest store (Mirage_kv.Key.v id) >|= function
      | Ok digest -> Some (to_hex digest)
      | Error _ -> None
  end

  module Key = struct
    let key_src = Logs.Src.create "hsm.key" ~doc:"HSM key log"
    module Access = (val Logs.src_log key_src : Logs.LOG)

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

    (* how a key is persisted in the kv store. note that while mirage-crypto
       provides s-expression conversions, these have been removed from the
       trunk version -- it is also not safe to embed s-expressions into json.
       to avoid these issues, we use PKCS8 encoding as PEM (embedding DER in
       json is not safe as well)!
    *)
    type priv = X509.Private_key.t
    let priv_to_yojson p =
      `String (Cstruct.to_string (X509.Private_key.encode_pem p))
    let priv_of_yojson = function
      | `String data ->
        begin match X509.Private_key.decode_pem (Cstruct.of_string data) with
          | Ok priv -> Ok priv
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
      purpose : Json.purpose ;
      priv : priv ;
      cert : (string * string) option ;
      operations : int ;
    } [@@deriving yojson]

    let encode_and_write t id key =
      let store = key_store t
      and value = key_to_yojson key
      and kv_key = Mirage_kv.Key.v id
      in
      Lwt_mutex.with_lock write_lock (fun () ->
          internal_server_error "Write key" Encrypted_store.pp_write_error
            (Encrypted_store.set store kv_key (Yojson.Safe.to_string value)))

    let add ~id t purpose priv =
      let open Lwt_result.Infix in
      let store = key_store t in
      let key = Mirage_kv.Key.v id in
      internal_server_error "Exist key" Encrypted_store.pp_error
        (Encrypted_store.exists store key) >>= function
      | Some _ ->
        Lwt.return (Error (Bad_request, "Key with id " ^ id ^ " already exists"))
      | None ->
        encode_and_write t id { purpose ; priv ; cert = None ; operations = 0 }

    let add_json ~id t purpose algorithm key =
      let b64err msg ctx data =
        Rresult.R.error_msgf
          "Invalid base64 encoded value (error: %s) in %S: %s"
          msg ctx data
      in
      let to_z ctx data =
        match Base64.decode data with
        | Ok num -> Ok (Mirage_crypto_pk.Z_extra.of_cstruct_be (Cstruct.of_string num))
        | Error `Msg msg -> b64err msg ctx data
      in
      match
        if algorithm = "RSA" then
          let open Rresult.R.Infix in
          to_z "primeP" key.Json.primeP >>= fun p ->
          to_z "primeQ" key.primeQ >>= fun q ->
          to_z "publicExponent" key.publicExponent >>= fun e ->
          Mirage_crypto_pk.Rsa.priv_of_primes ~e ~p ~q >>| fun key ->
          `RSA key
        else if algorithm = "ED25519" then
          match Base64.decode key.data with
          | Ok k ->
            (try Ok (`ED25519 (Hacl_ed25519.priv (Cstruct.of_string k))) with
               Invalid_argument e -> Error (`Msg ("invalid ED25519 key: " ^ e)))
          | Error `Msg m -> b64err m "data" key.data
        else Error (`Msg "Unsupported key algorithm.")
      with
      | Error `Msg e -> Lwt.return (Error (Bad_request, e))
      | Ok priv -> add ~id t purpose priv

    let add_pem ~id t purpose data =
      match X509.Private_key.decode_pem (Cstruct.of_string data) with
      | Error `Msg m -> Lwt.return (Error (Bad_request, m))
      | Ok priv -> add ~id t purpose priv

    let generate ~id t typ purpose ~length =
      if typ = "RSA" && 1024 <= length && length <= 8192 then begin
        let priv = Mirage_crypto_pk.Rsa.generate ~bits:length () in
        Metrics.key_op `Generate;
        add ~id t purpose (`RSA priv)
      end else if typ = "ED25519" then begin
        let priv = Hacl_ed25519.priv (Mirage_crypto_rng.generate 32) in
        Metrics.key_op `Generate;
        add ~id t purpose (`ED25519 priv)
      end
      else Lwt.return @@ Error (Bad_request, "Length must be between 1024 and 8192.")

    let remove t ~id =
      let open Lwt_result.Infix in
      let store = key_store t in
      Lwt_mutex.with_lock write_lock (fun () ->
          internal_server_error "Remove key" Encrypted_store.pp_write_error
            (Encrypted_store.remove store (Mirage_kv.Key.v id) >|= fun () ->
             Access.info (fun m -> m "removed (%s)" id)))

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
        Base64.encode_string @@ Cstruct.to_string @@ Mirage_crypto_pk.Z_extra.to_cstruct_be n
      in
      match key.priv with
      | `RSA k ->
        Json.rsaPublicKey_to_yojson
          { Json.purpose = key.purpose ;
            algorithm = "RSA" ;
            modulus = z_to_b64 k.Mirage_crypto_pk.Rsa.n ;
            publicExponent = z_to_b64 k.Mirage_crypto_pk.Rsa.e ;
            operations = key.operations ;
          }
      | `ED25519 k ->
        Json.ed25519PublicKey_to_yojson
          { Json.purpose = key.purpose ;
            algorithm = "ED25519" ;
            data = Base64.encode_string (Cstruct.to_string (Hacl_ed25519.priv_to_public k));
            operations = key.operations ;
          }

    let get_pem t ~id =
      let open Lwt_result.Infix in
      get_key t id >|= fun key ->
      let pub = X509.Private_key.public key.priv in
      Cstruct.to_string @@ X509.Public_key.encode_pem pub

    let csr_pem t ~id subject =
      let open Lwt_result.Infix in
      get_key t id >>= fun key ->
      match key.priv with
      | `RSA priv ->
        let subject' = Json.to_distinguished_name subject in
        let csr = X509.Signing_request.create subject' (`RSA priv) in
        let data = Cstruct.to_string @@ X509.Signing_request.encode_pem csr in
        Lwt.return (Ok data)
      | `ED25519 _ ->
        Lwt.return (Error (Bad_request, "CSR only supported for RSA keys"))

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

    module Oaep_md5 = Mirage_crypto_pk.Rsa.OAEP(Mirage_crypto.Hash.MD5)
    module Oaep_sha1 = Mirage_crypto_pk.Rsa.OAEP(Mirage_crypto.Hash.SHA1)
    module Oaep_sha224 = Mirage_crypto_pk.Rsa.OAEP(Mirage_crypto.Hash.SHA224)
    module Oaep_sha256 = Mirage_crypto_pk.Rsa.OAEP(Mirage_crypto.Hash.SHA256)
    module Oaep_sha384 = Mirage_crypto_pk.Rsa.OAEP(Mirage_crypto.Hash.SHA384)
    module Oaep_sha512 = Mirage_crypto_pk.Rsa.OAEP(Mirage_crypto.Hash.SHA512)

    let decrypt t ~id decrypt_mode data =
      let open Lwt_result.Infix in
      get_key t id >>= fun key_data ->
      let oneline = Astring.String.(concat ~sep:"" (cuts ~sep:"\n" data)) in
      match Base64.decode oneline with
      | Error `Msg msg ->
        Lwt.return (Error (Bad_request, "Couldn't decode data from base64: " ^ msg ^ "."))
      | Ok encrypted_data ->
        let encrypted_cs = Cstruct.of_string encrypted_data in
        match key_data.purpose, key_data.priv with
        | Decrypt, `RSA key | SignAndDecrypt, `RSA key ->
          let dec_cs_opt =
            match decrypt_mode with
            | Json.RAW ->
              (try Some (Mirage_crypto_pk.Rsa.decrypt ~key encrypted_cs)
               with Mirage_crypto_pk.Rsa.Insufficient_key -> None)
            | PKCS1 -> Mirage_crypto_pk.Rsa.PKCS1.decrypt ~key encrypted_cs
            | OAEP_MD5 -> Oaep_md5.decrypt ~key encrypted_cs
            | OAEP_SHA1 -> Oaep_sha1.decrypt ~key encrypted_cs
            | OAEP_SHA224 -> Oaep_sha224.decrypt ~key encrypted_cs
            | OAEP_SHA256 -> Oaep_sha256.decrypt ~key encrypted_cs
            | OAEP_SHA384 -> Oaep_sha384.decrypt ~key encrypted_cs
            | OAEP_SHA512 -> Oaep_sha512.decrypt ~key encrypted_cs
          in
          begin match dec_cs_opt with
            | None -> Lwt.return (Error (Bad_request, "Decryption failure."))
            | Some cs ->
              Metrics.key_op `Decrypt;
              (* ignore potential write error *)
              let open Lwt.Infix in
              let key_data' = { key_data with operations = succ key_data.operations } in
              encode_and_write t id key_data' >|= fun _ ->
              Ok (Base64.encode_string @@ Cstruct.to_string cs)
          end
        | Decrypt, _ | SignAndDecrypt, _ ->
          Lwt.return (Error (Bad_request, "Not an RSA key."))
        | Sign, _ ->
          Lwt.return (Error (Bad_request, "Key purpose is not decrypt."))

    module Pss_md5 = Mirage_crypto_pk.Rsa.PSS(Mirage_crypto.Hash.MD5)
    module Pss_sha1 = Mirage_crypto_pk.Rsa.PSS(Mirage_crypto.Hash.SHA1)
    module Pss_sha224 = Mirage_crypto_pk.Rsa.PSS(Mirage_crypto.Hash.SHA224)
    module Pss_sha256 = Mirage_crypto_pk.Rsa.PSS(Mirage_crypto.Hash.SHA256)
    module Pss_sha384 = Mirage_crypto_pk.Rsa.PSS(Mirage_crypto.Hash.SHA384)
    module Pss_sha512 = Mirage_crypto_pk.Rsa.PSS(Mirage_crypto.Hash.SHA512)

    let sign t ~id sign_mode data =
      let open Lwt_result.Infix in
      get_key t id >>= fun key_data ->
      let oneline = Astring.String.(concat ~sep:"" (cuts ~sep:"\n" data)) in
      match Base64.decode oneline with
      | Error `Msg msg ->
        Lwt.return (Error (Bad_request, "Couldn't decode data from base64: " ^ msg ^ "."))
      | Ok to_sign ->
        let to_sign_cs = Cstruct.of_string to_sign in
        match key_data.purpose, key_data.priv with
        | Sign, `RSA key | SignAndDecrypt, `RSA key ->
          begin try
              Lwt_result.lift
                (match sign_mode with
                 | Json.PKCS1 -> Ok (Mirage_crypto_pk.Rsa.PKCS1.sig_encode ~key to_sign_cs)
                 | PSS_MD5 -> Ok (Pss_md5.sign ~key (`Message to_sign_cs))
                 | PSS_SHA1 -> Ok (Pss_sha1.sign ~key (`Message to_sign_cs))
                 | PSS_SHA224 -> Ok (Pss_sha224.sign ~key (`Message to_sign_cs))
                 | PSS_SHA256 -> Ok (Pss_sha256.sign ~key (`Message to_sign_cs))
                 | PSS_SHA384 -> Ok (Pss_sha384.sign ~key (`Message to_sign_cs))
                 | PSS_SHA512 -> Ok (Pss_sha512.sign ~key (`Message to_sign_cs))
                 | ED25519 -> Error (Bad_request, "Invalid sign mode and key type combination."))
              >>= fun signature ->
              Metrics.key_op `Sign;
              (* ignore potential write error *)
              let open Lwt.Infix in
              let key_data' = { key_data with operations = succ key_data.operations } in
              encode_and_write t id key_data' >|= fun _ ->
              Ok (Base64.encode_string @@ Cstruct.to_string signature)
            with Mirage_crypto_pk.Rsa.Insufficient_key ->
              Lwt.return (Error (Bad_request, "Signing failure."))
          end
        | Sign, `ED25519 key ->
          begin match sign_mode with
            | ED25519 ->
              let signature = Hacl_ed25519.sign key to_sign_cs in
              Metrics.key_op `Sign;
              (* ignore potential write error *)
              let open Lwt.Infix in
              let key_data' = { key_data with operations = succ key_data.operations } in
              encode_and_write t id key_data' >|= fun _ ->
              Ok (Base64.encode_string @@ Cstruct.to_string signature)
            | _ ->
              Lwt.return (Error (Bad_request, "Invalid sign mode and key type combination."))
          end
        | SignAndDecrypt, `ED25519 _ ->
          Lwt.return (Error (Bad_request, "Invalid key purpose."))
        | Decrypt, _ ->
          Lwt.return (Error (Bad_request, "Key purpose is not sign."))

    let list_digest t =
      let open Lwt.Infix in
      let store = key_store t in
      Encrypted_store.digest store Mirage_kv.Key.empty >|= function
      | Ok digest -> Some (to_hex digest)
      | Error _ -> None

    let digest t ~id =
      let open Lwt.Infix in
      let store = key_store t in
      Encrypted_store.digest store (Mirage_kv.Key.v id) >|= function
      | Ok digest -> Some (to_hex digest)
      | Error _ -> None
  end

  let provision t ~unlock ~admin time =
    let open Lwt_result.Infix in
    (* state already checked in Handler_provision.service_available *)
    assert (state t = `Unprovisioned);
    let unlock_salt = Rng.generate Crypto.salt_len in
    let unlock_key = Crypto.key_of_passphrase ~salt:unlock_salt unlock in
    let domain_key = Rng.generate (Crypto.key_len * 2) in
    let auth_store_key, key_store_key =
      Cstruct.split domain_key Crypto.key_len
    in
    Lwt_mutex.with_lock write_lock (fun () ->
        KV.batch t.kv (fun b ->
            internal_server_error
              "Initializing configuration store" KV.pp_write_error
              (Config_store.set b Version Version.current) >>= fun () ->
            internal_server_error
              "Writing private RSA key" KV.pp_write_error
              (Config_store.set b Private_key t.key) >>= fun () ->
            internal_server_error
              "Writing certificate chain key" KV.pp_write_error
              (Config_store.set b Certificate (t.cert, t.chain)) >>= fun () ->
            internal_server_error
              "Initializing configuration store" KV.pp_write_error
              (Config_store.set b Version Version.current) >>= fun () ->
            let auth_store =
              Encrypted_store.v Authentication ~key:auth_store_key t.kv
            in
            let a_v_key, a_v_value =
              Encrypted_store.prepare_set auth_store Version.filename Version.(to_string current)
            in
            internal_server_error
              "Initializing authentication store" KV.pp_write_error
              (KV.set b a_v_key a_v_value) >>= fun () ->
            let key_store =
              Encrypted_store.v Key ~key:key_store_key t.kv
            in
            let k_v_key, k_v_value =
              Encrypted_store.prepare_set key_store Version.filename Version.(to_string current)
            in
            internal_server_error
              "Initializing key store" KV.pp_write_error
              (KV.set b k_v_key k_v_value) >>= fun () ->
            let keys = { domain_key ; auth_store ; key_store } in
            t.state <- Operational keys;
            let admin_k, admin_v =
              let name = "admin" in
              let admin = User.prepare_user ~name ~passphrase:admin ~role:`Administrator in
              let value = Yojson.Safe.to_string (User.user_to_yojson admin) in
              Encrypted_store.prepare_set auth_store (Mirage_kv.Key.v name) value
            in
            internal_server_error "set Administrator user" KV.pp_write_error
              (KV.set b admin_k admin_v) >>= fun () ->
            internal_server_error "set domain key" KV.pp_write_error
              (Domain_key_store.set b Passphrase ~unlock_key domain_key) >>= fun () ->
            internal_server_error "set unlock-salt" KV.pp_write_error
              (Config_store.set b Unlock_salt unlock_salt) >>= fun () ->
            set_time_offset b time))

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
        Lwt_mutex.with_lock write_lock (fun () ->
            KV.batch t.kv (fun b ->
                internal_server_error "Write unlock salt" KV.pp_write_error
                  (Config_store.set b Unlock_salt unlock_salt) >>= fun () ->
                internal_server_error "Write passphrase" KV.pp_write_error
                  (Domain_key_store.set b Passphrase ~unlock_key keys.domain_key)))
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
        Lwt_mutex.with_lock write_lock (fun () ->
            internal_server_error "Write unattended boot" KV.pp_write_error
              (Config_store.set t.kv Unattended_boot status) >>= fun () ->
            if status then begin
              let salt, unlock_key = salted t.device_id in
              KV.batch t.kv (fun b ->
                  internal_server_error "Write device ID salt" KV.pp_write_error
                    (Config_store.set b Device_id_salt salt) >>= fun () ->
                  internal_server_error "Write device ID" KV.pp_write_error
                    (Domain_key_store.set b Device_id ~unlock_key keys.domain_key))
            end else begin
              KV.batch t.kv (fun b ->
                  internal_server_error "Remove device ID salt" KV.pp_write_error
                    (Config_store.remove b Device_id_salt) >>= fun () ->
                  internal_server_error "Remove device ID" KV.pp_write_error
                    (Domain_key_store.remove b Device_id))
        end)
      | _ -> assert false (* Handler_config.service_available checked that we are operational *)

    let unattended_boot_digest t =
      let open Lwt.Infix in
      Config_store.digest t.kv Unattended_boot >|= function
      | Ok digest -> Some (to_hex digest)
      | Error _ -> None

    let tls_public_pem t =
      let public = X509.Private_key.public t.key in
      Lwt.return (Cstruct.to_string (X509.Public_key.encode_pem public))

    let tls_public_pem_digest t =
      let open Lwt.Infix in
      Config_store.digest t.kv Private_key >|= function
      | Ok digest -> Some (to_hex digest)
      | Error _ -> None

    let tls_cert_pem t =
      let chain = t.cert :: t.chain in
      Lwt.return (Cstruct.to_string (X509.Certificate.encode_pem_multiple chain))

    let set_tls_cert_pem t cert_data =
      (* validate the incoming chain (we'll use it for the TLS server):
         - there's one server certificate at either end (matching our private key)
         - the chain itself is properly signed (i.e. a full chain missing the TA)
         --> take the last element as TA (unchecked), and verify the chain!
      *)
      match X509.Certificate.decode_pem_multiple (Cstruct.of_string cert_data) with
      | Error `Msg m -> Lwt.return @@ Error (Bad_request, m)
      | Ok [] -> Lwt.return @@ Error (Bad_request, "empty certificate chain")
      | Ok (cert :: chain) ->
        if X509.Private_key.public t.key = X509.Certificate.public_key cert then
          let valid = match List.rev chain with
            | [] -> Ok cert
            | ta :: chain' ->
              let our_chain = cert :: List.rev chain' in
              let time () = Some (now ()) in
              Rresult.R.error_to_msg ~pp_error:X509.Validation.pp_chain_error
                (X509.Validation.verify_chain ~anchors:[ta] ~time ~host:None our_chain)
          in
          match valid with
          | Error `Msg m -> Lwt.return @@ Error (Bad_request, m)
          | Ok _ ->
            let open Lwt_result.Infix in
            Lwt_mutex.with_lock write_lock (fun () ->
                internal_server_error "Write certificate" KV.pp_write_error
                  (Config_store.set t.kv Certificate (cert, chain))) >>= fun r ->
            t.cert <- cert; t.chain <- chain;
            Lwt_result.ok (Lwt_mvar.put t.mbox (Tls (own_cert t))) >|= fun () ->
            r
        else
          Lwt.return @@ Error (Bad_request, "public key in certificate does not match private key.")

    let tls_cert_digest t =
      let open Lwt.Infix in
      Config_store.digest t.kv Certificate >|= function
      | Ok digest -> Some (to_hex digest)
      | Error _ -> None

    let tls_csr_pem t subject =
      let dn = Json.to_distinguished_name subject in
      let csr = X509.Signing_request.create dn t.key in
      Lwt.return (Cstruct.to_string (X509.Signing_request.encode_pem csr))

    let network t =
      let open Lwt.Infix in
      network_configuration t >|= fun (ipAddress, prefix, route) ->
      let netmask = Ipaddr.V4.Prefix.netmask prefix
      and gateway = match route with None -> Ipaddr.V4.any | Some ip -> ip
      in
      { Json.ipAddress ; netmask ; gateway }

    let set_network t network =
      let open Lwt_result.Infix in
      Lwt.return (
        let netmask = network.Json.netmask
        and address = network.ipAddress
        in
        Rresult.R.reword_error
          (function `Msg err ->
             Bad_request, "error parsing network configuration: " ^ err)
          (Ipaddr.V4.Prefix.of_netmask ~netmask ~address)) >>= fun prefix ->
      let route =
        if Ipaddr.V4.compare network.gateway Ipaddr.V4.any = 0 then
          None
        else
          Some network.gateway
      in
      Lwt_mutex.with_lock write_lock (fun () ->
          internal_server_error "Write network configuration" KV.pp_write_error
            Config_store.(set t.kv Ip_config (network.ipAddress, prefix, route))) >>= fun r ->
      Lwt_result.ok (Lwt_mvar.put t.mbox (Network (prefix, route))) >|= fun () ->
      r

    let network_digest t =
      let open Lwt.Infix in
      Config_store.digest t.kv Ip_config >|= function
      | Ok digest -> Some (to_hex digest)
      | Error _ -> None

    let default_log = { Json.ipAddress = Ipaddr.V4.any ; port = 514 ; logLevel = Info }

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
      let open Lwt_result.Infix in
      Lwt_mutex.with_lock write_lock (fun () ->
          internal_server_error "Write log config" KV.pp_write_error
            (Config_store.set t.kv Log_config (log.Json.ipAddress, log.port, log.logLevel))) >>= fun r ->
      Lwt_result.ok (Lwt_mvar.put t.mbox (Log log)) >|= fun () ->
      r

    let log_digest t =
      let open Lwt.Infix in
      Config_store.digest t.kv Log_config >|= function
      | Ok digest -> Some (to_hex digest)
      | Error _ -> None


    let set_backup_passphrase t ~passphrase =
      match t.state with
      | Operational _keys ->
        let open Lwt_result.Infix in
        let backup_salt, backup_key = salted passphrase in
        Lwt_mutex.with_lock write_lock (fun () ->
            KV.batch t.kv (fun b ->
                internal_server_error "Write backup salt" KV.pp_write_error
                  (Config_store.set b Backup_salt backup_salt) >>= fun () ->
                internal_server_error "Write backup key" KV.pp_write_error
                  (Config_store.set b Backup_key backup_key)))
      | _ -> assert false (* Handler_config.service_available checked that we are operational *)

    let time _t = Lwt.return (now ())

    let set_time t time =
      Lwt_mutex.with_lock write_lock (fun () -> set_time_offset t.kv time)
  end

  module System = struct
    let system_info t = t.system_info

    let reboot t = Lwt_mvar.put t.mbox Reboot

    let shutdown t = Lwt_mvar.put t.mbox Shutdown

    let reset t = Lwt_mvar.put t.mbox Reset

    let put_back stream chunk = if chunk = "" then stream else Lwt_stream.append (Lwt_stream.of_list [ chunk ]) stream

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

   let decode_length data =
     let data' = Cstruct.of_string data in
     let byte = Cstruct.get_uint8 data' 0 in
     let len = Cstruct.BE.get_uint16 data' 1 in
     byte lsl 16 + len

    let get_length stream =
      let open Lwt_result.Infix in
      read_n stream 3 >|= fun (data, stream') ->
      let length = decode_length data in
      (length, stream')

    let get_data (l, s) = read_n s l

    let get_field s =
      let open Lwt_result.Infix in
      get_length s >>=
      get_data

    let prefix_len s =
      let len_buf = Cstruct.create 3 in
      let length = String.length s in
      assert (length < 1 lsl 24); (* TODO *)
      Cstruct.set_uint8 len_buf 0 (length lsr 16);
      Cstruct.BE.set_uint16 len_buf 1 (length land 0xffff);
      Cstruct.to_string len_buf ^ s

    module Hash = Mirage_crypto.Hash.SHA256
    module Pss_sha256 = Mirage_crypto_pk.Rsa.PSS(Hash)

    let key = match X509.Public_key.decode_pem Crypto.software_update_key with
      | Ok `RSA key -> key
      | Ok _ -> invalid_arg "No RSA key from manufacturer. Contact manufacturer."
      | Error `Msg m -> invalid_arg m

    let update t s =
      let open Lwt_result.Infix in
      (* stream contains:
         - signature (hash of the rest)
         - changelog
         - version number
         - software image,
         first three are prefixed by 4 byte length *)
      get_field s >>= fun (signature, s') ->
      let hash = Hash.empty in
      get_field s' >>= fun (changes, s'') ->
      let hash' = Hash.feed hash (Cstruct.of_string @@ prefix_len changes) in
      get_field s'' >>= fun (version, s''') ->
      Lwt.return (version_of_string version) >>= fun version' ->
      let hash'' = Hash.feed hash' (Cstruct.of_string @@ prefix_len version) in
      Lwt_stream.fold_s (fun chunk acc ->
        match acc with
        | Error e -> Lwt.return (Error e)
        | Ok hash ->
          (*TODO stream to s_update*)
          let hash' = Hash.feed hash (Cstruct.of_string chunk) in
          Lwt.return @@ Ok hash')
        s''' (Ok hash'') >>= fun hash ->
      let final_hash = Hash.get hash in
      let signature = Cstruct.of_string signature in
      if Pss_sha256.verify ~key ~signature (`Digest final_hash) then
        let current = t.system_info.softwareVersion in
        if version_is_upgrade ~current ~update:version' then
        begin
          (* store changelog *)
          t.has_changes <- Some changes;
          Lwt.return (Ok changes)
        end
        else
          Lwt.return (Error (Conflict, "Software version downgrade not allowed."))
      else
        Lwt.return (Error (Bad_request, "Signature check of update image failed."))

    let commit_update t =
      match t.has_changes with
      | None -> Error (Precondition_failed, "No update available. Please upload a system image to /system/update.")
      | Some _changes -> Ok () (* TODO call hardware *)

    let cancel_update t =
      match t.has_changes with
      | None -> Error (Precondition_failed, "No update available. Please upload a system image to /system/update.")
      | Some _changes -> t.has_changes <- None; Ok ()

    let backup_version = Version.V0

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
                  let data = prefix_len key_str ^ data in
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
          let encrypted_version =
            let data = Cstruct.of_string (Version.to_string backup_version)
            and adata = Cstruct.of_string "backup-version"
            in
            Crypto.encrypt Rng.generate ~key:backup_key' ~adata data
          in
          push (Some (prefix_len (Cstruct.to_string encrypted_version)));
          backup_directory t.kv push backup_key' Mirage_kv.Key.empty >|= fun () ->
          push None;
          Ok ()

    let decode_value = get_field

    let split_kv data =
      (* len:key len:value *)
      let msg = "Missing length field in backup data. Backup not readable, try another one." in
      let key_len = decode_length data in
      if String.length data < key_len + 3
      then Error (Bad_request, msg)
      else
        let key = String.sub data 3 key_len in
        let val_start = 3 + key_len in
        let value = String.sub data val_start (String.length data - val_start) in
        Ok (key, value)

    let read_and_decrypt stream key =
      let open Lwt.Infix in
      decode_value stream >|= function
      | Error e -> Error e
      | Ok (encrypted_data, stream') ->
        let adata = Cstruct.of_string "backup" in
        match Crypto.decrypt ~key ~adata (Cstruct.of_string encrypted_data) with
        | Error `Insufficient_data -> Error (Bad_request, "Could not decrypt backup. Backup incomplete, try another one.")
        | Error `Not_authenticated -> Error (Bad_request, "Could not decrypt backup, authentication failed. Is the passphrase correct?")
        | Ok kv -> match split_kv (Cstruct.to_string kv) with
          | Ok kv' -> Ok (kv', stream')
          | Error e -> Error e

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
      let `Raw start_ts = Clock.now_raw () in
      Lwt.return @@ get_query_parameters uri >>== fun (new_time, backup_passphrase) ->
      decode_value stream >>== fun (backup_salt, stream') ->
      decode_value stream' >>== fun (version, stream'') ->
      let backup_key =
        Crypto.key_of_passphrase ~salt:(Cstruct.of_string backup_salt) backup_passphrase
      in
      let key = Crypto.GCM.of_secret backup_key in
      let adata = Cstruct.of_string "backup-version" in
      match Crypto.decrypt ~key ~adata (Cstruct.of_string version) with
      | Error `Insufficient_data ->
        Lwt.return @@ Error (Bad_request, "Could not decrypt backup version. Backup incomplete, try another one.")
      | Error `Not_authenticated ->
        Lwt.return @@ Error (Bad_request, "Could not decrypt backup version, authentication failed. Is the passphrase correct?")
      | Ok version ->
        Lwt_mutex.with_lock write_lock (fun () ->
            match Version.of_string (Cstruct.to_string version) with
            | Ok v when Version.compare backup_version v = `Equal ->
              begin
                let rec next stream =
                  Lwt_stream.is_empty stream >>= function
                  | true -> t.state <- Locked ; Lwt.return (Ok ())
                  | false ->
                    read_and_decrypt stream key >>== fun ((k, v), stream) ->
                    internal_server_error "restoring backup (writing to KV)" KV.pp_write_error
                      (KV.set t.kv (Mirage_kv.Key.v k) v) >>== fun () ->
                    next stream
                in
                next stream'' >>== fun () ->
                let `Raw stop_ts = Clock.now_raw () in
                let elapsed = Ptime.diff stop_ts start_ts in
                match Ptime.add_span new_time elapsed with
                | Some ts -> set_time_offset t.kv ts
                | None ->
                  t.state <- Unprovisioned;
                  Lwt.return @@ Error (Bad_request, "Invalid system time in restore request")
              end
            | _ ->
              let msg =
                Printf.sprintf
                  "Version mismatch on restore, provided backup version is %s, server expects %s"
                  (Cstruct.to_string version) (Version.to_string backup_version)
              in
              Lwt.return @@ Error (Bad_request, msg))
  end
end
