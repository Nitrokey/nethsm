module type S = sig

  module Metrics : sig
    val http_status : Cohttp.Code.status_code -> unit
    val http_response_time : float -> unit
    val retrieve : unit -> (string * string) list
  end

  val now : unit -> Ptime.t

  type status_code =
    | Internal_server_error
    | Bad_request
    | Forbidden
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
    | Factory_reset
    | Update of int * string Lwt_stream.t
    | Commit_update

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

    val tls_csr_pem : t -> Json.subject_req -> (string, error) result Lwt.t

    val tls_generate : t -> X509.Key_type.t -> length:int -> (unit, error) result Lwt.t

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

    val factory_reset : t -> unit Lwt.t

    val update : t -> string Lwt_stream.t -> (string, error) result Lwt.t

    val commit_update : t -> (unit, error) result Lwt.t

    val cancel_update : t -> (unit, error) result

    val backup : t -> (string option -> unit) ->
      (unit, error) result Lwt.t

    val restore : t -> Uri.t -> string Lwt_stream.t ->
      (unit, error) result Lwt.t
  end

  module User : sig

    module Info : sig
      type t

      val name : t -> string

      val role : t -> Json.role

      val tags : t -> Json.TagSet.t
    end

    val is_authenticated : t -> username:string -> passphrase:string ->
      bool Lwt.t

    val is_authorized : t -> string -> Json.role -> bool Lwt.t

    val list : t -> (string list, error) result Lwt.t

    val exists : t -> id:string -> (bool, error) result Lwt.t

    val get : t -> id:string -> (Info.t, error) result Lwt.t

    val add : id:string -> t -> role:Json.role -> passphrase:string ->
      name:string -> (unit, error) result Lwt.t

    val remove : t -> id:string -> (unit, error) result Lwt.t

    val set_passphrase : t -> id:string -> passphrase:string ->
      (unit, error) result Lwt.t

    val add_tag : t -> id:string -> tag:string -> (bool, error) result Lwt.t

    val remove_tag : t -> id:string -> tag:string -> (bool, error) result Lwt.t

    val list_digest : t -> string option Lwt.t

    val digest : t -> id:string -> string option Lwt.t
  end

  module Key : sig
    val exists : t -> id:string -> (bool, error) result Lwt.t

    val list : t -> filter_by_restrictions:bool -> user_id:string -> (string list, error) result Lwt.t

    val add_json : id:string -> t -> Json.MS.t -> Json.key_type -> Json.key -> Json.restrictions ->
      (unit, error) result Lwt.t

    val add_pem : id:string -> t -> Json.MS.t -> string -> Json.restrictions ->
      (unit, error) result Lwt.t

    val generate : id:string -> t -> Json.key_type -> Json.MS.t -> length:int -> Json.restrictions ->
      (unit, error) result Lwt.t

    val remove : t -> id:string -> (unit, error) result Lwt.t

    val get_json : t -> id:string -> (Yojson.Safe.t, error) result Lwt.t

    val get_pem : t -> id:string -> (string, error) result Lwt.t

    val csr_pem : t -> id:string -> Json.subject_req -> (string, error) result Lwt.t

    val get_cert : t -> id:string -> ((string * string) option, error) result Lwt.t

    val set_cert : t -> id:string -> content_type:string -> string -> (unit, error) result Lwt.t

    val remove_cert : t -> id:string -> (unit, error) result Lwt.t

    val get_restrictions : t -> id:string -> (Json.restrictions, error) result Lwt.t

    val add_restriction_tags : t -> id:string -> tag:string -> (bool, error) result Lwt.t

    val remove_restriction_tags : t -> id:string -> tag:string -> (bool, error) result Lwt.t

    val decrypt : t -> id:string -> user_id:string -> iv:string option -> Json.decrypt_mode -> string -> (string, error) result Lwt.t

    val encrypt : t -> id:string -> user_id:string -> iv:string option -> Json.encrypt_mode -> string -> (string * string option, error) result Lwt.t

    val sign : t -> id:string -> user_id:string -> Json.sign_mode -> string -> (string, error) result Lwt.t

    val list_digest : t -> filter_by_restrictions:bool -> string option Lwt.t

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

let build_tag = String.trim [%blob "buildTag"]
let software_version = String.trim [%blob "softwareVersion"]

module Make (Rng : Mirage_random.S) (KV : Mirage_kv.RW) (Time : Mirage_time.S) (Monotonic_clock : Mirage_clock.MCLOCK) (Clock : Hsm_clock.HSMCLOCK) = struct
  module Metrics = struct
    let db = Hashtbl.create 13

    let retrieve () =
      Hashtbl.fold (fun k v acc -> (k, v) :: acc) db []

    let sample_interval = Duration.of_sec 1

    let started = Monotonic_clock.elapsed_ns ()

    let now () = Int64.sub (Monotonic_clock.elapsed_ns ()) started

    let uptime_src =
      let open Metrics in
      let doc = "Uptime" in
      let data () =
        let seconds = Duration.to_sec (now ()) in
        Data.v [ int "uptime" seconds ]
      in
      Src.v ~doc ~tags:Metrics.Tags.[] ~data "uptime"

    let log_src =
      let open Metrics in
      let doc = "Log message types" in
      let data () =
        let warns = Logs.warn_count ()
        and errs = Logs.err_count ()
        in
        Data.v [ int "log warnings" warns ; int "log errors" errs ]
      in
      Src.v ~doc ~tags:Metrics.Tags.[] ~data "log msg type"

    let gc_src =
      let open Metrics in
      let doc = "Garbage collection" in
      let data () =
        let gc_stat = Gc.quick_stat () in
        let major_bytes = gc_stat.heap_words * 8 in
        Data.v [ int "gc major bytes" major_bytes ;
                 int "gc major collections" gc_stat.major_collections ;
                 int "gc minor collections" gc_stat.minor_collections ;
                 int "gc compactions" gc_stat.compactions ;
               ]
      in
      Src.v ~doc ~tags:Metrics.Tags.[] ~data "gc"

    let key_ops_src =
      let open Metrics in
      let doc = "Key operations" in
      let data (generate, sign, decrypt, encrypt) =
        Data.v [ int "generate" generate ; int "sign" sign ; int "decrypt" decrypt ; int "encrypt" encrypt ]
      in
      Src.v ~doc ~tags:Metrics.Tags.[] ~data "key operations"

    let ops = ref (0, 0, 0, 0)

    let key_op op =
      let g, s, d, e = !ops in
      (match op with
      | `Generate -> ops := g + 1, s, d, e
      | `Sign -> ops := g, s + 1, d, e
      | `Decrypt -> ops := g, s, d + 1, e
      | `Encrypt -> ops := g, s, d, e + 1);
      Metrics.add key_ops_src (fun t -> t) (fun m -> m !ops)

    let http_status = Hashtbl.create 7

    let http_status_src =
      let open Metrics in
      let doc = "HTTP status" in
      let data () =
        let codes =
          Hashtbl.fold
            (fun k v acc ->
               let key =
                 let v = if k = 0 then "total" else string_of_int k in
                 "http response " ^ v
               in
               uint key v :: acc)
            http_status []
        in
        Data.v codes
      in
      Src.v ~doc ~tags:Metrics.Tags.[] ~data "http status"

    let total_code = 0

    let http_status status =
      let code = Cohttp.Code.code_of_status status in
      let old_counter = match Hashtbl.find_opt http_status code with None -> 0 | Some x -> x in
      Hashtbl.replace http_status code (succ old_counter);
      let total = match Hashtbl.find_opt http_status total_code with None -> 0 | Some x -> x in
      Hashtbl.replace http_status total_code (succ total);
      Metrics.add http_status_src (fun t -> t) (fun m -> m ())

    let response_time = ref 0.0

    let http_response_time_src =
      let open Metrics in
      let doc = "HTTP response time" in
      let data () =
        Data.v [ float "http response time" !response_time ]
      in
      Src.v ~doc ~tags:Metrics.Tags.[] ~data "http response time"

    let http_response_time measured =
      if measured > 0. then begin
        (* exponentially weighted moving average / exponential smoothed / holt linear*)
        response_time := 0.7 *. !response_time +. 0.3 *. measured;
        Metrics.add http_response_time_src (fun t -> t) (fun m -> m ())
      end

    let writes = ref 0

    let write_src =
      let open Metrics in
      let doc = "KV writes" in
      let data () =
        Data.v [ int "kv write" !writes ]
      in
      Src.v ~doc ~tags:Metrics.Tags.[] ~data "KV writes"

    let write () =
      incr writes;
      Metrics.add write_src (fun t -> t) (fun m -> m ())

    let sample () =
      Metrics_lwt.periodically uptime_src;
      Metrics_lwt.periodically log_src;
      Metrics_lwt.periodically gc_src;
      let sleeper () = Time.sleep_ns sample_interval in
      Metrics_lwt.init_periodic ~gc:`None ~logs:false sleeper

    let set_mem_reporter () =
      let report ~tags ~data ~over _src k =
        let data_fields = Metrics.Data.fields data in
        let tag t =
          Fmt.to_to_string Metrics.pp_value t
        in
        let tags = List.map tag tags in
        let field f =
          String.concat "." (tags @ [ Fmt.to_to_string Metrics.pp_key f ]),
          Fmt.to_to_string Metrics.pp_value f
        in
        let fields = List.map field in
        List.iter
          (fun (field_name, field_value) -> Hashtbl.replace db field_name field_value)
          (fields data_fields);
        over (); k ()
      in
      let at_exit () = () in
      Metrics.enable_all ();
      Metrics.set_reporter {Metrics.report; now; at_exit};
      sample ()
  end

  (* fatal is called on error conditions we do not expect (hardware failure,
     KV inconsistency). The message will appear on the serial console of the
     hardware.. *)
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
    | Forbidden
    | Precondition_failed
    | Conflict
    | Too_many_requests

  (* string is the body, which may contain error message *)
  type error = status_code * string

  let error_to_code code =
    let status = match code with
    | Internal_server_error -> `Internal_server_error
    | Bad_request -> `Bad_request
    | Forbidden -> `Forbidden
    | Precondition_failed -> `Precondition_failed
    | Conflict -> `Conflict
    | Too_many_requests -> `Too_many_requests
    in
    Cohttp.Code.code_of_status status

  type operation = Write | Read | Unlock

  let internal_server_error operation context pp_err f =
    let open Lwt.Infix in
    f >|= function
    | Ok x -> Ok x
    | Error e ->
      let operation_message, error_message =
        match operation with
        | Write -> "writing to the key-value store", "Could not write to database. Check logs."
        | Read -> "read from the key-value store", "Could not read from database. Check logs."
        | Unlock -> "connecting to the key-value store", "Could not connect to database. Check logs."
      in
      Log.err (fun m -> m "Error: %a while %s: %s." pp_err e operation_message context);
      Error (Internal_server_error, error_message)

  let pp_state ppf s =
    Fmt.string ppf (match s with
        | `Unprovisioned -> "unprovisioned"
        | `Operational -> "operational"
        | `Locked -> "locked") [@@coverage off]

  type cb =
    | Log of Json.log
    | Network of Ipaddr.V4.Prefix.t * Ipaddr.V4.t option
    | Tls of Tls.Config.own_cert
    | Shutdown
    | Reboot
    | Factory_reset
    | Update of int * string Lwt_stream.t
    | Commit_update

  let cb_to_string = function
    | Log l -> "LOG " ^ Yojson.Safe.to_string (Json.log_to_yojson l)
    | Network (prefix, gw) ->
      let gw = match gw with None -> "no" | Some ip -> Ipaddr.V4.to_string ip in
      "NETWORK " ^ Ipaddr.V4.Prefix.to_string prefix ^ ", gateway: " ^ gw
    | Tls _ -> "TLS_CERTIFICATE"
    | Shutdown -> "SHUTDOWN"
    | Reboot -> "REBOOT"
    | Factory_reset -> "FACTORY-RESET"
    | Update _ -> "UPDATE"
    | Commit_update -> "COMMIT-UPDATE"

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
    mutable key : X509.Private_key.t ;
    mutable cert : X509.Certificate.t ;
    mutable chain : X509.Certificate.t list ;
    software_update_key : Mirage_crypto_pk.Rsa.pub ;
    kv : KV.t ;
    info : Json.info ;
    system_info : Json.system_info ;
    mbox : cb Lwt_mvar.t ;
    res_mbox : (unit, string) result Lwt_mvar.t ;
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

  let with_write_lock f =
    let open Lwt.Infix in
    Lwt_mutex.with_lock write_lock
      (fun () ->
         try f () >|= fun k -> Metrics.write (); k with
         | Invalid_argument txt ->
           Log.err (fun m -> m "Error while writing to key-value store: %s" txt);
           Lwt.return (Error (Internal_server_error, "Could not write to disk.")))

  let set_time_offset kv timestamp =
    Clock.set timestamp;
    let span = Clock.get_offset () in
    internal_server_error Write "Write time offset" KV.pp_write_error
      (Config_store.set kv Time_offset span)

  let prepare_keys kv slot credentials =
    let open Lwt_result.Infix in
    let get_salt_key = function
      | Domain_key_store.Passphrase -> Config_store.Unlock_salt
      | Domain_key_store.Device_id -> Config_store.Device_id_salt
    in
    internal_server_error Read "Prepare keys" Config_store.pp_error
      (Config_store.get kv (get_salt_key slot)) >>= fun salt ->
    let unlock_key = Crypto.key_of_passphrase ~salt credentials in
    Lwt_result.map_error (function `Msg m -> Forbidden, m)
      (Domain_key_store.get kv slot ~unlock_key) >|= fun domain_key ->
    let auth_store_key, key_store_key =
      Cstruct.split domain_key Crypto.key_len
    in
    (domain_key, auth_store_key, key_store_key)

  let unlock_store kv slot key =
    let open Lwt_result.Infix in
    let slot_str = Encrypted_store.slot_to_string slot in
    internal_server_error Unlock
      ("connecting to " ^ slot_str ^ " store")
      Encrypted_store.pp_connect_error
      (Encrypted_store.unlock Version.current slot ~key kv)
    >>= function
        | `Version_greater (stored, _t) ->
          (* upgrade code for authentication store *)
          Lwt.return @@ Error (Internal_server_error, Fmt.str "%s store too old (%a), no migration code" slot_str Version.pp stored)
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

  let generate_cert priv =
    (* this is before provisioning, our posix time may be not accurate *)
    let valid_from = Ptime.epoch
    and valid_until = Ptime.max
    in
    let dn = [ X509.Distinguished_name.(Relative_distinguished_name.singleton (CN "keyfender")) ] in
    match X509.Signing_request.create dn priv with
    | Error e ->
      fatal "creating signing request"
        ~pp_error:X509.Validation.pp_signature_error e
    | Ok csr ->
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

  let info t = t.info

  let own_cert t = `Single (t.cert :: t.chain, t.key)

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

    module Info = struct
      type t = {
        name : string ;
        salt : string ;
        digest : string ;
        role : Json.role ;
        tags : Json.TagSet.t ;
      }[@@deriving yojson]

      let name t = t.name

      let role t = t.role

      let tags t = t.tags

    end

    let user_src = Logs.Src.create "hsm.user" ~doc:"HSM user log"
    module Access = (val Logs.src_log user_src : Logs.LOG)

    let pp_role ppf r =
      Fmt.string ppf @@ match r with
      | `Administrator -> "R-Administrator"
      | `Operator -> "R-Operator"
      | `Metrics -> "R-Metrics"
      | `Backup -> "R-Backup"


    let read_decode store id =
      let open Lwt.Infix in
      Encrypted_store.get store (Mirage_kv.Key.v id) >|= function
      | Error e -> Error (`Encrypted_store e)
      | Ok data ->
        Rresult.R.reword_error
          (fun err -> `Json_decode err)
          (Json.decode Info.of_yojson data)

    let pp_find_error ppf = function
      | `Encrypted_store kv -> Encrypted_store.pp_error ppf kv
      | `Msg msg -> Fmt.string ppf msg
      | `Json_decode msg -> Fmt.pf ppf "json decode failure %s" msg

    let write store id user =
      let user_str = Yojson.Safe.to_string (Info.to_yojson user) in
      with_write_lock (fun () ->
          internal_server_error Write "Write user" Encrypted_store.pp_write_error
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
        let pass =
          Crypto.stored_passphrase
            ~salt:(Cstruct.of_string user.salt)
            (Cstruct.of_string passphrase)
        in
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
      internal_server_error Read "Exists user" Encrypted_store.pp_error
       (Encrypted_store.exists store (Mirage_kv.Key.v id) >|= function
        | None -> false
        | Some _ -> true)

    let get t ~id =
      let store = in_store t in
      internal_server_error Read "Read user" pp_find_error
        (read_decode store id)

    let prepare_user ~name ~passphrase ~role =
      let salt = Rng.generate Crypto.passphrase_salt_len in
      let digest = Crypto.stored_passphrase ~salt (Cstruct.of_string passphrase) in
      { Info.name ;
        salt = Cstruct.to_string salt ;
        digest = Cstruct.to_string digest ;
        role ;
        tags = Json.TagSet.empty }

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
            internal_server_error Read "Adding user" pp_find_error
              (Lwt.return e))

    let list t =
      let open Lwt_result.Infix in
      let store = in_store t in
      internal_server_error Read "List users" Encrypted_store.pp_error
        (Encrypted_store.list store Mirage_kv.Key.empty) >|= fun xs ->
      List.map fst (List.filter (fun (_, typ) -> typ = `Value) xs)

    let remove t ~id =
      let open Lwt_result.Infix in
      let store = in_store t in
      with_write_lock (fun () ->
          internal_server_error Write "Remove user" Encrypted_store.pp_write_error
            (Encrypted_store.remove store (Mirage_kv.Key.v id) >|= fun () ->
             Access.info (fun m -> m "removed (%s)" id)))

    let set_passphrase t ~id ~passphrase =
      let open Lwt_result.Infix in
      let store = in_store t in
      internal_server_error Read "Read user" pp_find_error
        (read_decode store id) >>= fun user ->
      let salt' = Rng.generate Crypto.passphrase_salt_len in
      let digest' = Crypto.stored_passphrase ~salt:salt' (Cstruct.of_string passphrase) in
      let user' =
        { user with salt = Cstruct.to_string salt' ;
                    digest = Cstruct.to_string digest' }
      in
      write store id user' >|= fun () ->
      Access.info (fun m -> m "changed %s (%s) passphrase" id user.name)

    let add_tag t ~id ~tag =
      let open Lwt_result.Infix in
      let store = in_store t in
      internal_server_error Read "Read user" pp_find_error
        (read_decode store id) >>= fun user ->
      if Info.role user = `Operator then
        if not (Json.TagSet.mem tag user.tags) then
          let user' =
            { user with tags = Json.TagSet.add tag user.tags}
          in
          write store id user' >|= fun () ->
          Access.info (fun m -> m "added a tag to %s (%s): %S" id user.name tag);
          true
        else
          Lwt.return_ok false
      else
        Lwt.return_error (Bad_request, "tag operations only exist on operator users")

    let remove_tag t ~id ~tag =
      let open Lwt_result.Infix in
      let store = in_store t in
      internal_server_error Read "Read user" pp_find_error
        (read_decode store id) >>= fun user ->
      if Info.role user = `Operator then
        if Json.TagSet.mem tag user.tags then
          let user' = { user with tags = Json.TagSet.remove tag user.tags} in
          write store id user' >|= fun () ->
          Access.info (fun m -> m "removed a tag from %s (%s): %S" id user.name tag);
          true
        else
          Lwt.return_ok false
      else
        Lwt.return_error (Bad_request, "tag operations only exist on operator users")

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

    (* how a key is persisted in the kv store. note that while mirage-crypto
       provides s-expression conversions, these have been removed from the
       trunk version -- it is also not safe to embed s-expressions into json.
       to avoid these issues, we use PKCS8 encoding as PEM (embedding DER in
       json is not safe as well)!
    *)
    type priv =
      | X509 of X509.Private_key.t
      | Generic of string
    let pem_tag = "PEM"
    let raw_tag = "raw"

    let priv_to_yojson p =
      match p with
      | Generic s -> `Assoc [raw_tag, `String (Base64.encode_string s)]
      | X509 p -> `Assoc [pem_tag,
            `String (Cstruct.to_string (X509.Private_key.encode_pem p))]
    let priv_of_yojson = function
      | `Assoc [(tag, `String data)] when tag=raw_tag ->
        begin match Base64.decode data with
          | Ok s -> Ok (Generic s)
          | Error `Msg m -> Error m
        end
      | `Assoc [(tag, `String data)] when tag=pem_tag ->
        begin match X509.Private_key.decode_pem (Cstruct.of_string data) with
          | Ok priv -> Ok (X509 priv)
          | Error `Msg m -> Error m
        end
      | _ -> Error "Expected { <format>: <data> } as private key"

    let exists t ~id =
      let open Lwt_result.Infix in
      let store = key_store t in
      internal_server_error Read "Exists key" Encrypted_store.pp_error
        (Encrypted_store.exists store (Mirage_kv.Key.v id) >|= function
          | None -> false
          | Some _ -> true)

    type key = {
      mechanisms : Json.MS.t ;
      priv : priv ;
      cert : (string * string) option ;
      operations : int ;
      restrictions : Json.restrictions;
    } [@@deriving yojson]

    let validate_restrictions ~user_info (restrictions: Json.restrictions) =
      if Json.TagSet.is_empty restrictions.tags then
        Ok ()
      else if Json.TagSet.disjoint restrictions.tags (User.Info.tags user_info) then
        Error (Forbidden, "tags restriction not met")
      else
        Ok ()

    (* boilerplate for dumping keys whose operations changed *)
    let cached_operations = Hashtbl.create 7

    let get_key t id =
      let open Lwt_result.Infix in
      let store = key_store t in
      let key = Mirage_kv.Key.v id in
      internal_server_error Read "Read key" Encrypted_store.pp_error
        (Encrypted_store.get store key) >>= fun key_raw ->
      Lwt.return (match Json.decode key_of_yojson key_raw with
          | Ok k ->
            let operations =
              match Hashtbl.find_opt cached_operations id with
              | None -> k.operations
              | Some v -> v
            in
            Ok { k with operations }
          | Error e -> Error (Internal_server_error, e))

    let list t ~filter_by_restrictions ~user_id =
      let open Lwt_result.Infix in
      let store = key_store t in
      internal_server_error Read "List keys" Encrypted_store.pp_error
        (Encrypted_store.list store Mirage_kv.Key.empty) >>= fun xs ->
        User.get t ~id:user_id >>= fun user_info ->
      let open Lwt.Infix in
      let is_admin = User.Info.role user_info = `Administrator in
      let is_usable k =
        validate_restrictions ~user_info k.restrictions |> Result.is_ok
      in
      let values_id = 
        List.filter_map (function
          | (id, `Value) -> Some id
          | _ -> None) xs
      in
      if is_admin || not filter_by_restrictions then
        (* bypass filter *)
        Lwt.return_ok values_id
      else
        (* keep only usable keys *)
        let filter id =
          get_key t id >|= function
          | Ok k when is_usable k -> Some id
          | _ -> None
        in
        Lwt_list.filter_map_s filter values_id >|= fun l -> Ok l

    let dump_keys t =
      let open Lwt.Infix in
      match t.state with
      | Unprovisioned | Locked -> Lwt.return_unit
      | Operational _ ->
        with_write_lock (fun () ->
            let store = key_store t in
            KV.batch t.kv (fun b ->
                Hashtbl.fold (fun id _ x ->
                    x >>= function
                    | Error e -> Lwt.return (Error e)
                    | Ok () ->
                      get_key t id >>= function
                      | Error (_, msg) ->
                        (* this should not happen *)
                        Log.err (fun m -> m "error %s while retrieving key %s"
                                    msg id);
                        Lwt.return (Ok ())
                      | Ok k ->
                        let k_v_key, k_v_value =
                          Encrypted_store.prepare_set store (Mirage_kv.Key.v id)
                            (Yojson.Safe.to_string (key_to_yojson k))
                        in
                        KV.set b k_v_key k_v_value >>= function
                        | Ok () -> Lwt.return (Ok ())
                        | Error e ->
                          Log.err (fun m -> m "error %a while writing key %s"
                                      KV.pp_write_error e id);
                          Lwt.return (Ok ()))
                  cached_operations (Lwt.return (Ok ())))) >|= function
        | Ok () -> Hashtbl.clear cached_operations
        | Error _ -> ()

    let encode_and_write t id key =
      let store = key_store t
      and value = key_to_yojson key
      and kv_key = Mirage_kv.Key.v id
      in
      Hashtbl.remove cached_operations id;
      with_write_lock (fun () ->
          internal_server_error Write "Write key" Encrypted_store.pp_write_error
            (Encrypted_store.set store kv_key (Yojson.Safe.to_string value)))

    let add ~id t mechanisms priv restrictions =
      let open Lwt_result.Infix in
      let store = key_store t in
      let key = Mirage_kv.Key.v id in
      internal_server_error Read "Exist key" Encrypted_store.pp_error
        (Encrypted_store.exists store key) >>= function
      | Some _ ->
        Lwt.return (Error (Bad_request, "Key with id " ^ id ^ " already exists"))
      | None ->
          encode_and_write t id {
            mechanisms ;
            priv ;
            cert = None ;
            operations = 0 ;
            restrictions }

    let add_json ~id t mechanisms typ key restrictions =
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
      let b64_data data = match Base64.decode data with
        | Ok k -> Ok k
        | Error `Msg m -> b64err m "data" data
      in
      let open Rresult.R.Infix in
      match
        match typ with
        | Json.RSA ->
          to_z "primeP" key.Json.primeP >>= fun p ->
          to_z "primeQ" key.primeQ >>= fun q ->
          to_z "publicExponent" key.publicExponent >>= fun e ->
          Mirage_crypto_pk.Rsa.priv_of_primes ~e ~p ~q >>| fun key ->
          X509 (`RSA key)
        | Json.Generic ->
            b64_data key.data >>| fun k ->
            Generic k
        | _ ->
          b64_data key.data >>= fun k ->
          let typ = match typ with
            | Json.Curve25519 -> `ED25519
            | EC_P224 -> `P224
            | EC_P256 -> `P256
            | EC_P384 -> `P384
            | EC_P521 -> `P521
            | RSA -> assert false
            | Generic -> assert false
          in
          X509.Private_key.of_cstruct (Cstruct.of_string k) typ >>| fun p -> X509 p
      with
      | Error `Msg e -> Lwt.return (Error (Bad_request, e))
      | Ok priv -> add ~id t mechanisms priv restrictions

    let add_pem ~id t mechanisms data restrictions =
      match X509.Private_key.decode_pem (Cstruct.of_string data) with
      | Error `Msg m -> Lwt.return (Error (Bad_request, m))
      | Ok priv -> add ~id t mechanisms (X509 priv) restrictions

    let generate_x509 typ ~length =
      let open Rresult in
      (match typ with
      | `RSA when 1024 <= length && length <= 8192  -> Ok (Some length, `RSA)
      | `RSA -> Error (Bad_request, "Length must be between 1024 and 8192.")
      | rest -> Ok (None, rest))
      >>| fun (bits, typ) ->
      X509.Private_key.generate ?bits typ

    let generate_generic ~length =
      if 128 <= length && length <= 8192 then
        Ok (Cstruct.to_string @@ Mirage_crypto_rng.generate ((length+7)/8))
      else
        Error (Bad_request, "Length must be between 128 and 8192.")

    let generate_key typ ~length =
      let open Rresult in
      match typ with
      | Json.Generic ->
        (generate_generic ~length >>| (fun key -> Generic key))
      | _ ->
        let x509_type = match typ with
          | Json.Generic -> assert false
          | RSA -> `RSA
          | Curve25519 -> `ED25519
          | EC_P224 -> `P224
          | EC_P256 -> `P256
          | EC_P384 -> `P384
          | EC_P521 -> `P521
        in
        (generate_x509 x509_type ~length >>| (fun key -> X509 key))

    let generate ~id t typ mechanisms ~length restrictions =
      let open Lwt_result.Infix in
      Lwt.return
        (generate_key typ ~length) >>= fun priv ->
        Metrics.key_op `Generate;
        add ~id t mechanisms priv restrictions

    let remove t ~id =
      let open Lwt_result.Infix in
      let store = key_store t in
      Hashtbl.remove cached_operations id;
      with_write_lock (fun () ->
          internal_server_error Write "Remove key" Encrypted_store.pp_write_error
            (Encrypted_store.remove store (Mirage_kv.Key.v id) >|= fun () ->
             Access.info (fun m -> m "removed (%s)" id)))

    let get_json t ~id =
      let open Lwt_result.Infix in
      let open Mirage_crypto_ec in
      get_key t id >|= fun pkey ->
      let cs_to_b64 cs = Base64.encode_string (Cstruct.to_string cs) in
      let key, typ =
        match pkey.priv with
        | X509 `RSA k ->
          let z_to_b64 n =
            Mirage_crypto_pk.Z_extra.to_cstruct_be n |> cs_to_b64
          in
          let modulus = z_to_b64 k.Mirage_crypto_pk.Rsa.n
          and publicExponent = z_to_b64 k.Mirage_crypto_pk.Rsa.e
          in
          Json.rsa_public_key_to_yojson { Json.modulus ; publicExponent }, Json.RSA
        | X509 `ED25519 k ->
          let data =
            Ed25519.(pub_of_priv k |> pub_to_cstruct |> cs_to_b64)
          in
          Json.ec_public_key_to_yojson { Json.data }, Json.Curve25519
        | X509 `P224 k ->
          let data =
            P224.Dsa.(pub_of_priv k |> pub_to_cstruct |> cs_to_b64)
          in
          Json.ec_public_key_to_yojson { Json.data }, Json.EC_P224
        | X509 `P256 k ->
          let data =
            P256.Dsa.(pub_of_priv k |> pub_to_cstruct |> cs_to_b64)
          in
          Json.ec_public_key_to_yojson { Json.data }, Json.EC_P256
        | X509 `P384 k ->
          let data =
            P384.Dsa.(pub_of_priv k |> pub_to_cstruct |> cs_to_b64)
          in
          Json.ec_public_key_to_yojson { Json.data }, Json.EC_P384
        | X509 `P521 k ->
          let data =
            P521.Dsa.(pub_of_priv k |> pub_to_cstruct |> cs_to_b64)
          in
          Json.ec_public_key_to_yojson { Json.data }, Json.EC_P521
        | Generic _ -> `Null, Json.Generic
      in
      Json.public_key_to_yojson
        { Json.mechanisms = pkey.mechanisms ;
          typ ;
          operations = pkey.operations ;
          key ;
          restrictions = pkey.restrictions }

    let get_pem t ~id =
      let open Lwt_result.Infix in
      get_key t id >>= fun key ->
      Lwt_result.lift @@ match key.priv with
        | X509 p ->
            let pub = X509.Private_key.public p in
            Ok (Cstruct.to_string @@ X509.Public_key.encode_pem pub)
        | Generic _ -> Error (Bad_request, "Generic keys have no public key")

    let csr_pem t ~id subject =
      let open Lwt_result.Infix in
      get_key t id >>= fun key ->
      let subject' = Json.to_distinguished_name subject in
      Lwt_result.lift @@ match key.priv with
        | X509 p -> (match X509.Signing_request.create subject' p with
          | Error `Msg e -> Error (Bad_request, "creating signing request: " ^ e)
          | Ok c -> Ok (Cstruct.to_string @@ X509.Signing_request.encode_pem c))
        | Generic _ -> Error (Bad_request, "Generic keys can't create certificates")

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
      | None -> Lwt.return (Error (Conflict, "Key does not contains a certificate"))
      | Some _ ->
        let key' = { key with cert = None } in
        encode_and_write t id key'

    let get_restrictions t ~id =
      let open Lwt_result.Infix in
      get_key t id >|= fun key ->
      key.restrictions

    let add_restriction_tags t ~id ~tag =
      let open Lwt_result.Infix in
      get_key t id >>= fun key ->
      if not (Json.TagSet.mem tag key.restrictions.tags) then
        let restrictions' =
          { Json.tags = Json.TagSet.add tag key.restrictions.tags }
        in
        encode_and_write t id {key with restrictions = restrictions'}
        >|= fun () ->
        true
      else
        Lwt.return_ok false

    let remove_restriction_tags t ~id ~tag =
      let open Lwt_result.Infix in
      get_key t id >>= fun key ->
      if Json.TagSet.mem tag key.restrictions.tags then
        let restrictions' = {
          Json.tags = Json.TagSet.remove tag key.restrictions.tags
        }
        in
        encode_and_write t id {key with restrictions = restrictions'}
        >|= fun () ->
        true
      else
        Lwt.return_ok false

    module Oaep_md5 = Mirage_crypto_pk.Rsa.OAEP(Mirage_crypto.Hash.MD5)
    module Oaep_sha1 = Mirage_crypto_pk.Rsa.OAEP(Mirage_crypto.Hash.SHA1)
    module Oaep_sha224 = Mirage_crypto_pk.Rsa.OAEP(Mirage_crypto.Hash.SHA224)
    module Oaep_sha256 = Mirage_crypto_pk.Rsa.OAEP(Mirage_crypto.Hash.SHA256)
    module Oaep_sha384 = Mirage_crypto_pk.Rsa.OAEP(Mirage_crypto.Hash.SHA384)
    module Oaep_sha512 = Mirage_crypto_pk.Rsa.OAEP(Mirage_crypto.Hash.SHA512)

    let validate_restrictions t ~user_id key_data =
      let open Lwt_result.Infix in
      User.get t ~id:user_id >>= fun user_info ->
      let validation = if User.Info.role user_info = `Administrator then Ok ()
        else validate_restrictions ~user_info key_data.restrictions
      in
      Result.map (fun () -> key_data) validation |> Lwt.return

    let decrypt t ~id ~user_id ~iv decrypt_mode data =
      let open Lwt_result.Infix in
      get_key t id >>= validate_restrictions t ~user_id >>= fun key_data ->
      let oneline = Astring.String.(concat ~sep:"" (cuts ~sep:"\n" data)) in
      Lwt_result.lift (
        let open Rresult.R.Infix in
        match Base64.decode oneline with
          | Error `Msg msg ->
            Error (Bad_request, "Couldn't decode data from base64: " ^ msg ^ ".")
          | Ok encrypted_data ->
            if Json.MS.mem (Json.mechanism_of_decrypt_mode decrypt_mode) key_data.mechanisms then
              begin match key_data.priv with
              | X509 `RSA key ->
                begin
                  let dec_cs =
                    let encrypted_cs = Cstruct.of_string encrypted_data in
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
                    | AES_CBC -> None
                  in
                  match dec_cs with
                  | None -> Error (Bad_request, "Decryption failure")
                  | Some cs -> Ok cs
                end
              | Generic key ->
                begin
                  let encrypted_cs = Cstruct.of_string encrypted_data in
                  begin match decrypt_mode with
                  | Json.AES_CBC ->
                    begin
                      match iv with
                      | None -> Error (Bad_request, "AES-CBC decrypt requires IV")
                      | Some iv ->
                        begin
                          try
                            let iv = Base64.decode_exn iv |> Cstruct.of_string in
                            let key = Mirage_crypto.Cipher_block.AES.CBC.of_secret @@ Cstruct.of_string key in
                            Ok (Mirage_crypto.Cipher_block.AES.CBC.decrypt ~key ~iv encrypted_cs)
                          with Invalid_argument err -> Error (Bad_request, "Decryption failed: " ^ err)
                        end
                    end
                  | _ -> Error (Bad_request, "decrypt mode not supported by Generic key")
                  end
                end
              | _ ->
                  Error (Bad_request, "Decryption only supported for RSA and Generic keys.")
              end
              >>= fun cs ->
                Metrics.key_op `Decrypt;
                Hashtbl.replace cached_operations id (succ key_data.operations);
                Ok (Base64.encode_string (Cstruct.to_string cs))
            else
              Error (Bad_request, "Key mechanisms do not allow requested decryption."))

    let encrypt t ~id ~user_id ~iv encrypt_mode data =
      let open Lwt_result.Infix in
      get_key t id >>= validate_restrictions t ~user_id >>= fun key_data ->
      let oneline = Astring.String.(concat ~sep:"" (cuts ~sep:"\n" data)) in
      Lwt_result.lift (
        let open Rresult.R.Infix in
        match Base64.decode oneline with
          | Error `Msg msg ->
            Error (Bad_request, "Couldn't decode data from base64: " ^ msg ^ ".")
          | Ok message_data ->
            if Json.MS.mem (Json.mechanism_of_encrypt_mode encrypt_mode) key_data.mechanisms then
              begin match key_data.priv with
              | Generic key ->
                begin
                  let message_cs = Cstruct.of_string message_data in
                  begin match encrypt_mode with
                  | Json.AES_CBC ->
                    begin
                      try
                        let iv = match iv with
                        | None -> Mirage_crypto_rng.generate Mirage_crypto.Cipher_block.AES.CBC.block_size
                        | Some iv -> Base64.decode_exn iv |> Cstruct.of_string
                        in
                        let key = Mirage_crypto.Cipher_block.AES.CBC.of_secret @@ Cstruct.of_string key in
                        Ok (Mirage_crypto.Cipher_block.AES.CBC.encrypt ~key ~iv message_cs
                                |> Cstruct.to_string |> Base64.encode_string,
                              Some (Cstruct.to_string iv |> Base64.encode_string))
                      with Invalid_argument err -> Error (Bad_request, "Encryption failed: " ^ err)
                    end
                  end
                end
              | _ ->
                Error (Bad_request, "Encryption only supported for Generic keys.")
              end
              >>= fun (cs, iv) ->
                Metrics.key_op `Encrypt;
                Hashtbl.replace cached_operations id (succ key_data.operations);
                Ok (cs, iv)
            else
              Error (Bad_request, "Key mechanisms do not allow requested encryption."))

    let sign t ~id ~user_id sign_mode data =
      let open Lwt_result.Infix in
      get_key t id >>= validate_restrictions t ~user_id >>= fun key_data ->
      let oneline = Astring.String.(concat ~sep:"" (cuts ~sep:"\n" data)) in
      match Base64.decode oneline with
      | Error `Msg msg ->
        Lwt.return (Error (Bad_request, "Couldn't decode data from base64: " ^ msg ^ "."))
      | Ok to_sign ->
        if Json.MS.mem (Json.mechanism_of_sign_mode sign_mode) key_data.mechanisms then
          let to_sign_cs = Cstruct.of_string to_sign in
          let open Rresult.R.Infix in
          Lwt.return
            (begin match key_data.priv, sign_mode with
               | X509 `RSA key, Json.PKCS1 ->
                 (try Ok (Mirage_crypto_pk.Rsa.PKCS1.sig_encode ~key to_sign_cs) with
                  | Mirage_crypto_pk.Rsa.Insufficient_key ->
                    Error (Bad_request, "Signing failure: RSA key too short."))
               | Generic _, _ -> Error (Bad_request, "Generic keys can't sign.")
               | X509 priv, _ ->
                 (match priv, sign_mode with
                  | `RSA _, Json.PSS_MD5 -> Ok (`RSA_PSS, `MD5, `Digest to_sign_cs)
                  | `RSA _, PSS_SHA1 -> Ok (`RSA_PSS, `SHA1, `Digest to_sign_cs)
                  | `RSA _, PSS_SHA224 -> Ok (`RSA_PSS, `SHA224, `Digest to_sign_cs)
                  | `RSA _, PSS_SHA256 -> Ok (`RSA_PSS, `SHA256, `Digest to_sign_cs)
                  | `RSA _, PSS_SHA384 -> Ok (`RSA_PSS, `SHA384, `Digest to_sign_cs)
                  | `RSA _, PSS_SHA512 -> Ok (`RSA_PSS, `SHA512, `Digest to_sign_cs)
                  | `ED25519 _, EdDSA -> Ok (`ED25519, `SHA512, `Message to_sign_cs)
                  | `P224 _, ECDSA -> Ok (`ECDSA, `SHA224, `Digest to_sign_cs)
                  | `P256 _, ECDSA -> Ok (`ECDSA, `SHA256, `Digest to_sign_cs)
                  | `P384 _, ECDSA -> Ok (`ECDSA, `SHA384, `Digest to_sign_cs)
                  | `P521 _, ECDSA -> Ok (`ECDSA, `SHA512, `Digest to_sign_cs)
                  | _ -> Error (Bad_request, "invalid sign mode")) >>= fun (scheme, hash, data) ->
                 Rresult.R.reword_error (function `Msg m -> Bad_request, m)
                   (X509.Private_key.sign hash ~scheme priv data)
             end >>| fun signature ->
             Metrics.key_op `Sign;
             Hashtbl.replace cached_operations id (succ key_data.operations);
             Base64.encode_string @@ Cstruct.to_string signature)
        else
          Lwt.return (Error (Bad_request, "Key mechanisms do not allow requested signing."))

    let list_digest t ~filter_by_restrictions =
      let open Lwt.Infix in
      if filter_by_restrictions then 
        Lwt.return_none
      else
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
    with_write_lock (fun () ->
        KV.batch t.kv (fun b ->
            internal_server_error Write
              "Initializing configuration store" KV.pp_write_error
              (Config_store.set b Version Version.current) >>= fun () ->
            internal_server_error Write
              "Writing private RSA key" KV.pp_write_error
              (Config_store.set b Private_key t.key) >>= fun () ->
            internal_server_error Write
              "Writing certificate chain key" KV.pp_write_error
              (Config_store.set b Certificate (t.cert, t.chain)) >>= fun () ->
            internal_server_error Write
              "Initializing configuration store" KV.pp_write_error
              (Config_store.set b Version Version.current) >>= fun () ->
            let auth_store =
              Encrypted_store.v Authentication ~key:auth_store_key t.kv
            in
            let a_v_key, a_v_value =
              Encrypted_store.prepare_set auth_store Version.filename Version.(to_string current)
            in
            internal_server_error Write
              "Initializing authentication store" KV.pp_write_error
              (KV.set b a_v_key a_v_value) >>= fun () ->
            let key_store =
              Encrypted_store.v Key ~key:key_store_key t.kv
            in
            let k_v_key, k_v_value =
              Encrypted_store.prepare_set key_store Version.filename Version.(to_string current)
            in
            internal_server_error Write
              "Initializing key store" KV.pp_write_error
              (KV.set b k_v_key k_v_value) >>= fun () ->
            let keys = { domain_key ; auth_store ; key_store } in
            t.state <- Operational keys;
            let admin_k, admin_v =
              let name = "admin" in
              let admin = User.prepare_user ~name ~passphrase:admin ~role:`Administrator in
              let value = Yojson.Safe.to_string (User.Info.to_yojson admin) in
              Encrypted_store.prepare_set auth_store (Mirage_kv.Key.v name) value
            in
            internal_server_error Write "set Administrator user" KV.pp_write_error
              (KV.set b admin_k admin_v) >>= fun () ->
            internal_server_error Write "set domain key" KV.pp_write_error
              (Domain_key_store.set b Passphrase ~unlock_key domain_key) >>= fun () ->
            internal_server_error Write "set unlock-salt" KV.pp_write_error
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
        with_write_lock (fun () ->
            KV.batch t.kv (fun b ->
                internal_server_error Write "Write unlock salt" KV.pp_write_error
                  (Config_store.set b Unlock_salt unlock_salt) >>= fun () ->
                internal_server_error Write "Write passphrase" KV.pp_write_error
                  (Domain_key_store.set b Passphrase ~unlock_key keys.domain_key)))
      | _ -> assert false (* Handler_config.service_available checked that we are operational *)

    let unattended_boot t =
      let open Lwt_result.Infix in
      internal_server_error Read "Read unattended boot" Config_store.pp_error
        (Config_store.get_opt t.kv Unattended_boot >|=
         function None -> false | Some v -> v)

    let set_unattended_boot t status =
      let open Lwt_result.Infix in
      (* (a) change setting in configuration store *)
      (* (b) add or remove salt in configuration store *)
      (* (c) add or remove to domain_key store *)
      match t.state with
      | Operational keys ->
        with_write_lock (fun () ->
            internal_server_error Write "Write unattended boot" KV.pp_write_error
              (Config_store.set t.kv Unattended_boot status) >>= fun () ->
            if status then begin
              let salt, unlock_key = salted t.device_id in
              KV.batch t.kv (fun b ->
                  internal_server_error Write "Write device ID salt" KV.pp_write_error
                    (Config_store.set b Device_id_salt salt) >>= fun () ->
                  internal_server_error Write "Write device ID" KV.pp_write_error
                    (Domain_key_store.set b Device_id ~unlock_key keys.domain_key))
            end else begin
              KV.batch t.kv (fun b ->
                  internal_server_error Write "Remove device ID salt" KV.pp_write_error
                    (Config_store.remove b Device_id_salt) >>= fun () ->
                  internal_server_error Write "Remove device ID" KV.pp_write_error
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
        let key_eq a b =
          Cstruct.equal
            (X509.Public_key.fingerprint a)
            (X509.Public_key.fingerprint b)
        in
        if key_eq (X509.Private_key.public t.key) (X509.Certificate.public_key cert) then
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
            with_write_lock (fun () ->
                internal_server_error Write "Write certificate" KV.pp_write_error
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
      Lwt.return
        (match X509.Signing_request.create dn t.key with
         | Ok csr -> Ok (Cstruct.to_string (X509.Signing_request.encode_pem csr))
         | Error `Msg m -> Error (Bad_request, "while creating CSR: " ^ m))

    let tls_generate t typ ~length =
      let open Lwt_result.Infix in
      (* generate key *)
      Lwt.return (Key.generate_x509 typ ~length)
      >>= fun priv ->
      (* generate self-signed certificate *)
      let cert, key = generate_cert priv in
      (* update store *)
      with_write_lock (fun () ->
        Config_store.batch t.kv @@ fun kv ->
        internal_server_error Write "Write tls private key" KV.pp_write_error
          (Config_store.set kv Private_key key)
        >>= fun () ->
        internal_server_error Write "Write tls certificate" KV.pp_write_error
          (Config_store.set kv Certificate (cert, [])))
      >>= fun () ->
      (* update state *)
      t.key <- key;
      t.cert <- cert;
      t.chain <- [];
      (* notify server *)
      Lwt_result.ok (Lwt_mvar.put t.mbox (Tls (own_cert t)))

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
      with_write_lock (fun () ->
          internal_server_error Write "Write network configuration" KV.pp_write_error
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
      with_write_lock (fun () ->
          internal_server_error Write "Write log config" KV.pp_write_error
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
        with_write_lock (fun () ->
            KV.batch t.kv (fun b ->
                internal_server_error Write "Write backup salt" KV.pp_write_error
                  (Config_store.set b Backup_salt backup_salt) >>= fun () ->
                internal_server_error Write "Write backup key" KV.pp_write_error
                  (Config_store.set b Backup_key backup_key)))
      | _ -> assert false (* Handler_config.service_available checked that we are operational *)

    let time _t = Lwt.return (now ())

    let set_time t time =
      with_write_lock (fun () -> set_time_offset t.kv time)
  end

  module System = struct
    let system_info t = t.system_info

    let reboot t =
      let open Lwt.Infix in
      Key.dump_keys t >>= fun () ->
      Lwt_mvar.put t.mbox Reboot

    let shutdown t =
      let open Lwt.Infix in
      Key.dump_keys t >>= fun () ->
      Lwt_mvar.put t.mbox Shutdown

    let factory_reset t = Lwt_mvar.put t.mbox Factory_reset

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

    let update_mutex = Lwt_mutex.create ()

    let update t s =
      match t.has_changes with
      | Some _ -> Lwt.return (Error (Conflict, "Update already in progress."))
      | None ->
        Lwt_mutex.with_lock update_mutex
          (fun () ->
             let open Lwt_result.Infix in
             (* stream contains:
                - signature (hash of the rest)
                - changelog
                - version number
                - 32bit size (in blocks of 512 bytes)
                - software image,
                first four are prefixed by 4 byte length *)
             get_field s >>= fun (signature, s) ->
             let hash = Hash.empty in
             get_field s >>= fun (changes, s) ->
             let hash = Hash.feed hash (Cstruct.of_string (prefix_len changes)) in
             get_field s >>= fun (version, s) ->
             Lwt.return (version_of_string version) >>= fun version' ->
             let hash = Hash.feed hash (Cstruct.of_string (prefix_len version)) in
             read_n s 4 >>= fun (blockss, s) ->
             let blocks =
               Int32.to_int (Cstruct.BE.get_uint32 (Cstruct.of_string blockss) 0)
             in
             let hash = Hash.feed hash (Cstruct.of_string blockss) in
             let bytes = 512 * blocks in
             let platform_stream, pushf = Lwt_stream.create () in
             Lwt_result.ok (Lwt_mvar.put t.mbox (Update (blocks, platform_stream))) >>= fun () ->
             Lwt_stream.fold_s (fun chunk acc ->
                 match acc with
                 | Error e -> Lwt.return (Error e)
                 | Ok (left, hash) ->
                   let left = left - String.length chunk in
                   let hash = Hash.feed hash (Cstruct.of_string chunk) in
                   pushf (Some chunk);
                   Lwt.return @@ Ok (left, hash))
               s (Ok (bytes, hash)) >>= fun (left, hash) ->
             pushf None;
             (let open Lwt.Infix in
              Lwt_mvar.take t.res_mbox >|= function
              | Ok () -> Ok ()
              | Error msg ->
                Log.warn (fun m -> m "during update, platform reported %s" msg);
                Error (Bad_request, "update failed: " ^ msg)) >>= fun () ->
             (Lwt.return
                (if left = 0 then
                   Ok ()
                 else
                   Error (Bad_request, "unexpected end of data"))) >>= fun () ->
             let final_hash = Hash.get hash in
             let signature = Cstruct.of_string signature in
             if Pss_sha256.verify ~key:t.software_update_key ~signature (`Digest final_hash) then
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
               Lwt.return (Error (Bad_request, "Signature check of update image failed.")))

    let commit_update t =
      let open Lwt.Infix in
      match t.has_changes with
      | None ->
        Lwt.return
          (Error (Precondition_failed, "No update available. Please upload a system image to /system/update."))
      | Some _changes ->
        Lwt_mvar.put t.mbox Commit_update >>= fun () ->
        Lwt_mvar.take t.res_mbox >>= function
        | Ok () ->
          Lwt_mvar.put t.mbox Reboot >|= fun () ->
          Ok ()
        | Error msg ->
          Log.warn (fun m -> m "commit of update failed %s" msg);
          Lwt.return (Error (Bad_request, "commit failed: " ^ msg))

    let cancel_update t =
      match t.has_changes with
      | None -> Error (Precondition_failed, "No update available. Please upload a system image to /system/update.")
      | Some _changes -> t.has_changes <- None; Ok ()

    (* the backup format is at the moment:
       - length of salt (encoded in 3 bytes); salt
       - length of (AES-GCM encrypted version); AES-GCM encrypted version [adata = backup-version]
       - indivial key, value entries of the store:
         - length of encrypted-k-v; AES GCM (length of key; key; data) [adata = backup] *)

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
                  let data = prefix_len key_str ^ data in
                  let adata = Cstruct.of_string "backup" in
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
        (* iterate over keys in KV store *)
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
        match Version.of_string (Cstruct.to_string version) with
        | Ok v when Version.compare backup_version v = `Equal ->
          with_write_lock (fun () ->
              KV.batch t.kv (fun b ->
                  begin
                    let rec next stream =
                      Lwt_stream.is_empty stream >>= function
                      | true -> t.state <- Locked ; Lwt.return (Ok ())
                      | false ->
                        read_and_decrypt stream key >>== fun ((k, v), stream) ->
                        internal_server_error Write "restoring backup (writing to KV)" KV.pp_write_error
                          (KV.set b (Mirage_kv.Key.v k) v) >>== fun () ->
                        next stream
                    in
                    next stream'' >>== fun () ->
                    let `Raw stop_ts = Clock.now_raw () in
                    let elapsed = Ptime.diff stop_ts start_ts in
                    match Ptime.add_span new_time elapsed with
                    | Some ts -> set_time_offset b ts
                    | None ->
                      t.state <- Unprovisioned;
                      Lwt.return @@ Error (Bad_request, "Invalid system time in restore request")
                  end))
        | _ ->
          let msg =
            Printf.sprintf
              "Version mismatch on restore, provided backup version is %s, server expects %s"
              (Cstruct.to_string version) (Version.to_string backup_version)
          in
          Lwt.return @@ Error (Bad_request, msg)
  end

  let boot ~device_id software_update_key kv =
    Metrics.set_mem_reporter ();
    let softwareVersion =
      match version_of_string software_version with
      | Ok v -> v
      | Error (_, msg) ->
        invalid_arg ("Invalid softwareVersion, broken NetHSM " ^ msg)
    in
    let info = { Json.vendor = "Nitrokey GmbH" ; product = "NetHSM" }
    and system_info = {
      Json.firmwareVersion = "N/A" ;
      softwareVersion ;
      hardwareVersion = "N/A";
      buildTag = build_tag
    }
    and has_changes = None
    and mbox = Lwt_mvar.create_empty ()
    and res_mbox = Lwt_mvar.create_empty ()
    in
    let open Lwt.Infix in
    begin
      let open Lwt_result.Infix in
      lwt_error_to_msg ~pp_error:Config_store.pp_error
        (Config_store.get_opt kv Version) >>= function
      | None ->
        (* uninitialized / unprovisioned device *)
        let priv = X509.Private_key.generate `P256 in
        let state = Unprovisioned
        and cert, key = generate_cert priv
        and chain = []
        in
        let t = { state ; has_changes ; key ; cert ; chain ; software_update_key ; kv ; info ; system_info ; mbox ; res_mbox ; device_id } in
        Lwt.return (Ok t)
      | Some version ->
        match Version.(compare current version) with
        | `Equal ->
          boot_config_store kv device_id >>= fun state ->
          certificate_chain kv >|= fun (cert, chain, key) ->
          { state ; has_changes ; key ; cert ; chain ; software_update_key ; kv ; info ; system_info ; mbox ; res_mbox ; device_id }
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
    | Ok t ->
      let dump_key_ops () =
        let rec dump () =
          Time.sleep_ns (Duration.of_hour 1) >>= fun () ->
          Key.dump_keys t >>= dump
        in
        dump ()
      in
      Lwt.async dump_key_ops;
      t, t.mbox, t.res_mbox
    | Error `Msg msg ->
      Log.err (fun m -> m "error booting %s" msg);
      invalid_arg "broken NetHSM"
end
