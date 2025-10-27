(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

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
    | Not_found

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

  val network_configuration :
    t -> (Ipaddr.V4.t * Ipaddr.V4.Prefix.t * Ipaddr.V4.t option) Lwt.t

  val provision :
    t -> unlock:string -> admin:string -> Ptime.t -> (unit, error) result Lwt.t

  val unlock_with_passphrase :
    t -> passphrase:string -> (unit, error) result Lwt.t

  val random : int -> string
  val generate_id : unit -> string

  module Nid : sig
    type t = { namespace : string option; id : string }

    val separator : string
    val unsafe_of_string : string -> t
    val of_string : string -> (t, string) result
    val to_string : t -> string
    val namespace : t -> string option
    val id : t -> string
  end

  module Config : sig
    val change_unlock_passphrase :
      t ->
      new_passphrase:string ->
      current_passphrase:string ->
      (unit, error) result Lwt.t

    val unattended_boot : t -> (bool, error) result Lwt.t
    val set_unattended_boot : t -> bool -> (unit, error) result Lwt.t
    val unattended_boot_digest : t -> string option Lwt.t
    val tls_public_pem : t -> string Lwt.t
    val tls_public_pem_digest : t -> string option Lwt.t
    val tls_cert_pem : t -> string Lwt.t
    val set_tls_cert_pem : t -> string -> (unit, error) result Lwt.t
    val tls_cert_digest : t -> string option Lwt.t
    val tls_csr_pem : t -> Json.subject_req -> (string, error) result Lwt.t

    val tls_generate :
      t -> X509.Key_type.t -> length:int -> (unit, error) result Lwt.t

    val network : t -> Json.network Lwt.t
    val set_network : t -> Json.network -> (unit, error) result Lwt.t
    val network_digest : t -> string option Lwt.t
    val log : t -> Json.log Lwt.t
    val set_log : t -> Json.log -> (unit, error) result Lwt.t
    val log_digest : t -> string option Lwt.t

    val change_backup_passphrase :
      t ->
      new_passphrase:string ->
      current_passphrase:string ->
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
    val backup : t -> (string option -> unit) -> (unit, error) result Lwt.t

    val restore :
      t -> string -> string Lwt_stream.t -> (unit, error) result Lwt.t
  end

  module User : sig
    module Info : sig
      type t

      val name : t -> string
      val role : t -> Json.role
      val tags : t -> Json.TagSet.t
    end

    val is_authenticated : t -> Nid.t -> passphrase:string -> bool Lwt.t
    val is_authorized : t -> Nid.t -> Json.role -> bool Lwt.t
    val list : namespace:string option -> t -> (string list, error) result Lwt.t
    val exists : t -> Nid.t -> (bool, error) result Lwt.t
    val get : t -> Nid.t -> (Info.t, error) result Lwt.t

    val add :
      t ->
      Nid.t ->
      role:Json.role ->
      passphrase:string ->
      name:string ->
      (unit, error) result Lwt.t

    val remove : t -> Nid.t -> (unit, error) result Lwt.t

    val set_passphrase :
      t -> Nid.t -> passphrase:string -> (unit, error) result Lwt.t

    val add_tag : t -> Nid.t -> tag:string -> (bool, error) result Lwt.t
    val remove_tag : t -> Nid.t -> tag:string -> (bool, error) result Lwt.t
    val list_digest : t -> string option Lwt.t
    val digest : t -> Nid.t -> string option Lwt.t
  end

  module Key : sig
    val exists :
      namespace:string option -> t -> id:string -> (bool, error) result Lwt.t

    val list :
      ?with_prefix:string ->
      namespace:string option ->
      t ->
      filter_by_restrictions:bool ->
      user_nid:Nid.t ->
      (string list, error) result Lwt.t

    val add_json :
      namespace:string option ->
      id:string ->
      t ->
      Json.MS.t ->
      Json.key_type ->
      Json.private_key ->
      Json.restrictions ->
      (unit, error) result Lwt.t

    val add_pem :
      namespace:string option ->
      id:string ->
      t ->
      Json.MS.t ->
      string ->
      Json.restrictions ->
      (unit, error) result Lwt.t

    val generate :
      namespace:string option ->
      id:string ->
      t ->
      Json.key_type ->
      Json.MS.t ->
      length:int ->
      Json.restrictions ->
      (unit, error) result Lwt.t

    val remove :
      namespace:string option -> t -> id:string -> (unit, error) result Lwt.t

    val move :
      namespace:string option ->
      t ->
      current_id:string ->
      new_id:string ->
      (unit, error) result Lwt.t

    val get_json :
      namespace:string option ->
      t ->
      id:string ->
      (Yojson.Safe.t, error) result Lwt.t

    val get_pem :
      namespace:string option -> t -> id:string -> (string, error) result Lwt.t

    val csr_pem :
      t ->
      namespace:string option ->
      id:string ->
      Json.subject_req ->
      (string, error) result Lwt.t

    val get_cert :
      namespace:string option ->
      t ->
      id:string ->
      ((string * string) option, error) result Lwt.t

    val set_cert :
      t ->
      namespace:string option ->
      id:string ->
      content_type:string ->
      string ->
      (unit, error) result Lwt.t

    val remove_cert :
      namespace:string option -> t -> id:string -> (unit, error) result Lwt.t

    val get_restrictions :
      namespace:string option ->
      t ->
      id:string ->
      (Json.restrictions, error) result Lwt.t

    val add_restriction_tags :
      namespace:string option ->
      t ->
      id:string ->
      tag:string ->
      (bool, error) result Lwt.t

    val remove_restriction_tags :
      namespace:string option ->
      t ->
      id:string ->
      tag:string ->
      (bool, error) result Lwt.t

    (* val encrypt : t -> id:string -> Json.encrypt_mode -> string -> (string, error) result Lwt.t *)

    val decrypt :
      t ->
      namespace:string option ->
      id:string ->
      user_nid:Nid.t ->
      iv:string option ->
      Json.decrypt_mode ->
      string ->
      (string, error) result Lwt.t

    val encrypt :
      t ->
      namespace:string option ->
      id:string ->
      user_nid:Nid.t ->
      iv:string option ->
      Json.encrypt_mode ->
      string ->
      (string * string option, error) result Lwt.t

    val sign :
      t ->
      namespace:string option ->
      id:string ->
      user_nid:Nid.t ->
      Json.sign_mode ->
      string ->
      (string, error) result Lwt.t

    val list_digest :
      namespace:string option ->
      t ->
      filter_by_restrictions:bool ->
      string option Lwt.t

    val digest :
      namespace:string option -> t -> id:string -> string option Lwt.t

    val remove_all_in_namespace :
      t -> namespace:string -> (unit, error) result Lwt.t
  end

  module Namespace : sig
    type id = string option

    val exists : t -> id -> (bool, error) result Lwt.t
    val create : t -> id -> (unit, error) result Lwt.t
    val list : t -> (string list, error) result Lwt.t
    val remove : t -> id -> (unit, error) result Lwt.t
  end
end

let to_hex str =
  let (`Hex hex) = Hex.of_string str in
  hex

let lwt_error_to_msg ~pp_error thing =
  let open Lwt.Infix in
  thing >|= fun x -> Rresult.R.error_to_msg ~pp_error x

let hsm_src = Logs.Src.create "hsm" ~doc:"HSM log"

module Log = (val Logs.src_log hsm_src : Logs.LOG)

let build_tag = String.trim [%blob "buildTag"]
let software_version = String.trim [%blob "softwareVersion"]

module Make (KV : Kv_ext.Ranged) = struct
  module Metrics = struct
    let db = Hashtbl.create 13
    let retrieve () = Hashtbl.fold (fun k v acc -> (k, v) :: acc) db []
    let sample_interval = Duration.of_sec 1
    let started = Mirage_mtime.elapsed_ns ()
    let now () = Int64.sub (Mirage_mtime.elapsed_ns ()) started

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
        let warns = Logs.warn_count () and errs = Logs.err_count () in
        Data.v [ int "log warnings" warns; int "log errors" errs ]
      in
      Src.v ~doc ~tags:Metrics.Tags.[] ~data "log msg type"

    let gc_src =
      let open Metrics in
      let doc = "Garbage collection" in
      let data () =
        let gc_stat = Gc.quick_stat () in
        let major_bytes = gc_stat.heap_words * 8 in
        Data.v
          [
            int "gc major bytes" major_bytes;
            int "gc major collections" gc_stat.major_collections;
            int "gc minor collections" gc_stat.minor_collections;
            int "gc compactions" gc_stat.compactions;
          ]
      in
      Src.v ~doc ~tags:Metrics.Tags.[] ~data "gc"

    let key_ops_src =
      let open Metrics in
      let doc = "Key operations" in
      let data (generate, sign, decrypt, encrypt) =
        Data.v
          [
            int "generate" generate;
            int "sign" sign;
            int "decrypt" decrypt;
            int "encrypt" encrypt;
          ]
      in
      Src.v ~doc ~tags:Metrics.Tags.[] ~data "key operations"

    let ops = ref (0, 0, 0, 0)

    let key_op op =
      let g, s, d, e = !ops in
      (match op with
      | `Generate -> ops := (g + 1, s, d, e)
      | `Sign -> ops := (g, s + 1, d, e)
      | `Decrypt -> ops := (g, s, d + 1, e)
      | `Encrypt -> ops := (g, s, d, e + 1));
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
      let old_counter =
        match Hashtbl.find_opt http_status code with None -> 0 | Some x -> x
      in
      Hashtbl.replace http_status code (succ old_counter);
      let total =
        match Hashtbl.find_opt http_status total_code with
        | None -> 0
        | Some x -> x
      in
      Hashtbl.replace http_status total_code (succ total);
      Metrics.add http_status_src (fun t -> t) (fun m -> m ())

    let response_time = ref 0.0

    let http_response_time_src =
      let open Metrics in
      let doc = "HTTP response time" in
      let data () = Data.v [ float "http response time" !response_time ] in
      Src.v ~doc ~tags:Metrics.Tags.[] ~data "http response time"

    let http_response_time measured =
      if measured > 0. then (
        (* exponentially weighted moving average / exponential smoothed / holt linear*)
        response_time := (0.7 *. !response_time) +. (0.3 *. measured);
        Metrics.add http_response_time_src (fun t -> t) (fun m -> m ()))

    let writes = ref 0

    let write_src =
      let open Metrics in
      let doc = "KV writes" in
      let data () = Data.v [ int "kv write" !writes ] in
      Src.v ~doc ~tags:Metrics.Tags.[] ~data "KV writes"

    let write () =
      incr writes;
      Metrics.add write_src (fun t -> t) (fun m -> m ())

    let sample () =
      Metrics_lwt.periodically uptime_src;
      Metrics_lwt.periodically log_src;
      Metrics_lwt.periodically gc_src;
      let sleeper () = Mirage_sleep.ns sample_interval in
      Metrics_lwt.init_periodic ~gc:`None ~logs:false sleeper

    let set_mem_reporter () =
      let report ~tags ~data ~over _src k =
        let data_fields = Metrics.Data.fields data in
        let tag t = Fmt.to_to_string Metrics.pp_value t in
        let tags = List.map tag tags in
        let field f =
          ( String.concat "." (tags @ [ Fmt.to_to_string Metrics.pp_key f ]),
            Fmt.to_to_string Metrics.pp_value f )
        in
        let fields = List.map field in
        List.iter
          (fun (field_name, field_value) ->
            Hashtbl.replace db field_name field_value)
          (fields data_fields);
        over ();
        k ()
      in
      let at_exit () = () in
      Metrics.enable_all ();
      Metrics.set_reporter { Metrics.report; now; at_exit };
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
    thing >|= function Ok a -> Ok a | Error e -> fatal prefix ~pp_error e

  type status_code =
    | Internal_server_error
    | Bad_request
    | Forbidden
    | Precondition_failed
    | Conflict
    | Too_many_requests
    | Not_found

  (* string is the body, which may contain error message *)
  type error = status_code * string

  let error_to_code code =
    let status =
      match code with
      | Internal_server_error -> `Internal_server_error
      | Bad_request -> `Bad_request
      | Forbidden -> `Forbidden
      | Precondition_failed -> `Precondition_failed
      | Conflict -> `Conflict
      | Too_many_requests -> `Too_many_requests
      | Not_found -> `Not_found
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
          | Write ->
              ( "writing to the key-value store",
                "Could not write to database. Check logs." )
          | Read ->
              ( "read from the key-value store",
                "Could not read from database. Check logs." )
          | Unlock ->
              ( "connecting to the key-value store",
                "Could not connect to database. Check logs." )
        in
        Log.err (fun m ->
            m "Error: %a while %s: %s." pp_err e operation_message context);
        Error (Internal_server_error, error_message)

  let pp_state ppf s =
    Fmt.string ppf
      (match s with
      | `Unprovisioned -> "unprovisioned"
      | `Operational -> "operational"
      | `Locked -> "locked")
  [@@coverage off]

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
        let gw =
          match gw with None -> "no" | Some ip -> Ipaddr.V4.to_string ip
        in
        "NETWORK " ^ Ipaddr.V4.Prefix.to_string prefix ^ ", gateway: " ^ gw
    | Tls _ -> "TLS_CERTIFICATE"
    | Shutdown -> "SHUTDOWN"
    | Reboot -> "REBOOT"
    | Factory_reset -> "FACTORY-RESET"
    | Update _ -> "UPDATE"
    | Commit_update -> "COMMIT-UPDATE"

  let version_of_string s =
    match Astring.String.cut ~sep:"." s with
    | None ->
        Error
          ( Bad_request,
            "Failed to parse version: no separator (.). A valid version would \
             be '4.2'." )
    | Some (major, minor) -> (
        try
          let ma = int_of_string major and mi = int_of_string minor in
          Ok (ma, mi)
        with Failure _ ->
          Error
            ( Bad_request,
              "Failed to parse version: Not a number. A valid version would be \
               '4.2'." ))

  let version_is_upgrade ~current ~update = fst current <= fst update

  module Nid = struct
    type t = { namespace : string option; id : string }

    let separator = "~"
    let namespace t = t.namespace
    let id t = t.id

    let pp fmt t =
      match t.namespace with
      | None -> Fmt.pf fmt "%s" t.id
      | Some n -> Fmt.pf fmt "%s%s%s" n separator t.id

    let unsafe_of_string s =
      match Astring.String.cut ~sep:separator s with
      | None -> { namespace = None; id = s }
      | Some (namespace, id) -> { namespace = Some namespace; id }

    let of_string s =
      let nid = unsafe_of_string s in
      match (Json.valid_namespace nid.namespace, Json.valid_id nid.id) with
      | Ok _, Ok _ -> Ok nid
      | Error e, _ | _, Error e -> Error e

    let to_string t =
      match t.namespace with None -> t.id | Some n -> n ^ separator ^ t.id
  end

  module Stores = struct
    module Config_store = Config_store.Make (KV)
    module Domain_key_store = Domain_key_store.Make (KV)
    module Encrypted_store = Encrypted_store.Make (KV)

    module User_info = struct
      type t = {
        name : string;
        salt : string;
        digest : string;
        role : Json.role;
        tags : Json.TagSet.t;
      }
      [@@deriving yojson]

      let name t = t.name
      let role t = t.role
      let tags t = t.tags
    end

    module User_store =
      Cached_store.Make (Json_store.Make (Encrypted_store) (User_info))

    module Key_info = struct
      (* how a key is persisted in the kv store. note that while mirage-crypto
         provides s-expression conversions, these have been removed from the
         trunk version -- it is also not safe to embed s-expressions into json.
         to avoid these issues, we use PKCS8 encoding as PEM (embedding DER in
         json is not safe as well)!
      *)
      type priv = X509 of X509.Private_key.t | Generic of string

      let pem_tag = "PEM"
      let raw_tag = "raw"

      let priv_to_yojson p =
        match p with
        | Generic s -> `Assoc [ (raw_tag, `String (Base64.encode_string s)) ]
        | X509 p ->
            `Assoc [ (pem_tag, `String (X509.Private_key.encode_pem p)) ]

      let priv_of_yojson = function
        | `Assoc [ (tag, `String data) ] when tag = raw_tag -> (
            match Base64.decode data with
            | Ok s -> Ok (Generic s)
            | Error (`Msg m) -> Error m)
        | `Assoc [ (tag, `String data) ] when tag = pem_tag -> (
            match X509.Private_key.decode_pem data with
            | Ok priv -> Ok (X509 priv)
            | Error (`Msg m) -> Error m)
        | _ -> Error "Expected { <format>: <data> } as private key"

      type t = {
        mechanisms : Json.MS.t;
        priv : priv;
        cert : (string * string) option;
        operations : int;
        restrictions : Json.restrictions;
      }
      [@@deriving yojson]
    end

    module Key_store =
      Cached_store.Make (Json_store.Make (Encrypted_store) (Key_info))

    module Namespace_info = struct
      type t = string [@@deriving yojson]
      (** Name of the namespace *)
    end

    module Namespace_store =
      Cached_store.Make (Json_store.Make (Encrypted_store) (Namespace_info))
  end

  open Stores

  type keys = {
    domain_key : string;
        (* needed when unlock passphrase changes and likely for unattended boot *)
    auth_store : User_store.t;
    key_store : Key_store.t;
    namespace_store : Namespace_store.t;
  }

  let equal_keys a b = String.equal a.domain_key b.domain_key

  type internal_state = Unprovisioned | Operational of keys | Locked
  [@@deriving eq]

  let to_external_state = function
    | Unprovisioned -> `Unprovisioned
    | Operational _ -> `Operational
    | Locked -> `Locked

  type t = {
    mutable state : internal_state;
    mutable has_changes : string option;
    mutable key : X509.Private_key.t;
    mutable cert : X509.Certificate.t;
    mutable chain : X509.Certificate.t list;
    software_update_key : Mirage_crypto_pk.Rsa.pub;
    kv : KV.t;
    info : Json.info;
    system_info : Json.system_info;
    mbox : cb Lwt_mvar.t;
    res_mbox : (unit, string) result Lwt_mvar.t;
    device_key : string;
    cache_settings : Cached_store.settings;
  }

  let state t = to_external_state t.state
  let lock t = t.state <- Locked

  let kv_equal a b =
    let open Lwt_result.Infix in
    let rec traverse root =
      let for_all acc path =
        Lwt.return acc >>= fun acc' ->
        traverse path >|= fun v -> acc' && v
      in
      KV.exists a root >>= fun a_typ ->
      KV.exists b root >>= fun b_typ ->
      match (a_typ, b_typ) with
      | Some `Value, Some `Value ->
          KV.get a root >>= fun v ->
          KV.get b root >>= fun v' -> Lwt_result.return (String.equal v v')
      | Some `Dictionary, Some `Dictionary ->
          KV.list a root >>= fun l ->
          KV.list b root >>= fun l' ->
          if List.length l = List.length l' && List.for_all2 ( = ) l l' then
            Lwt_list.fold_left_s for_all (Ok true) (fst (List.split l))
          else Lwt_result.return false
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

  let now () = Hsm_clock.now ()
  let write_lock = Lwt_mutex.create ()

  let with_write_lock f =
    let open Lwt.Infix in
    Lwt_mutex.with_lock write_lock (fun () ->
        try
          f () >|= fun k ->
          Metrics.write ();
          k
        with Invalid_argument txt ->
          Log.err (fun m -> m "Error while writing to key-value store: %s" txt);
          Lwt.return (Error (Internal_server_error, "Could not write to disk.")))

  let set_time_offset kv timestamp =
    Hsm_clock.set timestamp;
    let span = Hsm_clock.get_offset () in
    internal_server_error Write "Write time offset" KV.pp_write_error
      (Config_store.set kv Time_offset span)

  let decrypt_with_pass_key encrypted ~pass_key =
    let key = Crypto.GCM.of_secret pass_key in
    let adata = "passphrase" in
    Lwt_result.map_error
      (fun e -> (Forbidden, Fmt.str "%a" Crypto.pp_decryption_error e))
      (Lwt.return @@ Crypto.decrypt ~key ~adata encrypted)

  let encrypt_with_pass_key data ~pass_key =
    let key = Crypto.GCM.of_secret pass_key in
    let adata = "passphrase" in
    Crypto.encrypt Mirage_crypto_rng.generate ~key ~adata data

  let make_store_keys dk =
    let extend k t = Digestif.SHA256.(digest_string (k ^ t) |> to_raw_string) in
    (extend dk "auth_store", extend dk "key_store", extend dk "namespace_store")

  let load_keys kv device_key pass_key =
    let open Lwt_result.Infix in
    let slot =
      Stores.Domain_key_store.(
        if Option.is_none pass_key then Unattended else Attended)
    in
    Lwt_result.map_error
      (function `Msg m -> (Forbidden, m))
      (Domain_key_store.get kv slot ~encryption_key:device_key)
    >>= fun data ->
    (match pass_key with
      | None -> Lwt.return_ok data
      | Some k -> decrypt_with_pass_key data ~pass_key:k)
    >|= fun domain_key ->
    let auth_store_key, key_store_key, namespace_store_key =
      make_store_keys domain_key
    in
    (domain_key, auth_store_key, key_store_key, namespace_store_key)

  let unlock_store kv slot key =
    let open Lwt.Infix in
    let slot_str = Encrypted_store.slot_to_string slot in
    Encrypted_store.unlock Version.current slot ~key kv >>= function
    | Ok (`Version_greater (stored, _t)) ->
        (* upgrade code for authentication store *)
        Lwt.return
        @@ Error
             ( Internal_server_error,
               Fmt.str "%s store too old (%a), no migration code" slot_str
                 Version.pp stored )
    | Ok (`Kv store) -> Lwt.return @@ Ok store
    | Error (`Kv (`Not_found _)) when slot = Namespace ->
        Logs.warn (fun f ->
            f
              "This device has not been provisioned with a namespace store. \
               Initializing it on the fly with the provided key!");
        internal_server_error Write "provisioning namespace store"
          KV.pp_write_error
          (Encrypted_store.initialize Version.current Namespace ~key kv)
    | Error e ->
        internal_server_error Unlock
          ("connecting to " ^ slot_str ^ " store")
          Encrypted_store.pp_connect_error (Lwt_result.fail e)

  (* credential is device key with or without pass_key, depending on boot mode *)
  let unlock ?pass_key kv ~cache_settings ~device_key =
    let open Lwt_result.Infix in
    (* state is already checked in Handler_unlock.service_available *)
    load_keys kv device_key pass_key
    >>= fun (domain_key, as_key, ks_key, ns_key) ->
    unlock_store kv Authentication as_key >>= fun auth_store ->
    unlock_store kv Key ks_key >>= fun key_store ->
    unlock_store kv Namespace ns_key >|= fun namespace_store ->
    let auth_store = User_store.connect ~settings:cache_settings auth_store in
    let key_store = Key_store.connect ~settings:cache_settings key_store in
    let namespace_store =
      Namespace_store.connect ~settings:cache_settings namespace_store
    in
    let keys = { domain_key; auth_store; key_store; namespace_store } in
    Operational keys

  let unlock_with_device_key kv ~device_key = unlock kv ~device_key

  let unlock_with_passphrase t ~passphrase =
    let open Lwt_result.Infix in
    internal_server_error Read "Get passphrase salt" Config_store.pp_error
      (Config_store.get t.kv Config_store.Unlock_salt)
    >>= fun salt ->
    let pass_key = Crypto.key_of_passphrase ~salt passphrase in
    let device_key = t.device_key in
    unlock t.kv ~cache_settings:t.cache_settings ~device_key ~pass_key
    >|= fun state' -> t.state <- state'

  let check_unlock_passphrase t passphrase =
    let ( let* ) = Lwt.bind in
    let ( let** ) = Lwt_result.bind in
    let** salt =
      internal_server_error Read "Get passphrase salt" Config_store.pp_error
        (Config_store.get t.kv Config_store.Unlock_salt)
    in
    let pass_key = Crypto.key_of_passphrase ~salt passphrase in
    let device_key = t.device_key in
    let* keys = load_keys t.kv device_key (Some pass_key) in
    match (keys, t.state) with
    | Ok (dk, _, _, _), Operational { domain_key = dk'; _ }
      when String.equal dk dk' ->
        Lwt.return_ok ()
    | _ -> Lwt.return_error (Forbidden, "unlock passphrase is incorrect.")

  let generate_cert priv =
    (* this is before provisioning, our posix time may be not accurate *)
    let valid_from = Ptime.epoch and valid_until = Ptime.max in
    let dn =
      [
        X509.Distinguished_name.(
          Relative_distinguished_name.singleton (CN "keyfender"));
      ]
    in
    match X509.Signing_request.create dn priv with
    | Error e ->
        fatal "creating signing request"
          ~pp_error:X509.Validation.pp_signature_error e
    | Ok csr -> (
        match
          X509.Signing_request.sign csr ~valid_from ~valid_until priv dn
        with
        | Error e ->
            fatal "signing certificate signing request"
              ~pp_error:X509.Validation.pp_signature_error e
        | Ok cert -> (cert, priv))

  let create_csr_extensions subject =
    match subject.Json.subjectAltNames with
    | Some [] -> None
    | Some names ->
        let san_names = X509.General_name.(add DNS names empty) in
        let ext_map =
          X509.Extension.(add Subject_alt_name (false, san_names) empty)
        in
        Some X509.Signing_request.Ext.(add Extensions ext_map empty)
    | None ->
        let san_names =
          X509.General_name.(add DNS [ subject.commonName ] empty)
        in
        let ext_map =
          X509.Extension.(add Subject_alt_name (false, san_names) empty)
        in
        Some X509.Signing_request.Ext.(add Extensions ext_map empty)

  let certificate_chain kv =
    let open Lwt_result.Infix in
    lwt_error_fatal "get private key from configuration store"
      ~pp_error:Config_store.pp_error
      (Config_store.get kv Private_key)
    >>= fun priv ->
    lwt_error_fatal "get certificate from configuration store"
      ~pp_error:Config_store.pp_error
      (Config_store.get kv Certificate)
    >|= fun (cert, chain) -> (cert, chain, priv)

  let boot_config_store ~cache_settings kv device_key =
    let open Lwt_result.Infix in
    lwt_error_fatal "get time offset" ~pp_error:Config_store.pp_error
      ( Config_store.get_opt kv Time_offset >|= function
        | None -> ()
        | Some span -> (
            let (`Raw now_raw) = Hsm_clock.now_raw () in
            match Ptime.add_span now_raw span with
            | None ->
                Log.warn (fun m ->
                    m "time offset from config store out of range")
            | Some ts -> Hsm_clock.set ts) )
    >>= fun () ->
    lwt_error_fatal "get unlock-salt" ~pp_error:Config_store.pp_error
      (Config_store.get kv Unlock_salt)
    >>= fun _ ->
    lwt_error_fatal "get unattended boot" ~pp_error:Config_store.pp_error
      (Config_store.get_opt kv Unattended_boot)
    >>= function
    | Some true -> (
        let open Lwt.Infix in
        unlock_with_device_key ~cache_settings kv ~device_key >|= function
        | Ok s -> Ok s
        | Error (_, msg) ->
            Log.err (fun m -> m "unattended boot failed with %s" msg);
            Ok Locked)
    | None | Some false -> Lwt.return (Ok Locked)

  let info t = t.info
  let own_cert t = `Single (t.cert :: t.chain, t.key)

  let default_network_configuration =
    let ip = Ipaddr.V4.of_string_exn "192.168.1.1" in
    (ip, Ipaddr.V4.Prefix.make 24 ip, None)

  let network_configuration t =
    let open Lwt.Infix in
    Config_store.(get t.kv Ip_config) >|= function
    | Ok cfg -> cfg
    | Error e ->
        Log.warn (fun m ->
            m "error %a while retrieving IP, using default"
              Config_store.pp_error e);
        default_network_configuration

  let random n = Base64.encode_string @@ Mirage_crypto_rng.generate n

  let generate_id () =
    let (`Hex id) = Hex.of_string (Mirage_crypto_rng.generate 10) in
    id

  (*  Storage schema:
        /namespace_1
        ...
        /namespace_n
  *)
  module Namespace = struct
    let ns_src = Logs.Src.create "hsm.namespace" ~doc:"HSM namespace log"

    module Access = (val Logs.src_log ns_src : Logs.LOG)

    type id = string option

    let ns_store t =
      match t.state with
      | Operational keys -> keys.namespace_store
      | _ -> assert false

    let key_prefix namespace =
      match namespace with
      | None -> Mirage_kv.Key.empty
      | Some n -> Mirage_kv.Key.v ("." ^ n)

    let file_range namespace =
      let prefix = key_prefix namespace in
      (* list only the keys prefixed with ["namespace/0", "namespace0"[,
         to avoid listing subdirectories prefixed with '.'
         This allows efficient listing of keys from the root namespace (no
         matter how many namespaces or namespaced keys there are).
         Similarly, it will allow efficient listing of N-Keys without care for
         sub-namespaces if hierarchical namespaces are implemented, as long as
         each directory is prefixed by '.'.
      *)
      Kv_ext.Range.create ~prefix ~start:"0" ()

    let exists t = function
      | None ->
          (* Root namespace always exists *)
          Lwt_result.return true
      | Some n ->
          let open Lwt.Infix in
          let store = ns_store t in
          let key = Mirage_kv.Key.v n in
          internal_server_error Read "Exists key" Namespace_store.pp_read_error
            ( Namespace_store.get store key >|= function
              | Ok n' when n = n' -> Ok true
              | Error (`Store (`Not_found _)) -> Ok false
              | Error (`Store (`Kv (`Not_found _))) -> Ok false
              | Ok n' ->
                  Logs.err (fun f ->
                      f
                        "Namespace %s exists but its entry contains the wrong \
                         name (%s). Corrupted store?"
                        n n');
                  Error (`Store (`Not_found key))
              | Error e -> Error e )

    let create t = function
      | None -> Lwt_result.fail (Bad_request, "Root namespace always exists")
      | Some n ->
          let open Lwt_result.Infix in
          exists t (Some n) >>= fun namespace_exists ->
          if namespace_exists then
            Lwt_result.fail
              (Bad_request, Fmt.str "Namespace %s already exists" n)
          else
            let store = ns_store t in
            let key = Mirage_kv.Key.v n in
            with_write_lock (fun () ->
                internal_server_error Write "Create namespace"
                  Encrypted_store.pp_write_error
                  (Namespace_store.set store key n))
            >|= fun () -> Access.info (fun f -> f "created (%s)" n)

    let list t =
      let open Lwt_result.Infix in
      let store = ns_store t in
      internal_server_error Read "List namespaces" Encrypted_store.pp_error
        (Namespace_store.list store Mirage_kv.Key.empty)
      >>= fun xs ->
      let open Lwt.Infix in
      Lwt_list.map_s
        (function
          | n, `Dictionary ->
              Lwt.return
                (Error
                   ( Internal_server_error,
                     "Namespace store contains dictionary: "
                     ^ Mirage_kv.Key.to_string n ))
          | n, `Value -> Lwt.return_ok (Mirage_kv.Key.basename n))
        xs
      >|= fun l ->
      List.fold_right
        (fun acc x ->
          match (x, acc) with
          | Error e, _ -> Error e
          | _, Error e -> Error e
          | Ok l, Ok x -> Ok (x :: l))
        l (Ok [])

    let remove t = function
      | None -> Lwt_result.fail (Bad_request, "Cannot delete root namespace")
      | Some n ->
          let open Lwt_result.Infix in
          exists t (Some n) >>= fun namespace_exists ->
          if namespace_exists then
            (* Note that keys belonging to the namespace are not deleted here,
               but in the request handler instead *)
            let store = ns_store t in
            let key = Mirage_kv.Key.v n in
            with_write_lock (fun () ->
                internal_server_error Write "Delete namespace key"
                  Encrypted_store.pp_write_error
                  (Namespace_store.remove store key))
            >|= fun () -> Access.info (fun m -> m "removed (%s)" n)
          else
            Lwt_result.fail
              (Bad_request, Fmt.str "Namespace %s does not exist" n)
  end

  (*  Storage schema:
        /r_user_1
        ...
        /r_user_n
        /namespace_1~n1_user_1
        ...
        /namespace_1~n1_user_m
        ...
        /namespace_n~nn_user_m

        All functions take explicit nids (namespace, id) parameters, and never
        process a fully-qualified user name like "ns~id" as a single string.
        Parsing a string into a nid is assumed to be done in user-facing layers.
  *)
  module User = struct
    module Info = User_info

    let user_src = Logs.Src.create "hsm.user" ~doc:"HSM user log"

    module Access = (val Logs.src_log user_src : Logs.LOG)

    let pp_role ppf r =
      Fmt.string ppf
      @@
      match r with
      | `Administrator -> "R-Administrator"
      | `Operator -> "R-Operator"
      | `Metrics -> "R-Metrics"
      | `Backup -> "R-Backup"

    let make_store_key nid =
      let key = Nid.to_string nid in
      Mirage_kv.Key.(v key)

    let read store nid = User_store.get store (make_store_key nid)

    let write store nid data =
      with_write_lock (fun () ->
          let key = make_store_key nid in
          internal_server_error Write "Write user" User_store.pp_write_error
            (User_store.set store key data))

    (* functions below are exported, and take a Hsm.t directly, this the
       wrapper to unpack the auth_store handle. *)
    let in_store t =
      match t.state with
      | Operational keys -> keys.auth_store
      | _ -> assert false
    (* checked by webmachine Handler_user.service_available *)

    let get_user t nid =
      let keys = in_store t in
      read keys nid

    let is_authenticated t nid ~passphrase =
      let open Lwt.Infix in
      get_user t nid >|= function
      | Error e ->
          Access.warn (fun m ->
              m "%a unauthenticated: %a" Nid.pp nid User_store.pp_read_error e);
          false
      | Ok user ->
          let pass = Crypto.stored_passphrase ~salt:user.salt passphrase in
          String.equal pass user.digest

    let is_authorized t nid role =
      let open Lwt.Infix in
      get_user t nid >>= function
      | Error e ->
          Access.warn (fun m ->
              m "%a unauthorized for %a: %a" Nid.pp nid pp_role role
                User_store.pp_read_error e);
          Lwt.return false
      | Ok user -> (
          if
            (* Check that namespace exists already *)
            user.role <> role
          then Lwt.return false
          else
            Namespace.exists t nid.namespace >|= function
            | Error _ | Ok false -> false
            | Ok true -> true)

    let exists t nid =
      let open Lwt_result.Infix in
      let store = in_store t in
      internal_server_error Read "Exists user" User_store.pp_error
        ( User_store.exists store (make_store_key nid) >|= function
          | None -> false
          | Some _ -> true )

    let get t nid =
      let store = in_store t in
      internal_server_error Read "Read user" User_store.pp_read_error
        (read store nid)

    let prepare_user ~name ~passphrase ~role =
      let salt = Mirage_crypto_rng.generate Crypto.passphrase_salt_len in
      let digest = Crypto.stored_passphrase ~salt passphrase in
      { User_info.name; salt; digest; role; tags = Json.TagSet.empty }

    let add t nid ~role ~passphrase ~name =
      let open Lwt_result.Infix in
      let store = in_store t in
      Lwt.bind (read store nid) (function
        | Error (`Store (`Kv (`Not_found _))) ->
            let user = prepare_user ~name ~passphrase ~role in
            write store nid user >|= fun () ->
            Access.info (fun m ->
                m "added %s (%a): %a" name Nid.pp nid pp_role role)
        | Ok _ -> Lwt.return (Error (Conflict, "user already exists"))
        | Error _ as e ->
            internal_server_error Read "Adding user" User_store.pp_read_error
              (Lwt.return e))

    let efficient_list t namespace =
      let store = in_store t in
      (* no prefix: user store is flat *)
      let range =
        match namespace with
        | None -> Kv_ext.Range.create ()
        | Some n ->
            let start = n ^ Nid.separator in
            let stop =
              Kv_ext.Range.range_end_of_prefix (Bytes.of_string start)
              |> Bytes.unsafe_to_string
            in
            Kv_ext.Range.create ~start ~stop ()
      in
      User_store.list_range store range

    let list ~namespace t =
      let open Lwt.Infix in
      efficient_list t namespace >>= function
      | Error (`Not_found _ | `Kv (`Not_found _)) -> Lwt_result.return []
      | Error e ->
          internal_server_error Read "List users" Key_store.pp_error
            (Lwt_result.fail e)
      | Ok xs ->
          Lwt.return_ok
            (List.filter_map
               (function
                 | id, `Value -> Some (Mirage_kv.Key.basename id) | _ -> None)
               xs)

    let remove t nid =
      let open Lwt_result.Infix in
      let store = in_store t in
      with_write_lock (fun () ->
          internal_server_error Write "Remove user" User_store.pp_write_error
            ( User_store.remove store (make_store_key nid) >|= fun () ->
              Access.info (fun m -> m "removed (%a)" Nid.pp nid) ))

    let set_passphrase t nid ~passphrase =
      let open Lwt_result.Infix in
      let store = in_store t in
      internal_server_error Read "Read user" User_store.pp_read_error
        (read store nid)
      >>= fun user ->
      let salt' = Mirage_crypto_rng.generate Crypto.passphrase_salt_len in
      let digest' = Crypto.stored_passphrase ~salt:salt' passphrase in
      let user' = { user with salt = salt'; digest = digest' } in
      write store nid user' >|= fun () ->
      Access.info (fun m -> m "changed %a (%s) passphrase" Nid.pp nid user.name)

    let add_tag t nid ~tag =
      let open Lwt_result.Infix in
      let store = in_store t in
      internal_server_error Read "Read user" User_store.pp_read_error
        (read store nid)
      >>= fun user ->
      if Info.role user = `Operator then
        if not (Json.TagSet.mem tag user.tags) then (
          let user' = { user with tags = Json.TagSet.add tag user.tags } in
          write store nid user' >|= fun () ->
          Access.info (fun m ->
              m "added a tag to %a (%s): %S" Nid.pp nid user.name tag);
          true)
        else Lwt.return_ok false
      else
        Lwt.return_error
          (Bad_request, "tag operations only exist on operator users")

    let remove_tag t nid ~tag =
      let open Lwt_result.Infix in
      let store = in_store t in
      internal_server_error Read "Read user" User_store.pp_read_error
        (read store nid)
      >>= fun user ->
      if Info.role user = `Operator then
        if Json.TagSet.mem tag user.tags then (
          let user' = { user with tags = Json.TagSet.remove tag user.tags } in
          write store nid user' >|= fun () ->
          Access.info (fun m ->
              m "removed a tag from %a (%s): %S" Nid.pp nid user.name tag);
          true)
        else Lwt.return_ok false
      else
        Lwt.return_error
          (Bad_request, "tag operations only exist on operator users")

    let list_digest t =
      let open Lwt.Infix in
      let store = in_store t in
      User_store.digest store Mirage_kv.Key.empty >|= function
      | Ok digest -> Some (to_hex digest)
      | Error _ -> None

    let digest t nid =
      let open Lwt.Infix in
      let store = in_store t in
      User_store.digest store (make_store_key nid) >|= function
      | Ok digest -> Some (to_hex digest)
      | Error _ -> None
  end

  (*  Storage schema:
        /root_key_n
        ...
        /root_key_n
        /.namespace_1/ns_key1
        ...
        /.namespace_1/ns_key_n
        ...
        /.namespace_n/ns_key_n
  *)
  module Key = struct
    let key_src = Logs.Src.create "hsm.key" ~doc:"HSM key log"

    module Access = (val Logs.src_log key_src : Logs.LOG)

    (* functions below are exported, and take a Hsm.t directly, this the
       wrapper to unpack the auth_store handle. *)
    let key_store t =
      match t.state with
      | Operational keys -> keys.key_store
      | _ -> assert false
    (* checked by webmachine Handler_keys.service_available *)

    let make_store_key ~namespace id =
      let prefix = Namespace.key_prefix namespace in
      Mirage_kv.Key.(prefix / id)

    let exists ~namespace t ~id =
      let open Lwt_result.Infix in
      let store = key_store t in
      let key = make_store_key ~namespace id in
      internal_server_error Read "Exists key" Encrypted_store.pp_error
        ( Key_store.exists store key >|= function
          | None -> false
          | Some _ -> true )

    let validate_restrictions ~user_info (restrictions : Json.restrictions) =
      if Json.TagSet.is_empty restrictions.tags then Ok ()
      else if Json.TagSet.disjoint restrictions.tags (User.Info.tags user_info)
      then Error (Forbidden, "tags restriction not met")
      else Ok ()

    (* boilerplate for dumping keys whose operations changed *)
    let cached_operations = Hashtbl.create 7

    let get_key t ~namespace id =
      let open Lwt_result.Infix in
      let store = key_store t in
      let key = make_store_key ~namespace id in
      internal_server_error Read "Read key" Key_store.pp_read_error
        (Key_store.get store key)
      >>= fun key ->
      let operations =
        match Hashtbl.find_opt cached_operations (namespace, id) with
        | None -> key.operations
        | Some v -> v
      in
      Lwt.return (Ok { key with operations })

    let efficient_list t ?with_prefix namespace =
      let store = key_store t in
      let range = Namespace.file_range namespace in
      let range =
        match with_prefix with
        | Some prefix when prefix <> "" ->
            let start = prefix in
            let stop =
              Kv_ext.Range.range_end_of_prefix (Bytes.of_string start)
              |> Bytes.unsafe_to_string
            in
            { range with start = Some start; stop = Some stop }
        | _ -> range
      in
      Key_store.list_range store range

    let list ?with_prefix ~namespace t ~filter_by_restrictions ~user_nid =
      let open Lwt.Infix in
      efficient_list t ?with_prefix namespace >>= function
      | Error (`Not_found _ | `Kv (`Not_found _)) -> Lwt_result.return []
      | Error e ->
          internal_server_error Read "List keys" Key_store.pp_error
            (Lwt_result.fail e)
      | Ok xs ->
          let open Lwt_result.Infix in
          User.get t user_nid >>= fun user_info ->
          let open Lwt.Infix in
          let is_admin = User.Info.role user_info = `Administrator in
          let is_usable (k : Key_info.t) =
            validate_restrictions ~user_info k.restrictions |> Result.is_ok
          in
          let values_id =
            List.filter_map
              (function
                | id, `Value -> Some (Mirage_kv.Key.basename id) | _ -> None)
              xs
          in
          if is_admin || not filter_by_restrictions then
            (* bypass filter *)
            Lwt.return_ok values_id
          else
            (* keep only usable keys *)
            let filter id =
              get_key t ~namespace:None id >|= function
              | Ok k when is_usable k -> Some id
              | _ -> None
            in
            Lwt_list.filter_map_s filter values_id >|= fun l -> Ok l

    let dump_keys t =
      let open Lwt.Infix in
      match t.state with
      | Unprovisioned | Locked -> Lwt.return_unit
      | Operational _ -> (
          with_write_lock (fun () ->
              let store = key_store t in
              Key_store.batch store (fun b ->
                  Hashtbl.fold
                    (fun (namespace, id) _ x ->
                      x >>= function
                      | Error e -> Lwt.return (Error e)
                      | Ok () -> (
                          get_key t ~namespace id >>= function
                          | Error (_, msg) ->
                              (* this should not happen *)
                              Log.err (fun m ->
                                  m "error %s while retrieving key %s" msg id);
                              Lwt.return (Ok ())
                          | Ok k -> (
                              let key = make_store_key ~namespace id in
                              Key_store.set b key k >>= function
                              | Ok () -> Lwt.return (Ok ())
                              | Error e ->
                                  Log.err (fun m ->
                                      m "error %a while writing key %s"
                                        Key_store.pp_write_error e id);
                                  Lwt.return (Ok ()))))
                    cached_operations (Lwt.return (Ok ()))))
          >|= function
          | Ok () -> Hashtbl.clear cached_operations
          | Error _ -> ())

    let encode_and_write t ~namespace id key =
      let store = key_store t and kv_key = make_store_key ~namespace id in
      Hashtbl.remove cached_operations (namespace, id);
      with_write_lock (fun () ->
          internal_server_error Write "Write key" Key_store.pp_write_error
            (Key_store.set store kv_key key))

    let add ~namespace ~id t mechanisms priv restrictions =
      let open Lwt_result.Infix in
      let store = key_store t in
      let key = make_store_key ~namespace id in
      internal_server_error Read "Exist key" Key_store.pp_error
        (Key_store.exists store key)
      >>= function
      | Some _ ->
          Lwt.return
            (Error (Bad_request, "Key with id " ^ id ^ " already exists"))
      | None ->
          encode_and_write t ~namespace id
            { mechanisms; priv; cert = None; operations = 0; restrictions }
          >|= fun () ->
          Access.info (fun f -> f "created (%s)" id);
          if not (Json.TagSet.is_empty restrictions.tags) then
            Access.info (fun f ->
                f "tags (%s): %s" id
                  (Json.TagSet.to_yojson restrictions.tags |> Yojson.to_string))

    open Stores.Key_info

    let add_json ~namespace ~id t mechanisms typ (key : Json.private_key)
        restrictions =
      let b64err msg ctx data =
        Rresult.R.error_msgf
          "Invalid base64 encoded value (error: %s) in %S: %s" msg ctx data
      in
      let to_z ctx data =
        match Base64.decode data with
        | Ok num -> Ok (Mirage_crypto_pk.Z_extra.of_octets_be num)
        | Error (`Msg msg) -> b64err msg ctx data
      in
      let b64_data data =
        match Base64.decode data with
        | Ok k -> Ok k
        | Error (`Msg m) -> b64err m "data" data
      in
      let open Rresult.R.Infix in
      let prv t =
        X509.Private_key.of_string ~seed_or_data:`Data t key.data >>| fun p ->
        X509 p
      in
      match
        match typ with
        | Json.RSA ->
            to_z "primeP" key.primeP >>= fun p ->
            to_z "primeQ" key.primeQ >>= fun q ->
            to_z "publicExponent" key.publicExponent >>= fun e ->
            Mirage_crypto_pk.Rsa.priv_of_primes ~e ~p ~q >>| fun key ->
            X509 (`RSA key)
        | Generic -> b64_data key.data >>| fun k -> Generic k
        | Curve25519 -> prv `ED25519
        | EC_P224 -> Error (`Msg "P224 is unsupported")
        | EC_P256 -> prv `P256
        | EC_P384 -> prv `P384
        | EC_P521 -> prv `P521
        | EC_P256K1 -> prv `P256K1
        | BrainpoolP256 -> prv `BrainpoolP256
        | BrainpoolP384 -> prv `BrainpoolP384
        | BrainpoolP512 -> prv `BrainpoolP512
      with
      | Error (`Msg e) -> Lwt.return (Error (Bad_request, e))
      | Ok priv -> add ~namespace ~id t mechanisms priv restrictions

    let add_pem ~namespace ~id t mechanisms data restrictions =
      match X509.Private_key.decode_pem data with
      | Error (`Msg m) -> Lwt.return (Error (Bad_request, m))
      | Ok priv -> add ~namespace ~id t mechanisms (X509 priv) restrictions

    let generate_x509 typ ~length =
      let open Rresult in
      (match typ with
        | `RSA when 1024 <= length && length <= 8192 -> Ok (Some length, `RSA)
        | `RSA -> Error (Bad_request, "Length must be between 1024 and 8192.")
        | rest -> Ok (None, rest))
      >>| fun (bits, typ) -> X509.Private_key.generate ?bits typ

    let generate_generic ~length =
      if 128 <= length && length <= 8192 then
        Ok (Mirage_crypto_rng.generate ((length + 7) / 8))
      else Error (Bad_request, "Length must be between 128 and 8192.")

    let generate_key typ ~length =
      let open Rresult in
      let gen t = generate_x509 t ~length >>| fun key -> X509 key in
      match typ with
      | Json.Generic -> generate_generic ~length >>| fun key -> Generic key
      | RSA -> gen `RSA
      | Curve25519 -> gen `ED25519
      | EC_P224 -> Error (Bad_request, "P224 is unsupported")
      | EC_P256 -> gen `P256
      | EC_P384 -> gen `P384
      | EC_P521 -> gen `P521
      | EC_P256K1 -> gen `P256K1
      | BrainpoolP256 -> gen `BrainpoolP256
      | BrainpoolP384 -> gen `BrainpoolP384
      | BrainpoolP512 -> gen `BrainpoolP512

    let generate ~namespace ~id t typ mechanisms ~length restrictions =
      let open Lwt_result.Infix in
      Lwt.return (generate_key typ ~length) >>= fun priv ->
      Metrics.key_op `Generate;
      add ~namespace ~id t mechanisms priv restrictions

    let remove ~namespace t ~id =
      let open Lwt_result.Infix in
      let store = key_store t in
      Hashtbl.remove cached_operations (namespace, id);
      let key = make_store_key ~namespace id in
      with_write_lock (fun () ->
          internal_server_error Write "Remove key" Key_store.pp_write_error
            ( Key_store.remove store key >|= fun () ->
              Access.info (fun m -> m "removed (%s)" id) ))

    let move ~namespace t ~current_id ~new_id =
      let open Lwt_result.Infix in
      let store = key_store t in
      let current_key = make_store_key ~namespace current_id in
      let new_key = make_store_key ~namespace new_id in
      with_write_lock (fun () ->
          (* Check if new key already exists *)
          internal_server_error Read "Check new key exists" Key_store.pp_error
            (Key_store.exists store new_key)
          >>= function
          | Some _ ->
              Lwt.return
                (Error
                   (Conflict, Printf.sprintf "Key '%s' already exists" new_id))
          | None ->
              (* Get the key data *)
              internal_server_error Read "Get key data" Key_store.pp_read_error
                (Key_store.get store current_key)
              >>= fun key_data ->
              let operations =
                match
                  Hashtbl.find_opt cached_operations (namespace, current_id)
                with
                | None -> key_data.operations
                | Some v -> v
              in
              let key_data = { key_data with operations } in
              (* Write to new location *)
              internal_server_error Write "Write moved key"
                Key_store.pp_write_error
                (Key_store.set store new_key key_data)
              >>= fun () ->
              (* Remove old location *)
              internal_server_error Write "Remove old key"
                Key_store.pp_write_error
                (Key_store.remove store current_key)
              >|= fun () ->
              (* Update cache *)
              Hashtbl.remove cached_operations (namespace, current_id);
              Access.info (fun m -> m "moved (%s) to (%s)" current_id new_id))

    let remove_all_in_namespace t ~namespace =
      let open Lwt.Infix in
      efficient_list t (Some namespace) >>= function
      | Error (`Not_found _ | `Kv (`Not_found _)) -> Lwt.return (Ok ())
      | Error _ as e ->
          internal_server_error Read "List keys" Key_store.pp_error
            (Lwt.return e)
      | Ok xs ->
          Lwt_list.filter_map_s
            (function
              | _, `Dictionary -> Lwt.return None
              | id, `Value ->
                  remove ~namespace:(Some namespace) t
                    ~id:(Mirage_kv.Key.basename id)
                  >|= fun r -> Some r)
            xs
          >|= List.fold_left
                (function Error e -> fun _ -> Error e | _ -> fun x -> x)
                (Ok ())

    let get_json ~namespace t ~id =
      let open Lwt_result.Infix in
      let open Mirage_crypto_ec in
      get_key t ~namespace id >|= fun pkey ->
      let public, typ =
        match pkey.priv with
        | X509 (`RSA k) ->
            let z_to_b64 n =
              Mirage_crypto_pk.Z_extra.to_octets_be n |> Base64.encode_string
            in
            let modulus = z_to_b64 k.Mirage_crypto_pk.Rsa.n
            and publicExponent = z_to_b64 k.Mirage_crypto_pk.Rsa.e in
            ( Json.rsa_public_key_to_yojson { Json.modulus; publicExponent },
              Json.RSA )
        | X509 (`ED25519 k) ->
            let data =
              Ed25519.(pub_of_priv k |> pub_to_octets) |> Base64.encode_string
            in
            (Json.ec_public_key_to_yojson { Json.data }, Json.Curve25519)
        | X509 (`P256 k) ->
            let data =
              P256.Dsa.(pub_of_priv k |> pub_to_octets) |> Base64.encode_string
            in
            (Json.ec_public_key_to_yojson { Json.data }, Json.EC_P256)
        | X509 (`P384 k) ->
            let data =
              P384.Dsa.(pub_of_priv k |> pub_to_octets) |> Base64.encode_string
            in
            (Json.ec_public_key_to_yojson { Json.data }, Json.EC_P384)
        | X509 (`P521 k) ->
            let data =
              P521.Dsa.(pub_of_priv k |> pub_to_octets) |> Base64.encode_string
            in
            (Json.ec_public_key_to_yojson { Json.data }, Json.EC_P521)
        | X509 (`P256K1 k) ->
            let data =
              P256k1.Dsa.(pub_of_priv k |> pub_to_octets)
              |> Base64.encode_string
            in
            (Json.ec_public_key_to_yojson { Json.data }, Json.EC_P256K1)
        | X509 (`BrainpoolP256 k) ->
            let data =
              BrainpoolP256.Dsa.(pub_of_priv k |> pub_to_octets)
              |> Base64.encode_string
            in
            (Json.ec_public_key_to_yojson { Json.data }, Json.BrainpoolP256)
        | X509 (`BrainpoolP384 k) ->
            let data =
              BrainpoolP384.Dsa.(pub_of_priv k |> pub_to_octets)
              |> Base64.encode_string
            in
            (Json.ec_public_key_to_yojson { Json.data }, Json.BrainpoolP384)
        | X509 (`BrainpoolP512 k) ->
            let data =
              BrainpoolP512.Dsa.(pub_of_priv k |> pub_to_octets)
              |> Base64.encode_string
            in
            (Json.ec_public_key_to_yojson { Json.data }, Json.BrainpoolP512)
        | Generic _ -> (`Null, Json.Generic)
      in
      Json.public_key_to_yojson
        {
          Json.mechanisms = pkey.mechanisms;
          typ;
          operations = pkey.operations;
          public;
          restrictions = pkey.restrictions;
        }

    let get_pem ~namespace t ~id =
      let open Lwt_result.Infix in
      get_key t ~namespace id >>= fun key ->
      Lwt_result.lift
      @@
      match key.priv with
      | X509 p ->
          let pub = X509.Private_key.public p in
          Ok (X509.Public_key.encode_pem pub)
      | Generic _ -> Error (Bad_request, "Generic keys have no public key")

    let csr_pem t ~namespace ~id subject =
      let open Lwt_result.Infix in
      get_key t ~namespace id >>= fun key ->
      let dn = Json.to_distinguished_name subject in
      let extensions = create_csr_extensions subject in
      Lwt_result.lift
      @@
      match key.priv with
      | X509 p -> (
          match X509.Signing_request.create dn ?extensions p with
          | Error (`Msg e) ->
              Error (Bad_request, "creating signing request: " ^ e)
          | Ok c -> Ok (X509.Signing_request.encode_pem c))
      | Generic _ ->
          Error (Bad_request, "Generic keys can't create certificates")

    let get_cert ~namespace t ~id =
      let open Lwt_result.Infix in
      get_key t ~namespace id >|= fun key -> key.cert

    let set_cert t ~namespace ~id ~content_type data =
      let open Lwt_result.Infix in
      get_key t ~namespace id >>= fun key ->
      match key.cert with
      | Some _ ->
          Lwt.return (Error (Conflict, "Key already contains a certificate"))
      | None ->
          let key' = { key with cert = Some (content_type, data) } in
          encode_and_write t ~namespace id key'

    let remove_cert ~namespace t ~id =
      let open Lwt_result.Infix in
      get_key t ~namespace id >>= fun key ->
      match key.cert with
      | None ->
          Lwt.return
            (Error (Not_found, "There is no certificate for this KeyID."))
      | Some _ ->
          let key' = { key with cert = None } in
          encode_and_write t ~namespace id key'

    let get_restrictions ~namespace t ~id =
      let open Lwt_result.Infix in
      get_key t ~namespace id >|= fun key -> key.restrictions

    let add_restriction_tags ~namespace t ~id ~tag =
      let open Lwt_result.Infix in
      get_key t ~namespace id >>= fun key ->
      if not (Json.TagSet.mem tag key.restrictions.tags) then (
        let restrictions' =
          { Json.tags = Json.TagSet.add tag key.restrictions.tags }
        in
        Access.info (fun f -> f "update (%s): added tag %S" id tag);
        encode_and_write t ~namespace id
          { key with restrictions = restrictions' }
        >|= fun () -> true)
      else Lwt.return_ok false

    let remove_restriction_tags ~namespace t ~id ~tag =
      let open Lwt_result.Infix in
      get_key t ~namespace id >>= fun key ->
      if Json.TagSet.mem tag key.restrictions.tags then (
        let restrictions' =
          { Json.tags = Json.TagSet.remove tag key.restrictions.tags }
        in
        Access.info (fun f -> f "update (%s): removed tag %S" id tag);
        encode_and_write t ~namespace id
          { key with restrictions = restrictions' }
        >|= fun () -> true)
      else Lwt.return_ok false

    module Oaep_md5 = Mirage_crypto_pk.Rsa.OAEP (Digestif.MD5)
    module Oaep_sha1 = Mirage_crypto_pk.Rsa.OAEP (Digestif.SHA1)
    module Oaep_sha224 = Mirage_crypto_pk.Rsa.OAEP (Digestif.SHA224)
    module Oaep_sha256 = Mirage_crypto_pk.Rsa.OAEP (Digestif.SHA256)
    module Oaep_sha384 = Mirage_crypto_pk.Rsa.OAEP (Digestif.SHA384)
    module Oaep_sha512 = Mirage_crypto_pk.Rsa.OAEP (Digestif.SHA512)

    let validate_restrictions t ~user_nid key_data =
      let open Lwt_result.Infix in
      User.get t user_nid >>= fun user_info ->
      let validation =
        if User.Info.role user_info = `Administrator then Ok ()
        else validate_restrictions ~user_info key_data.restrictions
      in
      Result.map (fun () -> key_data) validation |> Lwt.return

    let decrypt t ~namespace ~id ~user_nid ~iv decrypt_mode data =
      let open Lwt_result.Infix in
      get_key t ~namespace id >>= validate_restrictions t ~user_nid
      >>= fun key_data ->
      let oneline = Astring.String.(concat ~sep:"" (cuts ~sep:"\n" data)) in
      Lwt_result.lift
        (let open Rresult.R.Infix in
         match Base64.decode oneline with
         | Error (`Msg msg) ->
             Error
               (Bad_request, "Couldn't decode data from base64: " ^ msg ^ ".")
         | Ok encrypted_data ->
             if
               Json.MS.mem
                 (Json.mechanism_of_decrypt_mode decrypt_mode)
                 key_data.mechanisms
             then (
               (match key_data.priv with
                 | X509 (`RSA key) -> (
                     let dec_cs =
                       match decrypt_mode with
                       | Json.RAW -> (
                           try
                             Some
                               (Mirage_crypto_pk.Rsa.decrypt ~key encrypted_data)
                           with Mirage_crypto_pk.Rsa.Insufficient_key -> None)
                       | PKCS1 ->
                           Mirage_crypto_pk.Rsa.PKCS1.decrypt ~key
                             encrypted_data
                       | OAEP_MD5 -> Oaep_md5.decrypt ~key encrypted_data
                       | OAEP_SHA1 -> Oaep_sha1.decrypt ~key encrypted_data
                       | OAEP_SHA224 -> Oaep_sha224.decrypt ~key encrypted_data
                       | OAEP_SHA256 -> Oaep_sha256.decrypt ~key encrypted_data
                       | OAEP_SHA384 -> Oaep_sha384.decrypt ~key encrypted_data
                       | OAEP_SHA512 -> Oaep_sha512.decrypt ~key encrypted_data
                       | AES_CBC -> None
                     in
                     match dec_cs with
                     | None -> Error (Bad_request, "Decryption failure")
                     | Some cs -> Ok cs)
                 | Generic key -> (
                     match decrypt_mode with
                     | Json.AES_CBC -> (
                         match iv with
                         | None ->
                             Error (Bad_request, "AES-CBC decrypt requires IV")
                         | Some iv -> (
                             try
                               let iv = Base64.decode_exn iv in
                               let key = Mirage_crypto.AES.CBC.of_secret key in
                               Ok
                                 (Mirage_crypto.AES.CBC.decrypt ~key ~iv
                                    encrypted_data)
                             with Invalid_argument err ->
                               Error (Bad_request, "Decryption failed: " ^ err))
                         )
                     | _ ->
                         Error
                           ( Bad_request,
                             "decrypt mode not supported by Generic key" ))
                 | _ ->
                     Error
                       ( Bad_request,
                         "Decryption only supported for RSA and Generic keys."
                       ))
               >>= fun data ->
               Metrics.key_op `Decrypt;
               Hashtbl.replace cached_operations (namespace, id)
                 (succ key_data.operations);
               Ok (Base64.encode_string data))
             else
               Error
                 ( Bad_request,
                   "Key mechanisms do not allow requested decryption." ))

    let encrypt t ~namespace ~id ~user_nid ~iv encrypt_mode data =
      let open Lwt_result.Infix in
      get_key t ~namespace id >>= validate_restrictions t ~user_nid
      >>= fun key_data ->
      let oneline = Astring.String.(concat ~sep:"" (cuts ~sep:"\n" data)) in
      Lwt_result.lift
        (let open Rresult.R.Infix in
         match Base64.decode oneline with
         | Error (`Msg msg) ->
             Error
               (Bad_request, "Couldn't decode data from base64: " ^ msg ^ ".")
         | Ok message_data ->
             if
               Json.MS.mem
                 (Json.mechanism_of_encrypt_mode encrypt_mode)
                 key_data.mechanisms
             then (
               (match key_data.priv with
                 | Generic key -> (
                     match encrypt_mode with
                     | Json.AES_CBC -> (
                         try
                           let iv =
                             match iv with
                             | None ->
                                 Mirage_crypto_rng.generate
                                   Mirage_crypto.AES.CBC.block_size
                             | Some iv -> Base64.decode_exn iv
                           in
                           let key = Mirage_crypto.AES.CBC.of_secret key in
                           Ok
                             ( Mirage_crypto.AES.CBC.encrypt ~key ~iv
                                 message_data
                               |> Base64.encode_string,
                               Some (Base64.encode_string iv) )
                         with Invalid_argument err ->
                           Error (Bad_request, "Encryption failed: " ^ err)))
                 | _ ->
                     Error
                       ( Bad_request,
                         "Encryption only supported for Generic keys." ))
               >>= fun (cs, iv) ->
               Metrics.key_op `Encrypt;
               Hashtbl.replace cached_operations (namespace, id)
                 (succ key_data.operations);
               Ok (cs, iv))
             else
               Error
                 ( Bad_request,
                   "Key mechanisms do not allow requested encryption." ))

    let sign t ~namespace ~id ~user_nid sign_mode data =
      let open Lwt_result.Infix in
      get_key t ~namespace id >>= validate_restrictions t ~user_nid
      >>= fun key_data ->
      let oneline = Astring.String.(concat ~sep:"" (cuts ~sep:"\n" data)) in
      match Base64.decode oneline with
      | Error (`Msg msg) ->
          Lwt.return
            (Error
               (Bad_request, "Couldn't decode data from base64: " ^ msg ^ "."))
      | Ok to_sign ->
          if
            Json.MS.mem
              (Json.mechanism_of_sign_mode sign_mode)
              key_data.mechanisms
          then
            let open Rresult.R.Infix in
            Lwt.return
              ( (match (key_data.priv, sign_mode) with
                  | X509 (`RSA key), Json.PKCS1 -> (
                      (* The PKCS#11 mechanism CKM_RSA_PKCS expects that the
                       _application_ prepends the DigestInfo, and therfore we
                       can't use the normal sign interface. *)
                      try
                        Ok (Mirage_crypto_pk.Rsa.PKCS1.sig_encode ~key to_sign)
                      with Mirage_crypto_pk.Rsa.Insufficient_key ->
                        Error
                          (Bad_request, "Signing failure: RSA key too short."))
                  | X509 (`P256K1 key), BIP340 -> (
                      try
                        let r, s =
                          Mirage_crypto_ec.P256k1.Dsa_bip340.sign_bip340 ~key
                            to_sign
                        in
                        Ok (r ^ s)
                      with Invalid_argument x ->
                        Error (Bad_request, "Signing failure: " ^ x))
                  | Generic _, _ ->
                      Error (Bad_request, "Generic keys can't sign.")
                  | X509 priv, _ ->
                      (match (priv, sign_mode) with
                        | `RSA _, Json.PSS_MD5 ->
                            Ok (`RSA_PSS, `MD5, `Digest to_sign)
                        | `RSA _, PSS_SHA1 ->
                            Ok (`RSA_PSS, `SHA1, `Digest to_sign)
                        | `RSA _, PSS_SHA224 ->
                            Ok (`RSA_PSS, `SHA224, `Digest to_sign)
                        | `RSA _, PSS_SHA256 ->
                            Ok (`RSA_PSS, `SHA256, `Digest to_sign)
                        | `RSA _, PSS_SHA384 ->
                            Ok (`RSA_PSS, `SHA384, `Digest to_sign)
                        | `RSA _, PSS_SHA512 ->
                            Ok (`RSA_PSS, `SHA512, `Digest to_sign)
                        | `ED25519 _, EdDSA ->
                            Ok (`ED25519, `SHA512, `Message to_sign)
                        | `P256 _, ECDSA -> Ok (`ECDSA, `SHA256, `Digest to_sign)
                        | `P384 _, ECDSA -> Ok (`ECDSA, `SHA384, `Digest to_sign)
                        | `P521 _, ECDSA -> Ok (`ECDSA, `SHA512, `Digest to_sign)
                        | `P256K1 _, ECDSA ->
                            Ok (`ECDSA, `SHA256, `Digest to_sign)
                        | `BrainpoolP256 _, ECDSA ->
                            Ok (`ECDSA, `SHA256, `Digest to_sign)
                        | `BrainpoolP384 _, ECDSA ->
                            Ok (`ECDSA, `SHA384, `Digest to_sign)
                        | `BrainpoolP512 _, ECDSA ->
                            Ok (`ECDSA, `SHA512, `Digest to_sign)
                        | _ -> Error (Bad_request, "invalid sign mode"))
                      >>= fun (scheme, hash, data) ->
                      Rresult.R.reword_error
                        (function `Msg m -> (Bad_request, m))
                        (X509.Private_key.sign ~rand_k:true hash ~scheme priv
                           data))
              >>| fun signature ->
                Metrics.key_op `Sign;
                Hashtbl.replace cached_operations (namespace, id)
                  (succ key_data.operations);
                Base64.encode_string signature )
          else
            Lwt.return
              (Error
                 (Bad_request, "Key mechanisms do not allow requested signing."))

    let list_digest ~namespace t ~filter_by_restrictions =
      let open Lwt.Infix in
      if filter_by_restrictions then Lwt.return_none
      else
        let key = Namespace.key_prefix namespace in
        let store = key_store t in
        Key_store.digest store key >|= function
        | Ok digest -> Some (to_hex digest)
        | Error _ -> None

    let digest ~namespace t ~id =
      let open Lwt.Infix in
      let store = key_store t in
      Key_store.digest store (make_store_key ~namespace id) >|= function
      | Ok digest -> Some (to_hex digest)
      | Error _ -> None
  end

  let provision t ~unlock ~admin time =
    let open Lwt_result.Infix in
    (* state already checked in Handler_provision.service_available *)
    let start = now () in
    assert (state t = `Unprovisioned);
    let unlock_salt = Mirage_crypto_rng.generate Crypto.salt_len in
    let unlock_key = Crypto.key_of_passphrase ~salt:unlock_salt unlock in
    let domain_key = Mirage_crypto_rng.generate Crypto.key_len in
    let auth_store_key, key_store_key, namespace_store_key =
      make_store_keys domain_key
    in
    with_write_lock (fun () ->
        KV.batch t.kv (fun b ->
            internal_server_error Write "Initializing configuration store"
              KV.pp_write_error
              (Config_store.set b Version Version.current)
            >>= fun () ->
            internal_server_error Write "Writing private RSA key"
              KV.pp_write_error
              (Config_store.set b Private_key t.key)
            >>= fun () ->
            internal_server_error Write "Writing certificate chain key"
              KV.pp_write_error
              (Config_store.set b Certificate (t.cert, t.chain))
            >>= fun () ->
            let auth_store =
              Encrypted_store.v Authentication ~key:auth_store_key t.kv
            in
            let a_v_key, a_v_value =
              Encrypted_store.prepare_set auth_store Version.filename
                Version.(to_string current)
            in
            internal_server_error Write "Initializing authentication store"
              KV.pp_write_error
              (KV.set b a_v_key a_v_value)
            >>= fun () ->
            let key_store = Encrypted_store.v Key ~key:key_store_key t.kv in
            let k_v_key, k_v_value =
              Encrypted_store.prepare_set key_store Version.filename
                Version.(to_string current)
            in
            internal_server_error Write "Initializing key store"
              KV.pp_write_error
              (KV.set b k_v_key k_v_value)
            >>= fun () ->
            (* Initializing the namespace store is also done on the fly if
               unlocking an old store without namespaces, in
               Encrypted_store.unlock *)
            let namespace_store =
              Encrypted_store.v Namespace ~key:namespace_store_key t.kv
            in
            let n_v_key, n_v_value =
              Encrypted_store.prepare_set namespace_store Version.filename
                Version.(to_string current)
            in
            internal_server_error Write "Initializing namespace store"
              KV.pp_write_error
              (KV.set b n_v_key n_v_value)
            >>= fun () ->
            let keys =
              {
                domain_key;
                auth_store = User_store.connect auth_store;
                key_store = Key_store.connect key_store;
                namespace_store = Namespace_store.connect namespace_store;
              }
            in
            t.state <- Operational keys;
            let admin_k, admin_v =
              let name = "admin" in
              let admin =
                User.prepare_user ~name ~passphrase:admin ~role:`Administrator
              in
              let value = Yojson.Safe.to_string (User_info.to_yojson admin) in
              Encrypted_store.prepare_set auth_store (Mirage_kv.Key.v name)
                value
            in
            internal_server_error Write "Write Administrator user"
              KV.pp_write_error (KV.set b admin_k admin_v)
            >>= fun () ->
            let enc_dk =
              encrypt_with_pass_key domain_key ~pass_key:unlock_key
            in
            let encryption_key = t.device_key in
            internal_server_error Write "Write passphrase domain key"
              KV.pp_write_error
              (Domain_key_store.set b Attended ~encryption_key enc_dk)
            >>= fun () ->
            internal_server_error Write "Write unlock-salt" KV.pp_write_error
              (Config_store.set b Unlock_salt unlock_salt)
            >>= fun () ->
            let time = Option.get Ptime.(add_span time (diff (now ()) start)) in
            set_time_offset b time))

  module Config = struct
    let change_unlock_passphrase t ~new_passphrase ~current_passphrase =
      match t.state with
      | Operational keys ->
          let open Lwt_result.Infix in
          check_unlock_passphrase t current_passphrase >>= fun () ->
          let salt = Mirage_crypto_rng.generate Crypto.salt_len in
          let pass_key = Crypto.key_of_passphrase ~salt new_passphrase in
          with_write_lock (fun () ->
              KV.batch t.kv (fun b ->
                  internal_server_error Write "Write unlock salt"
                    KV.pp_write_error
                    (Config_store.set b Unlock_salt salt)
                  >>= fun () ->
                  let enc_dk =
                    encrypt_with_pass_key keys.domain_key ~pass_key
                  in
                  let encryption_key = t.device_key in
                  internal_server_error Write "Write passphrase domain key"
                    KV.pp_write_error
                    (Domain_key_store.set b Attended enc_dk ~encryption_key)))
      | _ -> assert false
    (* Handler_config.service_available checked that we are operational *)

    let unattended_boot t =
      let open Lwt_result.Infix in
      internal_server_error Read "Read unattended boot" Config_store.pp_error
        ( Config_store.get_opt t.kv Unattended_boot >|= function
          | None -> false
          | Some v -> v )

    let set_unattended_boot t status =
      let open Lwt_result.Infix in
      (* (a) change setting in configuration store *)
      (* (b) add or remove to domain_key store *)
      match t.state with
      | Operational keys ->
          with_write_lock (fun () ->
              internal_server_error Write "Write unattended boot"
                KV.pp_write_error
                (Config_store.set t.kv Unattended_boot status)
              >>= fun () ->
              if status then
                let encryption_key = t.device_key in
                internal_server_error Write "Write unattended Domain Key"
                  KV.pp_write_error
                  (Domain_key_store.set t.kv Unattended ~encryption_key
                     keys.domain_key)
              else
                internal_server_error Write "Remove unattended Domain Key"
                  KV.pp_write_error
                  (Domain_key_store.remove t.kv Unattended))
      | _ -> assert false
    (* Handler_config.service_available checked that we are operational *)

    let unattended_boot_digest t =
      let open Lwt.Infix in
      Config_store.digest t.kv Unattended_boot >|= function
      | Ok digest -> Some (to_hex digest)
      | Error _ -> None

    let tls_public_pem t =
      let public = X509.Private_key.public t.key in
      Lwt.return (X509.Public_key.encode_pem public)

    let tls_public_pem_digest t =
      let open Lwt.Infix in
      Config_store.digest t.kv Private_key >|= function
      | Ok digest -> Some (to_hex digest)
      | Error _ -> None

    let tls_cert_pem t =
      let chain = t.cert :: t.chain in
      Lwt.return (X509.Certificate.encode_pem_multiple chain)

    let set_tls_cert_pem t cert_data =
      (* validate the incoming chain (we'll use it for the TLS server):
         - there's one server certificate at either end (matching our private key)
         - the chain itself is properly signed (i.e. a full chain missing the TA)
         --> take the last element as TA (unchecked), and verify the chain!
      *)
      match X509.Certificate.decode_pem_multiple cert_data with
      | Error (`Msg m) -> Lwt.return @@ Error (Bad_request, m)
      | Ok [] -> Lwt.return @@ Error (Bad_request, "empty certificate chain")
      | Ok (cert :: chain) ->
          let key_eq a b =
            String.equal
              (X509.Public_key.fingerprint a)
              (X509.Public_key.fingerprint b)
          in
          if
            key_eq
              (X509.Private_key.public t.key)
              (X509.Certificate.public_key cert)
          then (
            let valid =
              match List.rev chain with
              | [] -> Ok cert
              | ta :: chain' ->
                  let our_chain = cert :: List.rev chain' in
                  let time () = Some (now ()) in
                  Rresult.R.error_to_msg
                    ~pp_error:X509.Validation.pp_chain_error
                    (X509.Validation.verify_chain ~anchors:[ ta ] ~time
                       ~host:None our_chain)
            in
            match valid with
            | Error (`Msg m) -> Lwt.return @@ Error (Bad_request, m)
            | Ok _ ->
                let open Lwt_result.Infix in
                with_write_lock (fun () ->
                    internal_server_error Write "Write certificate"
                      KV.pp_write_error
                      (Config_store.set t.kv Certificate (cert, chain)))
                >>= fun r ->
                t.cert <- cert;
                t.chain <- chain;
                Lwt_result.ok (Lwt_mvar.put t.mbox (Tls (own_cert t)))
                >|= fun () -> r)
          else
            Lwt.return
            @@ Error
                 ( Bad_request,
                   "public key in certificate does not match private key." )

    let tls_cert_digest t =
      let open Lwt.Infix in
      Config_store.digest t.kv Certificate >|= function
      | Ok digest -> Some (to_hex digest)
      | Error _ -> None

    let tls_csr_pem t subject =
      let dn = Json.to_distinguished_name subject in
      let extensions = create_csr_extensions subject in
      Lwt.return
        (match X509.Signing_request.create dn ?extensions t.key with
        | Ok csr -> Ok (X509.Signing_request.encode_pem csr)
        | Error (`Msg m) -> Error (Bad_request, "while creating CSR: " ^ m))

    let tls_generate t typ ~length =
      let open Lwt_result.Infix in
      (* generate key *)
      Lwt.return (Key.generate_x509 typ ~length) >>= fun priv ->
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
      and gateway = match route with None -> Ipaddr.V4.any | Some ip -> ip in
      { Json.ipAddress; netmask; gateway }

    let set_network t network =
      let open Lwt_result.Infix in
      Lwt.return
        (let netmask = network.Json.netmask and address = network.ipAddress in
         Rresult.R.reword_error
           (function
             | `Msg err ->
                 (Bad_request, "error parsing network configuration: " ^ err))
           (Ipaddr.V4.Prefix.of_netmask ~netmask ~address))
      >>= fun prefix ->
      let route =
        if Ipaddr.V4.compare network.gateway Ipaddr.V4.any = 0 then None
        else Some network.gateway
      in
      with_write_lock (fun () ->
          internal_server_error Write "Write network configuration"
            KV.pp_write_error
            Config_store.(set t.kv Ip_config (network.ipAddress, prefix, route)))
      >>= fun r ->
      Lwt_result.ok (Lwt_mvar.put t.mbox (Network (prefix, route)))
      >|= fun () -> r

    let network_digest t =
      let open Lwt.Infix in
      Config_store.digest t.kv Ip_config >|= function
      | Ok digest -> Some (to_hex digest)
      | Error _ -> None

    let default_log =
      { Json.ipAddress = Ipaddr.V4.any; port = 514; logLevel = Info }

    let log t =
      let open Lwt.Infix in
      Config_store.get_opt t.kv Log_config >|= function
      | Ok None -> default_log
      | Ok (Some (ipAddress, port, logLevel)) -> { ipAddress; port; logLevel }
      | Error e ->
          Log.warn (fun m ->
              m "error %a while getting log configuration" Config_store.pp_error
                e);
          default_log

    let set_log t log =
      let open Lwt_result.Infix in
      with_write_lock (fun () ->
          internal_server_error Write "Write log config" KV.pp_write_error
            (Config_store.set t.kv Log_config
               (log.Json.ipAddress, log.port, log.logLevel)))
      >>= fun r ->
      Lwt_result.ok (Lwt_mvar.put t.mbox (Log log)) >|= fun () -> r

    let log_digest t =
      let open Lwt.Infix in
      Config_store.digest t.kv Log_config >|= function
      | Ok digest -> Some (to_hex digest)
      | Error _ -> None

    let check_backup_passphrase t passphrase =
      let ( let** ) = Lwt_result.bind in
      let** backup_key =
        internal_server_error Read "Read backup key" Config_store.pp_error
          (Config_store.get_opt t.kv Backup_key)
      in
      let** valid =
        match backup_key with
        | None -> Lwt.return_ok (passphrase = "")
        | Some backup_key ->
            let** salt =
              internal_server_error Read "Read backup salt"
                Config_store.pp_error
                (Config_store.get t.kv Backup_salt)
            in
            Lwt.return_ok
              (String.equal backup_key
                 (Crypto.key_of_passphrase ~salt passphrase))
      in
      if valid then Lwt.return_ok ()
      else Lwt.return_error (Forbidden, "backup passphrase is incorrect.")

    let change_backup_passphrase t ~new_passphrase ~current_passphrase =
      match t.state with
      | Operational _keys ->
          let open Lwt_result.Infix in
          check_backup_passphrase t current_passphrase >>= fun () ->
          let backup_salt = Mirage_crypto_rng.generate Crypto.salt_len in
          let backup_key =
            Crypto.key_of_passphrase ~salt:backup_salt new_passphrase
          in
          with_write_lock (fun () ->
              KV.batch t.kv (fun b ->
                  internal_server_error Write "Write backup salt"
                    KV.pp_write_error
                    (Config_store.set b Backup_salt backup_salt)
                  >>= fun () ->
                  internal_server_error Write "Write backup key"
                    KV.pp_write_error
                    (Config_store.set b Backup_key backup_key)))
      | _ -> assert false
    (* Handler_config.service_available checked that we are operational *)

    let time _t = Lwt.return (now ())
    let set_time t time = with_write_lock (fun () -> set_time_offset t.kv time)
  end

  module System = struct
    let system_info t = t.system_info

    let reboot t =
      let open Lwt.Infix in
      Key.dump_keys t >>= fun () -> Lwt_mvar.put t.mbox Reboot

    let shutdown t =
      let open Lwt.Infix in
      Key.dump_keys t >>= fun () -> Lwt_mvar.put t.mbox Shutdown

    let factory_reset t = Lwt_mvar.put t.mbox Factory_reset

    type stream_buffer = {
      stream : string Lwt_stream.t;
      mutable buf : string option;
    }

    let sb_of_stream stream = { stream; buf = None }

    let sb_is_empty sb =
      if sb.buf != None then Lwt.return false else Lwt_stream.is_empty sb.stream

    let sb_consume_buf sb =
      if sb.buf != None then (
        let buf = sb.buf in
        sb.buf <- None;
        buf)
      else None

    let sb_get sb =
      match sb_consume_buf sb with
      | None -> Lwt_stream.get sb.stream
      | x -> Lwt.return x

    let sb_fold f sb acc =
      let ( let* ) = Lwt.bind in
      let* acc =
        match sb_consume_buf sb with
        | None -> Lwt.return acc
        | Some buf -> f buf acc
      in
      Lwt_stream.fold_s f sb.stream acc

    let sb_read_n sb n =
      let buffer = Buffer.create n in
      let rec read () =
        let open Lwt.Infix in
        sb_get sb >>= function
        | None -> Lwt.return_error (Bad_request, "Unexpected end of data")
        | Some chunk ->
            let needed = n - Buffer.length buffer in
            let chunk_len = String.length chunk in
            if needed > chunk_len then (
              Buffer.add_string buffer chunk;
              (read [@tailcall]) ())
            else (
              Buffer.add_substring buffer chunk 0 needed;
              if chunk_len - needed > 0 then
                sb.buf <- Some (String.sub chunk needed (chunk_len - needed));
              let result = Buffer.contents buffer in
              Lwt.return_ok result)
      in
      read ()

    let decode_length data =
      let byte = String.get_uint8 data 0 in
      let len = String.get_uint16_be data 1 in
      (byte lsl 16) + len

    let get_length stream =
      let open Lwt_result.Infix in
      sb_read_n stream 3 >|= decode_length

    let get_field s =
      let open Lwt_result.Infix in
      get_length s >>= sb_read_n s

    let prefix_len s =
      let len_buf = Bytes.create 3 in
      let length = String.length s in
      assert (length < 1 lsl 24);
      (* TODO *)
      Bytes.set_uint8 len_buf 0 (length lsr 16);
      Bytes.set_uint16_be len_buf 1 (length land 0xffff);
      Bytes.unsafe_to_string len_buf ^ s

    module Hash = Digestif.SHA256

    let update_mutex = Lwt_mutex.create ()
    let update_header = "_NETHSM_UPDATE_\x00"

    let update t stream =
      match t.has_changes with
      | Some _ -> Lwt.return (Error (Conflict, "Update already in progress."))
      | None ->
          Lwt_mutex.with_lock update_mutex (fun () ->
              let open Lwt_result.Infix in
              (* stream contains:
                 - header '_NETHSM_UPDATE_\x00'
                 - signature (hash of the rest) §
                 - changelog §
                 - version number §
                 - 32bit size (in blocks of 512 bytes)
                 - software image,
                 §: prefixed by 4 byte length *)
              let sb = sb_of_stream stream in
              sb_read_n sb 16 >>= fun header ->
              (if header = update_header then Lwt.return_ok ()
               else Lwt.return_error (Bad_request, "Invalid update file"))
              >>= fun () ->
              get_field sb >>= fun signature ->
              let hash = Hash.empty in
              get_field sb >>= fun changes ->
              let hash = Hash.feed_string hash (prefix_len changes) in
              get_field sb >>= fun version ->
              Lwt.return (version_of_string version) >>= fun version' ->
              let hash = Hash.feed_string hash (prefix_len version) in
              sb_read_n sb 4 >>= fun blockss ->
              let blocks =
                Option.get
                  (Int32.unsigned_to_int (String.get_int32_be blockss 0))
              in
              let hash = Hash.feed_string hash blockss in
              let bytes = 512 * blocks in
              let platform_stream, pushf = Lwt_stream.create () in
              Lwt_result.ok
                (Lwt_mvar.put t.mbox (Update (blocks, platform_stream)))
              >>= fun () ->
              sb_fold
                (fun chunk acc ->
                  match acc with
                  | Error e -> Lwt.return (Error e)
                  | Ok (left, hash) ->
                      let left = left - String.length chunk in
                      let hash = Hash.feed_string hash chunk in
                      pushf (Some chunk);
                      Lwt.return @@ Ok (left, hash))
                sb
                (Ok (bytes, hash))
              >>= fun (left, hash) ->
              pushf None;
              (let open Lwt.Infix in
               Lwt_mvar.take t.res_mbox >|= function
               | Ok () -> Ok ()
               | Error msg ->
                   Log.warn (fun m ->
                       m "during update, platform reported %s" msg);
                   Error (Bad_request, "update failed: " ^ msg))
              >>= fun () ->
              Lwt.return
                (if left = 0 then Ok ()
                 else Error (Bad_request, "unexpected end of data"))
              >>= fun () ->
              let final_hash = Hash.(get hash |> to_raw_string) in
              if
                Mirage_crypto_pk.Rsa.PKCS1.verify
                  ~hashp:(function `SHA256 -> true | _ -> false)
                  ~key:t.software_update_key ~signature (`Digest final_hash)
              then
                let current = t.system_info.softwareVersion in
                if version_is_upgrade ~current ~update:version' then (
                  (* store changelog *)
                  t.has_changes <- Some changes;
                  Lwt.return (Ok changes))
                else
                  Lwt.return
                    (Error (Conflict, "Software version downgrade not allowed."))
              else
                Lwt.return
                  (Error (Bad_request, "Signature check of update image failed.")))

    let commit_update t =
      let open Lwt.Infix in
      match t.has_changes with
      | None ->
          Lwt.return
            (Error
               ( Precondition_failed,
                 "No update available. Please upload a system image to \
                  /system/update." ))
      | Some _changes -> (
          Lwt_mvar.put t.mbox Commit_update >>= fun () ->
          Lwt_mvar.take t.res_mbox >>= function
          | Ok () -> Lwt_mvar.put t.mbox Reboot >|= fun () -> Ok ()
          | Error msg ->
              Log.warn (fun m -> m "commit of update failed %s" msg);
              Lwt.return (Error (Bad_request, "commit failed: " ^ msg)))

    let cancel_update t =
      match t.has_changes with
      | None ->
          Error
            ( Precondition_failed,
              "No update available. Please upload a system image to \
               /system/update." )
      | Some _changes ->
          t.has_changes <- None;
          Ok ()

    (* the backup format is at the moment:
       - header "_NETHSM_BACKUP_" + 1 byte version
       - length of salt (encoded in 3 bytes); salt
       - length of ...; AES-GCM encrypted version [adata = backup-version]
       - length of ...; passphrase encrypted domain key
       - indivial key, value entries of the store:
         - length of encrypted-k-v; AES GCM (length of key; key; data) [adata = backup] *)

    let backup_header = "_NETHSM_BACKUP_"
    let backup_version_v0 = Char.chr 0

    let rec backup_directory kv push backup_key path =
      let open Lwt.Infix in
      KV.list kv path >>= function
      | Error e ->
          Log.err (fun m ->
              m "Error %a while listing path %a during backup." KV.pp_error e
                Mirage_kv.Key.pp path);
          Lwt.return_unit
      | Ok entries ->
          (* for each key, retrieve value and call push *)
          Lwt_list.iter_s
            (fun (key, kind) ->
              match kind with
              | `Value -> (
                  KV.get kv key >|= function
                  | Ok data ->
                      let key_str = Mirage_kv.Key.to_string key in
                      let data = prefix_len key_str ^ data in
                      let adata = "backup" in
                      let encrypted_data =
                        Crypto.encrypt Mirage_crypto_rng.generate
                          ~key:backup_key ~adata data
                      in
                      push (Some (prefix_len encrypted_data))
                  | Error e ->
                      Log.err (fun m ->
                          m "Error %a while retrieving value %a during backup."
                            KV.pp_error e Mirage_kv.Key.pp key))
              | `Dictionary -> backup_directory kv push backup_key key)
            entries

    let backup t push =
      let open Lwt.Infix in
      Config_store.get_opt t.kv Backup_key >>= function
      | Error e ->
          Log.err (fun m ->
              m "Error %a while reading backup key." Config_store.pp_error e);
          Lwt.return (Error (Internal_server_error, "Corrupted database."))
      | Ok None ->
          Lwt.return
            (Error
               ( Precondition_failed,
                 "Please configure backup key before doing a backup." ))
      | Ok (Some backup_key) -> (
          (* iterate over keys in KV store *)
          let backup_key' = Crypto.GCM.of_secret backup_key in
          Config_store.get t.kv Backup_salt >>= function
          | Error e ->
              Log.err (fun m ->
                  m "error %a while reading backup salt" Config_store.pp_error e);
              Lwt.return (Error (Internal_server_error, "Corrupted database."))
          | Ok backup_salt -> (
              let version_str = String.make 1 backup_version_v0 in
              push (Some (backup_header ^ version_str));
              push (Some (prefix_len backup_salt));
              let encrypted_version =
                let adata = "backup-version" in
                Crypto.encrypt Mirage_crypto_rng.generate ~key:backup_key'
                  ~adata version_str
              in
              push (Some (prefix_len encrypted_version));
              let encryption_key = t.device_key in
              Domain_key_store.get t.kv Attended ~encryption_key >>= function
              | Error e ->
                  Log.err (fun m ->
                      m "error %a while reading attended domain key"
                        Config_store.pp_error e);
                  Lwt.return
                    (Error (Internal_server_error, "Corrupted database."))
              | Ok locked_domkey ->
                  let encrypted_domkey =
                    let adata = "domain-key" in
                    Crypto.encrypt Mirage_crypto_rng.generate ~key:backup_key'
                      ~adata locked_domkey
                  in
                  push (Some (prefix_len encrypted_domkey));
                  backup_directory t.kv push backup_key' Mirage_kv.Key.empty
                  >|= fun () ->
                  push None;
                  Ok ()))

    let decode_value = get_field

    let split_kv data =
      (* len:key len:value *)
      let msg =
        "Missing length field in backup data. Backup not readable, try another \
         one."
      in
      let key_len = decode_length data in
      if String.length data < key_len + 3 then Error (Bad_request, msg)
      else
        let key = String.sub data 3 key_len in
        let val_start = 3 + key_len in
        let value =
          String.sub data val_start (String.length data - val_start)
        in
        Ok (key, value)

    let decrypt_backup ~key ~adata data =
      Lwt.return
      @@
      match Crypto.decrypt ~key ~adata data with
      | Error `Insufficient_data ->
          Error
            ( Bad_request,
              "Could not decrypt " ^ adata
              ^ ". Backup incomplete, try another one." )
      | Error `Not_authenticated ->
          Error
            ( Bad_request,
              "Could not decrypt " ^ adata
              ^ ", authentication failed. Is the passphrase correct?" )
      | Ok x -> Ok x

    let read_and_decrypt stream key =
      let ( let** ) = Lwt_result.bind in
      let** encrypted_data = decode_value stream in
      let adata = "backup" in
      let** kv = decrypt_backup ~key ~adata encrypted_data in
      let** kv = Lwt.return @@ split_kv kv in
      Lwt.return_ok kv

    (* runs the function while the stream has items *)
    let stream_while stream fn =
      let ( let* ) = Lwt.bind in
      let ( let** ) = Lwt_result.bind in
      let rec go () =
        let* empty = sb_is_empty stream in
        if empty then Lwt.return_ok ()
        else
          let** () = fn stream in
          (go [@tailcall]) ()
      in
      go ()

    module KeySet = Set.Make (Mirage_kv.Key)

    let restore_key ~is_operational ~backup_keys ~key ~kv stream =
      let ( let** ) = Lwt_result.bind in
      (* decrypt KV data *)
      let** k, v = read_and_decrypt stream key in
      let key = Mirage_kv.Key.v k in
      if is_operational then backup_keys := KeySet.add key !backup_keys;
      let should_restore_key =
        (not is_operational)
        || Option.is_some (Encrypted_store.slot_of_key key)
        || Mirage_kv.Key.equal key Config_store.(key_path Unlock_salt)
      in
      if should_restore_key then
        let** () =
          internal_server_error Write "restoring backup (writing to KV)"
            KV.pp_write_error (KV.set kv key v)
        in
        Lwt_result.return ()
      else Lwt_result.return ()

    let rec list_keys_rec ~kv prefix =
      let open Lwt_result.Infix in
      KV.list kv prefix >>= fun entries ->
      Lwt_list.fold_left_s
        (function
          | Error e -> fun _ -> Lwt_result.fail e
          | Ok acc -> (
              function
              | key, `Value -> Lwt_result.return (key :: acc)
              | prefix, `Dictionary ->
                  list_keys_rec ~kv prefix >>= fun subkeys ->
                  Lwt_result.return (subkeys @ acc)))
        (Ok []) entries

    let remove_extra_keys ~kv backup_keys =
      let ( let** ) = Lwt_result.bind in
      let auth_prefix = Encrypted_store.prefix_of_slot Authentication in
      let** auth_keys =
        internal_server_error Read "restoring backup (listing keys)" KV.pp_error
          (list_keys_rec ~kv auth_prefix)
      in
      let key_prefix = Encrypted_store.prefix_of_slot Key in
      let** key_keys =
        internal_server_error Read "restoring backup (listing keys)" KV.pp_error
          (list_keys_rec ~kv key_prefix)
      in
      let ns_prefix = Encrypted_store.prefix_of_slot Namespace in
      let** ns_keys =
        internal_server_error Read "restoring backup (listing keys)" KV.pp_error
          (list_keys_rec ~kv ns_prefix)
      in
      let keys = auth_keys @ key_keys @ ns_keys in
      List.filter_map
        (fun key ->
          if
            Option.is_some (Encrypted_store.slot_of_key key)
            && not (KeySet.mem key backup_keys)
          then (
            Log.info (fun f -> f "removing: %a\n%!" Mirage_kv.Key.pp key);
            Some key)
          else None)
        keys
      |> Lwt_list.fold_left_s
           (fun r k ->
             match r with
             | Error _ -> Lwt.return r
             | Ok () ->
                 internal_server_error Write
                   "restoring backup (removing keys from KV)" KV.pp_write_error
                   (KV.remove kv k))
           (Ok ())

    let restore t json stream =
      let sb = sb_of_stream stream in
      let ( let** ) = Lwt_result.bind in
      let (`Raw start_ts) = Hsm_clock.now_raw () in
      let initial_state = t.state in
      let is_operational =
        match t.state with Operational _ -> true | _ -> false
      in
      let** new_time, backup_passphrase_opt =
        match Json.decode_restore_req json with
        | Error e -> Lwt.return_error (Bad_request, e)
        | Ok x -> Lwt.return_ok x
      in
      let** header = sb_read_n sb (String.length backup_header + 1) in
      let** () =
        Lwt.return
        @@
        if String.(equal (sub header 0 (length backup_header)) backup_header)
        then Ok ()
        else Error (Bad_request, "Not a NetHSM backup file")
      in
      let version = String.(get header (length backup_header)) in
      let** () =
        Lwt.return
        @@
        match version with
        | x when x = backup_version_v0 -> Ok ()
        | _ ->
            let msg =
              Printf.sprintf
                "Version mismatch on restore, provided backup version is %d, \
                 server expects %d"
                (Char.code version)
                (Char.code backup_version_v0)
            in
            Error (Bad_request, msg)
      in
      let** salt = decode_value sb in
      let** backup_key =
        match backup_passphrase_opt with
        | None ->
            let** salt' =
              if is_operational then
                internal_server_error Read "Read backup salt"
                  Config_store.pp_error
                  (Config_store.get_opt t.kv Backup_salt)
              else Lwt.return_ok None
            in
            if Some salt = salt' then
              internal_server_error Read "Read backup key" Config_store.pp_error
                (Config_store.get t.kv Backup_key)
            else Lwt.return_error (Bad_request, "No backupPassphrase provided")
        | Some backup_passphrase ->
            Lwt.return_ok @@ Crypto.key_of_passphrase ~salt backup_passphrase
      in
      let key = Crypto.GCM.of_secret backup_key in
      let** version_int = decode_value sb in
      let adata = "backup-version" in
      let** version_int = decrypt_backup ~key ~adata version_int in
      let** () =
        Lwt.return
        @@
        if version = String.get version_int 0 then Ok ()
        else Error (Bad_request, "Internal and external version mismatch.")
      in
      let** encrypted_domain_key = decode_value sb in
      let adata = "domain-key" in
      let** locked_domain_key =
        decrypt_backup ~key ~adata encrypted_domain_key
      in
      (* when the mode is operational, we have to clear
         user and keys that are not in the backup. *)
      let backup_keys = ref KeySet.empty in
      with_write_lock (fun () ->
          let** () =
            KV.batch t.kv (fun b ->
                (* while the stream has content *)
                stream_while sb
                  (restore_key ~is_operational ~backup_keys ~key ~kv:b))
          in
          let** dk_rewritten =
            (* the domain key and/or device key might have changed if
               restored to a fresh or different device, so refresh the store
                *)
            let encryption_key = t.device_key in
            let open Lwt.Infix in
            let** dk_still_valid =
              (* there are 2 cases, where the stored domain key is valid:
                 1. the Domain Key Store has been restored during a full restore
                    from a backup created on the same device (same Device Key)
                 2. after operational restore from a backup with same Domain
                    Key and Unlock Passphrase as the current one
              *)
              Domain_key_store.get t.kv Attended ~encryption_key >>= function
              | Ok old_locked_domain_key
                when String.equal locked_domain_key old_locked_domain_key ->
                  Lwt_result.return true
              | Ok _ ->
                  Log.info (fun m -> m "Domain Key changed.");
                  Lwt_result.return false
              | Error _ ->
                  Log.info (fun m -> m "Device Key changed.");
                  Lwt_result.return false
            in
            if not dk_still_valid then (
              Log.info (fun m -> m "Rewriting stored Domain Key.");
              let** () =
                internal_server_error Write "Write locked domain key"
                  KV.pp_write_error
                  (Domain_key_store.set t.kv Attended ~encryption_key
                     locked_domain_key)
              in
              Lwt_result.return true)
            else Lwt_result.return false
          in
          let** () =
            KV.batch t.kv (fun b ->
                if is_operational then
                  (* we remove keys and users that not present in the backup.
                     if namespace store is not present in backup, the current
                     one will be emptied (all namespaces deleted) but will stay
                     provisioned. *)
                  remove_extra_keys ~kv:b !backup_keys
                else Lwt_result.return ())
          in
          let** () =
            if (not is_operational) || dk_rewritten then (
              (* If the restore was
                  - unprovisioned, or
                  - provisioned but with a new Domain Key
                 the end state after restore is locked.
                 if namespace store is not present in backup, it will be
                 provisioned here. *)
              let** new_state =
                boot_config_store ~cache_settings:t.cache_settings t.kv
                  t.device_key
              in
              t.state <- new_state;
              Lwt_result.return ())
            else Lwt_result.return ()
          in
          (match t.state with
          | Operational v ->
              User_store.clear_cache v.auth_store;
              Key_store.clear_cache v.key_store;
              Namespace_store.clear_cache v.namespace_store
          | _ -> ());
          let (`Raw stop_ts) = Hsm_clock.now_raw () in
          match new_time with
          | None -> Lwt.return_ok ()
          | Some new_time -> (
              let elapsed = Ptime.diff stop_ts start_ts in
              match Ptime.add_span new_time elapsed with
              | Some ts -> set_time_offset t.kv ts
              | None ->
                  t.state <- initial_state;
                  Lwt.return
                  @@ Error
                       (Bad_request, "Invalid system time in restore request")))
  end
  (* module System *)

  let default_cache_settings =
    {
      Cached_store.cache_size = 256;
      refresh_delay_s = None;
      evict_delay_s = 1.;
    }

  let boot ?(cache_settings = default_cache_settings) ~platform
      software_update_key kv =
    Metrics.set_mem_reporter ();
    let softwareVersion =
      match version_of_string software_version with
      | Ok v -> v
      | Error (_, msg) ->
          invalid_arg ("Invalid softwareVersion, broken NetHSM " ^ msg)
    in
    let info = { Json.vendor = "Nitrokey GmbH"; product = "NetHSM" }
    and device_key = Base64.decode_exn platform.Json.deviceKey
    and system_info =
      {
        Json.softwareVersion;
        softwareBuild = build_tag;
        firmwareVersion = platform.firmwareVersion;
        hardwareVersion = platform.hardwareVersion;
        deviceId = platform.deviceId;
        akPub = platform.akPub;
        pcr = platform.pcr;
      }
    and has_changes = None
    and mbox = Lwt_mvar.create_empty ()
    and res_mbox = Lwt_mvar.create_empty () in
    let open Lwt.Infix in
    (let open Lwt_result.Infix in
     lwt_error_to_msg ~pp_error:Config_store.pp_error
       (Config_store.get_opt kv Version)
     >>= function
     | None ->
         (* uninitialized / unprovisioned device *)
         let priv = X509.Private_key.generate `P256 in
         let state = Unprovisioned
         and cert, key = generate_cert priv
         and chain = [] in
         let t =
           {
             state;
             has_changes;
             key;
             cert;
             chain;
             software_update_key;
             kv;
             info;
             system_info;
             mbox;
             res_mbox;
             device_key;
             cache_settings;
           }
         in
         Lwt.return (Ok t)
     | Some version -> (
         let boot () =
           boot_config_store ~cache_settings kv device_key >>= fun state ->
           certificate_chain kv >|= fun (cert, chain, key) ->
           {
             state;
             has_changes;
             key;
             cert;
             chain;
             software_update_key;
             kv;
             info;
             system_info;
             mbox;
             res_mbox;
             device_key;
             cache_settings;
           }
         in

         match Version.(compare current version) with
         | `Equal -> boot ()
         | `Smaller ->
             let msg =
               "store has higher version than software, please update software \
                version"
             in
             Lwt.return (Error (`Msg msg))
         | `Greater ->
             (* here's the place to embed migration code, at least for the
                configuration store *)
             let msg =
               "store has smaller version than software, data will be migrated!"
             in
             Lwt.return (Error (`Msg msg))))
    >|= function
    | Ok t ->
        let dump_key_ops () =
          let rec dump () =
            Mirage_sleep.ns (Duration.of_hour 1) >>= fun () ->
            Key.dump_keys t >>= dump
          in
          dump ()
        in
        Lwt.async dump_key_ops;
        let discard_old_rate_limits () =
          let rec discard () =
            Mirage_sleep.ns (Duration.of_min 1) >>= fun () ->
            Rate_limit.discard_old_entries (now ());
            discard ()
          in
          discard ()
        in
        Lwt.async discard_old_rate_limits;
        (t, t.mbox, t.res_mbox)
    | Error (`Msg msg) ->
        Log.err (fun m -> m "error booting %s" msg);
        invalid_arg "broken NetHSM"

  let reset_rate_limit () = Rate_limit.reset_all ()
end
