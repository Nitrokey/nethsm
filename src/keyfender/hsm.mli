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

    val tls_generate : t -> X509.Key_type.t -> length:int ->
      (unit, error) result Lwt.t

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

      (* tags are only specified for operators *)
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

    (* val encrypt : t -> id:string -> Json.encrypt_mode -> string -> (string, error) result Lwt.t *)

    val decrypt : t -> id:string -> user_id:string -> iv:string option -> Json.decrypt_mode -> string -> (string, error) result Lwt.t

    val encrypt : t -> id:string -> user_id:string ->iv:string option -> Json.encrypt_mode -> string -> (string * string option, error) result Lwt.t

    val sign : t -> id:string -> user_id:string -> Json.sign_mode -> string -> (string, error) result Lwt.t

    val list_digest : t -> filter_by_restrictions:bool -> string option Lwt.t

    val digest : t -> id:string -> string option Lwt.t
  end
end

module Make (Rng : Mirage_random.S) (KV : Mirage_kv.RW) (Time : Mirage_time.S) (Monotonic_clock : Mirage_clock.MCLOCK) (Clock : Hsm_clock.HSMCLOCK) : sig
  include S

  val boot : device_id:string -> Mirage_crypto_pk.Rsa.pub -> KV.t -> (t * cb Lwt_mvar.t * (unit, string) result Lwt_mvar.t) Lwt.t

  val reset_rate_limit : unit -> unit
end

val build_tag : string
val software_version : string
