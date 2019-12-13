module type S = sig

  val now : unit -> Ptime.t

  type status_code =
    | Internal_server_error
    | Bad_request
    | Precondition_failed
    | Conflict

  (* string is the body, which may contain error message *)
  type error = status_code * string

  val error_to_code : status_code -> int

  val pp_state : Json.state Fmt.t

  type t

  val equal : t -> t -> bool Lwt.t

  val info : t -> Json.info

  val state : t -> Json.state

  val lock : t -> unit

  val certificate_chain : t ->
    (X509.Certificate.t * X509.Certificate.t list * X509.Private_key.t) Lwt.t

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

    val reboot : t -> unit

    val shutdown : t -> unit

    val reset : t -> (unit, error) result Lwt.t

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

    val add_json : id:string -> t -> Json.purpose -> p:string -> q:string -> e:string ->
      (unit, error) result Lwt.t

    val add_pem : id:string -> t -> Json.purpose -> string ->
      (unit, error) result Lwt.t

    val generate : id:string -> t -> Json.purpose -> length:int ->
      (unit, error) result Lwt.t

    val remove : t -> id:string -> (unit, error) result Lwt.t

    val get_json : t -> id:string -> (Json.publicKey, error) result Lwt.t

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

module Make (Rng : Mirage_random.S) (KV : Mirage_kv.RW) (Clock : Hsm_clock.HSMCLOCK) : sig
  include S

  val boot : KV.t -> t Lwt.t
end
