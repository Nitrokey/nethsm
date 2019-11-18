module type S = sig

  type status_code =
    | Internal_server_error
    | Bad_request
    | Precondition_failed
    | Conflict

  (* string is the body, which may contain error message *)
  type error = status_code * string

  val error_to_code : status_code -> int

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
    | `Busy
  ]

  val pp_state : state Fmt.t

  val state_to_yojson : state -> Yojson.Safe.t

  type version = int * int

  type system_info = {
    firmwareVersion : string ;
    softwareVersion : version ;
    hardwareVersion : string ;
  }

  val system_info_to_yojson : system_info -> Yojson.Safe.t

  type t

  val info : t -> info

  val state : t -> state

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

    val tls_public_pem : t -> string Lwt.t

    val tls_cert_pem : t -> string Lwt.t

    val set_tls_cert_pem : t -> string ->
      (unit, error) result Lwt.t

    val tls_csr_pem : t -> Json.subject_req -> string Lwt.t

    type network = {
      ipAddress : Ipaddr.V4.t ;
      netmask : Ipaddr.V4.t ;
      gateway : Ipaddr.V4.t ;
    }

    val network_to_yojson : network -> Yojson.Safe.t

    val network_of_yojson : Yojson.Safe.t -> (network, string) result

    val network : t -> network Lwt.t

    val set_network : t -> network ->
      (unit, error) result Lwt.t

    type log = { ipAddress : Ipaddr.V4.t ; port : int ; logLevel : Logs.level }

    val log_to_yojson : log -> Yojson.Safe.t

    val log_of_yojson : Yojson.Safe.t -> (log, string) result

    val log : t -> log Lwt.t

    val set_log : t -> log -> (unit, error) result Lwt.t

    val backup_passphrase : t -> passphrase:string ->
      (unit, error) result Lwt.t

    val time : t -> Ptime.t Lwt.t

    val set_time : t -> Ptime.t -> (unit, error) result Lwt.t
  end

  module System : sig
    val system_info : t -> system_info

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
    type role = [ `Administrator | `Operator | `Metrics | `Backup ]

    val role_of_yojson : Yojson.Safe.t -> (role, string) result
    val role_to_yojson : role -> Yojson.Safe.t

    val is_authenticated : t -> username:string -> passphrase:string ->
      bool Lwt.t

    val is_authorized : t -> string -> role -> bool Lwt.t

    val list : t -> (string list, error) result Lwt.t

    val exists : t -> id:string -> (bool, error) result Lwt.t

    val get : t -> id:string -> (string * role, error) result Lwt.t

    val add : id:string -> t -> role:role -> passphrase:string ->
      name:string -> (unit, error) result Lwt.t

    val remove : t -> id:string -> (unit, error) result Lwt.t

    val set_passphrase : t -> id:string -> passphrase:string ->
      (unit, error) result Lwt.t
  end

  module Keys : sig
    type purpose = Sign | Encrypt

    val purpose_of_yojson : Yojson.Safe.t -> (purpose, string) result

    val purpose_to_yojson : purpose -> Yojson.Safe.t

    val exists : t -> id:string -> (bool, error) result Lwt.t

    val list : t -> (string list, error) result Lwt.t

    val add_json : id:string -> t -> purpose -> p:string -> q:string -> e:string ->
      (unit, error) result Lwt.t

    val add_pem : id:string -> t -> purpose -> string ->
      (unit, error) result Lwt.t

    val generate : id:string -> t -> purpose -> length:int ->
      (unit, error) result Lwt.t

    val remove : t -> id:string -> (unit, error) result Lwt.t

    type publicKey = { purpose : purpose ; algorithm : string ; modulus : string ; publicExponent : string ; operations : int }

    val publicKey_to_yojson : publicKey -> Yojson.Safe.t

    val get_json : t -> id:string -> (publicKey, error) result Lwt.t

    val get_pem : t -> id:string -> (string, error) result Lwt.t

    val csr_pem : t -> id:string -> Json.subject_req -> (string, error) result Lwt.t

    val get_cert : t -> id:string -> ((string * string) option, error) result Lwt.t

    val set_cert : t -> id:string -> content_type:string -> string -> (unit, error) result Lwt.t

    val remove_cert : t -> id:string -> (unit, error) result Lwt.t

    type decrypt_mode = Raw | PKCS1 | OAEP_MD5 | OAEP_SHA1 | OAEP_SHA224 | OAEP_SHA256 | OAEP_SHA384 | OAEP_SHA512

    val decrypt_mode_of_yojson : Yojson.Safe.t -> (decrypt_mode, string) result

    val decrypt : t -> id:string -> decrypt_mode -> string -> (string, error) result Lwt.t

    type sign_mode = PKCS1 | PSS_MD5 | PSS_SHA1 | PSS_SHA224 | PSS_SHA256 | PSS_SHA384 | PSS_SHA512

    val sign_mode_of_yojson : Yojson.Safe.t -> (sign_mode, string) result

    val sign : t -> id:string -> sign_mode -> string -> (string, error) result Lwt.t
  end
end

module Make (Rng : Mirage_random.S) (KV : Mirage_kv.RW) (Pclock : Mirage_clock.PCLOCK) : sig
  include S

  val boot : KV.t -> t Lwt.t
end
