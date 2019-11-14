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

    type user = { name : string ; salt : string ; digest : string ; role : role }

    val user_of_yojson : Yojson.Safe.t -> (user, string) result

    val is_authenticated : t -> username:string -> passphrase:string ->
      bool Lwt.t

    val is_authorized : t -> string -> role -> bool Lwt.t

    val list : t -> (string list, error) result Lwt.t

    val exists : t -> string -> (bool, error) result Lwt.t

    val get : t -> string -> (user, error) result Lwt.t

    val add : ?id:string -> t -> role:role -> passphrase:string ->
      name:string -> (unit, error) result Lwt.t

    val remove : t -> string -> (unit, error) result Lwt.t

    val set_passphrase : t -> id:string -> passphrase:string ->
      (unit, error) result Lwt.t
  end
end

module Make (Rng : Mirage_random.C) (KV : Mirage_kv_lwt.RW) (Pclock : Mirage_clock.PCLOCK) : sig
  include S

  val boot : KV.t -> t Lwt.t
end
