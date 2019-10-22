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

  val state : t -> state

  val certificate_chain : t ->
    (X509.Certificate.t * X509.Certificate.t list * X509.Private_key.t) Lwt.t

  val network_configuration : t ->
    (Ipaddr.V4.t * Ipaddr.V4.Prefix.t * Ipaddr.V4.t option) Lwt.t

  val provision : t -> unlock:string -> admin:string -> Ptime.t ->
    (unit, [> `Msg of string ]) result Lwt.t

  val unlock : t -> passphrase:string ->
    (unit, [> `Msg of string ]) result Lwt.t

  module Config : sig
    val change_unlock_passphrase : t -> passphrase:string ->
      (unit, [> `Msg of string ]) result Lwt.t

    val unattended_boot : unit -> unit

    val tls_public_pem : t -> string Lwt.t

    val tls_cert_pem : t -> string Lwt.t

    val change_tls_cert_pem : t -> string ->
      (unit, [> `Msg of string ]) result Lwt.t

    val tls_csr_pem : t -> string Lwt.t

    type network = {
      ipAddress : Ipaddr.V4.t ;
      netmask : Ipaddr.V4.t ;
      gateway : Ipaddr.V4.t ;
    }

    val network_to_yojson : network -> Yojson.Safe.t

    val network_of_yojson : Yojson.Safe.t -> (network, string) result

    val network : t -> network Lwt.t

    val change_network : t -> network ->
      (unit, [> `Msg of string ]) result Lwt.t

    val logging : unit -> unit

    val backup_passphrase : unit -> unit

    val time : unit -> unit
  end

  module System : sig
    val system_info : t -> system_info

    val reboot : unit -> unit

    val shutdown : unit -> unit

    val reset : t -> unit

    val update : unit -> unit

    val backup : unit -> unit

    val restore : unit -> unit
  end

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

module Make (Rng : Mirage_random.C) (KV : Mirage_kv_lwt.RW) : sig
  include S

  val make : KV.t -> t Lwt.t
end
