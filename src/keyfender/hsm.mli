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

  val reboot : unit -> unit

  val shutdown : unit -> unit

  val reset : unit -> unit

  val add_user : t -> role:role -> passphrase:string -> name:string ->
    (unit, [> `Msg of string ]) result Lwt.t
end

module Make (Rng : Mirage_random.C) (KV : Mirage_kv_lwt.RW) : sig
  include S
  val make : KV.t -> t Lwt.t
end
