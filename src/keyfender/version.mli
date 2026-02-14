(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

(** Each store has its version that is persisted in the store, in a location
    that must not change:
    - config store : Version slot
    - other encrypted stores : .version file

    At boot or restore, the stored version number of any store is compared
    against the current version number for that store. These current version
    number can evolve independently and are immutable values in the software
    (see Current module).

    The semantics of each version number change must be documented here. *)

type t = V0 | V1  (** V1: move to device-specific config/domain key slots *)

val compare : t -> t -> [ `Smaller | `Equal | `Greater ]
val to_string : t -> string
val of_string : string -> (t, [> `Msg of string ]) result
val pp : t Fmt.t
val file : string
val filename : Mirage_kv.Key.t

module Current : sig
  val config_and_domain_store : t
  val authentication_store : t
  val key_store : t
  val namespace_store : t
end
