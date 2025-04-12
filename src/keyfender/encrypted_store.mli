(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

(** A key-value store implementation which encrypts and authenticates its values

    This module implements a key-value store which stores values encrypted and
    authenticated with AES-GCM. An underlying key-value store is used for
    persistency. The key (path) is used as additional data in the GCM/AEAD
    construction. This means the value stored for key [a] is not a valid value
    stored for key [b] unless [a] and [b] are equal. The IV is generated at
    random. The encrypted value stored is a concatenation of the IV, the
    authentication tag, and the encrypted data. *)
module Make (KV : Kv_ext.Ranged) : sig
  include
    Kv_ext.Ranged
      with type error =
        [ Mirage_kv.error
        | `Kv of KV.error
        | `Crypto of Crypto.decrypt_error
        | `Invalid_key of KV.key ]
       and type write_error =
        [ Mirage_kv.write_error
        | `Kv of KV.write_error
        | `Invalid_key of KV.key ]

  type slot = Authentication | Key | Namespace

  val pp_slot : slot Fmt.t
  val slot_to_string : slot -> string

  val initialize :
    Version.t -> slot -> key:string -> KV.t -> (t, KV.write_error) result Lwt.t
  (** [initialize version typ ~key kv] initializes the store, using [kv] as
      persistent storage, [typ] is the prefix for all keys read and written to
      [kv], and [key] is the symmetric secret for encryption and decryption. The
      version is written encrypted and authenticated to the store. *)

  val v : slot -> key:string -> KV.t -> t
  (** [v slot ~key kv] is an encrypted store. *)

  val prepare_set : t -> key -> string -> key * string
  (** [prepare_set t key value] prepares [key, value] being set in [t]. The
      returned key is the key to be used in the underlying store, and the value
      is the encrypted and authenticated value. *)

  type connect_error =
    [ error | `Msg of string | `Version_smaller of Version.t * Version.t ]
  (** The type of connection failures. *)

  val pp_connect_error : connect_error Fmt.t
  (** [pp_connect_error ppf err] pretty-prints the connect error [err] on [ppf].
  *)

  val unlock :
    Version.t ->
    slot ->
    key:string ->
    KV.t ->
    ([ `Kv of t | `Version_greater of Version.t * t ], connect_error) result
    Lwt.t
  (** [unlock version typ ~key kv] connects to a store, using [kv] as persistent
      storage, [typ] is the prefix for all keys read and written to [kv], and
      [key] is the symmetric secret for encryption and decryption. The
      [stored_version] is read and authenticated from the store, to verify that
      the key is correct. The [stored_version] and [version] are compared. If
      they are equal [`Kv kv] is returned, if [version] is greater,
      [`Version_greater (stored, t)] is returned. An error otherwise. *)

  type version_error = [ error | `Msg of string ]

  val get_version : t -> (Version.t, version_error) Lwt_result.t
  val set_version : t -> Version.t -> (unit, KV.write_error) Lwt_result.t

  val slot_of_key : KV.key -> slot option
  (** [slot_of_key key] returns the slot in which the key resides, or None if
      it's not part of the encrypted store. [key] should be a key of the
      underlying store. *)

  val prefix_of_slot : slot -> KV.key
  (** [prefix_of_slot slot] returns the prefix used to store values of [slot] in
      the underlying store. *)
end
