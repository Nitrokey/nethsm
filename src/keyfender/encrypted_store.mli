(** A key-value store implementation which encrypts and authenticates its values

    This module implements a key-value store which stores values encrypted and
    authenticated with AES-GCM. An underlying key-value store is used for
    persistency. The key (path) is used as additional data in the GCM/AEAD
    construction. This means the value stored for key [a] is not a valid value
    stored for key [b] unless [a] and [b] are equal. The IV is generated at
    random. The encrypted value stored is a concatenation of the IV, the
    authentication tag, and the encrypted data. *)
module Make (R : Mirage_random.S) (KV : Mirage_kv.RW) : sig
  include Mirage_kv.RW
    with type error = [
        | Mirage_kv.error
        | `Kv of KV.error
        | `Crypto of Crypto.decrypt_error
      ]

  type slot = Authentication | Key

  val pp_slot : slot Fmt.t

  val slot_to_string : slot -> string

  val initialize : Version.t -> slot ->
    key:Cstruct.t -> KV.t -> (t, write_error) result Lwt.t
  (** [initialize version typ ~key kv] initializes the store, using [kv] as
      persistent storage, [typ] is the prefix for all keys read and written to
      [kv], and [key] is the symmetric secret for encryption and decryption. The
      version is written encrypted and authenticated to the store. *)

  val v : slot -> key:Cstruct.t -> KV.t -> t
  (** [v slot ~key kv] is an encrypted store. *)

  val prepare_set : t -> key -> string -> key * string
  (** [prepare_set t key value] prepares [key, value] being set in [t]. The
      returned key is the key to be used in the underlying store, and the value
      is the encrypted and authenticated value. *)

  type connect_error =
    [ error | `Msg of string | `Version_smaller of Version.t * Version.t ]
  (** The type of connection failures. *)

  val pp_connect_error : connect_error Fmt.t
  (** [pp_connect_error ppf err] pretty-prints the connect error [err] on [ppf]. *)

  val unlock : Version.t -> slot ->
    key:Cstruct.t -> KV.t ->
    ([ `Kv of t | `Version_greater of Version.t * t ], connect_error) result Lwt.t
  (** [unlock version typ ~key kv] connects to a store, using [kv] as
      persistent storage, [typ] is the prefix for all keys read and written to
      [kv], and [key] is the symmetric secret for encryption and decryption. The
      [stored_version] is read and authenticated from the store, to verify that
      the key is correct. The [stored_version] and [version] are compared. If
      they are equal [`Kv kv] is returned, if [version] is greater,
      [`Version_greater (stored, t)] is returned. An error otherwise. *)

end
