(** A key-value store implementation which encrypts and authenticates its values

    This module implements a key-value store which stores values encrypted and
    authenticated with AES-GCM. An underlying key-value store is used for
    persistency. The key (path) is used as additional data in the GCM/AEAD
    construction. This means the value stored for key [a] is not a valid value
    stored for key [b] unless [a] and [b] are equal. The IV is generated at
    random. The encrypted value stored is a concatenation of the IV, the
    authentication tag, and the encrypted data. *)
module Make (R : Mirage_random.C) (KV : Mirage_kv_lwt.RW) : sig
  include Mirage_kv_lwt.RW
    with type error = [
        | Mirage_kv.error
        | `Kv of KV.error
        | `Crypto of Crypto.decrypt_error
      ]

  val connect : ?init:bool -> [ `Authentication | `Key ] -> key:Cstruct.t ->
    KV.t -> (t, [ `Msg of string ]) result Lwt.t
  (** [connect ~init typ ~key kv] connects to a store, using [kv] as persistent
      storage, [typ] is the prefix for all keys read and written to [kv],
      and [key] is the symmetric secret for encryption and decryption. If [init]
      is provided and [true] (defaults to [false]), a stub file is written.
      Otherwise, this stub file is read to verify that the key is appropriate.
 *)
end
