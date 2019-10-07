(** A KV implementation which encrypts their values

    This module implements a key-value store which stores values encrypted and
    authenticated with AES-GCM. An underlying key-value store is used for
    persistency. The key (path) is used as additional data in the GCM/AEAD
    construction. This means the value stored for key [a] is not a valid value
    stored for key [b] unless [a] and [b] are equal. The IV is generated at
    random. The encrypted value stored is a triple containing the IV, the
    authentication tag, and the encrypted data. *)
module Make (R : Mirage_random.C) (KV : Mirage_kv_lwt.RW) : sig
  include Mirage_kv_lwt.RW

  val connect : [ `Authentication | `Key ] -> key:Cstruct.t -> KV.t -> t
  (** [connect typ ~key kv] initializes a store, using [kv] as persistent
      storage, [typ] is the prefix for all keys read and written to [kv],
      and [key] is the symmetric secret for encryption and decryption. *)
end
