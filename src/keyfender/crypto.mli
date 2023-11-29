(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

val salt_len : int
(** The length of the salt used in password derivation, in bytes. *)

val key_len : int
(** The length of the symmetric key, in bytes. *)

module GCM : Mirage_crypto.Cipher_block.S.GCM

val key_of_passphrase : salt:Cstruct.t -> string -> Cstruct.t
(** Derive a symmetric key from a passphrase, using SCRYPT. *)

val set_test_params : unit -> unit
(** Sets the scrypt parameters. (for tests only) *)

val passphrase_salt_len : int
(** The length of the salt used for storing the passphrase. *)

val stored_passphrase : salt:Cstruct.t -> Cstruct.t -> Cstruct.t
(** Computes the stored passphrase from a salt and plain passphrase. *)

val encrypt :
  (int -> Cstruct.t) -> key:GCM.key -> adata:Cstruct.t -> Cstruct.t -> Cstruct.t
(** [encrypt rng ~key ~adata data] encrypts [data] using AES-GCM with the
    provided [key] and additional data [adata]. The [rng] is used to generate
    the nonce. The result is a concatenation of nonce, tag, encrypted data. *)

type decrypt_error = [ `Insufficient_data | `Not_authenticated ]
(** The type of decryption errors. *)

val pp_decryption_error : decrypt_error Fmt.t
(** [pp_decryption_error ppf de] pretty-prints the decryption error [de] on
    [ppf]. *)

val decrypt :
  key:GCM.key ->
  adata:Cstruct.t ->
  Cstruct.t ->
  (Cstruct.t, decrypt_error) result
(** [decrypt ~key ~adata data] attempts to decrypt [data], which is a
    concatenation of nonce, tag, encrypted data. The [key] and [adata] are used
    for decryption. *)
