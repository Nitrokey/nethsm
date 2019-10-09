val key_len : int

module GCM : Nocrypto.Cipher_block.S.GCM

val key_of_passphrase : salt:Cstruct.t -> string -> Cstruct.t

val encrypt : (int -> Cstruct.t) -> key:GCM.key -> adata:Cstruct.t ->
  Cstruct.t -> Cstruct.t

type decrypt_error = [ `Insufficient_data | `Not_authenticated ]

val decrypt : key:GCM.key -> adata:Cstruct.t -> Cstruct.t ->
  (Cstruct.t, decrypt_error) result

val pp_decryption_error : decrypt_error Fmt.t
