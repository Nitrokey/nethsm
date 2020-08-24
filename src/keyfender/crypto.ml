
module GCM = Mirage_crypto.Cipher_block.AES.GCM

let initial_key_rsa_bits = 1024 (* TODO increase for deployment *)

(* parameters for PBKDF2 *)
(* TODO increase for deployment to 100_000, for testing 1000 is fine! *)
let count = 1_000
let salt_len = 16

(* key length for AES256 is 32 byte = 256 bit *)
let key_len = 32

(* TODO before deploying, insert an appropriate RSA key *)
let software_update_key =
  {|-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx7ghfro+VEepYmy2V7HP
n5PSRdmGzxewcpmzxTtrZ10BygbEqhPsAr4fWI9pG7iRXzeza7DMjrQptzKsfSy6
dBFmSEZer+hJxuOdhBG/FX6pjwRrZpbOQxyr+aTlE3jm2XP12Cqx0wsYGIoJlWHb
Gb90IAx9zpdYQgHoJZ4x5ims5vo7h3puPEyVycJH5fMBB9h+2Bxc4BxaPKMm15JR
1B7ToB3g16SJY2B1t/aqNmqSBZC4HP1fCuSbBm83OgqRhdk1P6r/vqOVKrxVupDq
Kkdcf/dRBiQalJ9tQbVbs9OOYfQ6n25GvJTvGtqOEuggit32tV16JXCZjnYePAvt
NwIDAQAB
-----END PUBLIC KEY-----
|} |> Cstruct.of_string


module K = Pbkdf.Make(Mirage_crypto.Hash.SHA256)

let key_of_passphrase ~salt password =
  K.pbkdf2
    ~password:(Cstruct.of_string password)
    ~salt ~count ~dk_len:(Int32.of_int key_len)

(* from https://crypto.stackexchange.com/questions/5807/aes-gcm-and-its-iv-nonce-value *)
let iv_size = 12

let encrypt rng ~key ~adata data =
  (* generate an nonce at random, encrypt, and concatenate nonce + encrypted + tag *)
  let nonce = rng iv_size in
  let cipher = GCM.authenticate_encrypt ~key ~nonce ~adata data in
  Cstruct.append nonce cipher

type decrypt_error = [ `Insufficient_data | `Not_authenticated ]

let decrypt ~key ~adata data =
  (* data is a cstruct (IV + encrypted data + tag)
     IV is iv_size long, tag is block_size, and data of at least one byte *)
  if Cstruct.len data <= iv_size + GCM.tag_size then
    Error `Insufficient_data
  else
    let nonce, data' = Cstruct.split data iv_size in
    match GCM.authenticate_decrypt ~key ~nonce ~adata data' with
    | None -> Error `Not_authenticated
    | Some msg -> Ok msg

let pp_decryption_error ppf e=
  Fmt.string ppf (match e with
      | `Insufficient_data -> "insufficient data"
      | `Not_authenticated -> "not authenticated")
