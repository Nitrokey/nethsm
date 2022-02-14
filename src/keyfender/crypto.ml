
module GCM = Mirage_crypto.Cipher_block.AES.GCM

(* parameters for scrypt-kdf from https://blog.filippo.io/the-scrypt-parameters/ *)
let scrypt_n = 16384
let scrypt_r = 8
let scrypt_p = 1
let salt_len = 16

(* key length for AES256 is 32 byte = 256 bit *)
let key_len = 32

let software_update_key =
  match X509.Public_key.decode_pem ([%blob "update.pem"] |> Cstruct.of_string) with
  | Ok `RSA key -> key
  | Ok _ -> invalid_arg "No RSA key from manufacturer. Contact manufacturer."
  | Error `Msg m -> invalid_arg m

let key_of_passphrase ~salt password =
  Scrypt_kdf.scrypt_kdf
    ~password:(Cstruct.of_string password)
    ~salt ~n:scrypt_n ~r:scrypt_r ~p:scrypt_p ~dk_len:(Int32.of_int key_len)

let passphrase_salt_len = 16

let stored_passphrase ~salt plain =
  Mirage_crypto.Hash.SHA256.hmac ~key:salt plain

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
  if Cstruct.length data <= iv_size + GCM.tag_size then
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
