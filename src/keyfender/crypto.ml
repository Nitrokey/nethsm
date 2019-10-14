
module GCM = Nocrypto.Cipher_block.AES.GCM

let initial_key_rsa_bits = 4096

(* parameters for PBKDF2 *)
(* TODO increase for deployment to 100_000, for testing 1000 is fine! *)
let count = 1_000
let salt_len = 16

(* key length for AES128 is 16 byte = 128 bit *)
let key_len = 16

module K = Pbkdf.Make(Nocrypto.Hash.SHA256)

let key_of_passphrase ~salt password =
  K.pbkdf2
    ~password:(Cstruct.of_string password)
    ~salt ~count ~dk_len:(Int32.of_int key_len)

(* from https://crypto.stackexchange.com/questions/5807/aes-gcm-and-its-iv-nonce-value *)
let iv_size = 12

let encrypt rng ~key ~adata data =
  (* generate an IV at random, encrypt, and concatenate IV + tag + encrypted *)
  let iv = rng iv_size in
  let { GCM.message ; tag } = GCM.encrypt ~key ~iv ~adata data in
  Cstruct.concat [ iv ; tag ; message ]

type decrypt_error = [ `Insufficient_data | `Not_authenticated ]

let decrypt ~key ~adata data =
  (* data is a cstruct (IV + tag + encrypted data)
     IV is iv_size long, tag is block_size, and data of at least block_size *)
  if Cstruct.len data < iv_size + 2 * GCM.block_size then
    Error `Insufficient_data
  else
    let iv, data' = Cstruct.split data iv_size in
    let stored_tag, data'' = Cstruct.split data' GCM.block_size in
    let { GCM.message ; tag } = GCM.decrypt ~key ~iv ~adata data'' in
    if Cstruct.equal tag stored_tag then
      Ok message
    else
      Error `Not_authenticated

let pp_decryption_error ppf e=
  Fmt.string ppf (match e with
      | `Insufficient_data -> "insufficient data"
      | `Not_authenticated -> "not authenticated")
