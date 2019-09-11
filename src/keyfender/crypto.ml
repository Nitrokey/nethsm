
let count = 1000
let key_len = 16

module K = Pbkdf.Make(Nocrypto.Hash.SHA256)

let key_of_passphrase ~salt password =
  K.pbkdf2
    ~password:(Cstruct.of_string password)
    ~salt ~count ~dk_len:(Int32.of_int key_len)

module GCM = Nocrypto.Cipher_block.AES.GCM

let dk_adata = Cstruct.of_string "domain key"

let iv_size = 12

let decrypt_domain_key ~unlock_key data =
  (* data is a single cstruct, representing (nonce/iv, tag, enc data) *)
  if Cstruct.len data < 16 + iv_size + GCM.block_size then
    Error (`Msg "data too small")
  else
    let iv, data' = Cstruct.split data iv_size in
    let ctag, data'' = Cstruct.split data' 16 in
    let { GCM.message ; tag } =
      GCM.decrypt ~key:(GCM.of_secret unlock_key) ~iv ~adata:dk_adata data''
    in
    if Cstruct.equal tag ctag then
      Ok message
    else
      Error (`Msg "not authenticated")

let encrypt_domain_key rng ~unlock_key data =
  let iv = rng iv_size in
  let { GCM.message ; tag } =
    GCM.encrypt ~key:(GCM.of_secret unlock_key) ~iv ~adata:dk_adata data
  in
  Cstruct.concat [ iv ; tag ; message ]

