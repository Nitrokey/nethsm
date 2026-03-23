(* Copyright 2024 - 2026, CrypTops SAS
   SPDX-License-Identifier: EUPL-1.2
*)

(* Post-quantum cryptography via libcrux 0.0.8 (Cryspen).
   Rust static library (liblibcrux_ocaml.a) linked through C stubs
   (pqc_stubs_libcrux.c). Based on parsimoni-labs/ocaml-libcrux,
   extended to ML-DSA-87 + ML-KEM-768 with libcrux 0.0.8. *)

(* ML-DSA-87 (FIPS 204) — Digital Signature
   pk: 2592  sk: 4896  sig: 4627 bytes *)

module ML_DSA_87 = struct
  let public_key_size  = 2592
  let secret_key_size  = 4896
  let signature_size   = 4627

  external keypair : unit -> string * string
    = "caml_ml_dsa_87_keypair"

  external sign : string -> string -> string
    = "caml_ml_dsa_87_sign"

  external verify : string -> string -> string -> bool
    = "caml_ml_dsa_87_verify"
end

(* ML-KEM-768 (FIPS 203) — Key Encapsulation
   pk: 1184  sk: 2400  ct: 1088  ss: 32 bytes *)

module ML_KEM_768 = struct
  let public_key_size    = 1184
  let secret_key_size    = 2400
  let ciphertext_size    = 1088
  let shared_secret_size = 32

  external keypair : unit -> string * string
    = "caml_ml_kem_768_keypair"

  external encaps : string -> string * string
    = "caml_ml_kem_768_encaps"

  external decaps : string -> string -> string
    = "caml_ml_kem_768_decaps"
end
