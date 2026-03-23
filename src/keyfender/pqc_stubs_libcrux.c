/* Copyright 2024 - 2026, CrypTops SAS
   SPDX-License-Identifier: EUPL-1.2
*/

/* OCaml C stubs for libcrux 0.0.8 (Cryspen).
   Bridges OCaml GC with Rust FFI (liblibcrux_ocaml.a). */

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <string.h>
#include <stdint.h>

/* FIPS 204 / FIPS 203 sizes */
#define MLDSA87_PK_SIZE  2592
#define MLDSA87_SK_SIZE  4896
#define MLDSA87_SIG_SIZE 4627
#define MLKEM768_PK_SIZE 1184
#define MLKEM768_SK_SIZE 2400
#define MLKEM768_CT_SIZE 1088
#define MLKEM768_SS_SIZE 32

/* Rust FFI (liblibcrux_ocaml.a) */
extern int libcrux_ml_dsa_87_keypair(uint8_t *pk_out, uint8_t *sk_out);
extern int libcrux_ml_dsa_87_sign(const uint8_t *sk, const uint8_t *msg,
                                   size_t msg_len, uint8_t *sig_out,
                                   size_t *sig_len);
extern int libcrux_ml_dsa_87_verify(const uint8_t *pk, const uint8_t *msg,
                                     size_t msg_len, const uint8_t *sig,
                                     size_t sig_len);
extern int libcrux_ml_kem_768_keypair(uint8_t *pk_out, uint8_t *sk_out);
extern int libcrux_ml_kem_768_encaps(const uint8_t *pk, uint8_t *ct_out,
                                      uint8_t *ss_out);
extern int libcrux_ml_kem_768_decaps(const uint8_t *sk, const uint8_t *ct,
                                      uint8_t *ss_out);

/* ML-DSA-87 */

CAMLprim value caml_ml_dsa_87_keypair(value unit) {
    CAMLparam1(unit);
    CAMLlocal3(pair, pk_str, sk_str);

    uint8_t *pk = caml_stat_alloc(MLDSA87_PK_SIZE);
    uint8_t *sk = caml_stat_alloc(MLDSA87_SK_SIZE);

    if (libcrux_ml_dsa_87_keypair(pk, sk) != 0) {
        caml_stat_free(pk);
        caml_stat_free(sk);
        caml_failwith("ML-DSA-87: keypair generation failed");
    }

    pk_str = caml_alloc_initialized_string(MLDSA87_PK_SIZE, (char*)pk);
    sk_str = caml_alloc_initialized_string(MLDSA87_SK_SIZE, (char*)sk);

    pair = caml_alloc_tuple(2);
    Store_field(pair, 0, pk_str);
    Store_field(pair, 1, sk_str);

    caml_stat_free(pk);
    caml_stat_free(sk);
    CAMLreturn(pair);
}

CAMLprim value caml_ml_dsa_87_sign(value sk_val, value msg_val) {
    CAMLparam2(sk_val, msg_val);
    CAMLlocal1(sig_str);

    size_t sig_len = MLDSA87_SIG_SIZE;
    uint8_t *signature = caml_stat_alloc(MLDSA87_SIG_SIZE);

    if (libcrux_ml_dsa_87_sign(
            (uint8_t*)String_val(sk_val),
            (uint8_t*)String_val(msg_val),
            caml_string_length(msg_val),
            signature,
            &sig_len) != 0) {
        caml_stat_free(signature);
        caml_failwith("ML-DSA-87: signing failed");
    }

    sig_str = caml_alloc_initialized_string(sig_len, (char*)signature);
    caml_stat_free(signature);
    CAMLreturn(sig_str);
}

CAMLprim value caml_ml_dsa_87_verify(value pk_val, value msg_val,
                                      value sig_val) {
    CAMLparam3(pk_val, msg_val, sig_val);

    int rc = libcrux_ml_dsa_87_verify(
        (uint8_t*)String_val(pk_val),
        (uint8_t*)String_val(msg_val),
        caml_string_length(msg_val),
        (uint8_t*)String_val(sig_val),
        caml_string_length(sig_val));

    if (rc < 0)
        caml_failwith("ML-DSA-87: verify error");

    CAMLreturn(Val_bool(rc == 1));
}

/* ML-KEM-768 */

CAMLprim value caml_ml_kem_768_keypair(value unit) {
    CAMLparam1(unit);
    CAMLlocal3(pair, pk_str, sk_str);

    uint8_t *pk = caml_stat_alloc(MLKEM768_PK_SIZE);
    uint8_t *sk = caml_stat_alloc(MLKEM768_SK_SIZE);

    if (libcrux_ml_kem_768_keypair(pk, sk) != 0) {
        caml_stat_free(pk);
        caml_stat_free(sk);
        caml_failwith("ML-KEM-768: keypair generation failed");
    }

    pk_str = caml_alloc_initialized_string(MLKEM768_PK_SIZE, (char*)pk);
    sk_str = caml_alloc_initialized_string(MLKEM768_SK_SIZE, (char*)sk);

    pair = caml_alloc_tuple(2);
    Store_field(pair, 0, pk_str);
    Store_field(pair, 1, sk_str);

    caml_stat_free(pk);
    caml_stat_free(sk);
    CAMLreturn(pair);
}

CAMLprim value caml_ml_kem_768_encaps(value pk_val) {
    CAMLparam1(pk_val);
    CAMLlocal3(pair, ct_str, ss_str);

    uint8_t *ct = caml_stat_alloc(MLKEM768_CT_SIZE);
    uint8_t *ss = caml_stat_alloc(MLKEM768_SS_SIZE);

    if (libcrux_ml_kem_768_encaps(
            (uint8_t*)String_val(pk_val), ct, ss) != 0) {
        caml_stat_free(ct);
        caml_stat_free(ss);
        caml_failwith("ML-KEM-768: encapsulation failed");
    }

    ct_str = caml_alloc_initialized_string(MLKEM768_CT_SIZE, (char*)ct);
    ss_str = caml_alloc_initialized_string(MLKEM768_SS_SIZE, (char*)ss);

    pair = caml_alloc_tuple(2);
    Store_field(pair, 0, ct_str);
    Store_field(pair, 1, ss_str);

    caml_stat_free(ct);
    caml_stat_free(ss);
    CAMLreturn(pair);
}

CAMLprim value caml_ml_kem_768_decaps(value sk_val, value ct_val) {
    CAMLparam2(sk_val, ct_val);
    CAMLlocal1(ss_str);

    uint8_t *ss = caml_stat_alloc(MLKEM768_SS_SIZE);

    if (libcrux_ml_kem_768_decaps(
            (uint8_t*)String_val(sk_val),
            (uint8_t*)String_val(ct_val),
            ss) != 0) {
        caml_stat_free(ss);
        caml_failwith("ML-KEM-768: decapsulation failed");
    }

    ss_str = caml_alloc_initialized_string(MLKEM768_SS_SIZE, (char*)ss);
    caml_stat_free(ss);
    CAMLreturn(ss_str);
}
