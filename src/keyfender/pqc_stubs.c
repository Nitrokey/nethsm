/* pqc_stubs.c -- C FFI stubs for ML-DSA-87 and ML-KEM-768 via liboqs
 *
 * Copyright 2024-2026, CrypTops SAS (cryptops.fr)
 * SPDX-License-Identifier: EUPL-1.2
 *
 * Part of the AllEyes PQC project -- Post-Quantum Cryptography for NetHSM.
 */

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <string.h>
#include <oqs/oqs.h>

/* ---------- ML-DSA-87 (FIPS 204) ---------- */

CAMLprim value caml_ml_dsa_87_keypair(value unit) {
    CAMLparam1(unit);
    CAMLlocal3(pair, pk_str, sk_str);

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    if (sig == NULL)
        caml_failwith("ML-DSA-87: algorithm not available in liboqs");

    uint8_t *pk = caml_stat_alloc(sig->length_public_key);
    uint8_t *sk = caml_stat_alloc(sig->length_secret_key);

    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) {
        caml_stat_free(pk);
        caml_stat_free(sk);
        OQS_SIG_free(sig);
        caml_failwith("ML-DSA-87: keypair generation failed");
    }

    pk_str = caml_alloc_initialized_string(sig->length_public_key, (char*)pk);
    sk_str = caml_alloc_initialized_string(sig->length_secret_key, (char*)sk);

    pair = caml_alloc_tuple(2);
    Store_field(pair, 0, pk_str);
    Store_field(pair, 1, sk_str);

    caml_stat_free(pk);
    caml_stat_free(sk);
    OQS_SIG_free(sig);
    CAMLreturn(pair);
}

CAMLprim value caml_ml_dsa_87_sign(value sk_val, value msg_val) {
    CAMLparam2(sk_val, msg_val);
    CAMLlocal1(sig_str);

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    if (sig == NULL)
        caml_failwith("ML-DSA-87: algorithm not available");

    size_t sig_len = sig->length_signature;
    uint8_t *signature = caml_stat_alloc(sig_len);

    if (OQS_SIG_sign(sig, signature, &sig_len,
                      (uint8_t*)String_val(msg_val),
                      caml_string_length(msg_val),
                      (uint8_t*)String_val(sk_val)) != OQS_SUCCESS) {
        caml_stat_free(signature);
        OQS_SIG_free(sig);
        caml_failwith("ML-DSA-87: signing failed");
    }

    sig_str = caml_alloc_initialized_string(sig_len, (char*)signature);
    caml_stat_free(signature);
    OQS_SIG_free(sig);
    CAMLreturn(sig_str);
}

CAMLprim value caml_ml_dsa_87_verify(value pk_val, value msg_val,
                                      value sig_val) {
    CAMLparam3(pk_val, msg_val, sig_val);

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    if (sig == NULL)
        caml_failwith("ML-DSA-87: algorithm not available");

    OQS_STATUS rc = OQS_SIG_verify(sig,
        (uint8_t*)String_val(msg_val), caml_string_length(msg_val),
        (uint8_t*)String_val(sig_val), caml_string_length(sig_val),
        (uint8_t*)String_val(pk_val));

    OQS_SIG_free(sig);
    CAMLreturn(Val_bool(rc == OQS_SUCCESS));
}

/* ---------- ML-KEM-768 (FIPS 203) ---------- */

CAMLprim value caml_ml_kem_768_keypair(value unit) {
    CAMLparam1(unit);
    CAMLlocal3(pair, pk_str, sk_str);

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL)
        caml_failwith("ML-KEM-768: algorithm not available in liboqs");

    uint8_t *pk = caml_stat_alloc(kem->length_public_key);
    uint8_t *sk = caml_stat_alloc(kem->length_secret_key);

    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) {
        caml_stat_free(pk);
        caml_stat_free(sk);
        OQS_KEM_free(kem);
        caml_failwith("ML-KEM-768: keypair generation failed");
    }

    pk_str = caml_alloc_initialized_string(kem->length_public_key, (char*)pk);
    sk_str = caml_alloc_initialized_string(kem->length_secret_key, (char*)sk);

    pair = caml_alloc_tuple(2);
    Store_field(pair, 0, pk_str);
    Store_field(pair, 1, sk_str);

    caml_stat_free(pk);
    caml_stat_free(sk);
    OQS_KEM_free(kem);
    CAMLreturn(pair);
}

CAMLprim value caml_ml_kem_768_encaps(value pk_val) {
    CAMLparam1(pk_val);
    CAMLlocal3(pair, ct_str, ss_str);

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL)
        caml_failwith("ML-KEM-768: algorithm not available");

    uint8_t *ct = caml_stat_alloc(kem->length_ciphertext);
    uint8_t *ss = caml_stat_alloc(kem->length_shared_secret);

    if (OQS_KEM_encaps(kem, ct, ss,
                        (uint8_t*)String_val(pk_val)) != OQS_SUCCESS) {
        caml_stat_free(ct);
        caml_stat_free(ss);
        OQS_KEM_free(kem);
        caml_failwith("ML-KEM-768: encapsulation failed");
    }

    ct_str = caml_alloc_initialized_string(kem->length_ciphertext, (char*)ct);
    ss_str = caml_alloc_initialized_string(kem->length_shared_secret, (char*)ss);

    pair = caml_alloc_tuple(2);
    Store_field(pair, 0, ct_str);
    Store_field(pair, 1, ss_str);

    caml_stat_free(ct);
    caml_stat_free(ss);
    OQS_KEM_free(kem);
    CAMLreturn(pair);
}

CAMLprim value caml_ml_kem_768_decaps(value sk_val, value ct_val) {
    CAMLparam2(sk_val, ct_val);
    CAMLlocal1(ss_str);

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL)
        caml_failwith("ML-KEM-768: algorithm not available");

    uint8_t *ss = caml_stat_alloc(kem->length_shared_secret);

    if (OQS_KEM_decaps(kem, ss,
                        (uint8_t*)String_val(ct_val),
                        (uint8_t*)String_val(sk_val)) != OQS_SUCCESS) {
        caml_stat_free(ss);
        OQS_KEM_free(kem);
        caml_failwith("ML-KEM-768: decapsulation failed");
    }

    ss_str = caml_alloc_initialized_string(kem->length_shared_secret, (char*)ss);
    caml_stat_free(ss);
    OQS_KEM_free(kem);
    CAMLreturn(ss_str);
}
