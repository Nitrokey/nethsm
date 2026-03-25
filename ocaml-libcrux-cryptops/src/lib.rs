// =============================================================================
// libcrux-ocaml — C-callable Rust functions for ML-DSA-87 + ML-KEM-768
//
// These functions are called from OCaml via C stubs (pqc_stubs_libcrux.c).
// The C stubs handle OCaml GC (CAMLparam/CAMLreturn), this code does pure crypto.
//
// Backend: libcrux 0.0.8 (Cryspen, formally verified F*, INRIA)
// Algorithms: ML-DSA-87 (FIPS 204), ML-KEM-768 (FIPS 203)
//
// Copyright 2024-2026, CrypTops SAS (cryptops.fr)
// SPDX-License-Identifier: EUPL-1.2
// =============================================================================

use libcrux_ml_dsa::ml_dsa_87;
use libcrux_ml_kem::mlkem768;

// ML-DSA-87 sizes (FIPS 204)
pub const MLDSA87_PK_SIZE: usize = 2592;
pub const MLDSA87_SK_SIZE: usize = 4896;
pub const MLDSA87_SIG_SIZE: usize = 4627;
const MLDSA87_KEYGEN_RAND: usize = 32;
const MLDSA87_SIGN_RAND: usize = 32;

// ML-KEM-768 sizes (FIPS 203)
pub const MLKEM768_PK_SIZE: usize = 1184;
pub const MLKEM768_SK_SIZE: usize = 2400;
pub const MLKEM768_CT_SIZE: usize = 1088;
pub const MLKEM768_SS_SIZE: usize = 32;
const MLKEM768_KEYGEN_RAND: usize = 64;
const MLKEM768_ENCAPS_RAND: usize = 32;

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("OS RNG failure");
    buf
}

// ---------- ML-DSA-87 (FIPS 204) ----------

/// Generate ML-DSA-87 keypair.
/// Writes public key to `pk_out` (2592 bytes) and secret key to `sk_out` (4896 bytes).
/// Returns 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn libcrux_ml_dsa_87_keypair(pk_out: *mut u8, sk_out: *mut u8) -> i32 {
    if pk_out.is_null() || sk_out.is_null() {
        return -1;
    }
    let randomness: [u8; MLDSA87_KEYGEN_RAND] = random_bytes();
    let kp = ml_dsa_87::generate_key_pair(randomness);

    unsafe {
        core::ptr::copy_nonoverlapping(
            kp.verification_key.as_ref().as_ptr(),
            pk_out,
            MLDSA87_PK_SIZE,
        );
        core::ptr::copy_nonoverlapping(
            kp.signing_key.as_ref().as_ptr(),
            sk_out,
            MLDSA87_SK_SIZE,
        );
    }
    0
}

/// Sign a message with ML-DSA-87.
/// `sk` must point to 4896 bytes. `msg` + `msg_len` is the message.
/// Writes signature to `sig_out` (4627 bytes). `sig_len` receives actual length.
/// Returns 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn libcrux_ml_dsa_87_sign(
    sk: *const u8,
    msg: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
    sig_len: *mut usize,
) -> i32 {
    if sk.is_null() || msg.is_null() || sig_out.is_null() || sig_len.is_null() {
        return -1;
    }
    let sk_slice = unsafe { core::slice::from_raw_parts(sk, MLDSA87_SK_SIZE) };
    let msg_slice = unsafe { core::slice::from_raw_parts(msg, msg_len) };

    let mut sk_array = [0u8; MLDSA87_SK_SIZE];
    sk_array.copy_from_slice(sk_slice);
    let signing_key = ml_dsa_87::MLDSA87SigningKey::new(sk_array);
    let randomness: [u8; MLDSA87_SIGN_RAND] = random_bytes();

    match ml_dsa_87::sign(&signing_key, msg_slice, b"", randomness) {
        Ok(sig) => {
            let sig_bytes = sig.as_ref();
            unsafe {
                core::ptr::copy_nonoverlapping(sig_bytes.as_ptr(), sig_out, sig_bytes.len());
                *sig_len = sig_bytes.len();
            }
            0
        }
        Err(_) => -1,
    }
}

/// Verify a ML-DSA-87 signature.
/// Returns 1 if valid, 0 if invalid, -1 on error.
#[no_mangle]
pub extern "C" fn libcrux_ml_dsa_87_verify(
    pk: *const u8,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> i32 {
    if pk.is_null() || msg.is_null() || sig.is_null() {
        return -1;
    }
    if sig_len != MLDSA87_SIG_SIZE {
        return -1;
    }
    let pk_slice = unsafe { core::slice::from_raw_parts(pk, MLDSA87_PK_SIZE) };
    let msg_slice = unsafe { core::slice::from_raw_parts(msg, msg_len) };
    let sig_slice = unsafe { core::slice::from_raw_parts(sig, MLDSA87_SIG_SIZE) };

    let mut pk_array = [0u8; MLDSA87_PK_SIZE];
    pk_array.copy_from_slice(pk_slice);
    let vk = ml_dsa_87::MLDSA87VerificationKey::new(pk_array);

    let mut sig_array = [0u8; MLDSA87_SIG_SIZE];
    sig_array.copy_from_slice(sig_slice);
    let signature = ml_dsa_87::MLDSA87Signature::new(sig_array);

    match ml_dsa_87::verify(&vk, msg_slice, b"", &signature) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}

// ---------- ML-KEM-768 (FIPS 203) ----------

/// Generate ML-KEM-768 keypair.
/// Writes public key to `pk_out` (1184 bytes) and secret key to `sk_out` (2400 bytes).
/// Returns 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn libcrux_ml_kem_768_keypair(pk_out: *mut u8, sk_out: *mut u8) -> i32 {
    if pk_out.is_null() || sk_out.is_null() {
        return -1;
    }
    let randomness: [u8; MLKEM768_KEYGEN_RAND] = random_bytes();
    let kp = mlkem768::generate_key_pair(randomness);

    unsafe {
        core::ptr::copy_nonoverlapping(kp.pk().as_ref().as_ptr(), pk_out, MLKEM768_PK_SIZE);
        core::ptr::copy_nonoverlapping(kp.sk().as_ref().as_ptr(), sk_out, MLKEM768_SK_SIZE);
    }
    0
}

/// Encapsulate with ML-KEM-768.
/// `pk` must point to 1184 bytes.
/// Writes ciphertext to `ct_out` (1088 bytes) and shared secret to `ss_out` (32 bytes).
/// Returns 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn libcrux_ml_kem_768_encaps(
    pk: *const u8,
    ct_out: *mut u8,
    ss_out: *mut u8,
) -> i32 {
    if pk.is_null() || ct_out.is_null() || ss_out.is_null() {
        return -1;
    }
    let pk_slice = unsafe { core::slice::from_raw_parts(pk, MLKEM768_PK_SIZE) };
    let mlkem_pk = match libcrux_ml_kem::MlKemPublicKey::try_from(pk_slice) {
        Ok(pk) => pk,
        Err(_) => return -1,
    };
    let randomness: [u8; MLKEM768_ENCAPS_RAND] = random_bytes();

    let (ct, ss) = mlkem768::encapsulate(&mlkem_pk, randomness);
    unsafe {
        core::ptr::copy_nonoverlapping(ct.as_ref().as_ptr(), ct_out, MLKEM768_CT_SIZE);
        core::ptr::copy_nonoverlapping(ss.as_ref().as_ptr(), ss_out, MLKEM768_SS_SIZE);
    }
    0
}

/// Decapsulate with ML-KEM-768.
/// `sk` must point to 2400 bytes, `ct` to 1088 bytes.
/// Writes shared secret to `ss_out` (32 bytes).
/// Returns 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn libcrux_ml_kem_768_decaps(
    sk: *const u8,
    ct: *const u8,
    ss_out: *mut u8,
) -> i32 {
    if sk.is_null() || ct.is_null() || ss_out.is_null() {
        return -1;
    }
    let sk_slice = unsafe { core::slice::from_raw_parts(sk, MLKEM768_SK_SIZE) };
    let ct_slice = unsafe { core::slice::from_raw_parts(ct, MLKEM768_CT_SIZE) };

    let mlkem_sk = match libcrux_ml_kem::MlKemPrivateKey::try_from(sk_slice) {
        Ok(sk) => sk,
        Err(_) => return -1,
    };
    let mlkem_ct = match libcrux_ml_kem::MlKemCiphertext::try_from(ct_slice) {
        Ok(ct) => ct,
        Err(_) => return -1,
    };

    let ss = mlkem768::decapsulate(&mlkem_sk, &mlkem_ct);
    unsafe {
        core::ptr::copy_nonoverlapping(ss.as_ref().as_ptr(), ss_out, MLKEM768_SS_SIZE);
    }
    0
}
