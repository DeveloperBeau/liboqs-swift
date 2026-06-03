/**
 * \file oqs_safe.h
 * \brief Bounds-safe inline wrappers over the liboqs buffer functions.
 *
 * This is an ADDITIVE header — it is NOT part of upstream liboqs and does not
 * modify any vendored liboqs header. Each wrapper forwards verbatim to the real
 * OQS function; the only addition is `__sized_by(...)` annotations (from
 * <ptrcheck.h>) on the byte-buffer pointer parameters. Under Swift's
 * `SafeInteropWrappers` experimental feature the ClangImporter uses those
 * annotations to synthesize SAFE OVERLOADS that take
 * `Unsafe[Mutable]BufferPointer<UInt8>` (length inferred) instead of a raw
 * pointer + separate length argument, letting the Swift FFI layer drop the
 * manual `baseAddress?.assumingMemoryBound(to:)` bridging.
 *
 * The length parameters exist solely to give Swift the bounds; the wrappers
 * cast them to void and forward only the original arguments. Callers allocate
 * each output buffer to the algorithm's `length_*` size and pass that as the
 * matching length.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef OQS_SAFE_H
#define OQS_SAFE_H

#include <ptrcheck.h>
#include <oqs/oqs.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* ---- KEM ------------------------------------------------------------- */

static inline OQS_STATUS oqs_kem_keypair_safe(
        const OQS_KEM *kem,
        uint8_t *public_key __sized_by(pk_len), size_t pk_len,
        uint8_t *secret_key __sized_by(sk_len), size_t sk_len) {
    (void)pk_len;
    (void)sk_len;
    return OQS_KEM_keypair(kem, public_key, secret_key);
}

static inline OQS_STATUS oqs_kem_encaps_safe(
        const OQS_KEM *kem,
        uint8_t *ciphertext __sized_by(ct_len), size_t ct_len,
        uint8_t *shared_secret __sized_by(ss_len), size_t ss_len,
        const uint8_t *public_key __sized_by(pk_len), size_t pk_len) {
    (void)ct_len;
    (void)ss_len;
    (void)pk_len;
    return OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);
}

static inline OQS_STATUS oqs_kem_decaps_safe(
        const OQS_KEM *kem,
        uint8_t *shared_secret __sized_by(ss_len), size_t ss_len,
        const uint8_t *ciphertext __sized_by(ct_len), size_t ct_len,
        const uint8_t *secret_key __sized_by(sk_len), size_t sk_len) {
    (void)ss_len;
    (void)ct_len;
    (void)sk_len;
    return OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key);
}

/* ---- SIG (stateless) ------------------------------------------------- */

static inline OQS_STATUS oqs_sig_keypair_safe(
        const OQS_SIG *sig,
        uint8_t *public_key __sized_by(pk_len), size_t pk_len,
        uint8_t *secret_key __sized_by(sk_len), size_t sk_len) {
    (void)pk_len;
    (void)sk_len;
    return OQS_SIG_keypair(sig, public_key, secret_key);
}

/* `signature_len` is a normal out-pointer (the produced length), NOT a buffer,
 * so it stays a plain `size_t *`. Only the byte buffers carry `__sized_by`. */
static inline OQS_STATUS oqs_sig_sign_safe(
        const OQS_SIG *sig,
        uint8_t *signature __sized_by(sig_buf_len), size_t sig_buf_len,
        size_t *signature_len,
        const uint8_t *message __sized_by(message_len), size_t message_len,
        const uint8_t *secret_key __sized_by(sk_len), size_t sk_len) {
    (void)sig_buf_len;
    (void)sk_len;
    return OQS_SIG_sign(sig, signature, signature_len, message, message_len, secret_key);
}

static inline OQS_STATUS oqs_sig_verify_safe(
        const OQS_SIG *sig,
        const uint8_t *message __sized_by(message_len), size_t message_len,
        const uint8_t *signature __sized_by(signature_len), size_t signature_len,
        const uint8_t *public_key __sized_by(pk_len), size_t pk_len) {
    (void)pk_len;
    return OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
}

/* ---- SIG_STFL (stateful) --------------------------------------------- */

/* The secret-key object and store callback are opaque/pointers — left alone.
 * Only the public-key / message / signature byte buffers carry `__sized_by`. */

static inline OQS_STATUS oqs_sig_stfl_keypair_safe(
        const OQS_SIG_STFL *sig,
        uint8_t *public_key __sized_by(pk_len), size_t pk_len,
        OQS_SIG_STFL_SECRET_KEY *secret_key) {
    (void)pk_len;
    return OQS_SIG_STFL_keypair(sig, public_key, secret_key);
}

static inline OQS_STATUS oqs_sig_stfl_sign_safe(
        const OQS_SIG_STFL *sig,
        uint8_t *signature __sized_by(sig_buf_len), size_t sig_buf_len,
        size_t *signature_len,
        const uint8_t *message __sized_by(message_len), size_t message_len,
        OQS_SIG_STFL_SECRET_KEY *secret_key) {
    (void)sig_buf_len;
    return OQS_SIG_STFL_sign(sig, signature, signature_len, message, message_len, secret_key);
}

static inline OQS_STATUS oqs_sig_stfl_verify_safe(
        const OQS_SIG_STFL *sig,
        const uint8_t *message __sized_by(message_len), size_t message_len,
        const uint8_t *signature __sized_by(signature_len), size_t signature_len,
        const uint8_t *public_key __sized_by(pk_len), size_t pk_len) {
    (void)pk_len;
    return OQS_SIG_STFL_verify(sig, message, message_len, signature, signature_len, public_key);
}

#if defined(__cplusplus)
}
#endif

#endif /* OQS_SAFE_H */
