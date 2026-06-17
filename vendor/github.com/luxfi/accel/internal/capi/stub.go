//go:build cgo

// Package capi stub implementations.
// When the real libluxaccel is not installed, these weak-symbol C functions
// provide default implementations that return LUX_NO_BACKEND.
// When libluxaccel IS installed and linked (via CGO_LDFLAGS=-lluxaccel),
// the strong symbols from the real library override these.
package capi

/*
#include <lux/accel/c_api.h>
#include <stdlib.h>
#include <string.h>

// Weak-symbol stubs: overridden by real libluxaccel when linked.

__attribute__((weak)) const char* lux_version(void) { return "stub-0.0.0"; }
__attribute__((weak)) const char* lux_get_error(void) { return "no accel library"; }

__attribute__((weak)) lux_status lux_init(void) { return LUX_NO_BACKEND; }
__attribute__((weak)) void lux_shutdown(void) {}

__attribute__((weak)) lux_status lux_load_backend(const char* p) { return LUX_NO_BACKEND; }
__attribute__((weak)) int lux_backend_count(void) { return 0; }
__attribute__((weak)) lux_backend_type lux_backend_type_at(int i) { return 0; }
__attribute__((weak)) int lux_device_count(lux_backend_type b) { return 0; }
__attribute__((weak)) lux_status lux_get_device_info(lux_backend_type b, int i, lux_device_info* o) {
    if (o) memset(o, 0, sizeof(*o));
    return LUX_NO_BACKEND;
}

__attribute__((weak)) lux_status lux_session_create(lux_session* s) { if(s)*s=NULL; return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_session_create_with_backend(lux_backend_type b, lux_session* s) { if(s)*s=NULL; return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_session_create_with_device(lux_backend_type b, int d, lux_session* s) { if(s)*s=NULL; return LUX_NO_BACKEND; }
__attribute__((weak)) void lux_session_destroy(lux_session s) {}
__attribute__((weak)) lux_status lux_session_sync(lux_session s) { return LUX_NO_BACKEND; }

__attribute__((weak)) lux_status lux_tensor_create(lux_session s, lux_dtype d, const size_t* sh, size_t nd, lux_tensor* t) { if(t)*t=NULL; return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_tensor_create_with_data(lux_session s, lux_dtype d, const size_t* sh, size_t nd, const void* data, size_t len, lux_tensor* t) { if(t)*t=NULL; return LUX_NO_BACKEND; }
__attribute__((weak)) void lux_tensor_destroy(lux_tensor t) {}
__attribute__((weak)) size_t lux_tensor_ndim(lux_tensor t) { return 0; }
__attribute__((weak)) size_t lux_tensor_shape(lux_tensor t, size_t d) { return 0; }
__attribute__((weak)) size_t lux_tensor_numel(lux_tensor t) { return 0; }
__attribute__((weak)) size_t lux_tensor_bytes(lux_tensor t) { return 0; }
__attribute__((weak)) lux_dtype lux_tensor_dtype(lux_tensor t) { return 0; }
__attribute__((weak)) lux_status lux_tensor_to_host(lux_tensor t, void* d, size_t n) { return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_tensor_from_host(lux_tensor t, const void* d, size_t n) { return LUX_NO_BACKEND; }

// ML ops
__attribute__((weak)) lux_status lux_matmul(lux_session s, lux_tensor a, lux_tensor b, lux_tensor c) { return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_relu(lux_session s, lux_tensor i, lux_tensor o) { return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_gelu(lux_session s, lux_tensor i, lux_tensor o) { return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_softmax(lux_session s, lux_tensor i, lux_tensor o, int ax) { return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_layer_norm(lux_session s, lux_tensor i, lux_tensor g, lux_tensor b, lux_tensor o, float e) { return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_attention(lux_session s, lux_tensor q, lux_tensor k, lux_tensor v, lux_tensor o, float sc) { return LUX_NO_BACKEND; }

// Crypto ops
__attribute__((weak)) lux_status lux_sha256(lux_session s, lux_tensor i, lux_tensor o) { return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_keccak256(lux_session s, lux_tensor i, lux_tensor o) { return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_poseidon(lux_session s, lux_tensor i, lux_tensor o) { return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_ecdsa_verify_batch(lux_session s, lux_tensor m, lux_tensor sg, lux_tensor pk, lux_tensor r) { return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_ed25519_verify_batch(lux_session s, lux_tensor m, lux_tensor sg, lux_tensor pk, lux_tensor r) { return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_bls_verify_batch(lux_session s, lux_tensor m, lux_tensor sg, lux_tensor pk, lux_tensor r) { return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_merkle_root(lux_session s, lux_tensor l, lux_tensor r) { return LUX_NO_BACKEND; }

// ZK ops
__attribute__((weak)) lux_status lux_ntt(lux_session s, lux_tensor i, lux_tensor o, lux_tensor rt, uint64_t m) { return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_intt(lux_session s, lux_tensor i, lux_tensor o, lux_tensor ir, uint64_t m) { return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_msm(lux_session s, lux_tensor sc, lux_tensor ba, lux_tensor r) { return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_poly_mul(lux_session s, lux_tensor a, lux_tensor b, lux_tensor c, uint64_t m) { return LUX_NO_BACKEND; }

// Lattice/PQC ops
__attribute__((weak)) lux_status lux_kyber_keygen(lux_session s, lux_tensor pk, lux_tensor sk) { return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_kyber_encaps(lux_session s, lux_tensor pk, lux_tensor ct, lux_tensor ss) { return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_kyber_decaps(lux_session s, lux_tensor ct, lux_tensor sk, lux_tensor ss) { return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_dilithium_sign(lux_session s, lux_tensor m, lux_tensor sk, lux_tensor sg) { return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_dilithium_verify(lux_session s, lux_tensor m, lux_tensor sg, lux_tensor pk, int* v) { if(v)*v=0; return LUX_NO_BACKEND; }

// FHE ops
__attribute__((weak)) lux_status lux_bfv_encrypt(lux_session s, lux_tensor p, lux_tensor pk, lux_tensor c) { return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_bfv_decrypt(lux_session s, lux_tensor c, lux_tensor sk, lux_tensor p) { return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_bfv_add(lux_session s, lux_tensor a, lux_tensor b, lux_tensor r) { return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_bfv_multiply(lux_session s, lux_tensor a, lux_tensor b, lux_tensor rk, lux_tensor r) { return LUX_NO_BACKEND; }

// DEX ops
__attribute__((weak)) lux_status lux_constant_product_swap(lux_session s, lux_tensor rx, lux_tensor ry, lux_tensor ai, int d, lux_tensor ao, float f) { return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_compute_twap(lux_session s, lux_tensor p, lux_tensor ts, uint64_t st, uint64_t en, lux_tensor tw) { return LUX_NO_BACKEND; }
__attribute__((weak)) lux_status lux_match_orders(lux_session s, lux_tensor bi, lux_tensor ak, lux_tensor mt, lux_tensor pr, lux_tensor am) { return LUX_NO_BACKEND; }
*/
import "C"
