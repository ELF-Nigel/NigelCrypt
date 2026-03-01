#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

// C API for NigelCrypt

typedef enum nc_status {
    NC_OK = 0,
    NC_INVALID_ARGUMENT = 1,
    NC_POLICY_VIOLATION = 2,
    NC_REGION_VIOLATION = 3,
    NC_DECRYPT_FAILED = 4,
    NC_BUFFER_TOO_SMALL = 5,
    NC_NOT_SUPPORTED = 6,
    NC_STORAGE_ERROR = 7
} nc_status;

typedef enum nc_algorithm {
    NC_ALG_AES256_GCM = 1,
    NC_ALG_CHACHA20_POLY1305 = 2
} nc_algorithm;

typedef enum nc_binding {
    NC_BIND_NONE = 0,
    NC_BIND_PROCESS = 1
} nc_binding;

typedef enum nc_buffer_mode {
    NC_BUFFER_HEAP = 0,
    NC_BUFFER_VIRTUAL_LOCKED = 1,
    NC_BUFFER_VIRTUAL_GUARDED = 2
} nc_buffer_mode;

typedef struct nc_policy {
    int require_algorithm;
    nc_algorithm required_algorithm;
    int require_aad;
    int require_binding;
    nc_binding required_binding;
    uint32_t min_key_id;
} nc_policy;

typedef struct nc_decrypt_options {
    nc_buffer_mode buffer;
    int require_aad;
    int zero_on_failure;
} nc_decrypt_options;

typedef struct nc_strict_mode {
    int enabled;
    int require_aad;
    int require_binding;
    nc_algorithm require_algorithm;
} nc_strict_mode;

typedef struct nc_audit_info {
    uint16_t version;
    uint16_t algorithm;
    uint16_t binding;
    uint32_t key_id;
    uint32_t ciphertext_len;
    uint16_t custom_meta_len;
} nc_audit_info;

// Opaque handle
typedef struct nc_secure_string nc_secure_string;

const char* nc_version_string(void);
const char* nc_status_message(nc_status s);

void nc_set_policy(const nc_policy* p);
void nc_set_strict_mode(const nc_strict_mode* s);

// Create / destroy
nc_secure_string* nc_secure_string_new(void);
void nc_secure_string_free(nc_secure_string* s);

// Configure custom metadata (optional) before encrypt
nc_status nc_secure_string_set_custom_meta(nc_secure_string* s, const uint8_t* data, size_t len);

// Encrypt plaintext into the object
nc_status nc_secure_string_encrypt(
    nc_secure_string* s,
    const char* plain,
    size_t plain_len,
    const char* aad,
    size_t aad_len,
    nc_algorithm alg,
    nc_binding binding
);

// Import/export envelopes
nc_status nc_secure_string_import_envelope(nc_secure_string* s, const uint8_t* data, size_t len);
// Export allocates a buffer you must free with nc_free
nc_status nc_secure_string_export_envelope(nc_secure_string* s, uint8_t** out, size_t* out_len);

// Decrypt to caller-provided buffer
nc_status nc_secure_string_decrypt_to(
    nc_secure_string* s,
    char* out,
    size_t out_len,
    const char* aad,
    size_t aad_len,
    const nc_decrypt_options* opt,
    size_t* out_written
);

// Rekey (rotate to a new key provider id)
nc_status nc_secure_string_rekey(nc_secure_string* s, const char* aad, size_t aad_len, nc_algorithm alg, nc_binding binding);

// Audit envelope metadata without decrypt
nc_status nc_audit_envelope(const uint8_t* data, size_t len, nc_audit_info* info_out);

// DPAPI helpers (Windows)
// Output buffer allocated, must free with nc_free
nc_status nc_encrypt_blob_dpapi(const uint8_t* plain, size_t len, int local_machine, uint8_t** out, size_t* out_len);
// Output buffer allocated, must free with nc_free
nc_status nc_decrypt_blob_dpapi(const uint8_t* blob, size_t len, uint8_t** out, size_t* out_len);

// Memory helpers
void nc_free(void* p);

#ifdef __cplusplus
}
#endif
