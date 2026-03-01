#include "nigelcrypt/nigelcrypt_c.h"
#include "nigelcrypt/nigelcrypt.hpp"

#include <new>
#include <vector>

struct nc_secure_string {
    nigelcrypt::SecureString inner;
};

static nc_status to_status(nigelcrypt::Status s) {
    switch (s) {
        case nigelcrypt::Status::Ok: return NC_OK;
        case nigelcrypt::Status::InvalidArgument: return NC_INVALID_ARGUMENT;
        case nigelcrypt::Status::PolicyViolation: return NC_POLICY_VIOLATION;
        case nigelcrypt::Status::RegionViolation: return NC_REGION_VIOLATION;
        case nigelcrypt::Status::DecryptFailed: return NC_DECRYPT_FAILED;
        case nigelcrypt::Status::BufferTooSmall: return NC_BUFFER_TOO_SMALL;
        case nigelcrypt::Status::NotSupported: return NC_NOT_SUPPORTED;
        case nigelcrypt::Status::StorageError: return NC_STORAGE_ERROR;
        default: return NC_DECRYPT_FAILED;
    }
}

extern "C" {

const char* nc_version_string(void) {
    return nigelcrypt::version_string();
}

const char* nc_status_message(nc_status s) {
    return nigelcrypt::status_message(static_cast<nigelcrypt::Status>(s));
}

void nc_set_policy(const nc_policy* p) {
    if (!p) return;
    nigelcrypt::Policy pol;
    pol.require_algorithm = p->require_algorithm != 0;
    pol.required_algorithm = static_cast<nigelcrypt::Algorithm>(p->required_algorithm);
    pol.require_aad = p->require_aad != 0;
    pol.require_binding = p->require_binding != 0;
    pol.required_binding = static_cast<nigelcrypt::RuntimeBinding>(p->required_binding);
    pol.min_key_id = p->min_key_id;
    nigelcrypt::set_policy(pol);
}

void nc_set_strict_mode(const nc_strict_mode* s) {
    if (!s) return;
    nigelcrypt::StrictMode sm;
    sm.enabled = s->enabled != 0;
    sm.require_aad = s->require_aad != 0;
    sm.require_binding = s->require_binding != 0;
    sm.require_algorithm = static_cast<nigelcrypt::Algorithm>(s->require_algorithm);
    nigelcrypt::set_strict_mode(sm);
}

nc_secure_string* nc_secure_string_new(void) {
    try {
        return new nc_secure_string{};
    } catch (...) {
        return nullptr;
    }
}

void nc_secure_string_free(nc_secure_string* s) {
    delete s;
}

nc_status nc_secure_string_set_custom_meta(nc_secure_string* s, const uint8_t* data, size_t len) {
    if (!s) return NC_INVALID_ARGUMENT;
    if (!data && len) return NC_INVALID_ARGUMENT;
    try {
        std::vector<uint8_t> meta;
        if (data && len) {
            meta.assign(data, data + len);
        }
        s->inner.set_custom_meta(std::move(meta));
        return NC_OK;
    } catch (...) {
        return NC_INVALID_ARGUMENT;
    }
}

nc_status nc_secure_string_encrypt(
    nc_secure_string* s,
    const char* plain,
    size_t plain_len,
    const char* aad,
    size_t aad_len,
    nc_algorithm alg,
    nc_binding binding
) {
    if (!s || (!plain && plain_len)) return NC_INVALID_ARGUMENT;
    try {
        std::string_view p(plain ? plain : "", plain_len);
        std::string_view a(aad ? aad : "", aad_len);
        s->inner.encrypt(p, a, static_cast<nigelcrypt::Algorithm>(alg), static_cast<nigelcrypt::RuntimeBinding>(binding));
        return NC_OK;
    } catch (...) {
        return NC_DECRYPT_FAILED;
    }
}

nc_status nc_secure_string_import_envelope(nc_secure_string* s, const uint8_t* data, size_t len) {
    if (!s || (!data && len)) return NC_INVALID_ARGUMENT;
    try {
        std::vector<uint8_t> blob(data, data + len);
        s->inner = nigelcrypt::SecureString::import_envelope(blob);
        return NC_OK;
    } catch (...) {
        return NC_DECRYPT_FAILED;
    }
}

nc_status nc_secure_string_export_envelope(nc_secure_string* s, uint8_t** out, size_t* out_len) {
    if (!s || !out || !out_len) return NC_INVALID_ARGUMENT;
    try {
        std::vector<uint8_t> blob = s->inner.export_envelope();
        uint8_t* buf = static_cast<uint8_t*>(::malloc(blob.size()));
        if (!buf) return NC_STORAGE_ERROR;
        std::memcpy(buf, blob.data(), blob.size());
        *out = buf;
        *out_len = blob.size();
        return NC_OK;
    } catch (...) {
        return NC_STORAGE_ERROR;
    }
}

nc_status nc_secure_string_decrypt_to(
    nc_secure_string* s,
    char* out,
    size_t out_len,
    const char* aad,
    size_t aad_len,
    const nc_decrypt_options* opt,
    size_t* out_written
) {
    if (!s || !out || out_len == 0) return NC_INVALID_ARGUMENT;
    try {
        nigelcrypt::DecryptOptions o;
        if (opt) {
            o.buffer = static_cast<nigelcrypt::BufferMode>(opt->buffer);
            o.require_aad = opt->require_aad != 0;
            o.zero_on_failure = opt->zero_on_failure != 0;
        }
        std::string_view a(aad ? aad : "", aad_len);
        auto st = s->inner.decrypt_to(out, out_len, a, o, out_written);
        return to_status(st);
    } catch (...) {
        return NC_DECRYPT_FAILED;
    }
}

nc_status nc_secure_string_rekey(nc_secure_string* s, const char* aad, size_t aad_len, nc_algorithm alg, nc_binding binding) {
    if (!s) return NC_INVALID_ARGUMENT;
    try {
        std::string_view a(aad ? aad : "", aad_len);
        s->inner.rekey(a, static_cast<nigelcrypt::Algorithm>(alg), static_cast<nigelcrypt::RuntimeBinding>(binding));
        return NC_OK;
    } catch (...) {
        return NC_DECRYPT_FAILED;
    }
}

nc_status nc_audit_envelope(const uint8_t* data, size_t len, nc_audit_info* info_out) {
    if (!data || !info_out) return NC_INVALID_ARGUMENT;
    try {
        std::vector<uint8_t> blob(data, data + len);
        auto info = nigelcrypt::audit_envelope(blob);
        info_out->version = info.version;
        info_out->algorithm = static_cast<uint16_t>(info.algorithm);
        info_out->binding = static_cast<uint16_t>(info.binding);
        info_out->key_id = info.key_id;
        info_out->ciphertext_len = info.ciphertext_len;
        info_out->custom_meta_len = info.custom_meta_len;
        return NC_OK;
    } catch (...) {
        return NC_DECRYPT_FAILED;
    }
}

nc_status nc_encrypt_blob_dpapi(const uint8_t* plain, size_t len, int local_machine, uint8_t** out, size_t* out_len) {
    if (!out || !out_len) return NC_INVALID_ARGUMENT;
    if (!plain && len) return NC_INVALID_ARGUMENT;
    try {
        std::vector<uint8_t> p(plain, plain + len);
        auto blob = nigelcrypt::encrypt_blob_dpapi(p, local_machine != 0);
        uint8_t* buf = static_cast<uint8_t*>(::malloc(blob.size()));
        if (!buf) return NC_STORAGE_ERROR;
        std::memcpy(buf, blob.data(), blob.size());
        *out = buf;
        *out_len = blob.size();
        return NC_OK;
    } catch (...) {
        return NC_STORAGE_ERROR;
    }
}

nc_status nc_decrypt_blob_dpapi(const uint8_t* blob, size_t len, uint8_t** out, size_t* out_len) {
    if (!out || !out_len) return NC_INVALID_ARGUMENT;
    if (!blob && len) return NC_INVALID_ARGUMENT;
    try {
        std::vector<uint8_t> b(blob, blob + len);
        auto plain = nigelcrypt::decrypt_blob_dpapi(b);
        uint8_t* buf = static_cast<uint8_t*>(::malloc(plain.size()));
        if (!buf) return NC_STORAGE_ERROR;
        std::memcpy(buf, plain.data(), plain.size());
        *out = buf;
        *out_len = plain.size();
        return NC_OK;
    } catch (...) {
        return NC_STORAGE_ERROR;
    }
}

void nc_free(void* p) {
    ::free(p);
}

} // extern "C"
