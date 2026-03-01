#pragma once

// NigelCrypt - header-only, Windows-only string protection utility.
// Focus: real authenticated encryption, per-string keys, short plaintext lifetime.
// Non-goals: anti-debugging, polymorphism, tamper-evasion, or obfuscation guarantees.
//
// Usage:
//   #include "nigelcrypt.hpp"
//   using nigelcrypt::SecureString;
//
//   SecureString s("Sensitive API Key");
//   auto plain = s.decrypt();
//   // use plain.c_str(), then it is zeroed on destruction
//
// Notes:
// - If you pass a string literal, that literal is still present in the binary.
// - This library protects runtime storage of the string, not compile-time literals.

#if !defined(_WIN32)
#error NigelCrypt currently supports Windows only.
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace nigelcrypt {

namespace detail {

inline void secure_zero(void* ptr, size_t len) {
    if (ptr && len) {
        ::RtlSecureZeroMemory(ptr, len);
    }
}

inline void throw_status(const char* what, NTSTATUS status) {
    std::string msg = std::string(what) + " (NTSTATUS: 0x";
    char buf[9] = {};
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%08X", static_cast<unsigned>(status));
    msg += buf;
    msg += ")";
    throw std::runtime_error(msg);
}

class BcryptAlgHandle {
public:
    BcryptAlgHandle(const wchar_t* alg_id, ULONG flags) {
        NTSTATUS st = BCryptOpenAlgorithmProvider(&handle_, alg_id, nullptr, flags);
        if (st < 0) {
            throw_status("BCryptOpenAlgorithmProvider failed", st);
        }
    }

    ~BcryptAlgHandle() {
        if (handle_) {
            BCryptCloseAlgorithmProvider(handle_, 0);
        }
    }

    BCRYPT_ALG_HANDLE get() const { return handle_; }

private:
    BCRYPT_ALG_HANDLE handle_ = nullptr;
};

inline void gen_random(uint8_t* out, size_t len) {
    if (!out || len == 0) return;
    NTSTATUS st = BCryptGenRandom(nullptr, out, static_cast<ULONG>(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st < 0) {
        throw_status("BCryptGenRandom failed", st);
    }
}

inline std::vector<uint8_t> hmac_sha256(std::vector<uint8_t> key, std::vector<uint8_t> data) {
    BcryptAlgHandle alg(BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG);

    DWORD hash_len = 0;
    DWORD cb = 0;
    NTSTATUS st = BCryptGetProperty(alg.get(), BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_len), sizeof(hash_len), &cb, 0);
    if (st < 0) {
        throw_status("BCryptGetProperty(HASH_LENGTH) failed", st);
    }

    std::vector<uint8_t> hash_obj;
    DWORD obj_len = 0;
    st = BCryptGetProperty(alg.get(), BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&obj_len), sizeof(obj_len), &cb, 0);
    if (st < 0) {
        throw_status("BCryptGetProperty(OBJECT_LENGTH) failed", st);
    }
    hash_obj.resize(obj_len);

    BCRYPT_HASH_HANDLE h = nullptr;
    st = BCryptCreateHash(alg.get(), &h, hash_obj.data(), obj_len, key.data(), static_cast<ULONG>(key.size()), 0);
    if (st < 0) {
        throw_status("BCryptCreateHash failed", st);
    }

    st = BCryptHashData(h, data.data(), static_cast<ULONG>(data.size()), 0);
    if (st < 0) {
        BCryptDestroyHash(h);
        throw_status("BCryptHashData failed", st);
    }

    std::vector<uint8_t> out(hash_len);
    st = BCryptFinishHash(h, out.data(), static_cast<ULONG>(out.size()), 0);
    BCryptDestroyHash(h);
    if (st < 0) {
        throw_status("BCryptFinishHash failed", st);
    }

    return out;
}

inline std::vector<uint8_t> hkdf_sha256(
    std::vector<uint8_t> ikm,
    std::vector<uint8_t> salt,
    std::vector<uint8_t> info,
    size_t out_len
) {
    if (salt.empty()) {
        salt.resize(32, 0); // per HKDF spec: salt can be zeros
    }

    std::vector<uint8_t> prk = hmac_sha256(salt, ikm);

    std::vector<uint8_t> okm;
    okm.reserve(out_len);

    std::vector<uint8_t> t;
    uint8_t counter = 1;

    while (okm.size() < out_len) {
        std::vector<uint8_t> data;
        data.reserve(t.size() + info.size() + 1);
        data.insert(data.end(), t.begin(), t.end());
        data.insert(data.end(), info.begin(), info.end());
        data.push_back(counter++);

        t = hmac_sha256(prk, data);
        size_t need = out_len - okm.size();
        size_t take = (t.size() < need) ? t.size() : need;
        okm.insert(okm.end(), t.begin(), t.begin() + take);
    }

    return okm;
}

class MasterKey {
public:
    static const std::array<uint8_t, 32>& get() {
        static MasterKey inst;
        return inst.key_;
    }

private:
    MasterKey() {
        gen_random(key_.data(), key_.size());
    }

    std::array<uint8_t, 32> key_{};
};

inline void aes256_gcm_encrypt(
    const uint8_t* key, size_t key_len,
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* nonce, size_t nonce_len,
    std::vector<uint8_t>& ciphertext,
    std::array<uint8_t, 16>& tag
) {
    BcryptAlgHandle alg(BCRYPT_AES_ALGORITHM, 0);

    NTSTATUS st = BCryptSetProperty(alg.get(), BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)), sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (st < 0) {
        throw_status("BCryptSetProperty(CHAINING_MODE) failed", st);
    }

    DWORD obj_len = 0;
    DWORD cb = 0;
    st = BCryptGetProperty(alg.get(), BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&obj_len), sizeof(obj_len), &cb, 0);
    if (st < 0) {
        throw_status("BCryptGetProperty(OBJECT_LENGTH) failed", st);
    }

    std::vector<uint8_t> key_obj(obj_len);
    BCRYPT_KEY_HANDLE key_handle = nullptr;
    st = BCryptGenerateSymmetricKey(alg.get(), &key_handle, key_obj.data(), obj_len, const_cast<PUCHAR>(key), static_cast<ULONG>(key_len), 0);
    if (st < 0) {
        throw_status("BCryptGenerateSymmetricKey failed", st);
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(nonce);
    info.cbNonce = static_cast<ULONG>(nonce_len);
    info.pbTag = tag.data();
    info.cbTag = static_cast<ULONG>(tag.size());

    ULONG out_len = 0;
    ciphertext.resize(plaintext_len);
    st = BCryptEncrypt(
        key_handle,
        const_cast<PUCHAR>(plaintext),
        static_cast<ULONG>(plaintext_len),
        &info,
        nullptr,
        0,
        ciphertext.data(),
        static_cast<ULONG>(ciphertext.size()),
        &out_len,
        0
    );

    BCryptDestroyKey(key_handle);

    if (st < 0) {
        throw_status("BCryptEncrypt failed", st);
    }

    ciphertext.resize(out_len);
}

inline std::vector<uint8_t> aes256_gcm_decrypt(
    const uint8_t* key, size_t key_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* nonce, size_t nonce_len,
    const std::array<uint8_t, 16>& tag
) {
    BcryptAlgHandle alg(BCRYPT_AES_ALGORITHM, 0);

    NTSTATUS st = BCryptSetProperty(alg.get(), BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)), sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (st < 0) {
        throw_status("BCryptSetProperty(CHAINING_MODE) failed", st);
    }

    DWORD obj_len = 0;
    DWORD cb = 0;
    st = BCryptGetProperty(alg.get(), BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&obj_len), sizeof(obj_len), &cb, 0);
    if (st < 0) {
        throw_status("BCryptGetProperty(OBJECT_LENGTH) failed", st);
    }

    std::vector<uint8_t> key_obj(obj_len);
    BCRYPT_KEY_HANDLE key_handle = nullptr;
    st = BCryptGenerateSymmetricKey(alg.get(), &key_handle, key_obj.data(), obj_len, const_cast<PUCHAR>(key), static_cast<ULONG>(key_len), 0);
    if (st < 0) {
        throw_status("BCryptGenerateSymmetricKey failed", st);
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(nonce);
    info.cbNonce = static_cast<ULONG>(nonce_len);
    info.pbTag = const_cast<PUCHAR>(tag.data());
    info.cbTag = static_cast<ULONG>(tag.size());

    ULONG out_len = 0;
    std::vector<uint8_t> plaintext(ciphertext_len);
    st = BCryptDecrypt(
        key_handle,
        const_cast<PUCHAR>(ciphertext),
        static_cast<ULONG>(ciphertext_len),
        &info,
        nullptr,
        0,
        plaintext.data(),
        static_cast<ULONG>(plaintext.size()),
        &out_len,
        0
    );

    BCryptDestroyKey(key_handle);

    if (st < 0) {
        throw_status("BCryptDecrypt failed", st);
    }

    plaintext.resize(out_len);
    return plaintext;
}

} // namespace detail

class SecureStringView {
public:
    SecureStringView(char* ptr, size_t len)
        : ptr_(ptr), len_(len) {}

    SecureStringView(const SecureStringView&) = delete;
    SecureStringView& operator=(const SecureStringView&) = delete;

    SecureStringView(SecureStringView&& other) noexcept
        : ptr_(other.ptr_), len_(other.len_) {
        other.ptr_ = nullptr;
        other.len_ = 0;
    }

    SecureStringView& operator=(SecureStringView&& other) noexcept {
        if (this != &other) {
            reset();
            ptr_ = other.ptr_;
            len_ = other.len_;
            other.ptr_ = nullptr;
            other.len_ = 0;
        }
        return *this;
    }

    ~SecureStringView() { reset(); }

    const char* c_str() const { return ptr_ ? ptr_ : ""; }
    size_t size() const { return len_; }

    void reset() {
        if (ptr_) {
            detail::secure_zero(ptr_, len_);
            delete[] ptr_;
            ptr_ = nullptr;
            len_ = 0;
        }
    }

private:
    char* ptr_ = nullptr;
    size_t len_ = 0;
};

class SecureString {
public:
    SecureString() = default;

    explicit SecureString(std::string_view plain) {
        encrypt(plain);
    }

    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;

    SecureString(SecureString&& other) noexcept {
        *this = std::move(other);
    }

    SecureString& operator=(SecureString&& other) noexcept {
        if (this != &other) {
            clear();
            ciphertext_ = std::move(other.ciphertext_);
            nonce_ = other.nonce_;
            tag_ = other.tag_;
            salt_ = other.salt_;
            other.ciphertext_.clear();
            other.nonce_.fill(0);
            other.tag_.fill(0);
            other.salt_.fill(0);
        }
        return *this;
    }

    ~SecureString() { clear(); }

    void encrypt(std::string_view plain) {
        clear();

        detail::gen_random(salt_.data(), salt_.size());
        detail::gen_random(nonce_.data(), nonce_.size());

        std::vector<uint8_t> ikm(detail::MasterKey::get().begin(), detail::MasterKey::get().end());
        std::vector<uint8_t> salt(salt_.begin(), salt_.end());
        std::vector<uint8_t> info(nonce_.begin(), nonce_.end());

        std::vector<uint8_t> key = detail::hkdf_sha256(std::move(ikm), std::move(salt), std::move(info), 32);

        detail::aes256_gcm_encrypt(
            key.data(), key.size(),
            reinterpret_cast<const uint8_t*>(plain.data()), plain.size(),
            nonce_.data(), nonce_.size(),
            ciphertext_,
            tag_
        );

        detail::secure_zero(key.data(), key.size());
    }

    SecureStringView decrypt() const {
        if (ciphertext_.empty()) {
            return SecureStringView(nullptr, 0);
        }

        std::vector<uint8_t> ikm(detail::MasterKey::get().begin(), detail::MasterKey::get().end());
        std::vector<uint8_t> salt(salt_.begin(), salt_.end());
        std::vector<uint8_t> info(nonce_.begin(), nonce_.end());

        std::vector<uint8_t> key = detail::hkdf_sha256(std::move(ikm), std::move(salt), std::move(info), 32);

        std::vector<uint8_t> plain = detail::aes256_gcm_decrypt(
            key.data(), key.size(),
            ciphertext_.data(), ciphertext_.size(),
            nonce_.data(), nonce_.size(),
            tag_
        );

        detail::secure_zero(key.data(), key.size());

        char* out = new char[plain.size() + 1];
        if (!plain.empty()) {
            std::memcpy(out, plain.data(), plain.size());
        }
        out[plain.size()] = '\0';
        detail::secure_zero(plain.data(), plain.size());

        return SecureStringView(out, plain.size());
    }

    void clear() {
        if (!ciphertext_.empty()) {
            detail::secure_zero(ciphertext_.data(), ciphertext_.size());
            ciphertext_.clear();
        }
        detail::secure_zero(nonce_.data(), nonce_.size());
        detail::secure_zero(tag_.data(), tag_.size());
        detail::secure_zero(salt_.data(), salt_.size());
    }

private:
    std::vector<uint8_t> ciphertext_;
    std::array<uint8_t, 12> nonce_{}; // 96-bit nonce for GCM
    std::array<uint8_t, 16> tag_{};   // 128-bit tag
    std::array<uint8_t, 16> salt_{};  // per-string salt for HKDF
};

} // namespace nigelcrypt

