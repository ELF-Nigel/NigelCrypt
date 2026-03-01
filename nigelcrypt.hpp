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
#include <wincrypt.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace nigelcrypt {

enum class Algorithm : uint32_t {
    Aes256Gcm = 1,
    ChaCha20Poly1305 = 2
};

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

inline std::vector<uint8_t> sha256(std::vector<uint8_t> data) {
    BcryptAlgHandle alg(BCRYPT_SHA256_ALGORITHM, 0);

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
    st = BCryptCreateHash(alg.get(), &h, hash_obj.data(), obj_len, nullptr, 0, 0);
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

class KeyBlob {
public:
    KeyBlob() = default;
    explicit KeyBlob(const std::array<uint8_t, 32>& v) : bytes(v) {}

    KeyBlob(const KeyBlob&) = delete;
    KeyBlob& operator=(const KeyBlob&) = delete;

    KeyBlob(KeyBlob&& other) noexcept {
        bytes = other.bytes;
        secure_zero(other.bytes.data(), other.bytes.size());
    }

    KeyBlob& operator=(KeyBlob&& other) noexcept {
        if (this != &other) {
            secure_zero(bytes.data(), bytes.size());
            bytes = other.bytes;
            secure_zero(other.bytes.data(), other.bytes.size());
        }
        return *this;
    }

    ~KeyBlob() { secure_zero(bytes.data(), bytes.size()); }

    std::array<uint8_t, 32> bytes{};
};

enum class KeyScope {
    CurrentUser,
    LocalMachine
};

class KeyProvider {
public:
    virtual ~KeyProvider() = default;
    virtual KeyBlob get_master_key() = 0;
    virtual uint32_t key_id() const = 0;
};

class DpapiKeyProvider final : public KeyProvider {
public:
    explicit DpapiKeyProvider(KeyScope scope = KeyScope::CurrentUser, bool use_entropy = true, uint32_t key_id = 1)
        : scope_(scope), use_entropy_(use_entropy), key_id_(key_id) {
        std::array<uint8_t, 32> raw{};
        gen_random(raw.data(), raw.size());

        if (use_entropy_) {
            entropy_.resize(16);
            gen_random(entropy_.data(), entropy_.size());
        }

        DATA_BLOB input{};
        input.pbData = raw.data();
        input.cbData = static_cast<DWORD>(raw.size());

        DATA_BLOB entropy{};
        entropy.pbData = use_entropy_ ? entropy_.data() : nullptr;
        entropy.cbData = use_entropy_ ? static_cast<DWORD>(entropy_.size()) : 0;

        DATA_BLOB output{};
        DWORD flags = (scope_ == KeyScope::LocalMachine) ? CRYPTPROTECT_LOCAL_MACHINE : 0;

        if (!CryptProtectData(&input, L"NigelCryptKey", use_entropy_ ? &entropy : nullptr, nullptr, nullptr, flags, &output)) {
            throw std::runtime_error("CryptProtectData failed");
        }

        wrapped_.assign(output.pbData, output.pbData + output.cbData);
        LocalFree(output.pbData);

        secure_zero(raw.data(), raw.size());
    }

    KeyBlob get_master_key() override {
        std::lock_guard<std::mutex> lock(mu_);

        DATA_BLOB input{};
        input.pbData = wrapped_.data();
        input.cbData = static_cast<DWORD>(wrapped_.size());

        DATA_BLOB entropy{};
        entropy.pbData = use_entropy_ ? entropy_.data() : nullptr;
        entropy.cbData = use_entropy_ ? static_cast<DWORD>(entropy_.size()) : 0;

        DATA_BLOB output{};
        if (!CryptUnprotectData(&input, nullptr, use_entropy_ ? &entropy : nullptr, nullptr, nullptr, 0, &output)) {
            throw std::runtime_error("CryptUnprotectData failed");
        }

        if (output.cbData != 32) {
            LocalFree(output.pbData);
            throw std::runtime_error("Unexpected DPAPI key size");
        }

        std::array<uint8_t, 32> key{};
        std::memcpy(key.data(), output.pbData, 32);
        LocalFree(output.pbData);

        return KeyBlob(key);
    }

    uint32_t key_id() const override { return key_id_; }

private:
    KeyScope scope_;
    bool use_entropy_;
    uint32_t key_id_;
    std::vector<uint8_t> wrapped_;
    std::vector<uint8_t> entropy_;
    std::mutex mu_;
};

class CachedKeyProvider final : public KeyProvider {
public:
    explicit CachedKeyProvider(std::shared_ptr<KeyProvider> inner, uint64_t duration_ms = 300000)
        : inner_(std::move(inner)), duration_ms_(duration_ms) {
        if (!inner_) {
            throw std::invalid_argument("CachedKeyProvider requires a valid inner provider");
        }
    }

    KeyBlob get_master_key() override {
        std::lock_guard<std::mutex> lock(mu_);
        const uint64_t now = ::GetTickCount64();
        if (cached_ && (duration_ms_ == kForever || now < expires_at_)) {
            return KeyBlob(cached_->bytes);
        }
        cached_.reset();
        KeyBlob fresh = inner_->get_master_key();
        cached_ = std::make_unique<KeyBlob>(fresh.bytes);
        expires_at_ = (duration_ms_ == kForever) ? kForever : (now + duration_ms_);
        return fresh;
    }

    uint32_t key_id() const override { return inner_->key_id(); }

    static constexpr uint64_t kForever = ~static_cast<uint64_t>(0);

private:
    std::shared_ptr<KeyProvider> inner_;
    uint64_t duration_ms_;
    uint64_t expires_at_ = 0;
    std::unique_ptr<KeyBlob> cached_;
    std::mutex mu_;
};

class KeyRing {
public:
    KeyRing() = default;

    void set_primary(std::shared_ptr<KeyProvider> provider) {
        if (!provider) {
            throw std::invalid_argument("KeyProvider cannot be null");
        }
        std::lock_guard<std::mutex> lock(mu_);
        primary_ = std::move(provider);
        providers_[primary_->key_id()] = primary_;
    }

    void add_provider(std::shared_ptr<KeyProvider> provider) {
        if (!provider) {
            throw std::invalid_argument("KeyProvider cannot be null");
        }
        std::lock_guard<std::mutex> lock(mu_);
        providers_[provider->key_id()] = std::move(provider);
    }

    std::shared_ptr<KeyProvider> resolve(uint32_t key_id) const {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = providers_.find(key_id);
        if (it != providers_.end()) {
            return it->second;
        }
        return primary_;
    }

    std::shared_ptr<KeyProvider> primary() const {
        std::lock_guard<std::mutex> lock(mu_);
        return primary_;
    }

private:
    mutable std::mutex mu_;
    std::shared_ptr<KeyProvider> primary_;
    std::unordered_map<uint32_t, std::shared_ptr<KeyProvider>> providers_;
};

inline KeyRing& default_key_ring() {
    static KeyRing ring;
    static std::once_flag init;
    std::call_once(init, []() {
        auto dpapi = std::make_shared<DpapiKeyProvider>();
        auto cached = std::make_shared<CachedKeyProvider>(dpapi, CachedKeyProvider::kForever);
        ring.set_primary(cached);
    });
    return ring;
}

inline void set_default_key_provider(std::shared_ptr<KeyProvider> provider) {
    default_key_ring().set_primary(std::move(provider));
}

inline void aes256_gcm_encrypt(
    const uint8_t* key, size_t key_len,
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* aad, size_t aad_len,
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
    info.pbAuthData = const_cast<PUCHAR>(aad);
    info.cbAuthData = static_cast<ULONG>(aad_len);
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
    const uint8_t* aad, size_t aad_len,
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
    info.pbAuthData = const_cast<PUCHAR>(aad);
    info.cbAuthData = static_cast<ULONG>(aad_len);
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

inline void chacha20_poly1305_encrypt(
    const uint8_t* key, size_t key_len,
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* aad, size_t aad_len,
    std::vector<uint8_t>& ciphertext,
    std::array<uint8_t, 16>& tag
) {
    BcryptAlgHandle alg(BCRYPT_CHACHA20_POLY1305_ALGORITHM, 0);

    DWORD obj_len = 0;
    DWORD cb = 0;
    NTSTATUS st = BCryptGetProperty(alg.get(), BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&obj_len), sizeof(obj_len), &cb, 0);
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
    info.pbAuthData = const_cast<PUCHAR>(aad);
    info.cbAuthData = static_cast<ULONG>(aad_len);
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

inline std::vector<uint8_t> chacha20_poly1305_decrypt(
    const uint8_t* key, size_t key_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* aad, size_t aad_len,
    const std::array<uint8_t, 16>& tag
) {
    BcryptAlgHandle alg(BCRYPT_CHACHA20_POLY1305_ALGORITHM, 0);

    DWORD obj_len = 0;
    DWORD cb = 0;
    NTSTATUS st = BCryptGetProperty(alg.get(), BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&obj_len), sizeof(obj_len), &cb, 0);
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
    info.pbAuthData = const_cast<PUCHAR>(aad);
    info.cbAuthData = static_cast<ULONG>(aad_len);
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

using KeyProvider = detail::KeyProvider;
using KeyBlob = detail::KeyBlob;
using DpapiKeyProvider = detail::DpapiKeyProvider;
using CachedKeyProvider = detail::CachedKeyProvider;
using KeyRing = detail::KeyRing;
using KeyScope = detail::KeyScope;

inline void set_key_provider(std::shared_ptr<KeyProvider> provider) {
    detail::set_default_key_provider(std::move(provider));
}

inline KeyRing& key_ring() {
    return detail::default_key_ring();
}

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

    explicit SecureString(std::string_view plain, std::string_view aad = {}, Algorithm alg = Algorithm::Aes256Gcm) {
        encrypt(plain, aad, alg);
    }

    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;

    SecureString(SecureString&& other) noexcept {
        *this = std::move(other);
    }

    SecureString& operator=(SecureString&& other) noexcept {
        if (this != &other) {
            clear();
            version_ = other.version_;
            algorithm_ = other.algorithm_;
            key_id_ = other.key_id_;
            ciphertext_ = std::move(other.ciphertext_);
            nonce_ = other.nonce_;
            tag_ = other.tag_;
            salt_ = other.salt_;
            context_ = other.context_;
            other.ciphertext_.clear();
            other.nonce_.fill(0);
            other.tag_.fill(0);
            other.salt_.fill(0);
            other.context_.fill(0);
        }
        return *this;
    }

    ~SecureString() { clear(); }

    void encrypt(std::string_view plain, std::string_view aad = {}, Algorithm alg = Algorithm::Aes256Gcm) {
        clear();

        version_ = 1;
        algorithm_ = alg;

        detail::gen_random(salt_.data(), salt_.size());
        detail::gen_random(nonce_.data(), nonce_.size());
        detail::gen_random(context_.data(), context_.size());

        auto provider = detail::default_key_ring().primary();
        if (!provider) {
            throw std::runtime_error("No key provider configured");
        }
        key_id_ = provider->key_id();
        detail::KeyBlob master = provider->get_master_key();
        std::vector<uint8_t> ikm(master.bytes.begin(), master.bytes.end());
        std::vector<uint8_t> salt(salt_.begin(), salt_.end());
        std::vector<uint8_t> info;
        info.reserve(nonce_.size() + context_.size());
        info.insert(info.end(), nonce_.begin(), nonce_.end());
        info.insert(info.end(), context_.begin(), context_.end());

        std::vector<uint8_t> key = detail::hkdf_sha256(std::move(ikm), std::move(salt), std::move(info), 32);

        if (algorithm_ == Algorithm::Aes256Gcm) {
            detail::aes256_gcm_encrypt(
                key.data(), key.size(),
                reinterpret_cast<const uint8_t*>(plain.data()), plain.size(),
                nonce_.data(), nonce_.size(),
                reinterpret_cast<const uint8_t*>(aad.data()), aad.size(),
                ciphertext_,
                tag_
            );
        } else if (algorithm_ == Algorithm::ChaCha20Poly1305) {
            detail::chacha20_poly1305_encrypt(
                key.data(), key.size(),
                reinterpret_cast<const uint8_t*>(plain.data()), plain.size(),
                nonce_.data(), nonce_.size(),
                reinterpret_cast<const uint8_t*>(aad.data()), aad.size(),
                ciphertext_,
                tag_
            );
        } else {
            detail::secure_zero(key.data(), key.size());
            throw std::runtime_error("Unsupported algorithm");
        }

        detail::secure_zero(key.data(), key.size());
    }

    SecureStringView decrypt(std::string_view aad = {}) const {
        if (ciphertext_.empty()) {
            return SecureStringView(nullptr, 0);
        }

        auto provider = detail::default_key_ring().resolve(key_id_);
        if (!provider) {
            throw std::runtime_error("No key provider configured");
        }
        detail::KeyBlob master = provider->get_master_key();
        std::vector<uint8_t> ikm(master.bytes.begin(), master.bytes.end());
        std::vector<uint8_t> salt(salt_.begin(), salt_.end());
        std::vector<uint8_t> info;
        info.reserve(nonce_.size() + context_.size());
        info.insert(info.end(), nonce_.begin(), nonce_.end());
        info.insert(info.end(), context_.begin(), context_.end());

        std::vector<uint8_t> key = detail::hkdf_sha256(std::move(ikm), std::move(salt), std::move(info), 32);

        std::vector<uint8_t> plain;
        if (algorithm_ == Algorithm::Aes256Gcm) {
            plain = detail::aes256_gcm_decrypt(
                key.data(), key.size(),
                ciphertext_.data(), ciphertext_.size(),
                nonce_.data(), nonce_.size(),
                reinterpret_cast<const uint8_t*>(aad.data()), aad.size(),
                tag_
            );
        } else if (algorithm_ == Algorithm::ChaCha20Poly1305) {
            plain = detail::chacha20_poly1305_decrypt(
                key.data(), key.size(),
                ciphertext_.data(), ciphertext_.size(),
                nonce_.data(), nonce_.size(),
                reinterpret_cast<const uint8_t*>(aad.data()), aad.size(),
                tag_
            );
        } else {
            detail::secure_zero(key.data(), key.size());
            throw std::runtime_error("Unsupported algorithm");
        }

        detail::secure_zero(key.data(), key.size());

        char* out = new char[plain.size() + 1];
        if (!plain.empty()) {
            std::memcpy(out, plain.data(), plain.size());
        }
        out[plain.size()] = '\0';
        detail::secure_zero(plain.data(), plain.size());

        return SecureStringView(out, plain.size());
    }

    std::vector<uint8_t> export_envelope() const {
        static constexpr uint32_t kMagic = 0x5243474E; // 'NGCR'
        struct Header {
            uint32_t magic;
            uint16_t version;
            uint16_t alg;
            uint32_t key_id;
            uint32_t ciphertext_len;
        };

        Header h{};
        h.magic = kMagic;
        h.version = static_cast<uint16_t>(version_);
        h.alg = static_cast<uint16_t>(algorithm_);
        h.key_id = key_id_;
        h.ciphertext_len = static_cast<uint32_t>(ciphertext_.size());

        std::vector<uint8_t> out;
        out.reserve(sizeof(Header) + salt_.size() + nonce_.size() + context_.size() + tag_.size() + ciphertext_.size());

        const uint8_t* hp = reinterpret_cast<const uint8_t*>(&h);
        out.insert(out.end(), hp, hp + sizeof(Header));
        out.insert(out.end(), salt_.begin(), salt_.end());
        out.insert(out.end(), nonce_.begin(), nonce_.end());
        out.insert(out.end(), context_.begin(), context_.end());
        out.insert(out.end(), tag_.begin(), tag_.end());
        out.insert(out.end(), ciphertext_.begin(), ciphertext_.end());
        return out;
    }

    static SecureString import_envelope(const std::vector<uint8_t>& data) {
        static constexpr uint32_t kMagic = 0x5243474E; // 'NGCR'
        struct Header {
            uint32_t magic;
            uint16_t version;
            uint16_t alg;
            uint32_t key_id;
            uint32_t ciphertext_len;
        };

        if (data.size() < sizeof(Header)) {
            throw std::runtime_error("Envelope too small");
        }

        Header h{};
        std::memcpy(&h, data.data(), sizeof(Header));
        if (h.magic != kMagic || h.version == 0) {
            throw std::runtime_error("Invalid envelope header");
        }

        const size_t fixed = sizeof(Header) + 16 + 12 + 16 + 16;
        if (data.size() < fixed) {
            throw std::runtime_error("Envelope missing fields");
        }

        const size_t expected = fixed + h.ciphertext_len;
        if (data.size() != expected) {
            throw std::runtime_error("Envelope size mismatch");
        }

        SecureString s;
        s.version_ = h.version;
        s.algorithm_ = static_cast<Algorithm>(h.alg);
        s.key_id_ = h.key_id;

        size_t off = sizeof(Header);
        std::memcpy(s.salt_.data(), data.data() + off, s.salt_.size());
        off += s.salt_.size();
        std::memcpy(s.nonce_.data(), data.data() + off, s.nonce_.size());
        off += s.nonce_.size();
        std::memcpy(s.context_.data(), data.data() + off, s.context_.size());
        off += s.context_.size();
        std::memcpy(s.tag_.data(), data.data() + off, s.tag_.size());
        off += s.tag_.size();

        s.ciphertext_.assign(data.begin() + static_cast<long>(off), data.end());
        return s;
    }

    void clear() {
        if (!ciphertext_.empty()) {
            detail::secure_zero(ciphertext_.data(), ciphertext_.size());
            ciphertext_.clear();
        }
        detail::secure_zero(nonce_.data(), nonce_.size());
        detail::secure_zero(tag_.data(), tag_.size());
        detail::secure_zero(salt_.data(), salt_.size());
        detail::secure_zero(context_.data(), context_.size());
    }

private:
    uint16_t version_ = 1;
    Algorithm algorithm_ = Algorithm::Aes256Gcm;
    uint32_t key_id_ = 1;
    std::vector<uint8_t> ciphertext_;
    std::array<uint8_t, 12> nonce_{}; // 96-bit nonce for GCM
    std::array<uint8_t, 16> tag_{};   // 128-bit tag
    std::array<uint8_t, 16> salt_{};  // per-string salt for HKDF
    std::array<uint8_t, 16> context_{}; // per-string HKDF context
};

} // namespace nigelcrypt
