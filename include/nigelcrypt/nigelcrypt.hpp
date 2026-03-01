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
#include <functional>
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

enum class RuntimeBinding : uint16_t {
    None = 0,
    Process = 1
};


enum class BufferMode : uint16_t {
    Heap = 0,
    VirtualLocked = 1,
    VirtualGuarded = 2
};

struct DecryptOptions {
    BufferMode buffer = BufferMode::VirtualLocked;
    bool require_aad = false;
};


struct Policy {
    Algorithm required_algorithm = Algorithm::Aes256Gcm;
    bool require_algorithm = false;
    bool require_aad = false;
    RuntimeBinding required_binding = RuntimeBinding::None;
    bool require_binding = false;
    uint32_t min_key_id = 0;
};

inline Policy& default_policy() {
    static Policy p{};
    return p;
}

inline void set_policy(const Policy& policy) {
    default_policy() = policy;
}

struct RegionPolicy {
    bool enable = false;
    std::vector<std::string> allowlist;
    std::vector<std::string> blocklist;
    // If set, the app provides a region string (e.g., "US", "DE").
    std::function<std::string()> resolver;
};

inline RegionPolicy& region_policy() {
    static RegionPolicy p{};
    return p;
}

inline void set_region_policy(const RegionPolicy& p) {
    region_policy() = p;
}

namespace detail {

inline void secure_zero(void* ptr, size_t len) {
    if (ptr && len) {
        ::RtlSecureZeroMemory(ptr, len);
    }
}


struct BufferAlloc {
    char* ptr = nullptr;
    void* base = nullptr;
    size_t len = 0;
    size_t alloc = 0;
    size_t lock = 0;
    BufferMode mode = BufferMode::Heap;
};

inline size_t page_size() {
    static size_t ps = 0;
    if (ps == 0) {
        SYSTEM_INFO si{};
        ::GetSystemInfo(&si);
        ps = static_cast<size_t>(si.dwPageSize);
    }
    return ps;
}

inline BufferAlloc alloc_buffer(size_t len, BufferMode mode) {
    BufferAlloc b{};
    b.len = len;

    if (len == 0) {
        return b;
    }

    const size_t total_len = len + 1;

    if (mode == BufferMode::Heap) {
        b.ptr = new char[total_len];
        b.base = b.ptr;
        b.alloc = total_len;
        b.mode = BufferMode::Heap;
        return b;
    }

    const size_t ps = page_size();
    const size_t pages = (total_len + ps - 1) / ps;
    const size_t total_pages = pages + (mode == BufferMode::VirtualGuarded ? 1 : 0);
    const size_t total_bytes = total_pages * ps;

    void* base = ::VirtualAlloc(nullptr, total_bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!base) {
        b.ptr = new char[total_len];
        b.base = b.ptr;
        b.alloc = total_len;
        b.mode = BufferMode::Heap;
        return b;
    }

    if (mode == BufferMode::VirtualGuarded) {
        DWORD old_protect = 0;
        ::VirtualProtect(static_cast<char*>(base) + pages * ps, ps, PAGE_NOACCESS, &old_protect);
    }

    if (mode == BufferMode::VirtualLocked) {
        if (::VirtualLock(base, pages * ps)) {
            b.lock = pages * ps;
        }
    }

    b.ptr = static_cast<char*>(base);
    b.base = base;
    b.alloc = total_bytes;
    b.mode = mode;
    return b;
}

inline void free_buffer(BufferAlloc& b) {
    if (!b.ptr) {
        return;
    }
    secure_zero(b.ptr, b.len + 1);
    if (b.mode == BufferMode::Heap) {
        delete[] b.ptr;
    } else {
        if (b.lock) {
            ::VirtualUnlock(b.base, b.lock);
        }
        ::VirtualFree(b.base, 0, MEM_RELEASE);
    }
    b.ptr = nullptr;
    b.base = nullptr;
    b.len = 0;
    b.alloc = 0;
    b.lock = 0;
    b.mode = BufferMode::Heap;
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

inline std::array<uint8_t, 32> pbkdf2_sha256(
    std::string_view passphrase,
    const std::vector<uint8_t>& salt,
    uint64_t iterations
) {
    if (passphrase.empty()) {
        throw std::invalid_argument("Passphrase cannot be empty");
    }
    if (salt.empty()) {
        throw std::invalid_argument("Salt cannot be empty");
    }
    if (iterations == 0) {
        throw std::invalid_argument("Iterations must be > 0");
    }

    BcryptAlgHandle alg(BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG);

    std::array<uint8_t, 32> out{};
    NTSTATUS st = BCryptDeriveKeyPBKDF2(
        alg.get(),
        reinterpret_cast<PUCHAR>(const_cast<char*>(passphrase.data())),
        static_cast<ULONG>(passphrase.size()),
        const_cast<PUCHAR>(salt.data()),
        static_cast<ULONG>(salt.size()),
        iterations,
        out.data(),
        static_cast<ULONG>(out.size()),
        0
    );
    if (st < 0) {
        throw_status("BCryptDeriveKeyPBKDF2 failed", st);
    }
    return out;
}

inline void append_u16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
}

inline void append_u32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

inline uint16_t read_u16(const std::vector<uint8_t>& in, size_t& off) {
    if (off + 2 > in.size()) {
        throw std::runtime_error("Envelope truncated");
    }
    uint16_t v = static_cast<uint16_t>(in[off]) |
                 (static_cast<uint16_t>(in[off + 1]) << 8);
    off += 2;
    return v;
}

inline uint32_t read_u32(const std::vector<uint8_t>& in, size_t& off) {
    if (off + 4 > in.size()) {
        throw std::runtime_error("Envelope truncated");
    }
    uint32_t v = static_cast<uint32_t>(in[off]) |
                 (static_cast<uint32_t>(in[off + 1]) << 8) |
                 (static_cast<uint32_t>(in[off + 2]) << 16) |
                 (static_cast<uint32_t>(in[off + 3]) << 24);
    off += 4;
    return v;
}

inline std::vector<uint8_t> runtime_binding_bytes(RuntimeBinding binding) {
    if (binding == RuntimeBinding::None) {
        return {};
    }

    std::vector<uint8_t> out;
    out.reserve(24);

    const uint32_t pid = ::GetCurrentProcessId();
    const uintptr_t module_base = reinterpret_cast<uintptr_t>(::GetModuleHandleW(nullptr));
    static int runtime_salt = 0;
    const uintptr_t salt_addr = reinterpret_cast<uintptr_t>(&runtime_salt);

    append_u32(out, pid);
    append_u32(out, static_cast<uint32_t>(module_base & 0xFFFFFFFFu));
    append_u32(out, static_cast<uint32_t>((module_base >> 32) & 0xFFFFFFFFu));
    append_u32(out, static_cast<uint32_t>(salt_addr & 0xFFFFFFFFu));
    append_u32(out, static_cast<uint32_t>((salt_addr >> 32) & 0xFFFFFFFFu));

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

class PasswordKeyProvider final : public KeyProvider {
public:
    PasswordKeyProvider(std::string passphrase, std::vector<uint8_t> salt, uint64_t iterations, uint32_t key_id = 1)
        : passphrase_(std::move(passphrase)), salt_(std::move(salt)), iterations_(iterations), key_id_(key_id) {
        if (passphrase_.empty()) {
            throw std::invalid_argument("Passphrase cannot be empty");
        }
        if (salt_.empty()) {
            throw std::invalid_argument("Salt cannot be empty");
        }
        if (iterations_ < kMinIterations) {
            throw std::invalid_argument("Iterations must be >= 100000");
        }
    }

    KeyBlob get_master_key() override {
        std::lock_guard<std::mutex> lock(mu_);
        auto key = pbkdf2_sha256(passphrase_, salt_, iterations_);
        return KeyBlob(key);
    }

    uint32_t key_id() const override { return key_id_; }

private:
    static constexpr uint64_t kMinIterations = 100000;
    std::string passphrase_;
    std::vector<uint8_t> salt_;
    uint64_t iterations_;
    uint32_t key_id_;
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
using PasswordKeyProvider = detail::PasswordKeyProvider;
using CachedKeyProvider = detail::CachedKeyProvider;
using KeyRing = detail::KeyRing;
using KeyScope = detail::KeyScope;

inline void set_key_provider(std::shared_ptr<KeyProvider> provider) {
    detail::set_default_key_provider(std::move(provider));
}

inline KeyRing& key_ring() {
    return detail::default_key_ring();
}

const char* version_string();

class SecureStringView {
public:
    SecureStringView() = default;

    explicit SecureStringView(detail::BufferAlloc buf)
        : buf_(buf) {}

    SecureStringView(const SecureStringView&) = delete;
    SecureStringView& operator=(const SecureStringView&) = delete;

    SecureStringView(SecureStringView&& other) noexcept {
        *this = std::move(other);
    }

    SecureStringView& operator=(SecureStringView&& other) noexcept {
        if (this != &other) {
            reset();
            buf_ = other.buf_;
            other.buf_.ptr = nullptr;
            other.buf_.base = nullptr;
            other.buf_.len = 0;
            other.buf_.alloc = 0;
            other.buf_.lock = 0;
            other.buf_.mode = BufferMode::Heap;
        }
        return *this;
    }

    ~SecureStringView() { reset(); }

    const char* c_str() const { return buf_.ptr ? buf_.ptr : ""; }
    size_t size() const { return buf_.len; }

    void reset() {
        detail::free_buffer(buf_);
    }

    void wipe_now() {
        reset();
    }

private:
    detail::BufferAlloc buf_{};
};

class SecureString {
public:
    SecureString() = default;

    explicit SecureString(
        std::string_view plain,
        std::string_view aad = {},
        Algorithm alg = Algorithm::Aes256Gcm,
        RuntimeBinding binding = RuntimeBinding::Process
    ) {
        encrypt(plain, aad, alg, binding);
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
            binding_ = other.binding_;
            key_id_ = other.key_id_;
            ciphertext_ = std::move(other.ciphertext_);
            nonce_ = other.nonce_;
            tag_ = other.tag_;
            salt_ = other.salt_;
            context_ = other.context_;
            custom_meta_ = std::move(other.custom_meta_);
            other.ciphertext_.clear();
            other.nonce_.fill(0);
            other.tag_.fill(0);
            other.salt_.fill(0);
            other.context_.fill(0);
            other.custom_meta_.clear();
            other.binding_ = RuntimeBinding::Process;
        }
        return *this;
    }

    ~SecureString() { clear(); }

    void encrypt(
        std::string_view plain,
        std::string_view aad = {},
        Algorithm alg = Algorithm::Aes256Gcm,
        RuntimeBinding binding = RuntimeBinding::Process
    ) {
        auto provider = detail::default_key_ring().primary();
        if (!provider) {
            throw std::runtime_error("No key provider configured");
        }
        encrypt_with_provider(plain, aad, alg, binding, provider);
    }

    SecureStringView decrypt(std::string_view aad = {}) const {
        DecryptOptions opt;
        return decrypt(aad, opt);
    }

    SecureStringView decrypt(std::string_view aad, const DecryptOptions& options) const {
        const Policy& pol = default_policy();
        const RegionPolicy& rp = region_policy();
        if (options.require_aad || pol.require_aad) {
            if (aad.empty()) {
                throw std::runtime_error("AAD is required for decryption");
            }
        }
        if (pol.require_algorithm && algorithm_ != pol.required_algorithm) {
            throw std::runtime_error("Algorithm does not satisfy policy");
        }
        if (pol.require_binding && binding_ != pol.required_binding) {
            throw std::runtime_error("Binding does not satisfy policy");
        }
        if (pol.min_key_id && key_id_ < pol.min_key_id) {
            throw std::runtime_error("Key id does not satisfy policy");
        }
        if (rp.enable) {
            if (!rp.resolver) {
                throw std::runtime_error("Region policy enabled but no resolver provided");
            }
            const std::string region = rp.resolver();
            if (!rp.blocklist.empty()) {
                for (const auto& b : rp.blocklist) {
                    if (region == b) {
                        throw std::runtime_error("Region is blocked by policy");
                    }
                }
            }
            if (!rp.allowlist.empty()) {
                bool allowed = false;
                for (const auto& a : rp.allowlist) {
                    if (region == a) {
                        allowed = true;
                        break;
                    }
                }
                if (!allowed) {
                    throw std::runtime_error("Region is not allowed by policy");
                }
            }
        }
        if (ciphertext_.empty()) {
            return SecureStringView(detail::BufferAlloc{});
        }

        auto provider = detail::default_key_ring().resolve(key_id_);
        if (!provider) {
            throw std::runtime_error("No key provider configured");
        }
        detail::KeyBlob master = provider->get_master_key();
        std::vector<uint8_t> ikm(master.bytes.begin(), master.bytes.end());
        std::vector<uint8_t> salt(salt_.begin(), salt_.end());
        std::vector<uint8_t> info;
        info.reserve(nonce_.size() + context_.size() + 32 + 32);
        info.insert(info.end(), nonce_.begin(), nonce_.end());
        info.insert(info.end(), context_.begin(), context_.end());

        std::vector<uint8_t> aad_hash;
        if (!aad.empty()) {
            aad_hash = detail::sha256(std::vector<uint8_t>(aad.begin(), aad.end()));
            info.insert(info.end(), aad_hash.begin(), aad_hash.end());
        }

        std::vector<uint8_t> binding_bytes = detail::runtime_binding_bytes(binding_);
        if (!binding_bytes.empty()) {
            info.insert(info.end(), binding_bytes.begin(), binding_bytes.end());
        }

        std::vector<uint8_t> key = detail::hkdf_sha256(std::move(ikm), std::move(salt), std::move(info), 32);

        std::vector<uint8_t> auth_data;
        auth_data.reserve(aad.size() + binding_bytes.size());
        auth_data.insert(auth_data.end(), aad.begin(), aad.end());
        auth_data.insert(auth_data.end(), binding_bytes.begin(), binding_bytes.end());

        std::vector<uint8_t> plain;
        if (algorithm_ == Algorithm::Aes256Gcm) {
            plain = detail::aes256_gcm_decrypt(
                key.data(), key.size(),
                ciphertext_.data(), ciphertext_.size(),
                nonce_.data(), nonce_.size(),
                auth_data.empty() ? nullptr : auth_data.data(), auth_data.size(),
                tag_
            );
        } else if (algorithm_ == Algorithm::ChaCha20Poly1305) {
            plain = detail::chacha20_poly1305_decrypt(
                key.data(), key.size(),
                ciphertext_.data(), ciphertext_.size(),
                nonce_.data(), nonce_.size(),
                auth_data.empty() ? nullptr : auth_data.data(), auth_data.size(),
                tag_
            );
        } else {
            detail::secure_zero(key.data(), key.size());
            throw std::runtime_error("Unsupported algorithm");
        }

        detail::secure_zero(key.data(), key.size());

        detail::BufferAlloc buf = detail::alloc_buffer(plain.size(), options.buffer);
        if (plain.size() && !buf.ptr) {
            detail::secure_zero(plain.data(), plain.size());
            throw std::runtime_error("Failed to allocate plaintext buffer");
        }

        if (!plain.empty()) {
            std::memcpy(buf.ptr, plain.data(), plain.size());
            buf.ptr[plain.size()] = '\0';
        } else if (buf.ptr) {
            buf.ptr[0] = '\0';
        }

        detail::secure_zero(plain.data(), plain.size());

        return SecureStringView(std::move(buf));
    }


    void rekey(
        std::string_view aad = {},
        Algorithm alg = Algorithm::Aes256Gcm,
        RuntimeBinding binding = RuntimeBinding::Process
    ) {
        auto provider = detail::default_key_ring().primary();
        if (!provider) {
            throw std::runtime_error("No key provider configured");
        }
        rekey(provider, aad, alg, binding);
    }

    void rekey(
        std::shared_ptr<KeyProvider> provider,
        std::string_view aad = {},
        Algorithm alg = Algorithm::Aes256Gcm,
        RuntimeBinding binding = RuntimeBinding::Process
    ) {
        if (!provider) {
            throw std::invalid_argument("KeyProvider cannot be null");
        }
        auto plain = decrypt(aad);
        encrypt_with_provider(std::string_view(plain.c_str(), plain.size()), aad, alg, binding, provider);
    }


    void set_custom_meta(std::vector<uint8_t> meta) {
        custom_meta_ = std::move(meta);
    }

    const std::vector<uint8_t>& custom_meta() const {
        return custom_meta_;
    }

    std::vector<uint8_t> export_envelope() const {
        static constexpr uint32_t kMagic = 0x5243474E; // 'NGCR'
        const bool v2 = version_ >= 2;
        const bool v3 = version_ >= 3;
        const size_t header = v3 ? (4 + 2 + 2 + 2 + 4 + 4 + 2) : (v2 ? (4 + 2 + 2 + 2 + 4 + 4) : (4 + 2 + 2 + 4 + 4));
        const size_t meta_len = v3 ? custom_meta_.size() : 0;
        const size_t hash_len = v2 ? 32 : 0;

        std::vector<uint8_t> out;
        out.reserve(header + 16 + 12 + 16 + 16 + meta_len + hash_len + ciphertext_.size());

        detail::append_u32(out, kMagic);
        detail::append_u16(out, static_cast<uint16_t>(version_));
        detail::append_u16(out, static_cast<uint16_t>(algorithm_));
        if (v2) {
            detail::append_u16(out, static_cast<uint16_t>(binding_));
        }
        detail::append_u32(out, key_id_);
        detail::append_u32(out, static_cast<uint32_t>(ciphertext_.size()));
        if (v3) {
            detail::append_u16(out, static_cast<uint16_t>(custom_meta_.size()));
        }

        out.insert(out.end(), salt_.begin(), salt_.end());
        out.insert(out.end(), nonce_.begin(), nonce_.end());
        out.insert(out.end(), context_.begin(), context_.end());
        out.insert(out.end(), tag_.begin(), tag_.end());
        if (v3 && !custom_meta_.empty()) {
            out.insert(out.end(), custom_meta_.begin(), custom_meta_.end());
        }

        if (v2) {
            std::vector<uint8_t> meta;
            meta.reserve(2 + 2 + 2 + 4 + 4 + 2 + salt_.size() + nonce_.size() + context_.size() + tag_.size() + custom_meta_.size());
            detail::append_u16(meta, static_cast<uint16_t>(version_));
            detail::append_u16(meta, static_cast<uint16_t>(algorithm_));
            detail::append_u16(meta, static_cast<uint16_t>(binding_));
            detail::append_u32(meta, key_id_);
            detail::append_u32(meta, static_cast<uint32_t>(ciphertext_.size()));
            if (v3) {
                detail::append_u16(meta, static_cast<uint16_t>(custom_meta_.size()));
            }
            meta.insert(meta.end(), salt_.begin(), salt_.end());
            meta.insert(meta.end(), nonce_.begin(), nonce_.end());
            meta.insert(meta.end(), context_.begin(), context_.end());
            meta.insert(meta.end(), tag_.begin(), tag_.end());
            if (v3 && !custom_meta_.empty()) {
                meta.insert(meta.end(), custom_meta_.begin(), custom_meta_.end());
            }

            std::vector<uint8_t> meta_hash = detail::sha256(std::move(meta));
            out.insert(out.end(), meta_hash.begin(), meta_hash.end());
        }

        out.insert(out.end(), ciphertext_.begin(), ciphertext_.end());
        return out;
    }

    static SecureString import_envelope(const std::vector<uint8_t>& data) {
        static constexpr uint32_t kMagic = 0x5243474E; // 'NGCR'
        if (data.size() < 4 + 2 + 2 + 4 + 4) {
            throw std::runtime_error("Envelope too small");
        }

        size_t off = 0;
        const uint32_t magic = detail::read_u32(data, off);
        const uint16_t version = detail::read_u16(data, off);
        if (magic != kMagic || version == 0) {
            throw std::runtime_error("Invalid envelope header");
        }

        uint16_t alg = 0;
        uint16_t binding = static_cast<uint16_t>(RuntimeBinding::None);
        uint32_t key_id = 0;
        uint32_t ciphertext_len = 0;
        uint16_t meta_len = 0;

        if (version == 1) {
            alg = detail::read_u16(data, off);
            key_id = detail::read_u32(data, off);
            ciphertext_len = detail::read_u32(data, off);
        } else if (version == 2) {
            alg = detail::read_u16(data, off);
            binding = detail::read_u16(data, off);
            key_id = detail::read_u32(data, off);
            ciphertext_len = detail::read_u32(data, off);
        } else {
            alg = detail::read_u16(data, off);
            binding = detail::read_u16(data, off);
            key_id = detail::read_u32(data, off);
            ciphertext_len = detail::read_u32(data, off);
            meta_len = detail::read_u16(data, off);
        }

        const bool v2 = version >= 2;
        const bool v3 = version >= 3;
        const size_t fixed = (version == 1 ? (4 + 2 + 2 + 4 + 4)
                          : (version == 2 ? (4 + 2 + 2 + 2 + 4 + 4)
                                          : (4 + 2 + 2 + 2 + 4 + 4 + 2)))
                           + 16 + 12 + 16 + 16 + (v3 ? meta_len : 0) + (v2 ? 32 : 0);
        if (data.size() < fixed) {
            throw std::runtime_error("Envelope missing fields");
        }

        const size_t expected = fixed + ciphertext_len;
        if (data.size() != expected) {
            throw std::runtime_error("Envelope size mismatch");
        }

        SecureString s;
        s.version_ = version;
        s.algorithm_ = static_cast<Algorithm>(alg);
        s.binding_ = static_cast<RuntimeBinding>(binding);
        s.key_id_ = key_id;

        std::memcpy(s.salt_.data(), data.data() + off, s.salt_.size());
        off += s.salt_.size();
        std::memcpy(s.nonce_.data(), data.data() + off, s.nonce_.size());
        off += s.nonce_.size();
        std::memcpy(s.context_.data(), data.data() + off, s.context_.size());
        off += s.context_.size();
        std::memcpy(s.tag_.data(), data.data() + off, s.tag_.size());
        off += s.tag_.size();

        if (v3 && meta_len) {
            s.custom_meta_.assign(data.begin() + int(off), data.begin() + int(off + meta_len));
            off += meta_len;
        }

        if (v2) {
            std::vector<uint8_t> meta_hash(32);
            std::memcpy(meta_hash.data(), data.data() + off, meta_hash.size());
            off += meta_hash.size();

            std::vector<uint8_t> meta;
            meta.reserve(2 + 2 + 2 + 4 + 4 + 2 + s.salt_.size() + s.nonce_.size() + s.context_.size() + s.tag_.size() + s.custom_meta_.size());
            detail::append_u16(meta, static_cast<uint16_t>(version));
            detail::append_u16(meta, static_cast<uint16_t>(alg));
            detail::append_u16(meta, static_cast<uint16_t>(binding));
            detail::append_u32(meta, key_id);
            detail::append_u32(meta, ciphertext_len);
            if (v3) {
                detail::append_u16(meta, meta_len);
            }
            meta.insert(meta.end(), s.salt_.begin(), s.salt_.end());
            meta.insert(meta.end(), s.nonce_.begin(), s.nonce_.end());
            meta.insert(meta.end(), s.context_.begin(), s.context_.end());
            meta.insert(meta.end(), s.tag_.begin(), s.tag_.end());
            if (v3 && !s.custom_meta_.empty()) {
                meta.insert(meta.end(), s.custom_meta_.begin(), s.custom_meta_.end());
            }

            std::vector<uint8_t> computed = detail::sha256(std::move(meta));
            if (computed != meta_hash) {
                throw std::runtime_error("Envelope metadata hash mismatch");
            }
        } else {
            s.binding_ = RuntimeBinding::None;
        }

        s.ciphertext_.assign(data.begin() + int(off), data.end());
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
        if (!custom_meta_.empty()) {
            detail::secure_zero(custom_meta_.data(), custom_meta_.size());
            custom_meta_.clear();
        }
    }

private:
    uint16_t version_ = 1;
    Algorithm algorithm_ = Algorithm::Aes256Gcm;
    RuntimeBinding binding_ = RuntimeBinding::Process;
    uint32_t key_id_ = 1;
    std::vector<uint8_t> ciphertext_;
    std::array<uint8_t, 12> nonce_{}; // 96-bit nonce for GCM
    std::array<uint8_t, 16> tag_{};   // 128-bit tag
    std::array<uint8_t, 16> salt_{};  // per-string salt for HKDF
    std::array<uint8_t, 16> context_{}; // per-string HKDF context
};

} // namespace nigelcrypt
