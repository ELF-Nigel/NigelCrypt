# NigelCrypt

Header-only, Windows-only string protection utility focused on **real authenticated encryption**, **per-string keys**, and **short plaintext lifetimes** at runtime. It is **not** an anti-analysis or obfuscation framework. It protects runtime storage, not compile-time literals.

**Author contacts**
- Discord: `chefendpoint`
- Telegram: `ELF_Nigel`

## What This Is
- AES-256-GCM authenticated encryption (confidentiality + integrity).
- Optional ChaCha20-Poly1305 authenticated encryption.
- Per-string key derivation via HKDF-SHA256.
- A DPAPI-wrapped master key (default) so no global static key is embedded.
- Short plaintext lifetime with secure zeroing of buffers.
- Optional Associated Data (AAD) to bind decryption to a context.
- Versioned envelope export/import for storage and key rotation.

## What This Is Not
- Not anti-debugging, anti-tamper, or polymorphic obfuscation.
- Not a way to remove compile-time literals from a binary.
- Not a replacement for secure server-side secret storage.

## Requirements
- Windows (user-mode)
- C++20
- Windows CNG / DPAPI
- Link against `bcrypt.lib` and `crypt32.lib`

## Quick Start

```cpp
#include "nigelcrypt.hpp"

int main() {
    using nigelcrypt::SecureString;

    SecureString secret("Sensitive API Key");
    auto plain = secret.decrypt();

    // use plain.c_str(), then it is zeroed on destruction
    return 0;
}
```

## Algorithm Selection
Choose AES-256-GCM (default) or ChaCha20-Poly1305:

```cpp
using nigelcrypt::Algorithm;
SecureString s("token", {}, Algorithm::ChaCha20Poly1305);
```

## Associated Data (AAD)
AAD binds decryption to a context (e.g., a feature name or runtime state). The same AAD must be provided to decrypt.

```cpp
SecureString s("token", "api:v1");
auto p = s.decrypt("api:v1");
```

If the AAD does not match, decryption fails with an exception.

## Key Management
By default, NigelCrypt uses a DPAPI-wrapped master key created at runtime and kept encrypted in memory. This avoids a single static key compiled into the binary.

### Key Ring & Rotation
Each encrypted string stores a `key_id`. You can register multiple providers to enable rotation:

```cpp
using nigelcrypt::key_ring;
auto& ring = key_ring();
ring.add_provider(std::make_shared<nigelcrypt::DpapiKeyProvider>(nigelcrypt::KeyScope::CurrentUser, true, 2));
// primary provider is used for new encryptions
```

### Cached Key Provider
To reduce DPAPI calls, wrap a provider with caching:

```cpp
using nigelcrypt::CachedKeyProvider;
auto dpapi = std::make_shared<nigelcrypt::DpapiKeyProvider>();
auto cached = std::make_shared<CachedKeyProvider>(dpapi, CachedKeyProvider::kForever);
nigelcrypt::set_key_provider(cached);
```

You can provide your own key provider:

```cpp
struct MyProvider : nigelcrypt::KeyProvider {
    nigelcrypt::KeyBlob get_master_key() override {
        std::array<uint8_t, 32> key = {/* ... */};
        return nigelcrypt::KeyBlob(key);
    }
    uint32_t key_id() const override { return 10; }
};

nigelcrypt::set_key_provider(std::make_shared<MyProvider>());
```

Note: ChaCha20-Poly1305 requires a Windows version that exposes the CNG algorithm `BCRYPT_CHACHA20_POLY1305_ALGORITHM`.

## Envelope Export/Import
Persist encrypted data as a self-describing envelope:

```cpp
auto blob = secret.export_envelope();
auto s2 = nigelcrypt::SecureString::import_envelope(blob);
auto p = s2.decrypt();
```

## Security Notes
- **String literals remain in the binary.** This library protects runtime storage, not compile-time literals.
- AES-GCM and ChaCha20-Poly1305 provide integrity checks; tampered ciphertext fails to decrypt.
- Plaintext is zeroed immediately after use in `SecureStringView`.

## Files
- `nigelcrypt.hpp` – the full implementation.

## License
Add your preferred license text here.
