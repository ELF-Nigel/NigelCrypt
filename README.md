# NigelCrypt

Header-only, Windows-only string protection utility focused on **real authenticated encryption**, **per-string keys**, and **short plaintext lifetimes** at runtime. It is **not** an anti-analysis or obfuscation framework. It protects runtime storage, not compile-time literals.

**Author contacts**
- Discord: `chefendpoint`
- Telegram: `ELF_Nigel`

## What This Is
- AES-256-GCM authenticated encryption (confidentiality + integrity).
- Per-string key derivation via HKDF-SHA256.
- A DPAPI-wrapped master key (default) so no global static key is embedded.
- Short plaintext lifetime with secure zeroing of buffers.
- Optional Associated Data (AAD) to bind decryption to a context.

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

## Associated Data (AAD)
AAD binds decryption to a context (e.g., a feature name or runtime state). The same AAD must be provided to decrypt.

```cpp
SecureString s("token", "api:v1");
auto p = s.decrypt("api:v1");
```

If the AAD does not match, decryption fails with an exception.

## Key Management
By default, NigelCrypt uses a DPAPI-wrapped master key created at runtime and kept encrypted in memory. This avoids a single static key compiled into the binary.

You can provide your own key provider:

```cpp
struct MyProvider : nigelcrypt::KeyProvider {
    nigelcrypt::KeyBlob get_master_key() override {
        std::array<uint8_t, 32> key = {/* ... */};
        return nigelcrypt::KeyBlob(key);
    }
};

nigelcrypt::set_key_provider(std::make_shared<MyProvider>());
```

## Security Notes
- **String literals remain in the binary.** This library protects runtime storage, not compile-time literals.
- AES-GCM provides integrity checks; tampered ciphertext fails to decrypt.
- Plaintext is zeroed immediately after use in `SecureStringView`.

## Files
- `nigelcrypt.hpp` – the full implementation.

## License
Add your preferred license text here.
