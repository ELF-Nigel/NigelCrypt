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
- Optional build-time packing to keep plaintext out of your binary.
- Optional runtime binding to process context for stronger in-memory protection.
- Hardened plaintext buffers (VirtualLock/guard-page) with configurable options.

## What This Is Not
- Not anti-debugging, anti-tamper, or polymorphic obfuscation.
- Not a way to remove compile-time literals from a binary.
- Not a replacement for secure server-side secret storage.

## Requirements

## SDK / Library Usage
Build with CMake to get static/shared libs or use header-only target:

```
cmake -S . -B build -DNIGELCRYPT_BUILD_SHARED=ON -DNIGELCRYPT_BUILD_STATIC=ON
cmake --build build --config Release
```

CMake targets:
- `nigelcrypt_static`
- `nigelcrypt_shared`
- `nigelcrypt_header` (header-only)

Include header:
```cpp
#include "nigelcrypt/nigelcrypt.hpp"
```
- Windows (user-mode)
- C++20
- Windows CNG / DPAPI
- Link against `bcrypt.lib` and `crypt32.lib`

## Quick Start

```cpp
#include "nigelcrypt/nigelcrypt.hpp"

int main() {
    using nigelcrypt::SecureString;

    SecureString secret("Sensitive API Key");
    auto plain = secret.decrypt();

    // use plain.c_str(), then it is zeroed on destruction
    return 0;
}
```

## Avoiding Embedded String Literals (Build-Time Packing)
If you want to ensure plaintext is **not embedded** in the binary, you must avoid string literals. Use the packer tool to encrypt a plaintext file at build time, then embed only ciphertext.

### 1) Create a plaintext file (not checked into source control)
```
secret.txt
```

### 2) Run the packer (on Windows)
```
set NIGELCRYPT_PASSPHRASE=your-strong-passphrase
nigelcrypt_pack --in secret.txt --out packed/secret_blob.hpp --name secret --pass-env NIGELCRYPT_PASSPHRASE --binding none --iterations 1000000 --meta-hex 4e6967656c4372797074
```

This generates `packed/secret_blob.hpp` containing only ciphertext, salt, iteration count, and key id.

### 3) Decrypt at runtime
```cpp
#include \"nigelcrypt.hpp\"
#include \"packed/secret_blob.hpp\"

const char* pass = std::getenv(\"NIGELCRYPT_PASSPHRASE\");
auto provider = std::make_shared<nigelcrypt::PasswordKeyProvider>(
    std::string(pass),
    std::vector<uint8_t>(nigelcrypt_packed::secret_salt.begin(), nigelcrypt_packed::secret_salt.end()),
    nigelcrypt_packed::secret_iterations,
    nigelcrypt_packed::secret_key_id
);
nigelcrypt::set_key_provider(provider);

auto s = nigelcrypt::SecureString::import_envelope(
    std::vector<uint8_t>(nigelcrypt_packed::secret_blob.begin(), nigelcrypt_packed::secret_blob.end())
);
auto plain = s.decrypt();
```

**Important:** The passphrase must be supplied at runtime (env var, user input, secure vault). Do not hardcode it.

### Sample PowerShell Script
`tools/pack_sample.ps1` builds the packer and generates the header:

```
$env:NIGELCRYPT_PASSPHRASE = "your-strong-passphrase"
.\tools\pack_sample.ps1 -PlaintextPath .\secret.txt
```


## Custom Metadata (Uniqueness)
You can embed custom, application-specific metadata into the envelope. This keeps the crypto standard while making your envelope format unique to your app.

```cpp
// Set custom metadata before encrypting
std::vector<uint8_t> meta = {0x4E,0x69,0x67,0x65,0x6C,0x43,0x72,0x79,0x70,0x74}; // "NigelCrypt"
SecureString s;
s.set_custom_meta(meta);
s.encrypt("runtime-only", {}, Algorithm::Aes256Gcm, RuntimeBinding::Process);
```

This metadata is included in the envelope and integrity-hashed.

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
Note: `PasswordKeyProvider` enforces a minimum of 100,000 PBKDF2 iterations.

## Runtime Binding
For in-memory strings created at runtime, you can bind encryption to the current process. This makes ciphertext invalid if moved to another process.

```cpp
using nigelcrypt::RuntimeBinding;
SecureString s("runtime-only", {}, Algorithm::Aes256Gcm, RuntimeBinding::Process);
```

Do not use process binding for build-time packed blobs, because the packer runs in a different process.


## Policy (App-Specific Rules)
You can enforce app-specific rules at runtime:

```cpp
nigelcrypt::Policy p;
p.require_aad = true;
p.require_algorithm = true;
p.required_algorithm = nigelcrypt::Algorithm::Aes256Gcm;
p.require_binding = true;
p.required_binding = nigelcrypt::RuntimeBinding::Process;
p.min_key_id = 2;

nigelcrypt::set_policy(p);
```

Decryption will fail if the policy is not satisfied.

## Strict Mode
Strict mode hard-fails decryption unless AAD, process binding, and algorithm requirements are met:

```cpp
nigelcrypt::StrictMode sm;
sm.enabled = true;
sm.require_aad = true;
sm.require_binding = true;
sm.require_algorithm = nigelcrypt::Algorithm::Aes256Gcm;
nigelcrypt::set_strict_mode(sm);
```

## Region Policy (Optional)
Region policy is **application-defined**. You provide a resolver that returns a region string (e.g., "US"). This is suitable for licensing (best-effort).

```cpp
nigelcrypt::RegionPolicy rp;
rp.enable = true;
rp.resolver = []() { return std::string("US"); };
rp.allowlist = {"US", "CA"};
// or use blocklist: rp.blocklist = {"RU"};
nigelcrypt::set_region_policy(rp);
```

If the resolver says the region is blocked or not allowed, decryption fails.

## DPAPI Secure Storage
Encrypt/decrypt arbitrary blobs with DPAPI:

```cpp
std::vector<uint8_t> blob = {1,2,3};
auto protected_blob = nigelcrypt::encrypt_blob_dpapi(blob, true);
auto plain_blob = nigelcrypt::decrypt_blob_dpapi(protected_blob);
```

## Audit Envelope Metadata
Inspect envelope metadata without decrypting:

```cpp
auto info = nigelcrypt::audit_envelope(blob);
```

## Decrypt Options (Memory Hardening)
You can control how plaintext buffers are allocated and whether AAD is required:

```cpp
nigelcrypt::DecryptOptions opt;
opt.buffer = nigelcrypt::BufferMode::VirtualGuarded; // adds a guard page
opt.require_aad = true; // refuse decrypt if AAD is empty

auto plain = s.decrypt("api:v1", opt);
```

`BufferMode::VirtualLocked` (default) uses `VirtualLock` when possible. If locking fails, it falls back to an unlocked allocation.

### Protect/Unprotect Plaintext Pages
You can temporarily protect decrypted buffers with `PAGE_NOACCESS`:

```cpp
auto plain = s.decrypt("api:v1", opt);
plain.protect();   // memory becomes inaccessible
plain.unprotect(); // restore access
```

### Decrypt Into Caller Buffer
For stack‑based buffers (no heap allocations):

```cpp
char buf[256] = {};
size_t n = s.decrypt_to(buf, sizeof(buf), "api:v1");
// use buf, then wipe if desired
```

### Hardened Defaults
You can opt into stricter defaults:

```cpp
auto policy = nigelcrypt::hardened_policy();
nigelcrypt::set_policy(policy);

auto opt = nigelcrypt::hardened_decrypt_options();
auto plain = s.decrypt("aad:packed", opt);
```

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
This is a github template, there was no assigned license.
