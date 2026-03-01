#include "nigelcrypt.hpp"

#include <iostream>
#include <memory>

// Example usage and notes for NigelCrypt.
//
// Notes:
// - String literals are still embedded in your binary. This library protects
//   runtime storage, not compile-time literals.
// - Decryption returns a SecureStringView that zeroes its buffer on destruction.
// - Use AAD to bind decryption to a context (must match for decrypt).
// - Use the key ring for rotation; each SecureString stores a key_id.
// - ChaCha20-Poly1305 requires a Windows version that exposes
//   BCRYPT_CHACHA20_POLY1305_ALGORITHM.
//
// Build (MSVC):
//   cl /std:c++20 /EHsc example.cpp
//
// Build (CMake-less, MinGW, etc.) make sure to link:
//   bcrypt.lib and crypt32.lib (MSVC) or -lbcrypt -lcrypt32 (MinGW).

int main() {
    using nigelcrypt::Algorithm;
    using nigelcrypt::CachedKeyProvider;
    using nigelcrypt::DpapiKeyProvider;
    using nigelcrypt::KeyScope;
    using nigelcrypt::SecureString;

    // Optionally configure a cached DPAPI provider to avoid frequent DPAPI calls.
    // The primary provider is used for new encryptions.
    auto dpapi = std::make_shared<DpapiKeyProvider>(KeyScope::CurrentUser, true, 1);
    auto cached = std::make_shared<CachedKeyProvider>(dpapi, CachedKeyProvider::kForever);
    nigelcrypt::set_key_provider(cached);

    // Basic encryption/decryption with default algorithm (AES-256-GCM).
    SecureString api_key("Sensitive API Key");
    {
        auto plain = api_key.decrypt();
        std::cout << "API key: " << plain.c_str() << "\n";
        // plain is wiped when it goes out of scope
    }

    // Use Associated Data (AAD) to bind decryption to a context.
    SecureString token("token-value", "api:v1");
    {
        auto plain = token.decrypt("api:v1");
        std::cout << "Token: " << plain.c_str() << "\n";
    }

    // Select ChaCha20-Poly1305 (if supported by your Windows CNG build).
    SecureString chacha_secret("chacha-secret", {}, Algorithm::ChaCha20Poly1305);
    {
        auto plain = chacha_secret.decrypt();
        std::cout << "ChaCha: " << plain.c_str() << "\n";
    }

    // Export/import envelope for persistence or transport.
    auto envelope = api_key.export_envelope();
    auto imported = SecureString::import_envelope(envelope);
    {
        auto plain = imported.decrypt();
        std::cout << "Imported: " << plain.c_str() << "\n";
    }

    // Key rotation example: add another provider with a different key_id.
    // New encryptions use the primary provider. Old data can still decrypt
    // if the old provider remains registered in the key ring.
    auto& ring = nigelcrypt::key_ring();
    ring.add_provider(std::make_shared<DpapiKeyProvider>(KeyScope::CurrentUser, true, 2));

    return 0;
}
