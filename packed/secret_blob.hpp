#pragma once
#include <array>
#include <cstdint>

// Placeholder. Generate a real blob with tools/nigelcrypt_pack.
namespace nigelcrypt_packed {
inline constexpr uint32_t secret_iterations = 1000000;
inline constexpr uint32_t secret_key_id = 1;
inline constexpr std::array<uint8_t, 16> secret_salt = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};
inline constexpr std::array<uint8_t, 0> secret_blob = {};
// Optional custom metadata is carried inside the envelope when generated.
} // namespace nigelcrypt_packed
