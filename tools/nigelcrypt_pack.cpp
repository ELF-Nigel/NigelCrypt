#include "../nigelcrypt.hpp"

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

static void usage() {
    std::cout
        << "NigelCrypt packer\n"
        << "Usage:\n"
        << "  nigelcrypt_pack --in <file> --out <header> --name <symbol> --pass-env <VAR> [options]\n"
        << "Options:\n"
        << "  --alg <aes|chacha>        Algorithm (default: aes)\n"
        << "  --aad <text>              Optional associated data\n"
        << "  --iterations <n>          PBKDF2 iterations (default: 200000)\n"
        << "  --key-id <n>              Key id stored in envelope (default: 1)\n"
        << "  --salt-hex <hex>          16-byte salt in hex (default: random)\n"
        << "  --binding <none|process>  Runtime binding mode (default: none)\n"
        << "\nNotes:\n"
        << "- Passphrase is read from environment via --pass-env. Avoid passing on the command line.\n"
        << "- Output header contains ciphertext only (no plaintext).\n";
}

static bool read_file(const std::string& path, std::string& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}

static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("salt hex length must be even");
    }
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        auto nibble = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(10 + (c - 'a'));
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(10 + (c - 'A'));
            throw std::runtime_error("invalid hex");
        };
        uint8_t b = (nibble(hex[i]) << 4) | nibble(hex[i + 1]);
        out.push_back(b);
    }
    return out;
}

static void write_header(
    const std::string& out_path,
    const std::string& name,
    const std::vector<uint8_t>& blob,
    const std::vector<uint8_t>& salt,
    uint32_t iterations,
    uint32_t key_id
) {
    std::ofstream out(out_path, std::ios::binary);
    if (!out) {
        throw std::runtime_error("failed to open output header");
    }

    out << "#pragma once\n";
    out << "#include <array>\n";
    out << "#include <cstdint>\n\n";
    out << "namespace nigelcrypt_packed {\n";

    out << "inline constexpr uint32_t " << name << "_iterations = " << iterations << ";\n";
    out << "inline constexpr uint32_t " << name << "_key_id = " << key_id << ";\n";

    out << "inline constexpr std::array<uint8_t, " << salt.size() << "> " << name << "_salt = {";
    for (size_t i = 0; i < salt.size(); ++i) {
        out << static_cast<unsigned>(salt[i]);
        if (i + 1 != salt.size()) out << ",";
    }
    out << "};\n";

    out << "inline constexpr std::array<uint8_t, " << blob.size() << "> " << name << "_blob = {";
    for (size_t i = 0; i < blob.size(); ++i) {
        out << static_cast<unsigned>(blob[i]);
        if (i + 1 != blob.size()) out << ",";
    }
    out << "};\n";

    out << "} // namespace nigelcrypt_packed\n";
}

int main(int argc, char** argv) {
    std::string in_path;
    std::string out_path;
    std::string name;
    std::string pass_env;
    std::string aad;
    std::string alg = "aes";
    std::string salt_hex;
    std::string binding = "none";
    uint32_t iterations = 200000;
    uint32_t key_id = 1;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto need = [&](const char* opt) -> std::string {
            if (i + 1 >= argc) {
                throw std::runtime_error(std::string("Missing value for ") + opt);
            }
            return argv[++i];
        };

        if (arg == "--in") in_path = need("--in");
        else if (arg == "--out") out_path = need("--out");
        else if (arg == "--name") name = need("--name");
        else if (arg == "--pass-env") pass_env = need("--pass-env");
        else if (arg == "--aad") aad = need("--aad");
        else if (arg == "--alg") alg = need("--alg");
        else if (arg == "--iterations") iterations = static_cast<uint32_t>(std::stoul(need("--iterations")));
        else if (arg == "--key-id") key_id = static_cast<uint32_t>(std::stoul(need("--key-id")));
        else if (arg == "--salt-hex") salt_hex = need("--salt-hex");
        else if (arg == "--binding") binding = need("--binding");
        else if (arg == "--help" || arg == "-h") {
            usage();
            return 0;
        } else {
            throw std::runtime_error("Unknown argument: " + arg);
        }
    }

    if (in_path.empty() || out_path.empty() || name.empty() || pass_env.empty()) {
        usage();
        return 2;
    }

    std::string passphrase;
    {
        const char* p = std::getenv(pass_env.c_str());
        if (!p || !*p) {
            throw std::runtime_error("Passphrase env var not set: " + pass_env);
        }
        passphrase = p;
    }

    std::string plaintext;
    if (!read_file(in_path, plaintext)) {
        throw std::runtime_error("Failed to read input file");
    }

    std::vector<uint8_t> salt;
    if (!salt_hex.empty()) {
        salt = hex_to_bytes(salt_hex);
    } else {
        salt.resize(16);
        nigelcrypt::detail::gen_random(salt.data(), salt.size());
    }

    nigelcrypt::Algorithm algorithm = nigelcrypt::Algorithm::Aes256Gcm;
    if (alg == "aes") {
        algorithm = nigelcrypt::Algorithm::Aes256Gcm;
    } else if (alg == "chacha") {
        algorithm = nigelcrypt::Algorithm::ChaCha20Poly1305;
    } else {
        throw std::runtime_error("Unknown algorithm: " + alg);
    }

    nigelcrypt::RuntimeBinding bind = nigelcrypt::RuntimeBinding::None;
    if (binding == "none") {
        bind = nigelcrypt::RuntimeBinding::None;
    } else if (binding == "process") {
        bind = nigelcrypt::RuntimeBinding::Process;
    } else {
        throw std::runtime_error("Unknown binding: " + binding);
    }

    auto provider = std::make_shared<nigelcrypt::PasswordKeyProvider>(passphrase, salt, iterations, key_id);
    nigelcrypt::set_key_provider(provider);

    nigelcrypt::SecureString s(plaintext, aad, algorithm, bind);
    auto blob = s.export_envelope();

    write_header(out_path, name, blob, salt, iterations, key_id);

    return 0;
}
