#ifndef SECURITY_H
#define SECURITY_H

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace security {
using Bytes = std::vector<unsigned char>;
constexpr std::uint32_t iterations = 600000;

void wipe(std::string& text) noexcept;
void wipe(Bytes& bytes) noexcept;

struct Secret {
    std::string value;
    ~Secret() { wipe(value); }
};

struct Key {
    std::array<unsigned char, 32> value{};
    Key() = default;
    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;
    ~Key();
};

struct PrivateBuffer {
    Bytes value;
    ~PrivateBuffer() { wipe(value); }
};

struct Encrypted {
    Bytes nonce;
    Bytes tag;
    Bytes ciphertext;
};

Bytes randomBytes(std::size_t count);
void deriveKey(const std::string& password, const Bytes& salt, Key& key);
bool equal(const unsigned char* left, const unsigned char* right,
           std::size_t count) noexcept;
Encrypted encrypt(const Bytes& plaintext, const Key& key,
                  const std::string& account);
void decrypt(const Encrypted& input, const Key& key,
             const std::string& account, PrivateBuffer& output);
}

#endif
