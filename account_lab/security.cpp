#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include "security.h"
#include <stdexcept>

namespace security {
namespace {
void check(NTSTATUS status) {
    if (status < 0) {
        throw std::runtime_error("Cryptographic operation failed.");
    }
}

class Algorithm {
public:
    BCRYPT_ALG_HANDLE handle = nullptr;
    Algorithm(LPCWSTR name, ULONG flags = 0) {
        check(BCryptOpenAlgorithmProvider(&handle, name, nullptr, flags));
    }
    ~Algorithm() { if (handle) BCryptCloseAlgorithmProvider(handle, 0); }
    Algorithm(const Algorithm&) = delete;
    Algorithm& operator=(const Algorithm&) = delete;
};

class AesKey {
    Algorithm algorithm{BCRYPT_AES_ALGORITHM};
public:
    BCRYPT_KEY_HANDLE handle = nullptr;
    explicit AesKey(const Key& key) {
        check(BCryptSetProperty(algorithm.handle, BCRYPT_CHAINING_MODE,
              reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
              sizeof(BCRYPT_CHAIN_MODE_GCM), 0));
        check(BCryptGenerateSymmetricKey(algorithm.handle, &handle, nullptr, 0,
              const_cast<PUCHAR>(key.value.data()),
              static_cast<ULONG>(key.value.size()), 0));
    }
    ~AesKey() { if (handle) BCryptDestroyKey(handle); }
    AesKey(const AesKey&) = delete;
    AesKey& operator=(const AesKey&) = delete;
};
}

void wipe(std::string& text) noexcept {
    if (!text.empty()) SecureZeroMemory(text.data(), text.size());
    text.clear();
}

void wipe(Bytes& bytes) noexcept {
    if (!bytes.empty()) SecureZeroMemory(bytes.data(), bytes.size());
    bytes.clear();
}

Key::~Key() { SecureZeroMemory(value.data(), value.size()); }

Bytes randomBytes(std::size_t count) {
    if (count > 4096) throw std::runtime_error("Random request is too large.");
    Bytes result(count);
    check(BCryptGenRandom(nullptr, result.data(), static_cast<ULONG>(count),
                         BCRYPT_USE_SYSTEM_PREFERRED_RNG));
    return result;
}

void deriveKey(const std::string& password, const Bytes& salt, Key& key) {
    if (password.size() > 128 || salt.size() != 16) {
        throw std::runtime_error("Invalid key derivation parameters.");
    }
    Algorithm sha256(BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    check(BCryptDeriveKeyPBKDF2(sha256.handle,
          reinterpret_cast<PUCHAR>(const_cast<char*>(password.data())),
          static_cast<ULONG>(password.size()), const_cast<PUCHAR>(salt.data()),
          static_cast<ULONG>(salt.size()), iterations, key.value.data(),
          static_cast<ULONG>(key.value.size()), 0));
}

bool equal(const unsigned char* left, const unsigned char* right,
           std::size_t count) noexcept {
    volatile unsigned char difference = 0;
    for (std::size_t i = 0; i < count; ++i) {
        difference = static_cast<unsigned char>(difference | (left[i] ^ right[i]));
    }
    return difference == 0;
}

Encrypted encrypt(const Bytes& plaintext, const Key& key,
                  const std::string& account) {
    if (plaintext.empty() || plaintext.size() > 256 || account.size() > 32) {
        throw std::runtime_error("Invalid encryption input.");
    }
    AesKey aes(key);
    Encrypted result{randomBytes(12), Bytes(16), Bytes(plaintext.size())};
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = result.nonce.data();
    info.cbNonce = static_cast<ULONG>(result.nonce.size());
    info.pbTag = result.tag.data();
    info.cbTag = static_cast<ULONG>(result.tag.size());
    // Bind the encrypted profile to its account name.
    info.pbAuthData = reinterpret_cast<PUCHAR>(const_cast<char*>(account.data()));
    info.cbAuthData = static_cast<ULONG>(account.size());
    ULONG written = 0;
    check(BCryptEncrypt(aes.handle, const_cast<PUCHAR>(plaintext.data()),
          static_cast<ULONG>(plaintext.size()), &info, nullptr, 0,
          result.ciphertext.data(), static_cast<ULONG>(result.ciphertext.size()),
          &written, 0));
    if (written != result.ciphertext.size()) {
        throw std::runtime_error("Unexpected encryption output.");
    }
    return result;
}

void decrypt(const Encrypted& input, const Key& key,
             const std::string& account, PrivateBuffer& output) {
    if (input.nonce.size() != 12 || input.tag.size() != 16 ||
        input.ciphertext.empty() || input.ciphertext.size() > 256) {
        throw std::runtime_error("Invalid encrypted profile.");
    }
    AesKey aes(key);
    Bytes tag = input.tag;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(input.nonce.data());
    info.cbNonce = static_cast<ULONG>(input.nonce.size());
    info.pbTag = tag.data();
    info.cbTag = static_cast<ULONG>(tag.size());
    info.pbAuthData = reinterpret_cast<PUCHAR>(const_cast<char*>(account.data()));
    info.cbAuthData = static_cast<ULONG>(account.size());
    output.value.resize(input.ciphertext.size());
    ULONG written = 0;
    NTSTATUS status = BCryptDecrypt(aes.handle,
          const_cast<PUCHAR>(input.ciphertext.data()),
          static_cast<ULONG>(input.ciphertext.size()), &info, nullptr, 0,
          output.value.data(), static_cast<ULONG>(output.value.size()), &written, 0);
    if (status < 0 || written != output.value.size()) {
        wipe(output.value);
        throw std::runtime_error("Profile authentication failed: data may be damaged.");
    }
}
}

#else
#include "security.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <memory>
#include <stdexcept>

namespace security {
namespace {
void check(int status) {
    if (status != 1) throw std::runtime_error("Cryptographic operation failed.");
}
using Context = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
Context context() {
    Context result(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!result) throw std::runtime_error("Cannot allocate cipher context.");
    return result;
}
}

void wipe(std::string& text) noexcept {
    if (!text.empty()) OPENSSL_cleanse(text.data(), text.size());
    text.clear();
}
void wipe(Bytes& bytes) noexcept {
    if (!bytes.empty()) OPENSSL_cleanse(bytes.data(), bytes.size());
    bytes.clear();
}
Key::~Key() { OPENSSL_cleanse(value.data(), value.size()); }

Bytes randomBytes(std::size_t count) {
    if (count > 4096) throw std::runtime_error("Random request is too large.");
    Bytes result(count);
    if (count) check(RAND_bytes(result.data(), static_cast<int>(count)));
    return result;
}
void deriveKey(const std::string& password, const Bytes& salt, Key& key) {
    if (password.size() > 128 || salt.size() != 16) {
        throw std::runtime_error("Invalid key derivation parameters.");
    }
    check(PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
          salt.data(), static_cast<int>(salt.size()), static_cast<int>(iterations),
          EVP_sha256(), static_cast<int>(key.value.size()), key.value.data()));
}
bool equal(const unsigned char* left, const unsigned char* right,
           std::size_t count) noexcept {
    return CRYPTO_memcmp(left, right, count) == 0;
}
Encrypted encrypt(const Bytes& plaintext, const Key& key,
                  const std::string& account) {
    if (plaintext.empty() || plaintext.size() > 256 || account.size() > 32) {
        throw std::runtime_error("Invalid encryption input.");
    }
    auto ctx = context();
    Encrypted result{randomBytes(12), Bytes(16), Bytes(plaintext.size() + 16)};
    check(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr));
    check(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                             static_cast<int>(result.nonce.size()), nullptr));
    check(EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.value.data(), result.nonce.data()));
    int count = 0;
    check(EVP_EncryptUpdate(ctx.get(), nullptr, &count,
          reinterpret_cast<const unsigned char*>(account.data()), static_cast<int>(account.size())));
    check(EVP_EncryptUpdate(ctx.get(), result.ciphertext.data(), &count,
                            plaintext.data(), static_cast<int>(plaintext.size())));
    int total = count;
    check(EVP_EncryptFinal_ex(ctx.get(), result.ciphertext.data() + total, &count));
    total += count;
    if (total != static_cast<int>(plaintext.size())) {
        throw std::runtime_error("Unexpected encryption output.");
    }
    result.ciphertext.resize(static_cast<std::size_t>(total));
    check(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                             static_cast<int>(result.tag.size()), result.tag.data()));
    return result;
}
void decrypt(const Encrypted& input, const Key& key,
             const std::string& account, PrivateBuffer& output) {
    if (input.nonce.size() != 12 || input.tag.size() != 16 ||
        input.ciphertext.empty() || input.ciphertext.size() > 256 || account.size() > 32) {
        throw std::runtime_error("Invalid encrypted profile.");
    }
    wipe(output.value);
    auto ctx = context();
    try {
        check(EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr));
        check(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                                 static_cast<int>(input.nonce.size()), nullptr));
        check(EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.value.data(), input.nonce.data()));
        int count = 0;
        check(EVP_DecryptUpdate(ctx.get(), nullptr, &count,
              reinterpret_cast<const unsigned char*>(account.data()), static_cast<int>(account.size())));
        output.value.resize(input.ciphertext.size() + 16);
        check(EVP_DecryptUpdate(ctx.get(), output.value.data(), &count,
                               input.ciphertext.data(), static_cast<int>(input.ciphertext.size())));
        int total = count;
        Bytes tag = input.tag;
        check(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                                 static_cast<int>(tag.size()), tag.data()));
        if (EVP_DecryptFinal_ex(ctx.get(), output.value.data() + total, &count) != 1) {
            throw std::runtime_error("Profile authentication failed: data may be damaged.");
        }
        total += count;
        if (total != static_cast<int>(input.ciphertext.size())) {
            throw std::runtime_error("Unexpected decryption output.");
        }
        output.value.resize(static_cast<std::size_t>(total));
    } catch (...) {
        wipe(output.value);
        throw;
    }
}
}
#endif
