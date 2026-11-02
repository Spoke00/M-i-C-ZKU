#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif
#include "account.h"
#include <algorithm>
#include <array>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <set>
#include <sstream>
#include <stdexcept>

namespace {
constexpr std::array<char, 8> magic{'S', 'A', 'C', 'C', 'T', '0', '0', '1'};
constexpr std::uint32_t maxAccounts = 10000;

bool digit(char c) { return c >= '0' && c <= '9'; }

void writeU32(std::ostream& out, std::uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) {
        out.put(static_cast<char>((value >> (i * 8)) & 255));
    }
}

std::uint32_t readU32(std::istream& in) {
    std::uint32_t result = 0;
    for (unsigned i = 0; i < 4; ++i) {
        int c = in.get();
        if (c == std::char_traits<char>::eof()) {
            throw std::runtime_error("Database is truncated.");
        }
        result |= static_cast<std::uint32_t>(c) << (i * 8);
    }
    return result;
}

security::Bytes readBytes(std::istream& in, std::size_t count) {
    security::Bytes result(count);
    if (!in.read(reinterpret_cast<char*>(result.data()),
                 static_cast<std::streamsize>(count))) {
        throw std::runtime_error("Database is truncated.");
    }
    return result;
}

void writeBytes(std::ostream& out, const security::Bytes& bytes) {
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
}

void serializeProfile(const Profile& profile, security::PrivateBuffer& buffer) {
    if ((!profile.phone.empty() && profile.phone.size() > 16) ||
        profile.card.size() > 19 || profile.cvv.size() > 4) {
        throw std::runtime_error("Profile field is too long.");
    }
    // One-byte lengths followed by bytes; the whole payload is encrypted.
    buffer.value.reserve(42);
    for (const auto* field : {&profile.phone, &profile.card, &profile.cvv}) {
        buffer.value.push_back(static_cast<unsigned char>(field->size()));
        buffer.value.insert(buffer.value.end(), field->begin(), field->end());
    }
}

void parseProfile(const security::PrivateBuffer& buffer, Profile& profile) {
    std::size_t offset = 0;
    Profile parsed;
    for (auto* field : {&parsed.phone, &parsed.card, &parsed.cvv}) {
        if (offset >= buffer.value.size()) {
            throw std::runtime_error("Invalid profile data.");
        }
        std::size_t length = buffer.value[offset++];
        if (length > buffer.value.size() - offset) {
            throw std::runtime_error("Invalid profile field length.");
        }
        field->assign(reinterpret_cast<const char*>(buffer.value.data() + offset), length);
        offset += length;
    }
    security::Secret normalized;
    if (offset != buffer.value.size() ||
        (!parsed.phone.empty() &&
         (!normalizePhone(parsed.phone, normalized.value) || normalized.value != parsed.phone)) ||
        (!parsed.card.empty() &&
         (!normalizeCard(parsed.card, normalized.value) || normalized.value != parsed.card)) ||
        (!parsed.cvv.empty() && !validCvv(parsed.cvv))) {
        throw std::runtime_error("Invalid profile values.");
    }
    profile = parsed;
}

std::string randomHex(std::size_t count) {
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    for (unsigned char c : security::randomBytes(count)) {
        result += hex[c >> 4];
        result += hex[c & 15];
    }
    return result;
}
}

Profile::~Profile() {
    security::wipe(phone);
    security::wipe(card);
    security::wipe(cvv);
}

bool validLogin(const std::string& value) {
    if (value.size() < 3 || value.size() > 32) return false;
    return std::all_of(value.begin(), value.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               digit(c) || c == '_' || c == '-' || c == '.';
    });
}

bool validPassword(const std::string& value) {
    return value.size() >= 8 && value.size() <= 128 &&
        std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return c >= 32 && c <= 126;
        });
}

bool normalizePhone(const std::string& input, std::string& output) {
    security::wipe(output);
    if (input.empty() || input.front() != '+') return false;
    output = "+";
    for (std::size_t i = 1; i < input.size(); ++i) {
        char c = input[i];
        if (digit(c)) output += c;
        else if (c != ' ' && c != '-' && c != '(' && c != ')') return false;
    }
    return output.size() >= 11 && output.size() <= 16 && output[1] != '0';
}

bool normalizeCard(const std::string& input, std::string& output) {
    security::wipe(output);
    for (char c : input) {
        if (digit(c)) output += c;
        else if (c != ' ' && c != '-') return false;
    }
    if (output.size() < 13 || output.size() > 19 || output.front() == '0') return false;
    int sum = 0;
    bool twice = false;
    for (auto it = output.rbegin(); it != output.rend(); ++it) {
        int n = *it - '0';
        if (twice) { n *= 2; if (n > 9) n -= 9; }
        sum += n;
        twice = !twice;
    }
    return sum % 10 == 0;
}

bool validCvv(const std::string& value) {
    return (value.size() == 3 || value.size() == 4) &&
           std::all_of(value.begin(), value.end(), digit);
}

std::string mask(const std::string& value) {
    if (value.empty()) return "[not set]";
    if (value.size() <= 4) return std::string(value.size(), '*');
    return std::string(value.size() - 4, '*') + value.substr(value.size() - 4);
}

std::string fuzzCvv(const std::string& value) {
    if (value.empty()) return "[not set]";
    std::string result(value.size(), '0');
    do {
        for (char& c : result) {
            unsigned char random;
            // Rejection sampling avoids modulo bias.
            do { random = security::randomBytes(1)[0]; } while (random >= 250);
            c = static_cast<char>('0' + random % 10);
        }
    } while (result == value);
    return result + " (synthetic)";
}

Logger::Logger(const std::string& path) : file(path, std::ios::app) {
    if (!file) throw std::runtime_error("Cannot open audit log.");
}

void Logger::write(const std::string& action, const std::string& login,
                   const std::string& details) {
    std::string actor = "guest";
    if (!login.empty()) {
        auto found = actors.find(login);
        if (found == actors.end()) {
            // Synthetic aliases stay consistent within this application run.
            found = actors.emplace(login, "user_" + randomHex(6)).first;
        }
        actor = found->second;
    }
    std::time_t now = std::time(nullptr);
    std::tm local{};
#ifdef _WIN32
    if (localtime_s(&local, &now) != 0) {
#else
    if (localtime_r(&now, &local) == nullptr) {
#endif
        throw std::runtime_error("Cannot get log timestamp.");
    }
    file << std::put_time(&local, "%Y-%m-%d %H:%M:%S")
         << " | " << action << " | actor=" << actor;
    if (!details.empty()) file << " | " << details;
    file << '\n';
    file.flush();
    if (!file) throw std::runtime_error("Cannot write audit log.");
}

AccountStore::AccountStore(const std::string& filename) : path(filename) { load(); }

bool AccountStore::exists(const std::string& login) const {
    for (const auto& record : records) {
        if (record.login == login) return true;
    }
    return false;
}

void AccountStore::load() {
    if (!std::filesystem::exists(path)) return;
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("Cannot open account database.");
    std::array<char, 8> header{};
    if (!in.read(header.data(), header.size()) || header != magic ||
        readU32(in) != security::iterations) {
        throw std::runtime_error("Unsupported or damaged database header.");
    }
    std::uint32_t count = readU32(in);
    if (count > maxAccounts) throw std::runtime_error("Database account limit exceeded.");
    std::set<std::string> names;
    for (std::uint32_t i = 0; i < count; ++i) {
        Record record;
        std::uint32_t length = readU32(in);
        if (length < 3 || length > 32) throw std::runtime_error("Invalid stored login length.");
        auto login = readBytes(in, length);
        record.login.assign(login.begin(), login.end());
        if (!validLogin(record.login) || !names.insert(record.login).second) {
            throw std::runtime_error("Invalid or duplicate stored login.");
        }
        record.passwordSalt = readBytes(in, 16);
        record.passwordHash = readBytes(in, 32);
        record.keySalt = readBytes(in, 16);
        record.profile.nonce = readBytes(in, 12);
        record.profile.tag = readBytes(in, 16);
        length = readU32(in);
        if (length < 3 || length > 256) throw std::runtime_error("Invalid encrypted profile length.");
        record.profile.ciphertext = readBytes(in, length);
        records.push_back(std::move(record));
    }
    if (in.peek() != std::char_traits<char>::eof()) {
        throw std::runtime_error("Unexpected bytes after database records.");
    }
}

void AccountStore::save(const std::vector<Record>& updated) const {
    std::string temporary = path + "." + randomHex(8) + ".tmp";
    try {
        std::ofstream out(temporary, std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("Cannot create temporary database.");
        out.write(magic.data(), magic.size());
        writeU32(out, security::iterations);
        writeU32(out, static_cast<std::uint32_t>(updated.size()));
        for (const Record& record : updated) {
            writeU32(out, static_cast<std::uint32_t>(record.login.size()));
            out.write(record.login.data(), static_cast<std::streamsize>(record.login.size()));
            writeBytes(out, record.passwordSalt);
            writeBytes(out, record.passwordHash);
            writeBytes(out, record.keySalt);
            writeBytes(out, record.profile.nonce);
            writeBytes(out, record.profile.tag);
            writeU32(out, static_cast<std::uint32_t>(record.profile.ciphertext.size()));
            writeBytes(out, record.profile.ciphertext);
        }
        out.flush();
        if (!out) throw std::runtime_error("Cannot write account database.");
        out.close();
        if (!out) throw std::runtime_error("Cannot close account database.");
#ifdef _WIN32
        if (!MoveFileExA(temporary.c_str(), path.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            throw std::runtime_error("Cannot replace account database.");
        }
#else
        std::filesystem::rename(temporary, path);
#endif
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        throw;
    }
}

bool AccountStore::create(const std::string& login, const std::string& password) {
    if (!validLogin(login) || !validPassword(password)) {
        throw std::runtime_error("Invalid registration values.");
    }
    if (exists(login)) return false;
    if (records.size() >= maxAccounts) throw std::runtime_error("Account limit reached.");
    Record record;
    record.login = login;
    record.passwordSalt = security::randomBytes(16);
    record.keySalt = security::randomBytes(16);
    security::Key verifier;
    security::deriveKey(password, record.passwordSalt, verifier);
    record.passwordHash.assign(verifier.value.begin(), verifier.value.end());
    security::Key encryptionKey;
    security::deriveKey(password, record.keySalt, encryptionKey);
    Profile empty;
    security::PrivateBuffer plaintext;
    serializeProfile(empty, plaintext);
    record.profile = security::encrypt(plaintext.value, encryptionKey, login);
    auto updated = records;
    updated.push_back(std::move(record));
    save(updated);
    records.swap(updated);
    return true;
}

bool AccountStore::authenticate(const std::string& login, const std::string& password,
                                security::Key& sessionKey, Profile& profile) const {
    const Record* found = nullptr;
    for (const auto& record : records) if (record.login == login) found = &record;
    // Unknown accounts still perform the expensive password derivation.
    security::Bytes salt = found ? found->passwordSalt : security::Bytes(16, 0);
    security::Key verifier;
    security::deriveKey(password, salt, verifier);
    if (!found || !security::equal(verifier.value.data(),
                                   found->passwordHash.data(), verifier.value.size())) return false;
    security::deriveKey(password, found->keySalt, sessionKey);
    security::PrivateBuffer plaintext;
    security::decrypt(found->profile, sessionKey, login, plaintext);
    parseProfile(plaintext, profile);
    return true;
}

void AccountStore::update(const std::string& login, const security::Key& sessionKey,
                          const Profile& profile) {
    auto updated = records;
    for (auto& record : updated) {
        if (record.login == login) {
            security::PrivateBuffer plaintext;
            serializeProfile(profile, plaintext);
            record.profile = security::encrypt(plaintext.value, sessionKey, login);
            save(updated);
            records.swap(updated);
            return;
        }
    }
    throw std::runtime_error("Account no longer exists.");
}
