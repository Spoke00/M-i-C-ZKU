#ifndef ACCOUNT_H
#define ACCOUNT_H

#include "security.h"
#include <fstream>
#include <map>
#include <string>
#include <vector>

struct Profile {
    std::string phone;
    std::string card;
    std::string cvv;
    ~Profile();
};

bool validLogin(const std::string& value);
bool validPassword(const std::string& value);
bool normalizePhone(const std::string& input, std::string& output);
bool normalizeCard(const std::string& input, std::string& output);
bool validCvv(const std::string& value);
std::string mask(const std::string& value);
std::string fuzzCvv(const std::string& value);

class Logger {
    std::ofstream file;
    std::map<std::string, std::string> actors;
public:
    explicit Logger(const std::string& path);
    void write(const std::string& action, const std::string& login = "",
               const std::string& details = "");
};

class AccountStore {
    struct Record {
        std::string login;
        security::Bytes passwordSalt;
        security::Bytes passwordHash;
        security::Bytes keySalt;
        security::Encrypted profile;
    };
    std::string path;
    std::vector<Record> records;
    void load();
    void save(const std::vector<Record>& updated) const;
public:
    explicit AccountStore(const std::string& filename);
    bool exists(const std::string& login) const;
    bool create(const std::string& login, const std::string& password);
    bool authenticate(const std::string& login, const std::string& password,
                      security::Key& sessionKey, Profile& profile) const;
    void update(const std::string& login, const security::Key& sessionKey,
                const Profile& profile);
};

#endif
