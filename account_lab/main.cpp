#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <conio.h>
#include <io.h>
#else
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/file.h>
#endif
#include "account.h"
#include <algorithm>
#include <cstdio>
#include <iostream>
#include <stdexcept>

namespace {
struct InputClosed {};

#ifndef _WIN32
class HiddenTerminal {
    termios saved{};
    bool active = false;
public:
    explicit HiddenTerminal(bool enabled) {
        if (!enabled) return;
        if (tcgetattr(STDIN_FILENO, &saved) != 0) {
            throw std::runtime_error("Cannot read terminal settings.");
        }
        termios mode = saved;
        mode.c_lflag &= static_cast<tcflag_t>(~(ECHO | ICANON | ISIG));
        mode.c_cc[VMIN] = 1;
        mode.c_cc[VTIME] = 0;
        if (tcsetattr(STDIN_FILENO, TCSANOW, &mode) != 0) {
            throw std::runtime_error("Cannot hide terminal input.");
        }
        active = true;
    }
    ~HiddenTerminal() {
        if (active) tcsetattr(STDIN_FILENO, TCSANOW, &saved);
    }
    HiddenTerminal(const HiddenTerminal&) = delete;
    HiddenTerminal& operator=(const HiddenTerminal&) = delete;
};
#endif

void cabinet(AccountStore& store, Logger& log, const std::string& login,
             const security::Key& key, Profile& profile);

bool readInput(const std::string& prompt, security::Secret& output, bool hidden = false) {
    std::cout << prompt << std::flush;
    security::wipe(output.value);
    output.value.reserve(256);
    bool overflow = false;
#ifdef _WIN32
    bool console = hidden && _isatty(_fileno(stdin));
#else
    bool console = hidden && isatty(STDIN_FILENO);
    HiddenTerminal terminal(console);
#endif
    while (true) {
#ifdef _WIN32
        int c = console ? _getch() : std::cin.get();
#else
        int c = std::cin.get();
        if (console && c == 4) throw InputClosed{};
#endif
        if (c == EOF || (console && (c == 3 || c == 26))) {
            std::cout << '\n';
            throw InputClosed{};
        }
#ifdef _WIN32
        if (console && (c == 0 || c == 224)) { _getch(); continue; }
#endif
        if (c == '\n' || (console && c == '\r')) break;
        if (!console && c == '\r') continue;
        if (console && (c == '\b' || c == 127)) {
            if (!overflow && !output.value.empty()) {
                output.value.back() = '\0';
                output.value.pop_back();
                std::cout << "\b \b" << std::flush;
            }
            continue;
        }
        if (output.value.size() == 256) { overflow = true; continue; }
        output.value += static_cast<char>(c);
        if (console) std::cout << '*' << std::flush;
    }
    if (console) std::cout << '\n';
    if (overflow) security::wipe(output.value);
    return !overflow;
}

void registerAccount(AccountStore& store, Logger& log) {
    log.write("REGISTER_OPEN");
    security::Secret login;
    while (true) {
        bool fits = readInput("New login (3-32 letters, digits, _, -, .; Enter to cancel): ", login);
        if (fits && login.value.empty()) {
            log.write("REGISTER_CANCELLED", "", "reason=empty_login");
            std::cout << "Registration cancelled.\n";
            return;
        }
        if (!fits || !validLogin(login.value)) {
            log.write("REGISTER_REJECTED", "", "reason=invalid_login");
            std::cout << "Invalid login. Use 3-32 English letters, digits, _, - or .\n";
            continue;
        }
        log.write("REGISTER_LOGIN_ENTERED", login.value);
        if (store.exists(login.value)) {
            log.write("REGISTER_REJECTED", login.value, "reason=login_already_exists");
            std::cout << "Login already exists. Choose another login.\n";
            continue;
        }
        break;
    }

    security::Secret password, confirmation;
    while (true) {
        bool fits = readInput("Password (8-128 printable ASCII characters; Enter to cancel): ", password);
        if (fits && password.value.empty()) {
            log.write("REGISTER_CANCELLED", login.value, "reason=empty_password");
            std::cout << "Registration cancelled.\n";
            return;
        }
        if (!fits || !validPassword(password.value)) {
            log.write("REGISTER_REJECTED", login.value, "reason=invalid_password_format");
            std::cout << "Invalid password. Use 8-128 printable ASCII characters.\n";
            continue;
        }
        log.write("REGISTER_PASSWORD_ENTERED", login.value, "password=[not logged]");
        break;
    }

    while (true) {
        bool fits = readInput("Confirm password (Enter to cancel): ", confirmation, true);
        if (fits && confirmation.value.empty()) {
            log.write("REGISTER_CANCELLED", login.value, "reason=empty_confirmation");
            std::cout << "Registration cancelled.\n";
            return;
        }
        if (!fits || confirmation.value != password.value) {
            log.write("REGISTER_REJECTED", login.value, "reason=password_mismatch");
            std::cout << "Passwords do not match. Try again.\n";
            continue;
        }
        log.write("REGISTER_CONFIRMATION_ENTERED", login.value, "password=[not logged]");
        break;
    }

    bool created = store.create(login.value, password.value);
    log.write(created ? "REGISTER_SUCCESS" : "REGISTER_REJECTED", login.value,
              created ? "" : "reason=login_already_exists");
    if (!created) {
        std::cout << "Login already exists.\n";
        return;
    }
    security::Key key;
    Profile profile;
    if (!store.authenticate(login.value, password.value, key, profile)) {
        throw std::runtime_error("Unable to sign in to the newly created account.");
    }
    security::wipe(password.value);
    security::wipe(confirmation.value);
    log.write("LOGIN_SUCCESS", login.value, "method=automatic_after_registration");
    std::cout << "Account created. Signed in automatically.\n";
    cabinet(store, log, login.value, key, profile);
}

void cabinet(AccountStore& store, Logger& log, const std::string& login,
             const security::Key& key, Profile& profile) {
    try {
        while (true) {
            std::cout << "\n--- Personal account ---\n"
                      << "1. View profile\n2. Update phone\n3. Update bank card\n"
                      << "4. Update CVV\n0. Sign out\n";
            security::Secret choice;
            if (!readInput("Choice: ", choice)) {
                log.write("MENU_REJECTED", login, "reason=input_too_long");
                std::cout << "Input is too long.\n";
                continue;
            }
            if (choice.value == "0") {
                log.write("LOGOUT", login);
                return;
            }
            if (choice.value == "1") {
                log.write("PROFILE_VIEW", login, "phone=" + mask(profile.phone) +
                          "; card=" + mask(profile.card) + "; cvv=" + fuzzCvv(profile.cvv));
                std::cout << "Phone: " << mask(profile.phone)
                          << "\nBank card: " << mask(profile.card)
                          << "\nCVV: " << (profile.cvv.empty() ? "[not set]" : "[hidden]") << '\n';
                continue;
            }
            if (choice.value != "2" && choice.value != "3" && choice.value != "4") {
                log.write("MENU_REJECTED", login, "reason=unknown_choice");
                std::cout << "Unknown menu option.\n";
                continue;
            }
            const std::string field = choice.value == "2" ? "phone" :
                                      choice.value == "3" ? "card" : "cvv";
            log.write("PROFILE_EDIT_OPEN", login, "field=" + field);
            security::Secret input, normalized;
            std::string prompt = field == "phone" ? "Phone (10 digits, without +7 or 8): " :
                                 field == "card" ? "Bank card (13-19 digits, Luhn checksum): " :
                                                   "CVV (3 or 4 digits): ";
            bool valid = readInput(prompt, input);
            if (valid && input.value.empty()) {
                log.write("PROFILE_EDIT_CANCELLED", login, "field=" + field);
                std::cout << "Update cancelled.\n";
                continue;
            }
            if (valid) {
                if (field == "phone") {
                    valid = input.value.size() == 10 &&
                        std::all_of(input.value.begin(), input.value.end(), [](char c) {
                            return c >= '0' && c <= '9';
                        });
                    if (valid) normalized.value = "+7" + input.value;
                }
                else if (field == "card") valid = normalizeCard(input.value, normalized.value);
                else { valid = validCvv(input.value); normalized.value = input.value; }
            }
            if (!valid) {
                log.write("PROFILE_EDIT_REJECTED", login, "field=" + field + "; reason=invalid_format");
                if (field == "phone") std::cout << "Invalid phone. Enter exactly 10 digits without +7 or 8.\n";
                else if (field == "card") std::cout << "Invalid card. Enter 13-19 digits with a valid Luhn checksum.\n";
                else std::cout << "Invalid CVV. Enter 3 or 4 digits.\n";
                continue;
            }
            Profile updated = profile;
            if (field == "phone") { security::wipe(updated.phone); updated.phone = normalized.value; }
            else if (field == "card") { security::wipe(updated.card); updated.card = normalized.value; }
            else { security::wipe(updated.cvv); updated.cvv = normalized.value; }
            // Write the sanitized intent before changing the database.
            const std::string safe = field == "cvv" ? fuzzCvv(normalized.value) : mask(normalized.value);
            log.write("PROFILE_UPDATE_REQUEST", login, field + "=" + safe);
            store.update(login, key, updated);
            profile = updated;
            log.write("PROFILE_UPDATE_SUCCESS", login, "field=" + field);
            std::cout << "Saved.\n";
        }
    } catch (const InputClosed&) {
        log.write("LOGOUT", login, "reason=input_closed");
        throw;
    }
}

void signIn(AccountStore& store, Logger& log) {
    log.write("LOGIN_OPEN");
    security::Secret login, password;
    if (!readInput("Login: ", login) || !validLogin(login.value)) {
        log.write("LOGIN_FAILED", "", "reason=invalid_login_format");
        std::cout << "Invalid login or password.\n";
        return;
    }
    log.write("LOGIN_NAME_ENTERED", login.value);
    if (!readInput("Password: ", password) || !validPassword(password.value)) {
        log.write("LOGIN_FAILED", login.value, "reason=invalid_credentials");
        std::cout << "Invalid login or password.\n";
        return;
    }
    log.write("LOGIN_ATTEMPT", login.value, "password=[not logged]");
    security::Key key;
    Profile profile;
    if (!store.authenticate(login.value, password.value, key, profile)) {
        log.write("LOGIN_FAILED", login.value, "reason=invalid_credentials");
        std::cout << "Invalid login or password.\n";
        return;
    }
    security::wipe(password.value);
    log.write("LOGIN_SUCCESS", login.value);
    std::cout << "Signed in.\n";
    cabinet(store, log, login.value, key, profile);
}
}

int main() {
    // Prevent concurrent instances from overwriting each other's records.
#ifdef _WIN32
    HANDLE lock = CreateMutexW(nullptr, TRUE, L"Local\\SecureAccountLab_v1");
    if (!lock || GetLastError() == ERROR_ALREADY_EXISTS) {
        std::cerr << "Cannot start: another instance is running or the lock is unavailable.\n";
        if (lock) CloseHandle(lock);
        return 1;
    }
#else
    int lock = open(".account_lab.lock", O_CREAT | O_RDWR, 0600);
    if (lock < 0 || flock(lock, LOCK_EX | LOCK_NB) != 0) {
        std::cerr << "Cannot start: this database is in use or the lock is unavailable.\n";
        if (lock >= 0) close(lock);
        return 1;
    }
#endif
    int result = 0;
    try {
        Logger log("audit.log");
        log.write("APPLICATION_START");
        try {
            AccountStore store("accounts.bin");
            std::cout << "Secure Account Lab\nUse fictional training data only.\n"
                      << "Storage: accounts.bin | Audit: audit.log\n";
            while (true) {
                std::cout << "\n--- Main menu ---\n1. Create account\n2. Sign in\n0. Exit\n";
                security::Secret choice;
                if (!readInput("Choice: ", choice)) {
                    log.write("MENU_REJECTED", "", "reason=input_too_long");
                    std::cout << "Input is too long.\n";
                    continue;
                }
                if (choice.value == "0") { log.write("APPLICATION_EXIT"); break; }
                if (choice.value == "1") registerAccount(store, log);
                else if (choice.value == "2") signIn(store, log);
                else {
                    log.write("MENU_REJECTED", "", "reason=unknown_choice");
                    std::cout << "Unknown menu option.\n";
                }
            }
        } catch (const InputClosed&) {
            log.write("APPLICATION_EXIT", "", "reason=input_closed");
        } catch (const std::exception&) {
            // Exception text is not copied into the log to avoid data leaks.
            log.write("APPLICATION_ERROR", "", "reason=storage_or_crypto_failure; application_stopped");
            throw;
        }
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        result = 1;
    }
#ifdef _WIN32
    ReleaseMutex(lock);
    CloseHandle(lock);
#else
    flock(lock, LOCK_UN);
    close(lock);
#endif
    return result;
}
