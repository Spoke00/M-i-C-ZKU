# Secure Account Lab

Interactive C++17 console application with registration, authentication, a personal account and readable audit logging.

## Features

- Unique logins; passwords of 8-128 printable ASCII characters.
- Automatic sign-in after registration.
- Visible password entry and masked password confirmation.
- Phone input: exactly 10 digits without +7 or 8; +7 is added when saving.
- Bank card validation using the Luhn checksum; CVV of 3 or 4 digits.
- Binary account storage with PBKDF2-HMAC-SHA-256 password verification, random salts and 600,000 iterations.
- AES-256-GCM encryption of phone, card and CVV using a separately salted password-derived key.
- Masked phone/card values and synthetic login/CVV values in audit logs.
- Windows BCrypt and Linux OpenSSL implementations in the same five C++ source/header files.

Use fictional training data. This is an educational application.

## Docker

Start Docker Desktop in Linux container mode. From the repository root:

    cd account_lab
    docker compose build
    docker compose run --rm account-lab

For later launches, repeat only the run command. Rebuild after changing C++ code.
Choose 0 to sign out, then 0 in the main menu to exit.

The project directory is mounted at /data. The program creates accounts.bin
and audit.log in this directory. These files survive container removal and
are excluded from Git and the Docker build context. Existing Windows account
databases have the same format.

Run only one version at a time. Close the Windows executable before starting
the container against the same database.

## Windows build

With MinGW-w64, run from account_lab:

    g++ -std=c++17 -O2 -Wall -Wextra -static main.cpp account.cpp security.cpp -o account_lab.exe -lbcrypt
    .\account_lab.exe

## Linux build

Install g++ and the OpenSSL development package, then run from account_lab:

    g++ -std=c++17 -O2 -Wall -Wextra main.cpp account.cpp security.cpp -o account_lab -lcrypto
    ./account_lab

## Files

| File | Purpose |
| --- | --- |
| main.cpp | Interactive menus and input |
| account.h | Profile, storage and logger declarations |
| account.cpp | Binary database, input validation and audit logging |
| security.h | Cryptography declarations |
| security.cpp | Password derivation and authenticated encryption |
| Dockerfile | Multi-stage Linux image build |
| compose.yaml | Interactive terminal and persistent host directory |
| .dockerignore | Restricts the image build context to source/build files |
| .gitignore | Excludes local databases, logs, binaries and secrets |

## Verification

Registration, duplicate-login rejection, wrong-password rejection, saved profiles
after restart and masked/synthetic logs were checked during development.
Docker build and interactive execution were confirmed by the project owner.
