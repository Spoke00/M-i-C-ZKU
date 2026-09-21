# Cryptography Lab Tasks

This repository contains two console applications for text encryption/decryption, implemented in C++.

## Tasks

### Task 1 — Caesar Cipher
A classic shift cipher supporting:
- Russian and English alphabets
- Custom user-defined alphabets
- Interactive CLI and command-line modes

### Task 2 — Substitution Cipher
A monoalphabetic substitution cipher with:
- Random key generation
- Key persistence via `key.txt`
- Interactive menu and CLI modes

## Build & Run

### Without Docker
```bash
g++ task1.cpp -o task1.exe -fexec-charset=CP1251
g++ task2.cpp -o task2.exe -fexec-charset=CP1251
./task1.exe
./task2.exe